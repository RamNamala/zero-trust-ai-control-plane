"""Adversarial review: attempts to break each task from the outside.

Every test states the behaviour a hostile or buggy peer should get. Tests that fail on the
pre-hardening code mark real findings (see PITFALLS #49-#55). The rest are probes that held,
kept as regression guards.
"""

from __future__ import annotations

import ast
import asyncio
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from conftest import FakeClock
from test_task1_mcp_server import McpStdioProc, t1  # noqa: F401 - fixture re-export
from test_task2_mcp_gateway import (  # noqa: F401 - fixture re-export
    Gateway,
    GatewayFactory,
    call,
    get_record,
    gw,
    make_gateway,
    mint,
    rpc,
)
from test_task4_router import LEAK_MARKERS, REQUEST, TENANT, _fast, _post, router

from control_plane.common.settings import Settings
from control_plane.task3_streaming_guardrail.gateway import guard_events, redact_completion_body
from control_plane.task3_streaming_guardrail.patterns import REDACTED, redact
from control_plane.task3_streaming_guardrail.redactor import StreamingPIIRedactor
from control_plane.task3_streaming_guardrail.sse import DONE, SSEEvent, iter_sse
from control_plane.task4_resilient_router.providers import (
    ChatRequest,
    CompletionResult,
    HttpProvider,
    MockProvider,
)
from control_plane.task4_resilient_router.rate_limiter import (
    RateLimitExceededError,
    SQLiteRateLimiter,
)
from control_plane.task4_resilient_router.tokens import estimate_prompt_tokens

SRC = Path(__file__).resolve().parents[1] / "src" / "control_plane"
CARD = "4111111111111111"
SSN = "123-45-6789"
EMAIL = "sarah.connor@cyberdyne.io"


# =========================================================================== T1 - stdio server


def _raw_call(id_: int, name_json: str, arguments_json: str | None) -> bytes:
    params = f'{{"name":{name_json}' + (
        f',"arguments":{arguments_json}}}' if arguments_json is not None else "}"
    )
    return f'{{"jsonrpc":"2.0","id":{id_},"method":"tools/call","params":{params}}}'.encode()


_HUGE = "A" * 100_000
T1_ODD_ARGUMENTS: list[tuple[str, str | None]] = [
    ('"get_customer_record"', None),  # arguments missing
    ('"get_customer_record"', "null"),
    ('"get_customer_record"', "[]"),
    ('"get_customer_record"', '"CUST-10042"'),
    ('"get_customer_record"', "42"),
    ('"get_customer_record"', '{"customer_id":["CUST-10042"]}'),
    ('"get_customer_record"', '{"customer_id":{"id":"CUST-10042"}}'),
    ('"get_customer_record"', '{"customer_id":10042}'),
    ('"get_customer_record"', '{"customer_id":null}'),
    ('"get_customer_record"', '{"customer_id":true}'),
    ('"get_customer_record"', '{"customer_id":"CUST-10042\\n"}'),
    ('"get_customer_record"', f'{{"customer_id":"CUST-{_HUGE}"}}'),
    ('"get_customer_record"', '{"customer_id":"CUST-\\uff11\\uff10\\uff10\\uff14\\uff12"}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":1e309,"reason":"damaged item"}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":-1e309,"reason":"damaged item"}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":-0.0,"reason":"damaged item"}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":1e-320,"reason":"damaged item"}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":[50],"reason":"damaged item"}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":{"v":50},"reason":"damaged item"}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":"50","reason":"damaged item"}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":true,"reason":"damaged item"}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":null,"reason":"damaged item"}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":50,"reason":["damaged item"]}'),
    ('"trigger_refund"', '{"customer_id":"CUST-10042","amount":50,"reason":12345678901}'),
    ('"trigger_refund"', f'{{"customer_id":"CUST-10042","amount":50,"reason":"{_HUGE}"}}'),
    ("123", "{}"),
    ("null", "{}"),
    ('["admin_reset_key"]', "{}"),
    ('{"n":"get_customer_record"}', "{}"),
]


@pytest.mark.subprocess
async def test_t1_odd_json_types_are_32602_and_never_echoed(t1: McpStdioProc) -> None:  # noqa: F811
    for i, (name_json, args_json) in enumerate(T1_ODD_ARGUMENTS):
        await t1.send_raw(_raw_call(5000 + i, name_json, args_json))
        response = await t1.recv_id(5000 + i)
        case = f"name={name_json[:40]} arguments={(args_json or '<missing>')[:60]}"
        assert "result" not in response, case
        assert response["error"]["code"] == -32602, case
        assert len(json.dumps(response)) < 4_000, f"input echoed back: {case}"
    assert _HUGE not in t1.stderr_text  # nor logged


# Frames the SDK can't turn into a request. JSON-RPC 2.0 still owes an error *response*
# (-32700 for unparseable text, -32600 for a structurally invalid request), not a log
# notification, or a client waiting on the request hangs.
T1_UNPARSEABLE: list[tuple[bytes, int]] = [
    (b"{not json", -32700),
    (b"\xff\xfe", -32700),
    # A lone surrogate is valid JSON syntax but not valid Unicode; the SDK's parser rejects it.
    (
        b'{"jsonrpc":"2.0","id":6001,"method":"tools/call","params":{"name":"trigger_refund",'
        b'"arguments":{"customer_id":"CUST-10042","amount":50,"reason":"damaged \\ud800 item"}}}',
        -32700,
    ),
    (b'{"jsonrpc":"2.0","id":6002}', -32600),
    (b'"just a string"', -32600),
    (b"[]", -32600),
    (b'[{"jsonrpc":"2.0","id":6003,"method":"tools/list"}]', -32600),
]


@pytest.mark.subprocess
@pytest.mark.parametrize(("frame", "code"), T1_UNPARSEABLE, ids=lambda v: repr(v)[:30])
async def test_t1_unparseable_frames_get_a_jsonrpc_error_response(
    t1: McpStdioProc,  # noqa: F811
    frame: bytes,
    code: int,
) -> None:
    await t1.send_raw(frame)
    response = await t1.recv()
    assert response.get("method") is None, f"got a notification instead of a response: {response}"
    assert response["error"]["code"] == code and "id" in response
    assert "damaged" not in json.dumps(response)  # the frame is never echoed


@pytest.mark.subprocess
async def test_t1_concurrent_requests_on_one_session(t1: McpStdioProc) -> None:  # noqa: F811
    customers = ("CUST-10042", "CUST-20017", "CUST-30555")
    ids = list(range(7000, 7060))
    for id_ in ids:  # all written before any reply is read
        cid = customers[id_ % 3]
        await t1.send(
            {
                "jsonrpc": "2.0",
                "id": id_,
                "method": "tools/call",
                "params": {"name": "get_customer_record", "arguments": {"customer_id": cid}},
            }
        )
    seen: dict[int, dict[str, Any]] = {}
    while len(seen) < len(ids):
        message = await t1.recv()
        seen[message["id"]] = message
    for id_ in ids:
        record = seen[id_]["result"]["structuredContent"]
        assert record["customer_id"] == customers[id_ % 3]


@pytest.mark.subprocess
async def test_t1_garbage_frames_do_not_kill_the_session(t1: McpStdioProc) -> None:  # noqa: F811
    for garbage in (b"[" * 100_000, b"{not json", b'"just a string"', b"[]", b"\xff\xfe"):
        await t1.send_raw(garbage)
    response = await t1.call_tool("get_customer_record", {"customer_id": "CUST-10042"})
    assert response["result"]["structuredContent"]["customer_id"] == "CUST-10042"
    for line in t1.stdout_lines:
        json.loads(line)  # stdout stayed pure JSON-RPC throughout


# =========================================================================== T2 - MCP gateway


async def test_t2_params_as_array_for_tools_call_is_32602(gw: Gateway) -> None:  # noqa: F811
    response = await gw.post(rpc("tools/call", 1, None) | {"params": ["admin_reset_key", {}]})
    assert response.json()["error"]["code"] == -32602
    assert gw.downstream_calls == 0


@pytest.mark.parametrize("name", [123, None, True, ["admin_reset_key"], {"n": "admin_reset_key"}])
async def test_t2_non_string_tool_name_is_32602(gw: Gateway, name: Any) -> None:  # noqa: F811
    response = await gw.post(rpc("tools/call", 1, {"name": name, "arguments": {}}), role="admin")
    assert response.json()["error"]["code"] == -32602
    assert gw.downstream_calls == 0


async def test_t2_batch_of_1000_messages_is_rejected_without_forwarding(
    gw: Gateway,  # noqa: F811
) -> None:
    # One authenticated POST must not fan out into 1,000 downstream tool executions.
    batch = [get_record(i) for i in range(1000)]
    response = await gw.post(batch)
    body = response.json()
    assert isinstance(body, dict) and body["error"]["code"] == -32600, str(body)[:200]
    assert gw.downstream_calls == 0


async def test_t2_batch_at_the_cap_is_answered_in_order(gw: Gateway) -> None:  # noqa: F811
    batch = [get_record(i) if i % 2 else call("admin_reset_key", i) for i in range(100)]
    response = await gw.post(batch)
    body = response.json()
    assert [m["id"] for m in body] == list(range(100))
    assert all(("result" in m) == bool(m["id"] % 2) for m in body)


async def test_t2_2mb_chunked_body_is_413(gw: Gateway) -> None:  # noqa: F811
    async def chunks() -> AsyncIterator[bytes]:  # no Content-Length: the stream must be capped
        for _ in range(32):
            yield b" " * 65_536

    response = await gw.client.post(
        "/mcp",
        content=chunks(),
        headers={**gw.auth("viewer"), "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert gw.downstream_calls == 0


async def test_t2_duplicate_authorization_headers_are_rejected(gw: Gateway) -> None:  # noqa: F811
    # A front proxy may honour the last header while we honour the first: refuse the ambiguity.
    headers = [
        ("Authorization", f"Bearer {mint(gw.settings, 'viewer')}"),
        ("Authorization", f"Bearer {mint(gw.settings, 'admin')}"),
        ("Content-Type", "application/json"),
    ]
    response = await gw.client.post(
        "/mcp", content=json.dumps(get_record(1)).encode(), headers=headers
    )
    assert response.status_code == 401
    assert gw.downstream_calls == 0


def _forge(settings: Settings, kind: str) -> str:
    now = int(time.time())
    claims = {"sub": "x", "role": "admin", "iat": now, "exp": now + 60}
    if kind == "alg_none":
        return jwt.encode(claims, key=None, algorithm="none")  # type: ignore[arg-type]
    if kind == "wrong_secret":
        return jwt.encode(claims, "another-secret-that-is-32-bytes-long", algorithm="HS256")
    if kind == "hs512_same_secret":
        return jwt.encode(claims, settings.jwt_hs256_secret, algorithm="HS512")
    if kind == "role_list":
        return jwt.encode({**claims, "role": ["admin"]}, settings.jwt_hs256_secret)
    if kind == "role_case":
        return jwt.encode({**claims, "role": "Admin"}, settings.jwt_hs256_secret)
    raise AssertionError(kind)


@pytest.mark.parametrize(
    "kind", ["alg_none", "wrong_secret", "hs512_same_secret", "role_list", "role_case"]
)
# Forging HS512 with the 36-byte test secret is the point; PyJWT warns that it's short.
@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
async def test_t2_forged_jwts_are_401(gw: Gateway, kind: str) -> None:  # noqa: F811
    headers = {"Authorization": f"Bearer {_forge(gw.settings, kind)}"}
    response = await gw.post(call("admin_reset_key", 1), role=None, headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == -32002
    assert gw.downstream_calls == 0


@pytest.mark.parametrize("scheme", ["bearer", "BEARER", "Bearer"])
async def test_t2_bearer_scheme_any_case(gw: Gateway, scheme: str) -> None:  # noqa: F811
    headers = {"Authorization": f"{scheme} {mint(gw.settings, 'viewer')}"}
    response = await gw.post(get_record(1), role=None, headers=headers)
    assert response.status_code == 200 and "result" in response.json()


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
async def test_t2_non_standard_json_numbers_are_parse_errors(
    gw: Gateway,  # noqa: F811
    literal: str,
) -> None:
    raw = (
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"trigger_refund",'
        f'"arguments":{{"customer_id":"CUST-10042","amount":{literal},"reason":"damaged item"}}}}}}'
    ).encode()
    response = await gw.post(raw)
    assert response.json()["error"]["code"] == -32700
    assert gw.downstream_calls == 0


@pytest.mark.parametrize("role", ["viewer", None])
async def test_t2_deeply_nested_json_is_not_a_500(gw: Gateway, role: str | None) -> None:  # noqa: F811
    response = await gw.post(b"[" * 50_000 + b"]" * 50_000, role=role)
    assert response.status_code == (200 if role else 401), response.text[:200]
    assert response.json()["error"]["code"] == (-32700 if role else -32002)


@pytest.mark.parametrize("method", ["TOOLS/CALL", "Tools/call", "tools/call ", "tools//call"])
async def test_t2_method_spelling_variants_never_bypass_rbac(
    gw: Gateway,  # noqa: F811
    method: str,
) -> None:
    # A downstream that normalizes method names would execute an admin tool the gateway
    # waved through as "not tools/call". Unknown methods are answered locally.
    response = await gw.post(rpc(method, 1, {"name": "admin_reset_key", "arguments": {}}))
    assert response.json()["error"]["code"] == -32601
    assert gw.downstream_calls == 0


# =========================================================================== T3 - guardrail


def _stream(chunks: list[str], max_hold: int = 256) -> str:
    redactor = StreamingPIIRedactor(max_hold)
    return "".join(redactor.feed(c) for c in chunks) + redactor.flush()


def _chunkings(text: str) -> list[list[str]]:
    return [
        [text],
        list(text),
        [text[i : i + 3] for i in range(0, len(text), 3)],
        [text[i : i + 7] for i in range(0, len(text), 7)],
    ]


T3_TEXTS = {
    "pii_first_char": f"{EMAIL} is the contact",
    "pii_last_char": f"the SSN is {SSN}",
    "only_pii": CARD,
    "redacted_literal_in_input": "already [REDACTED] here, and [REDACT",
    "email_then_card_no_space": f"{EMAIL}{CARD} end",
    "card_then_email_no_space": f"card {CARD}{EMAIL} end",
    "unicode_and_emoji": f"🙂 café — {EMAIL} ✅ 日本語 {SSN} 🎉",
    "ten_thousand_chars": ("lorem ipsum dolor sit amet " * 370) + f" {CARD} " + EMAIL,
}


@pytest.mark.parametrize("name", list(T3_TEXTS))
def test_t3_edge_texts_match_one_shot_redaction(name: str) -> None:
    text = T3_TEXTS[name]
    expected, _ = redact(text)
    for chunks in _chunkings(text):
        assert _stream(chunks) == expected


@pytest.mark.parametrize(
    "pii", [CARD, SSN, "4111 1111 1111 1111", EMAIL], ids=["card", "ssn", "spaced", "email"]
)
@pytest.mark.parametrize("lead", [0, 10, 100, 255])
def test_t3_forced_flush_never_splits_pii(pii: str, lead: int) -> None:
    # A PII value inside an unbroken run longer than max_hold: the forced cut must not land
    # inside the value and emit half of it before the rest arrives.
    text = "x" * lead + pii + "x" * 300
    for chunks in ([text], [text[:150], text[150:]], list(text)):
        out = _stream(chunks)
        assert pii not in out
        assert pii.replace(" ", "")[:8] not in out.replace(" ", ""), out[:120]


def _sse(chunk: dict[str, Any]) -> SSEEvent:
    return SSEEvent(data=json.dumps(chunk))


async def _events(items: list[SSEEvent]) -> AsyncIterator[SSEEvent]:
    for item in items:
        yield item


async def _guard(items: list[SSEEvent]) -> str:
    out = [frame async for frame in guard_events(_events(items), 256, "cid-test-0001")]
    return b"".join(out).decode()


def _frame(delta: dict[str, Any], **choice: Any) -> SSEEvent:
    return _sse({"id": "c1", "choices": [{"index": 0, "delta": delta, **choice}]})


async def test_t3_pii_in_non_content_delta_fields_is_redacted() -> None:
    args_a, args_b = '{"email":"sarah.con', 'nor@cyberdyne.io"}'
    items = [
        _frame({"role": "assistant"}),
        _frame({"tool_calls": [{"index": 0, "id": "t1", "function": {"arguments": args_a}}]}),
        _frame({"tool_calls": [{"index": 0, "function": {"arguments": args_b}}]}),
        _frame({"refusal": f"I won't share {SSN}"}),
        _frame(
            {"content": "ok"},
            logprobs={"content": [{"token": CARD, "logprob": -0.1, "bytes": [52, 49]}]},
        ),
        _frame({}, finish_reason="stop"),
        SSEEvent(data=DONE),
    ]
    out = await _guard(items)
    for pii in (EMAIL, "cyberdyne.io", SSN, CARD):
        assert pii not in out, pii


def test_t3_non_stream_tool_calls_and_content_parts_are_redacted() -> None:
    body = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": f"mail {EMAIL}"}],
                    "tool_calls": [
                        {"function": {"name": "f", "arguments": json.dumps({"ssn": SSN})}}
                    ],
                    "refusal": f"card {CARD}",
                }
            }
        ]
    }
    redact_completion_body(body)
    text = json.dumps(body)
    for pii in (EMAIL, SSN, CARD):
        assert pii not in text, pii


async def test_t3_empty_and_role_only_deltas_pass_through() -> None:
    items = [
        _frame({"role": "assistant", "content": ""}),
        _frame({"content": ""}),
        _frame({}),
        _frame({"content": f"hi {EMAIL}"}),
        _frame({}, finish_reason="stop"),
        SSEEvent(data=DONE),
    ]
    out = await _guard(items)
    assert '"role": "assistant"' in out
    assert EMAIL not in out and REDACTED in out
    assert out.count("data: [DONE]") == 1


async def test_t3_done_twice_yields_one_trailer() -> None:
    items = [_frame({"content": SSN}), SSEEvent(data=DONE), _frame({"content": EMAIL})]
    items.append(SSEEvent(data=DONE))
    out = await _guard(items)
    assert out.count("event: guardrail") == 1 and out.count("data: [DONE]") == 1
    assert SSN not in out and EMAIL not in out


async def test_t3_missing_done_flushes_redacted_tail_then_error() -> None:
    items = [_frame({"content": "contact sarah.connor@cyber"}), _frame({"content": "dyne.io"})]
    out = await _guard(items)
    assert "sarah.connor" not in out and REDACTED in out
    assert "event: error" in out and "GATEWAY_UPSTREAM_FAILURE" in out


async def test_t3_sse_parser_bounds_an_unterminated_frame() -> None:
    # An upstream that never sends the blank line must not grow one event without bound.
    consumed = 0

    async def lines() -> AsyncIterator[str]:
        nonlocal consumed
        for _ in range(400_000):
            consumed += 1
            yield "data: xxxxxxxxxxxxxxxx"

    out = b"".join([f async for f in guard_events(iter_sse(lines()), 256, None)]).decode()
    assert "event: error" in out
    assert consumed < 400_000, "the whole unterminated frame was buffered"


# =========================================================================== T4 - router


async def test_t4_two_tenants_hammering_concurrently(tmp_db_path: Path) -> None:
    async with SQLiteRateLimiter(tmp_db_path, limit=50_000, window_seconds=60) as lim:

        async def one(tenant: str) -> bool:
            try:
                await lim.reserve(tenant, 5_000)
            except RateLimitExceededError:
                return False
            return True

        results = await asyncio.gather(*(one(t) for _ in range(40) for t in ("ta", "tb")))
        assert sum(results[0::2]) == 10 and sum(results[1::2]) == 10
        assert await lim.usage("ta") == 50_000 and await lim.usage("tb") == 50_000


async def test_t4_reconcile_after_window_expiry_does_not_resurrect(
    tmp_db_path: Path, fake_clock: FakeClock
) -> None:
    async with SQLiteRateLimiter(tmp_db_path, window_seconds=60, clock=fake_clock) as lim:
        old = await lim.reserve("t", 40_000)
        fake_clock.advance(61)
        await lim.reserve("t", 40_000)  # evicts the expired row
        await lim.reconcile(old.id, 45_000)  # long-running request settles late
        assert await lim.usage("t") == 40_000
        await lim.reserve("t", 10_000)  # 40k + 10k fits exactly


async def test_t4_clock_going_backwards_two_seconds(
    tmp_db_path: Path, fake_clock: FakeClock
) -> None:
    async with SQLiteRateLimiter(tmp_db_path, window_seconds=60, clock=fake_clock) as lim:
        start = fake_clock.now
        await lim.reserve("t", 45_000)
        fake_clock.advance(-2)
        with pytest.raises(RateLimitExceededError) as excinfo:
            await lim.reserve("t", 10_000)
        assert 0 < excinfo.value.retry_after_ms <= 62_000
        fake_clock.set(start + 60.001)
        await lim.reserve("t", 10_000)


@pytest.mark.parametrize("max_tokens", [0, -1, -50_000, True, "7", 1.5])
async def test_t4_invalid_max_tokens_is_422_and_charges_nothing(
    settings_override: Settings, max_tokens: Any
) -> None:
    primary, backup = MockProvider("primary"), MockProvider("backup")
    async with router(settings_override, primary, backup) as (client, lim):
        response = await _post(client, {**REQUEST, "max_tokens": max_tokens})
        assert response.status_code == 422, (max_tokens, response.status_code)
        assert await lim.usage(TENANT) == 0
    assert primary.calls == backup.calls == 0


async def test_t4_huge_max_tokens_is_413(settings_override: Settings) -> None:
    async with router(settings_override, MockProvider("p"), MockProvider("b")) as (client, lim):
        response = await _post(client, {**REQUEST, "max_tokens": 10**30})
        assert response.status_code == 413
        assert await lim.usage(TENANT) == 0


async def test_t4_primary_200_with_malformed_json_fails_over(settings_override: Settings) -> None:
    def bad(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"choices": [ not json', headers={"x": "y"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(bad)) as raw:
        primary = HttpProvider("primary", "http://primary.invalid/v1/chat/completions", raw)
        backup = MockProvider("backup")
        async with router(_fast(settings_override), primary, backup) as (client, _):
            response = await _post(client)
    assert response.status_code == 200
    assert response.headers["X-Routed-Provider"] == "backup"
    assert response.headers["X-Failover-Reason"] == "http_5xx"


async def test_t4_backup_hanging_forever_respects_total_deadline(
    settings_override: Settings,
) -> None:
    settings = _fast(settings_override, request_deadline_seconds=1.0)
    primary, backup = MockProvider("p", delay=60), MockProvider("b", delay=3600)
    async with router(settings, primary, backup) as (client, lim):
        started = time.perf_counter()
        response = await _post(client)
        elapsed = time.perf_counter() - started
        assert response.status_code == 502 and elapsed < 2.0
        assert await lim.usage(TENANT) == 0
    assert primary.cancelled and backup.cancelled


class _HangsAfterFirstChunk:
    def __init__(self, name: str) -> None:
        self.name = name
        self.closed = False

    async def complete(self, req: ChatRequest) -> CompletionResult:  # pragma: no cover
        raise NotImplementedError

    async def stream(self, req: ChatRequest) -> AsyncIterator[bytes]:
        try:
            yield b'data: {"choices":[{"index":0,"delta":{"content":"hel"}}]}\n\n'
            await asyncio.sleep(3600)
            yield b"data: [DONE]\n\n"
        finally:
            self.closed = True


async def test_t4_stream_that_stalls_after_first_byte_is_cut_off(
    settings_override: Settings,
) -> None:
    settings = _fast(settings_override).model_copy(update={"stream_idle_timeout_seconds": 0.5})
    primary = _HangsAfterFirstChunk("primary")
    async with router(settings, primary, MockProvider("b")) as (client, lim):
        started = time.perf_counter()
        response = await asyncio.wait_for(_post(client, {**REQUEST, "stream": True}), timeout=5.0)
        assert time.perf_counter() - started < 3.0
        assert "event: error" in response.text
        assert await lim.usage(TENANT) > 0  # charged for what was generated, then settled
    assert primary.closed


async def test_t4_client_cancel_during_primary_wait_releases_reservation(
    settings_override: Settings,
) -> None:
    settings = settings_override.model_copy(update={"primary_timeout_seconds": 5.0})
    primary = MockProvider("primary", delay=5.0)
    async with router(settings, primary, MockProvider("b")) as (client, lim):
        task = asyncio.create_task(_post(client))
        for _ in range(100):
            await asyncio.sleep(0.01)
            if await lim.usage(TENANT) > 0:
                break
        assert await lim.usage(TENANT) > 0
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await lim.usage(TENANT) == 0
    assert primary.cancelled


async def test_t4_oversized_body_is_413_before_any_provider_call(
    settings_override: Settings,
) -> None:
    primary, backup = MockProvider("p"), MockProvider("b")
    body = {**REQUEST, "padding": "x" * 2_000_000}  # outside messages: invisible to the estimate
    async with router(settings_override, primary, backup) as (client, lim):
        response = await _post(client, body)
        assert response.status_code == 413
        assert await lim.usage(TENANT) == 0
    assert primary.calls == backup.calls == 0


async def test_t4_oversized_chunked_body_is_413(settings_override: Settings) -> None:
    async def chunks() -> AsyncIterator[bytes]:  # no Content-Length: the stream must be capped
        yield json.dumps(REQUEST)[:-1].encode() + b', "padding": "'
        for _ in range(40):
            yield b"x" * 65_536
        yield b'"}'

    primary = MockProvider("p")
    async with router(settings_override, primary, MockProvider("b")) as (client, lim):
        response = await client.post(
            "/v1/chat/completions",
            content=chunks(),
            headers={"X-Tenant-Key": TENANT, "Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"
        assert await lim.usage(TENANT) == 0
    assert primary.calls == 0


def test_t4_estimate_counts_tool_calls_and_names() -> None:
    blob = "x" * 4_000
    messages = [
        {"role": "assistant", "content": None, "tool_calls": [{"function": {"arguments": blob}}]},
        {"role": "tool", "tool_call_id": "c1", "name": blob, "content": "ok"},
    ]
    assert estimate_prompt_tokens(messages) >= 2 * len(blob) // 4


# =========================================================================== integration / leaks

_ALLOWED_PRINT = {"task1_mcp_server/server.py"}  # emit_chaos: the whole point


def _guarded_id_subscripts(tree: ast.AST) -> set[int]:
    """``x["id"]`` inside ``"id" in x and ...`` can't raise on a notification."""
    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            first, rest = node.values[0], node.values[1:]
            if (
                isinstance(first, ast.Compare)
                and isinstance(first.left, ast.Constant)
                and first.left.value == "id"
                and isinstance(first.ops[0], ast.In)
            ):
                for value in rest:
                    guarded.update(id(n) for n in ast.walk(value))
    return guarded


def _smells(tree: ast.AST, rel: str) -> list[str]:
    """Code, not text: docstrings that *mention* print() or str(exc) are fine."""
    hits: list[str] = []
    guarded = _guarded_id_subscripts(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "print" and rel not in _ALLOWED_PRINT:
                hits.append(f"{rel}:{node.lineno}: print(")
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                hits.append(f"{rel}:{node.lineno}: bare except")
            elif (
                isinstance(node.type, ast.Name)
                and node.type.id in {"Exception", "BaseException"}
                and all(isinstance(stmt, ast.Pass) for stmt in node.body)
            ):
                hits.append(f"{rel}:{node.lineno}: except Exception: pass")
            if node.name is not None:
                for inner in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                    if (
                        isinstance(inner, ast.Call)
                        and isinstance(inner.func, ast.Name)
                        and inner.func.id in {"str", "repr"}
                        and any(isinstance(a, ast.Name) and a.id == node.name for a in inner.args)
                    ):
                        hits.append(f"{rel}:{inner.lineno}: {inner.func.id}({node.name})")
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in {"request", "msg", "message", "payload"}
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "id"
            and id(node) not in guarded
        ):
            hits.append(f"{rel}:{node.lineno}: {node.value.id}['id']")
    return hits


def test_source_has_no_leaky_idioms() -> None:
    hits: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        hits += _smells(ast.parse(path.read_text(encoding="utf-8")), rel)
    assert not hits, "\n".join(hits)


@pytest.mark.subprocess
async def test_integration_error_paths_leak_nothing(settings_override: Settings) -> None:
    from control_plane.integration.app import create_app
    from control_plane.integration.mock_agent_llm import LEAKY_MODEL, AgentMockProvider

    app = create_app(
        settings_override,
        primary=AgentMockProvider("primary", delay=0.5),
        backup=AgentMockProvider("backup"),
    )
    viewer = {"Authorization": f"Bearer {mint(settings_override, 'viewer')}"}
    tenant = {"X-Tenant-Key": "leak-probe-tenant"}
    llm = "/v1/chat/completions"
    probes: list[tuple[str, dict[str, str], bytes]] = [
        (llm, tenant, b"{"),
        (llm, tenant, b"[" * 50_000 + b"]" * 50_000),
        (llm, tenant, json.dumps({"model": "m", "messages": "nope"}).encode()),
        (llm, tenant, json.dumps({**REQUEST, "model": LEAKY_MODEL}).encode()),
        (llm, tenant, json.dumps({**REQUEST, "model": LEAKY_MODEL, "stream": True}).encode()),
        (llm, {}, json.dumps(REQUEST).encode()),
        ("/mcp", {}, json.dumps(get_record(1)).encode()),
        ("/mcp", viewer, b"{"),
        ("/mcp", viewer, b"[" * 50_000 + b"]" * 50_000),
        ("/mcp", viewer, json.dumps(call("admin_reset_key", 1)).encode()),
        ("/mcp", viewer, json.dumps(get_record(1, "CUST-12")).encode()),
        ("/mcp", viewer, json.dumps(get_record(1, "CUST-99999")).encode()),
        ("/mcp", viewer, json.dumps(rpc("no/such/method", 1)).encode()),
    ]
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://cp") as client,
    ):
        for path, headers, body in probes:
            response = await client.post(
                path, content=body, headers={"Content-Type": "application/json", **headers}
            )
            text = response.text + json.dumps(dict(response.headers))
            assert response.status_code != 500, (path, body[:60], text[:300])
            for marker in (*LEAK_MARKERS, "control_plane", "sqlite", "999-01-4242"):
                assert marker not in text, (path, body[:60], marker, text[:300])
