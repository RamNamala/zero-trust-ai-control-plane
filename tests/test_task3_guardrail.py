"""Task 3 - streaming PII guardrail (acceptance contract - docs/ACCEPTANCE_MATRIX.md).

The redactor tests run first and need no HTTP. The gateway tests wire the gateway to the mock LLM
in-process with ``httpx.ASGITransport``, except the timing and lifecycle tests: ASGITransport
buffers the whole response (PITFALLS #41), so those run both apps under uvicorn on loopback.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import uvicorn
from conftest import JsonLogCapture
from hypothesis import given, settings
from hypothesis import strategies as st

from control_plane.common.settings import Settings
from control_plane.task3_streaming_guardrail.gateway import create_app
from control_plane.task3_streaming_guardrail.mock_llm import PRESETS, MockLLMState, create_mock_llm
from control_plane.task3_streaming_guardrail.patterns import REDACTED, redact
from control_plane.task3_streaming_guardrail.redactor import StreamingPIIRedactor
from control_plane.task3_streaming_guardrail.sse import DONE, SSEEvent, encode_event, iter_sse

# --- Redactor (no HTTP) ---------------------------------------------------------------------


def run(chunks: list[str], max_hold: int = 256) -> tuple[str, StreamingPIIRedactor]:
    r = StreamingPIIRedactor(max_hold=max_hold)
    out = "".join(r.feed(c) for c in chunks) + r.flush()
    return out, r


def assert_no_partial_leak(chunks: list[str], secret_digits: str) -> None:
    """No emitted piece, nor the concatenation, may contain the secret's digits."""
    r = StreamingPIIRedactor()
    pieces = [r.feed(c) for c in chunks] + [r.flush()]
    joined = "".join(pieces)
    assert secret_digits not in "".join(ch for ch in joined if ch.isdigit())


def test_ssn_split_across_three_chunks() -> None:
    chunks = ["My SSN is 123-", "45-67", "89. Thanks"]
    out, r = run(chunks)
    assert out == f"My SSN is {REDACTED}. Thanks"
    assert r.redaction_count == 1
    assert_no_partial_leak(chunks, "123456789")


def test_email_split_across_three_chunks() -> None:
    chunks = ["Email alice.smi", "th@compa", "ny.org now"]
    out, r = run(chunks)
    assert out == f"Email {REDACTED} now"
    assert r.redaction_count == 1
    assert "alice" not in out and "compa" not in out


@pytest.mark.parametrize(
    "chunks",
    [
        ["Card 4532-01", "51-1283-", "0366 ok"],
        ["Card 4532 01", "51 1283 ", "0366 ok"],
    ],
    ids=["dashed", "spaced"],
)
def test_credit_card_split_across_three_chunks(chunks: list[str]) -> None:
    out, r = run(chunks)
    assert out == f"Card {REDACTED} ok"
    assert r.redaction_count == 1
    assert_no_partial_leak(chunks, "4532015112830366")


PROPERTY_TEXT = (
    "Hi Sarah, reach alice.smith@company.org or call. SSN 123-45-6789, card "
    "4532-0151-1283-0366 and 4532 0151 1283 0366. Order 12345 ok. "
    "sarah.connor@cyberdyne.io / 999-01-4242. Long: "
    + "x" * 120
    + ".y@"
    + "sub." * 20
    + "example.com done."
)


@settings(max_examples=2000, deadline=None)
@given(st.lists(st.integers(0, len(PROPERTY_TEXT)), max_size=40))
def test_chunking_invariance_property(cuts: list[int]) -> None:
    points = sorted(set(cuts)) + [len(PROPERTY_TEXT)]
    parts, prev = [], 0
    for c in points:
        parts.append(PROPERTY_TEXT[prev:c])
        prev = c
    out, r = run(parts)
    expected, count = redact(PROPERTY_TEXT)
    assert out == expected
    assert r.redaction_count == count
    assert r.forced_flushes == 0


@pytest.mark.parametrize(
    "text",
    [
        "Order 1234567890123456 shipped",  # 16 digits, fails Luhn
        "Call 555-123-4567 today",  # phone-shaped, not SSN-shaped
        "Tracking 4532-0151-1283-0367 ok",  # card-shaped, one digit off Luhn
        "Ref 12345 and 2026-11-03",  # short runs and a date
        "Invoice +1 (415) 555 0100",
    ],
)
def test_non_luhn_digit_runs_not_redacted(text: str) -> None:
    for size in (1, 3, len(text)):
        chunks = [text[i : i + size] for i in range(0, len(text), size)]
        out, r = run(chunks)
        assert out == text
        assert r.redaction_count == 0


def test_flush_emits_tail_and_resets() -> None:
    r = StreamingPIIRedactor()
    assert r.feed("SSN 123-45-") == "SSN "  # digit tail held back
    assert r.buffered_chars == len("123-45-")
    assert r.flush() == "123-45-"  # incomplete SSN at end of stream: nothing to redact
    assert r.buffered_chars == 0
    assert r.flush() == ""
    # Reusable after flush, and the old tail doesn't bleed into the next text.
    assert r.feed("6789 ok!") == "6789 ok!"  # "!" can't extend either tail class
    assert r.feed("bob@ex") == ""
    assert r.flush() == "bob@ex"  # no TLD yet -> not an email
    assert r.feed("a b@example.com") == "a "
    assert r.flush() == REDACTED
    assert r.redaction_count == 1


def test_peak_buffer_bounded_over_10k_chunks() -> None:
    rng = random.Random(1234)  # noqa: S311 - reproducible test data, not crypto
    max_hold, max_chunk = 256, 16
    vocab = [
        "hello ",
        "world. ",
        "alice.smith@company.org ",
        "123-45-6789 ",
        "4532 0151 1283 0366 ",
        "4532-0151-1283-0366, ",
        "order 98765 ",
        "\n",
        "ok; ",
    ]
    text = "".join(rng.choice(vocab) for _ in range(12_000))
    chunks: list[str] = []
    i = 0
    while i < len(text):
        n = rng.randint(1, max_chunk)
        chunks.append(text[i : i + n])
        i += n
    assert len(chunks) >= 10_000

    out, r = run(chunks, max_hold=max_hold)
    print(f"\npeak_buffer_chars={r.peak_buffer_chars} chunks={len(chunks)} chars={len(text)}")
    assert r.peak_buffer_chars <= max_hold + max_chunk
    assert out == redact(text)[0]
    assert r.forced_flushes == 0


def test_run_longer_than_max_hold_is_force_flushed_and_counted() -> None:
    """The documented trade-off: memory stays bounded, and the recall loss is counted."""
    r = StreamingPIIRedactor(max_hold=32)
    out = "".join(r.feed(c) for c in ["a" * 30, "b" * 30, "c" * 30]) + r.flush()
    assert out == "a" * 30 + "b" * 30 + "c" * 30
    assert r.peak_buffer_chars <= 32 + 30
    assert r.forced_flushes >= 1


# --- SSE parser -----------------------------------------------------------------------------


async def _aiter(items: list[str]) -> AsyncIterator[str]:
    for item in items:
        yield item


async def parse_sse(text: str) -> list[SSEEvent]:
    return [e async for e in iter_sse(_aiter(text.split("\n")))]


async def test_sse_parser_handles_comments_multiline_and_eof() -> None:
    raw = ": keep-alive\n\nevent: note\ndata: line one\ndata:line two\nid: 7\n\ndata: [DONE]"
    events = await parse_sse(raw)
    assert events == [
        SSEEvent(data="line one\nline two", event="note"),
        SSEEvent(data="[DONE]"),
    ]
    assert encode_event("a\nb", event="x") == b"event: x\ndata: a\ndata: b\n\n"


# --- Gateway, in-process (content and ordering) ----------------------------------------------

CID = "test-correlation-0001"


def chat(model: str, stream: bool = True) -> dict[str, Any]:
    return {"model": model, "messages": [{"role": "user", "content": "hi"}], "stream": stream}


def chunks_of(events: list[SSEEvent]) -> list[dict[str, Any]]:
    return [json.loads(e.data) for e in events if e.event is None and e.data != DONE]


def content_of(events: list[SSEEvent], index: int = 0) -> str:
    return "".join(
        c["delta"].get("content", "")
        for chunk in chunks_of(events)
        for c in chunk["choices"]
        if c["index"] == index
    )


@dataclass
class InProc:
    client: httpx.AsyncClient
    mock: MockLLMState

    async def stream(self, model: str) -> tuple[httpx.Response, list[SSEEvent]]:
        resp = await self.client.post(
            "/v1/chat/completions", json=chat(model), headers={"X-Correlation-ID": CID}
        )
        return resp, await parse_sse(resp.text)


@pytest.fixture
async def inproc(settings_override: Settings) -> AsyncIterator[InProc]:
    """Gateway -> mock LLM wired in-process. Fine for content and ordering checks, NOT for
    timing: ASGITransport buffers whole responses (PITFALLS #41)."""
    mock = create_mock_llm()
    settings = settings_override.model_copy(
        update={"llm_upstream_url": "http://mock-llm/v1/chat/completions"}
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock), base_url="http://mock-llm"
    ) as upstream:
        app = create_app(settings, client=upstream)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gw"
        ) as client:
            yield InProc(client, mock.state.mock)


async def test_finish_reason_frame_flushes_before_forwarding(inproc: InProc) -> None:
    _, events = await inproc.stream("mock-card_split")
    chunks = chunks_of(events)
    finish_at = next(i for i, c in enumerate(chunks) if c["choices"][0]["finish_reason"])
    content_at = [i for i, c in enumerate(chunks) if c["choices"][0]["delta"].get("content")]
    assert content_at and max(content_at) < finish_at
    assert content_at[-1] == finish_at - 1  # the flushed tail directly precedes the finish frame
    assert "content" not in chunks[finish_at]["choices"][0]["delta"]
    assert content_of(events) == f"Card {REDACTED} ok"


async def test_multi_choice_streams_have_independent_buffers(inproc: InProc) -> None:
    _, events = await inproc.stream("mock-multi_choice")
    assert content_of(events, 0) == f"A: card {REDACTED} done."
    assert content_of(events, 1) == f"B: mail {REDACTED} done."
    trailer = next(e for e in events if e.event == "guardrail")
    assert json.loads(trailer.data)["pii_redactions"] == 2


async def test_sse_headers_disable_proxy_buffering(inproc: InProc) -> None:
    resp, _ = await inproc.stream("mock-ssn_split")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert resp.headers["cache-control"] == "no-cache"
    assert resp.headers["x-accel-buffering"] == "no"
    assert resp.headers["x-guardrail"] == "pii-redaction/v1"
    assert resp.headers["x-correlation-id"] == CID


async def test_guardrail_trailer_reports_redaction_count(
    inproc: InProc, caplog_json: JsonLogCapture
) -> None:
    _, events = await inproc.stream("mock-ssn_split")
    assert content_of(events) == f"My SSN is {REDACTED}. Thanks"
    assert events[-1] == SSEEvent(data=DONE)
    assert events[-2].event == "guardrail"
    trailer = json.loads(events[-2].data)
    assert trailer["pii_redactions"] == 1
    assert trailer["correlation_id"] == CID

    (record,) = caplog_json.events("guardrail_stream")
    assert record["outcome"] == "ok"
    assert record["pii_redactions"] == 1
    assert record["correlation_id"] == CID
    assert "123-45" not in caplog_json.text and "6789" not in caplog_json.text
    assert inproc.mock.last_headers.get("x-correlation-id") == CID


async def test_non_stream_completion_is_redacted(inproc: InProc) -> None:
    resp = await inproc.client.post("/v1/chat/completions", json=chat("mock-email_split", False))
    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"]["content"] == f"Email {REDACTED} now"
    assert resp.headers["x-guardrail-redactions"] == "1"


# --- Gateway over real loopback sockets (timing and lifecycle) -------------------------------


@asynccontextmanager
async def serve(app: Any) -> AsyncIterator[str]:
    """Run ``app`` under uvicorn on an ephemeral 127.0.0.1 port inside this event loop."""
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error", lifespan="off")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        async with asyncio.timeout(5):
            while not server.started:  # noqa: ASYNC110 - uvicorn exposes a flag, not an Event
                await asyncio.sleep(0.01)
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


@dataclass
class Live:
    client: httpx.AsyncClient
    mock: MockLLMState


@pytest.fixture
async def live(settings_override: Settings) -> AsyncIterator[Live]:
    mock = create_mock_llm()
    async with serve(mock) as mock_url, httpx.AsyncClient() as upstream:
        settings = settings_override.model_copy(
            update={"llm_upstream_url": f"{mock_url}/v1/chat/completions"}
        )
        async with (
            serve(create_app(settings, client=upstream)) as gw_url,
            httpx.AsyncClient(base_url=gw_url, timeout=10) as client,
        ):
            yield Live(client, mock.state.mock)


def _content(event: SSEEvent) -> str:
    if event.event is not None or event.data == DONE:
        return ""
    return "".join(c["delta"].get("content", "") for c in json.loads(event.data)["choices"])


async def test_first_safe_chunk_yielded_before_stream_ends(live: Live) -> None:
    text, ttft_ms = "", float("inf")
    started = time.perf_counter()
    async with live.client.stream(
        "POST", "/v1/chat/completions", json=chat("mock-slow_first_then_pause")
    ) as resp:
        async for event in iter_sse(resp.aiter_lines()):
            if text := _content(event):
                ttft_ms = (time.perf_counter() - started) * 1000
                break
    print(f"\nTTFT={ttft_ms:.1f} ms (upstream pauses 1000 ms after the first chunk)")
    assert text == "Hello there, "
    assert ttft_ms < 200


async def test_gateway_never_reads_full_upstream_body(live: Live) -> None:
    total = len(PRESETS["slow_long"])
    async with live.client.stream(
        "POST", "/v1/chat/completions", json=chat("mock-slow_long")
    ) as resp:
        async for event in iter_sse(resp.aiter_lines()):
            if _content(event):
                break
        # The client already has redacted content while the upstream is still near the start.
        assert live.mock.chunks_sent < total // 10
        assert not live.mock.completed


async def test_client_disconnect_closes_upstream(live: Live, caplog_json: JsonLogCapture) -> None:
    seen = 0
    async with live.client.stream(
        "POST", "/v1/chat/completions", json=chat("mock-slow_long")
    ) as resp:
        async for event in iter_sse(resp.aiter_lines()):
            seen += bool(_content(event))
            if seen == 2:
                break  # leaving the block closes the connection mid-stream
    await asyncio.wait_for(live.mock.upstream_closed.wait(), timeout=1.0)
    assert not live.mock.completed
    assert live.mock.chunks_sent < len(PRESETS["slow_long"])
    async with asyncio.timeout(1):
        while not caplog_json.events("guardrail_stream"):  # noqa: ASYNC110 - polling a log sink
            await asyncio.sleep(0.01)
    assert caplog_json.events("guardrail_stream")[0]["outcome"] == "client_disconnected"


async def test_upstream_error_midstream_emits_sanitized_error_frame(live: Live) -> None:
    resp = await live.client.post(
        "/v1/chat/completions",
        json=chat("mock-error_midstream"),
        headers={"X-Correlation-ID": CID},
    )
    assert resp.status_code == 200
    events = await parse_sse(resp.text)
    assert "".join(_content(e) for e in events) == f"Partial answer for {REDACTED} see ticket 4532"
    assert events[-1].event == "error"
    error = json.loads(events[-1].data)["error"]
    assert error["code"] == "GATEWAY_UPSTREAM_FAILURE"
    assert error["correlation_id"] == CID
    for leak in ("Traceback", "/srv/", "10.0.0.7", "sk-live", "UpstreamFailure", "bob@"):
        assert leak not in resp.text
    assert DONE not in resp.text
