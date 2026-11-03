"""Task 2 - MCP security gateway (acceptance contract - docs/ACCEPTANCE_MATRIX.md).

The gateway is wired to the mock downstream entirely in-process: caller -> ASGITransport ->
gateway -> HttpDownstream -> ASGITransport -> mock. No sockets, and the mock's call counters and
recorded headers/payload let every test assert what actually reached the downstream.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from fastapi import FastAPI

from control_plane.common.settings import Settings
from control_plane.task2_mcp_gateway.auth import AuthError, authenticate, parse_bearer
from control_plane.task2_mcp_gateway.downstream import HttpDownstream
from control_plane.task2_mcp_gateway.mock_downstream import create_mock_app
from control_plane.task2_mcp_gateway.policy import ToolClass, classify, decide
from control_plane.task2_mcp_gateway.proxy import create_app

SECRET = "SECRET-ARG-7c1e"  # noqa: S105 - argument sentinel, not a credential
DENIAL = (
    "Unauthorized Tool Call: Role 'viewer' is not permitted to invoke administrative tool "
    "'admin_reset_key'."
)
UNAVAILABLE = "Upstream MCP server unavailable"
ALL_TOOLS = {"get_customer_record", "trigger_refund", "admin_reset_key"}


# --------------------------------------------------------------------------- helpers


def mint(settings: Settings, role: str = "viewer", /, **claims: Any) -> str:
    """``claims`` override the defaults; ``None`` removes a claim (e.g. ``exp=None``)."""
    now = int(time.time())
    body: dict[str, Any] = {"sub": f"test-{role}", "role": role, "iat": now, "exp": now + 300}
    body.update(claims)
    body = {k: v for k, v in body.items() if v is not None}
    return jwt.encode(body, settings.jwt_hs256_secret, algorithm="HS256")


def rpc(method: str, id_: Any = 1, params: dict[str, Any] | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def notification(method: str = "notifications/initialized") -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": method}


def call(name: str, id_: Any = 1, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return rpc("tools/call", id_, {"name": name, "arguments": arguments or {}})


def get_record(id_: Any = 1, customer_id: str = "CUST-10042") -> dict[str, Any]:
    return call("get_customer_record", id_, {"customer_id": customer_id})


@dataclass
class Gateway:
    client: httpx.AsyncClient
    mock: FastAPI
    settings: Settings

    def auth(self, role: str = "viewer") -> dict[str, str]:
        return {"Authorization": f"Bearer {mint(self.settings, role)}"}

    async def post(
        self, payload: Any, role: str | None = "viewer", headers: dict[str, str] | None = None
    ) -> httpx.Response:
        merged = {**(self.auth(role) if role else {}), **(headers or {})}
        if isinstance(payload, bytes):
            return await self.client.post(
                "/mcp", content=payload, headers={"Content-Type": "application/json", **merged}
            )
        return await self.client.post("/mcp", json=payload, headers=merged)

    @property
    def calls(self) -> dict[str, int]:
        return dict(self.mock.state.calls)

    @property
    def downstream_calls(self) -> int:
        return sum(self.calls.values())


GatewayFactory = Callable[..., Awaitable[Gateway]]


@pytest.fixture
async def make_gateway(settings_override: Settings) -> AsyncIterator[GatewayFactory]:
    async with AsyncExitStack() as stack:

        async def factory(
            transport: httpx.AsyncBaseTransport | None = None, **overrides: Any
        ) -> Gateway:
            settings = settings_override.model_copy(update=overrides)
            mock = create_mock_app()
            ds = await stack.enter_async_context(
                httpx.AsyncClient(
                    transport=transport or httpx.ASGITransport(app=mock), base_url="http://mock"
                )
            )
            app = create_app(settings, downstream=HttpDownstream("http://mock/mcp", ds))
            client = await stack.enter_async_context(
                httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw")
            )
            return Gateway(client, mock, settings)

        yield factory


@pytest.fixture
async def gw(make_gateway: GatewayFactory) -> Gateway:
    return await make_gateway()


# --------------------------------------------------------------------------- JSON-RPC parsing


@pytest.mark.parametrize("role", ["viewer", "admin"])
async def test_tools_list_proxied_for_viewer_and_admin(gw: Gateway, role: str) -> None:
    response = await gw.post(rpc("tools/list", 1), role=role)
    assert response.status_code == 200
    body = response.json()
    assert body["jsonrpc"] == "2.0" and body["id"] == 1
    assert {t["name"] for t in body["result"]["tools"]} == ALL_TOOLS
    assert gw.calls["tools/list"] == 1


@pytest.mark.parametrize("id_", ["abc", "7", 7, 0, None], ids=repr)
async def test_id_type_preserved(gw: Gateway, id_: Any) -> None:
    for payload in (rpc("tools/list", id_), get_record(id_), call("admin_reset_key", id_)):
        response = await gw.post(payload)
        body = response.json()
        assert "id" in body
        assert body["id"] == id_ and type(body["id"]) is type(id_)
        assert f'"id":{json.dumps(id_)}' in response.text.replace(" ", "")
    # The downstream saw an internal id, never the caller's.
    assert gw.mock.state.last_payload["id"] == 0


async def test_parse_error_returns_32700_null_id(gw: Gateway) -> None:
    for raw in (b'{"jsonrpc": "2.0", "method": "tools/list", "id": 1', b"\xff\xfe", b""):
        response = await gw.post(raw)
        assert response.status_code == 200
        assert response.json() == {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": "Parse error"},
        }
    assert gw.downstream_calls == 0


@pytest.mark.parametrize(
    ("payload", "expected_ids"),
    [
        (42, None),
        ("tools/list", None),
        (None, None),
        ({"jsonrpc": "2.0", "id": 1}, 1),  # missing method
        ({"jsonrpc": "2.0", "id": "x", "method": 5}, "x"),  # non-string method
        ({"jsonrpc": "1.0", "id": "x", "method": "tools/list"}, "x"),  # wrong version
        ({"id": 3, "method": "tools/list"}, 3),  # no jsonrpc member
        ({"jsonrpc": "2.0", "id": True, "method": "tools/list"}, None),  # bool id is invalid
        ([], None),  # empty batch -> one object, not an array
        ([1, 2], [None, None]),
    ],
    ids=repr,
)
async def test_invalid_request_shapes_return_32600(
    gw: Gateway, payload: Any, expected_ids: Any
) -> None:
    response = await gw.post(json.dumps(payload).encode())
    assert response.status_code == 200
    body = response.json()
    if isinstance(expected_ids, list):
        assert isinstance(body, list)
        assert [r["id"] for r in body] == expected_ids
        assert all(r["error"]["code"] == -32600 for r in body)
    else:
        assert isinstance(body, dict)
        assert body["id"] == expected_ids
        assert body["error"]["code"] == -32600
    assert gw.downstream_calls == 0


async def test_notification_returns_202_empty_body(gw: Gateway) -> None:
    response = await gw.post(notification())
    assert response.status_code == 202
    assert response.content == b""
    assert response.headers["X-Correlation-ID"]
    assert gw.calls["notifications/initialized"] == 1  # forwarded, just not answered


async def test_null_id_is_a_request_not_a_notification(gw: Gateway) -> None:
    response = await gw.post(rpc("tools/list", None))
    assert response.status_code == 200
    assert response.json()["id"] is None


async def test_batch_mixed_allow_deny_preserves_order(gw: Gateway) -> None:
    batch = [
        get_record(1),
        call("admin_reset_key", "two"),
        notification(),
        rpc("tools/list", 3),
        call(" admin_reset_key", 4),
    ]
    response = await gw.post(batch)
    assert response.status_code == 200
    body = response.json()
    assert [r["id"] for r in body] == [1, "two", 3, 4]
    assert "result" in body[0]
    assert body[1]["error"] == {"code": -32001, "message": DENIAL}
    assert "result" in body[2]
    assert body[3]["error"]["code"] == -32602

    sent = gw.mock.state.last_payload
    assert isinstance(sent, list)
    assert [m["method"] for m in sent] == [
        "tools/call",
        "notifications/initialized",
        "tools/list",
    ]
    assert sent[0]["params"]["name"] == "get_customer_record"
    assert "id" not in sent[1]
    assert gw.calls.get("tools/call:admin_reset_key", 0) == 0


async def test_duplicate_ids_in_batch_are_not_crossed(gw: Gateway) -> None:
    batch = [get_record(1, "CUST-00001"), get_record(1, "CUST-00002")]
    body = (await gw.post(batch)).json()
    assert [r["id"] for r in body] == [1, 1]
    assert [r["result"]["structuredContent"]["customer_id"] for r in body] == [
        "CUST-00001",
        "CUST-00002",
    ]


async def test_batch_of_only_notifications_returns_202(gw: Gateway) -> None:
    batch = [notification(), notification("notifications/cancelled"), notification()]
    response = await gw.post(batch)
    assert response.status_code == 202
    assert response.content == b""
    assert gw.calls["notifications/initialized"] == 2


async def test_denied_notification_gets_no_response(gw: Gateway) -> None:
    denied_notification = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "admin_reset_key"},
    }
    response = await gw.post([denied_notification, notification()])
    assert response.status_code == 202
    assert response.content == b""
    assert gw.calls.get("tools/call", 0) == 0


# --------------------------------------------------------------------------- forwarding


async def test_authorization_header_not_passed_downstream(make_gateway: GatewayFactory) -> None:
    gw = await make_gateway()
    caller_auth = gw.auth("viewer")
    await gw.post(get_record(), role=None, headers=caller_auth)
    assert "authorization" not in gw.mock.state.last_headers

    gw = await make_gateway(t2_downstream_token="gateway-own-credential")  # noqa: S106
    caller_auth = gw.auth("viewer")
    await gw.post(get_record(), role=None, headers=caller_auth)
    forwarded = gw.mock.state.last_headers["authorization"]
    assert forwarded == "Bearer gateway-own-credential"
    assert caller_auth["Authorization"] != forwarded


async def test_forwarded_headers_allowlist(gw: Gateway) -> None:
    await gw.post(
        rpc("tools/list"),
        headers={
            "Mcp-Session-Id": "sess-1",
            "MCP-Protocol-Version": "2025-06-18",
            "Cookie": "session=steal-me",
            "X-Internal-Debug": "1",
        },
    )
    seen = gw.mock.state.last_headers
    assert seen["mcp-session-id"] == "sess-1"
    assert seen["mcp-protocol-version"] == "2025-06-18"
    assert seen["accept"] == "application/json, text/event-stream"
    assert "x-forwarded-for" in seen
    assert "cookie" not in seen and "x-internal-debug" not in seen


async def test_correlation_id_propagated_downstream_and_echoed(gw: Gateway) -> None:
    cid = "corr-test-12345678"
    response = await gw.post(get_record(), headers={"X-Correlation-ID": cid})
    assert response.headers["X-Correlation-ID"] == cid
    assert gw.mock.state.last_headers["x-correlation-id"] == cid
    assert gw.mock.state.last_payload["params"]["_meta"] == {"correlationId": cid}

    # Invalid IDs are replaced, and the replacement still flows end to end.
    response = await gw.post(get_record(), headers={"X-Correlation-ID": "bad id\r\nX: y"})
    generated = response.headers["X-Correlation-ID"]
    assert generated != "bad id\r\nX: y"
    assert gw.mock.state.last_headers["x-correlation-id"] == generated


def _raising_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused to http://10.0.0.5:9/mcp", request=request)

    return httpx.MockTransport(handler)


def _garbage_transport() -> httpx.MockTransport:
    return httpx.MockTransport(lambda _: httpx.Response(200, content=b"<html>oops</html>"))


def _error_status_transport() -> httpx.MockTransport:
    return httpx.MockTransport(lambda _: httpx.Response(503, text="db at 10.0.0.5 down"))


@pytest.mark.parametrize(
    "transport_factory",
    [_raising_transport, _garbage_transport, _error_status_transport],
    ids=["connect-error", "non-json", "http-503"],
)
async def test_downstream_unavailable_returns_sanitized_32603(
    make_gateway: GatewayFactory,
    transport_factory: Callable[[], httpx.MockTransport],
) -> None:
    gw = await make_gateway(transport=transport_factory())
    response = await gw.post(get_record("req-9"))
    assert response.status_code == 200
    assert response.json() == {
        "jsonrpc": "2.0",
        "id": "req-9",
        "error": {"code": -32603, "message": UNAVAILABLE},
    }

    # Local denials in the same batch still come back, in order.
    response = await gw.post([get_record(1), call("admin_reset_key", 2)])
    body = response.json()
    assert [r["error"]["code"] for r in body] == [-32603, -32001]
    for leak in ("10.0.0.5", "mock", "Traceback", "oops", "ConnectError"):
        assert leak not in response.text


# --------------------------------------------------------------------------- authorization


async def test_viewer_can_call_get_customer_record(gw: Gateway) -> None:
    response = await gw.post(get_record(5))
    body = response.json()
    assert response.status_code == 200
    assert body["id"] == 5 and body["result"]["isError"] is False
    assert gw.calls["tools/call:get_customer_record"] == 1


async def test_viewer_admin_tool_blocked_32001_exact_message(gw: Gateway) -> None:
    response = await gw.post(call("admin_reset_key", "abc"))
    assert response.status_code == 200
    assert response.json() == {
        "jsonrpc": "2.0",
        "id": "abc",
        "error": {"code": -32001, "message": DENIAL},
    }


async def test_deny_http_status_is_configurable(make_gateway: GatewayFactory) -> None:
    gw = await make_gateway(t2_deny_http_status=403)
    response = await gw.post(call("admin_reset_key", "abc"))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == -32001
    # Batches stay 200: a single status can't describe several outcomes.
    assert (await gw.post([call("admin_reset_key", 1), get_record(2)])).status_code == 200


async def test_blocked_call_never_reaches_downstream(gw: Gateway) -> None:
    for id_, name in enumerate(["admin_reset_key", "Admin_Reset_Key", "ADMIN_x"]):
        await gw.post(call(name, id_, {"tenant": SECRET}))
    assert gw.downstream_calls == 0
    assert gw.mock.state.last_payload is None


async def test_admin_can_call_admin_reset_key(gw: Gateway) -> None:
    response = await gw.post(call("admin_reset_key", 1, {"tenant": "acme"}), role="admin")
    body = response.json()
    assert response.status_code == 200
    assert body["result"]["structuredContent"] == {"status": "key_rotated"}
    assert gw.calls["tools/call:admin_reset_key"] == 1


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("Admin_reset_key", -32001),  # case-insensitive prefix
        ("ADMIN_RESET_KEY", -32001),
        (" admin_reset_key", -32602),  # leading space
        ("admin_reset_key ", -32602),
        ("admin_reset_key​", -32602),  # zero-width space
        ("​admin_reset_key", -32602),
        ("admin_reset_key\n", -32602),  # Python `$` would accept this
        ("аdmin_reset_key", -32602),  # Cyrillic a look-alike
        ("admin‐reset", -32602),  # Unicode hyphen
        ("", -32602),
        ("x" * 129, -32602),
    ],
    ids=repr,
)
async def test_tool_name_smuggling_rejected(gw: Gateway, name: str, code: int) -> None:
    body = (await gw.post(call(name, "s"))).json()
    assert body["id"] == "s"
    assert body["error"]["code"] == code
    assert gw.downstream_calls == 0


@pytest.mark.parametrize(
    "params",
    [None, [], {"arguments": {}}, {"name": 7}, {"name": None}],
    ids=repr,
)
async def test_tools_call_without_string_name_is_32602(gw: Gateway, params: Any) -> None:
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
    if params is not None:
        msg["params"] = params
    body = (await gw.post(msg)).json()
    # `params: []` is a valid JSON-RPC shape, so it fails the tools/call check (-32602), not -32600.
    assert body["error"]["code"] == -32602
    assert gw.downstream_calls == 0


def _bad_auth_headers(settings: Settings) -> list[tuple[str, dict[str, str]]]:
    good = mint(settings, "admin")
    exp = int(time.time()) + 60
    forged = jwt.encode(
        {"role": "admin", "exp": exp}, "other-secret-that-is-also-32-bytes!!", algorithm="HS256"
    )
    unsigned = jwt.encode({"role": "admin", "exp": exp}, None, algorithm="none")
    return [
        ("missing", {}),
        ("empty", {"Authorization": ""}),
        ("scheme-only", {"Authorization": "Bearer"}),
        ("scheme-space", {"Authorization": "Bearer "}),
        ("basic", {"Authorization": "Basic YWRtaW46YWRtaW4="}),
        ("double-space", {"Authorization": f"Bearer  {good}"}),
        ("two-tokens", {"Authorization": f"Bearer {good} {good}"}),
        ("trailing-space", {"Authorization": f"Bearer {good} "}),
        ("garbage-jwt", {"Authorization": "Bearer not.a.jwt"}),
        ("wrong-secret", {"Authorization": f"Bearer {forged}"}),
        ("alg-none", {"Authorization": f"Bearer {unsigned}"}),
        ("no-role", {"Authorization": f"Bearer {mint(settings, 'viewer', role=None)}"}),
        ("unknown-role", {"Authorization": f"Bearer {mint(settings, 'superuser')}"}),
        ("static-dev", {"Authorization": "Bearer admin-secret-token"}),
    ]


async def test_missing_or_malformed_bearer_401(gw: Gateway) -> None:
    for label, headers in _bad_auth_headers(gw.settings):
        response = await gw.post(get_record("req-1"), role=None, headers=headers)
        assert response.status_code == 401, label
        assert response.headers["WWW-Authenticate"] == "Bearer", label
        assert response.headers["X-Correlation-ID"], label
        assert response.json() == {
            "jsonrpc": "2.0",
            "id": "req-1",
            "error": {"code": -32002, "message": "Unauthenticated"},
        }, label
    # Unparseable body: id falls back to null.
    response = await gw.post(b"{nope", role=None)
    assert response.status_code == 401
    assert response.json()["id"] is None
    assert gw.downstream_calls == 0


async def test_bearer_scheme_is_case_insensitive(gw: Gateway) -> None:
    token = mint(gw.settings, "viewer")
    for scheme in ("bearer", "BEARER", "BeArEr"):
        response = await gw.post(
            rpc("tools/list"), role=None, headers={"Authorization": f"{scheme} {token}"}
        )
        assert response.status_code == 200, scheme


async def test_jwt_expired_and_clock_skew_leeway(make_gateway: GatewayFactory) -> None:
    gw = await make_gateway()  # leeway 30s (default)
    now = int(time.time())

    async def status(**claims: Any) -> int:
        token = mint(gw.settings, "viewer", **claims)
        headers = {"Authorization": f"Bearer {token}"}
        return (await gw.post(rpc("tools/list"), role=None, headers=headers)).status_code

    assert await status(exp=now - 10) == 200  # expired, but within skew leeway
    assert await status(exp=now - 120) == 401  # expired beyond leeway
    assert await status(nbf=now + 10) == 200  # issuer clock slightly ahead
    assert await status(nbf=now + 120) == 401  # not yet valid
    assert await status(exp=None) == 401  # exp is mandatory

    strict = await make_gateway(jwt_leeway_seconds=0)
    token = mint(strict.settings, "viewer", exp=now - 10)
    response = await strict.post(
        rpc("tools/list"), role=None, headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


async def test_jwt_audience_enforced_when_configured(make_gateway: GatewayFactory) -> None:
    gw = await make_gateway(jwt_audience="mcp-gateway")

    async def status(**claims: Any) -> int:
        headers = {"Authorization": f"Bearer {mint(gw.settings, 'viewer', **claims)}"}
        return (await gw.post(rpc("tools/list"), role=None, headers=headers)).status_code

    assert await status(aud="mcp-gateway") == 200
    assert await status(aud="someone-else") == 401
    assert await status() == 401


def _unsigned(payload: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


async def test_insecure_dev_tokens_disabled_by_default(
    make_gateway: GatewayFactory, settings_override: Settings
) -> None:
    assert Settings().allow_insecure_dev_tokens is False  # ambient CP_* cleared by the fixture
    assert settings_override.allow_insecure_dev_tokens is False

    dev_tokens = ["admin-secret-token", "viewer-secret-token", _unsigned({"role": "admin"})]
    gw = await make_gateway()
    for token in dev_tokens:
        headers = {"Authorization": f"Bearer {token}"}
        response = await gw.post(call("admin_reset_key"), role=None, headers=headers)
        assert response.status_code == 401, token
    assert gw.downstream_calls == 0

    # Explicitly opted in, they work (and still go through RBAC).
    dev = await make_gateway(allow_insecure_dev_tokens=True)
    expectations = {
        "admin-secret-token": "admin",
        "viewer-secret-token": "viewer",
        _unsigned({"role": "admin"}): "admin",
        _unsigned({"role": "viewer"}): "viewer",
    }
    for token, role in expectations.items():
        headers = {"Authorization": f"Bearer {token}"}
        response = await dev.post(rpc("tools/list"), role=None, headers=headers)
        assert response.status_code == 200, token
        assert response.headers["X-MCP-Caller-Role"] == role
    for bad in (
        _unsigned({"role": "superuser"}),
        _unsigned({}),
        _unsigned(["admin"]),
        "admin-secret",
    ):
        response = await dev.post(
            rpc("tools/list"), role=None, headers={"Authorization": f"Bearer {bad}"}
        )
        assert response.status_code == 401, bad


async def test_dev_tokens_warn_at_startup(settings_override: Settings, caplog_json: Any) -> None:
    app = create_app(settings_override.model_copy(update={"allow_insecure_dev_tokens": True}))
    async with app.router.lifespan_context(app):
        pass
    assert caplog_json.events("insecure_dev_tokens_enabled")


# --------------------------------------------------------------------------- defense in depth


async def test_mask_admin_tools_for_viewer_when_header_set(make_gateway: GatewayFactory) -> None:
    gw = await make_gateway()
    mask = {"X-Mask-Unauthorized-Tools": "true"}

    async def names(role: str, headers: dict[str, str] | None = None) -> set[str]:
        body = (await gw.post(rpc("tools/list"), role=role, headers=headers)).json()
        return {t["name"] for t in body["result"]["tools"]}

    assert await names("viewer", mask) == ALL_TOOLS - {"admin_reset_key"}
    assert await names("viewer", {"X-Mask-Unauthorized-Tools": "TRUE"}) == ALL_TOOLS - {
        "admin_reset_key"
    }
    assert await names("viewer") == ALL_TOOLS  # off unless asked
    assert await names("viewer", {"X-Mask-Unauthorized-Tools": "false"}) == ALL_TOOLS
    assert await names("admin", mask) == ALL_TOOLS  # admins see everything

    # Masking applies per slot inside a batch, too.
    body = (await gw.post([rpc("tools/list", 1), rpc("initialize", 2)], headers=mask)).json()
    assert "admin_reset_key" not in {t["name"] for t in body[0]["result"]["tools"]}
    assert body[1]["result"]["serverInfo"]["name"] == "mock-downstream"

    by_setting = await make_gateway(mcp_mask_unauthorized_tools=True)
    body = (await by_setting.post(rpc("tools/list"))).json()
    assert "admin_reset_key" not in {t["name"] for t in body["result"]["tools"]}


# --------------------------------------------------------------------------- diagnostics


async def test_caller_role_and_policy_headers(gw: Gateway) -> None:
    cases: list[tuple[Any, str, str]] = [
        (get_record(), "viewer", "allow"),
        (call("admin_reset_key"), "viewer", "deny"),
        ([get_record(1), call("admin_reset_key", 2)], "viewer", "mixed"),
        (call("admin_reset_key"), "admin", "allow"),
        (notification(), "viewer", "allow"),
    ]
    for payload, role, decision in cases:
        response = await gw.post(payload, role=role)
        assert response.headers["X-MCP-Caller-Role"] == role
        assert response.headers["X-MCP-Policy-Decision"] == decision
        assert response.headers["X-Correlation-ID"]


async def test_request_too_large_413(make_gateway: GatewayFactory) -> None:
    gw = await make_gateway(max_request_body_bytes=256)
    payload = get_record()
    payload["params"]["arguments"]["pad"] = "x" * 512
    response = await gw.post(payload)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == -32600
    assert gw.downstream_calls == 0


async def test_audit_log_has_decisions_but_no_arguments_or_tokens(
    gw: Gateway, caplog_json: Any
) -> None:
    viewer_auth = gw.auth("viewer")
    batch = [
        call("trigger_refund", 1, {"customer_id": "CUST-10042", "amount": 5, "reason": SECRET}),
        call("admin_reset_key", 2, {"tenant": SECRET}),
        call("admin_reset_key​", 3, {"tenant": SECRET}),
    ]
    await gw.post(batch, role=None, headers=viewer_auth)
    await gw.post(get_record(), role=None, headers={"Authorization": "Bearer nope"})

    decisions = caplog_json.events("mcp_policy_decision")
    assert [(d["tool"], d["decision"]) for d in decisions] == [
        ("trigger_refund", "allow"),
        ("admin_reset_key", "deny"),
        (None, "deny"),  # invalid names are not echoed into logs
    ]
    assert all(d["role"] == "viewer" and "latency_ms" in d for d in decisions)
    assert caplog_json.events("mcp_auth_failed")[0]["reason"] == "dev_tokens_disabled"
    assert caplog_json.events("mcp_request")[0]["decision"] == "mixed"
    assert SECRET not in caplog_json.text
    assert viewer_auth["Authorization"].split()[1] not in caplog_json.text
    assert "CUST-10042" not in caplog_json.text


# --------------------------------------------------------------------------- policy (pure)


@pytest.mark.parametrize(
    ("role", "method", "tool", "allow", "code"),
    [
        ("viewer", "tools/list", None, True, None),
        ("viewer", "initialize", None, True, None),
        ("viewer", "tools/call", "get_customer_record", True, None),
        ("viewer", "tools/call", "trigger_refund", True, None),
        ("viewer", "tools/call", "admin_reset_key", False, -32001),
        ("viewer", "tools/call", "ADMIN_reset_key", False, -32001),
        ("viewer", "tools/call", "admin_", False, -32001),
        ("viewer", "tools/call", "administrator", True, None),  # no underscore -> not admin_
        ("viewer", "tools/call", "my_admin_tool", True, None),  # prefix only
        ("admin", "tools/call", "admin_reset_key", True, None),
        ("admin", "tools/call", "get_customer_record", True, None),
        ("admin", "tools/list", None, True, None),
        ("viewer", "tools/call", " admin_reset_key", False, -32602),
        ("admin", "tools/call", " admin_reset_key", False, -32602),  # bad name even for admin
        ("admin", "tools/call", None, False, -32602),
        ("admin", "tools/call", "a" * 128, True, None),
        ("admin", "tools/call", "a" * 129, False, -32602),
        ("admin", "tools/call", "ns.tool-v2", True, None),
        ("superuser", "tools/call", "get_customer_record", False, -32001),  # default deny
        ("superuser", "tools/list", None, False, -32001),
        ("", "tools/list", None, False, -32001),
        ("Admin", "tools/call", "admin_reset_key", False, -32001),  # roles are case-sensitive
    ],
)
def test_policy_decide_table(
    role: str, method: str, tool: str | None, allow: bool, code: int | None
) -> None:
    decision = decide(role, method, tool)
    assert decision.allow is allow
    assert decision.error_code == code
    assert decision.reason


def test_policy_classify() -> None:
    assert classify("admin_x") is ToolClass.ADMIN
    assert classify("AdMiN_x") is ToolClass.ADMIN
    assert classify("get_customer_record") is ToolClass.STANDARD


# --------------------------------------------------------------------------- auth (pure)


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        (None, "missing"),
        ("", "missing"),
        ("Bearer", "malformed"),
        ("Bearer  abc", "malformed"),
        ("Bearer abc def", "malformed"),
        ("Bearer abc\n", "malformed"),
        ("Bearer abé", "malformed"),
        ("Basic abc", "malformed"),
    ],
)
def test_parse_bearer_rejects(header: str | None, reason: str) -> None:
    with pytest.raises(AuthError) as excinfo:
        parse_bearer(header)
    assert excinfo.value.reason == reason


def test_authenticate_jwt_principal(settings_override: Settings) -> None:
    token = mint(settings_override, "admin", sub="alice")
    principal = authenticate(f"Bearer {token}", settings_override)
    assert (principal.role, principal.subject, principal.token_kind) == ("admin", "alice", "jwt")


@pytest.mark.parametrize(
    ("claims", "reason"),
    [
        ({"exp": int(time.time()) - 3600}, "expired"),
        ({"nbf": int(time.time()) + 3600}, "not_yet_valid"),
        ({"exp": None}, "invalid"),
        ({"role": "root"}, "bad_role"),
        ({"role": None}, "bad_role"),
        ({"role": ["admin"]}, "bad_role"),
    ],
)
def test_authenticate_jwt_failures(
    settings_override: Settings, claims: dict[str, Any], reason: str
) -> None:
    token = mint(settings_override, "viewer", **claims)
    with pytest.raises(AuthError) as excinfo:
        authenticate(f"Bearer {token}", settings_override)
    assert excinfo.value.reason == reason


def test_authenticate_rejects_hs256_token_signed_with_other_secret(
    settings_override: Settings,
) -> None:
    token = jwt.encode(
        {"role": "admin", "exp": int(time.time()) + 60},
        "a-completely-different-secret-32bytes",
        algorithm="HS256",
    )
    with pytest.raises(AuthError) as excinfo:
        authenticate(f"Bearer {token}", settings_override)
    assert excinfo.value.reason == "invalid"


def test_dev_tokens_script_mints_valid_jwt(settings_override: Settings) -> None:
    path = Path(__file__).resolve().parents[1] / "scripts" / "dev_tokens.py"
    spec = importlib.util.spec_from_file_location("dev_tokens", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for role in ("admin", "viewer"):
        token = module.mint(role, settings_override.jwt_hs256_secret, 60)
        principal = authenticate(f"Bearer {token}", settings_override)
        assert principal.role == role and principal.token_kind == "jwt"  # noqa: S105
