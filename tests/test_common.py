"""Cross-cutting contract: correlation IDs, error envelope, sanitization, JSON-RPC helpers."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from control_plane.common import jsonrpc
from control_plane.common.correlation import CorrelationIdMiddleware, is_valid_correlation_id
from control_plane.common.errors import ErrorCode, GatewayError, install_exception_handlers
from control_plane.common.logging import audit, get_logger, log_event
from control_plane.common.settings import Settings

SECRET_MARKERS = ("Traceback", "/srv/app/secrets.py", "sk-live-abc123", "SELECT * FROM")
VALID_CID = "test-corr-0001"


class Item(BaseModel):
    n: int


def build_app() -> FastAPI:
    app = FastAPI()
    install_exception_handlers(app)
    app.add_middleware(CorrelationIdMiddleware)

    @app.get("/ok")
    async def ok() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/unauth")
    async def unauth() -> None:
        raise HTTPException(
            status_code=401,
            detail="internal detail: user table lookup failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.get("/limited")
    async def limited() -> None:
        raise GatewayError(ErrorCode.RATE_LIMITED, headers={"Retry-After": "3"})

    @app.post("/items")
    async def items(item: Item) -> dict[str, int]:
        return {"n": item.n}

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError(
            "db failed at /srv/app/secrets.py running SELECT * FROM users with key sk-live-abc123"
        )

    return app


@pytest.fixture
async def client() -> Any:
    transport = httpx.ASGITransport(app=build_app(), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def raw_asgi_call(app: Any, headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    """Drive the app with raw ASGI so we can send header bytes httpx refuses to build."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/ok",
        "raw_path": b"/ok",
        "root_path": "",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 1),
        "server": ("test", 80),
    }
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    return {k.decode().lower(): v.decode() for k, v in start["headers"]}


# --- correlation IDs ----------------------------------------------------------------------


async def test_correlation_id_generated_when_missing(client: httpx.AsyncClient) -> None:
    r = await client.get("/ok")
    assert r.status_code == 200
    assert uuid.UUID(r.headers["x-correlation-id"]).version == 4


async def test_correlation_id_accepted_when_valid(client: httpx.AsyncClient) -> None:
    r = await client.get("/ok", headers={"X-Correlation-ID": VALID_CID})
    assert r.headers["x-correlation-id"] == VALID_CID


@pytest.mark.parametrize(
    "bad",
    [
        b"abc\nINJECTED",
        b"abcdefgh\r\nSet-Cookie: x=1",
        b"valid-id-1234\n",
        b"short",
        b"a" * 129,
        b"has space here",
        b"semi;colon;id",
        "café-12345".encode(),
    ],
)
async def test_correlation_id_replaced_when_malicious(bad: bytes) -> None:
    headers = await raw_asgi_call(build_app(), [(b"x-correlation-id", bad)])
    echoed = headers["x-correlation-id"]
    assert echoed.encode() != bad
    assert "\n" not in echoed and "INJECTED" not in echoed
    assert uuid.UUID(echoed).version == 4


def test_correlation_id_validator_uses_fullmatch() -> None:
    assert is_valid_correlation_id("abcdefgh")
    assert not is_valid_correlation_id("abcdefgh\n")  # `$` would accept this
    assert not is_valid_correlation_id(None)


@pytest.mark.parametrize(
    ("method", "path", "body", "status"),
    [
        ("GET", "/unauth", None, 401),
        ("GET", "/limited", None, 429),
        ("POST", "/items", {"n": "x"}, 422),
        ("GET", "/boom", None, 500),
        ("GET", "/no-such-route", None, 404),
    ],
)
async def test_correlation_id_echoed_on_error_responses(
    client: httpx.AsyncClient, method: str, path: str, body: Any, status: int
) -> None:
    r = await client.request(method, path, json=body, headers={"X-Correlation-ID": VALID_CID})
    assert r.status_code == status
    assert r.headers["x-correlation-id"] == VALID_CID
    assert r.json()["error"]["correlation_id"] == VALID_CID


# --- error envelope -----------------------------------------------------------------------


async def test_error_envelope_shape(client: httpx.AsyncClient) -> None:
    r = await client.get("/limited")
    assert r.status_code == 429
    assert r.headers["retry-after"] == "3"
    body = r.json()
    assert set(body) == {"error"}
    err = body["error"]
    assert set(err) == {"code", "message", "request_id", "correlation_id", "timestamp"}
    assert err["code"] == "RATE_LIMITED"
    assert uuid.UUID(err["request_id"]).version == 4
    ts = datetime.fromisoformat(err["timestamp"])
    assert ts.utcoffset() is not None and ts.utcoffset().total_seconds() == 0  # type: ignore[union-attr]
    assert err["correlation_id"] == r.headers["x-correlation-id"]


async def test_http_exception_detail_not_leaked(client: httpx.AsyncClient) -> None:
    r = await client.get("/unauth")
    assert r.json()["error"]["code"] == "UNAUTHENTICATED"
    assert r.headers["www-authenticate"] == "Bearer"
    assert "user table" not in r.text


async def test_validation_error_reduced_to_paths_without_input_echo(
    client: httpx.AsyncClient,
) -> None:
    r = await client.post("/items", json={"n": "SECRET-INPUT-123"})
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "INVALID_REQUEST"
    assert err["details"][0]["loc"] == ["body", "n"]
    assert set(err["details"][0]) == {"loc", "msg"}
    assert "SECRET-INPUT-123" not in r.text


async def test_unhandled_exception_returns_no_traceback(
    client: httpx.AsyncClient, caplog_json: Any
) -> None:
    r = await client.get("/boom", headers={"X-Correlation-ID": VALID_CID})
    assert r.status_code == 500
    assert r.json()["error"]["code"] == "INTERNAL_ERROR"
    for marker in SECRET_MARKERS:
        assert marker not in r.text
    # ...but operators get the full story on stderr, tagged with the same correlation ID.
    logged = caplog_json.events("unhandled_exception")
    assert len(logged) == 1
    assert logged[0]["correlation_id"] == VALID_CID
    assert "Traceback" in logged[0]["traceback"] and logged[0]["exc_type"] == "RuntimeError"


# --- logging ------------------------------------------------------------------------------


async def test_logs_are_json_with_request_correlation_id(caplog_json: Any) -> None:
    app = build_app()
    log = get_logger("test")

    @app.get("/logs")
    async def logs() -> dict[str, str]:
        log_event(log, "handled", value="line1\nFORGED")
        audit("policy_decision", decision="allow", tool="get_customer_record")
        return {}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        await c.get("/logs", headers={"X-Correlation-ID": VALID_CID})

    assert all("\n" not in line for line in caplog_json.lines)  # newline in value is escaped
    (handled,) = caplog_json.events("handled")
    assert handled["correlation_id"] == VALID_CID and handled["value"] == "line1\nFORGED"
    (decision,) = caplog_json.events("policy_decision")
    assert decision["logger"] == "control_plane.audit" and decision["correlation_id"] == VALID_CID
    assert set(handled) >= {"ts", "level", "logger", "event", "correlation_id"}


def test_logging_goes_to_stderr_not_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    from control_plane.common.logging import configure_logging

    configure_logging("INFO")
    log_event(get_logger("test"), "stderr_probe")
    out, err = capsys.readouterr()
    assert out == ""
    assert json.loads(err.strip().splitlines()[-1])["event"] == "stderr_probe"


# --- settings -----------------------------------------------------------------------------


def test_settings_defaults_match_brief(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    for key in list(os.environ):
        if key.startswith("CP_"):
            monkeypatch.delenv(key)
    s = Settings()
    assert s.rate_limit_tokens_per_window == 50_000
    assert s.rate_limit_window_seconds == 60.0
    assert s.primary_timeout_seconds == 3.0
    assert s.redactor_max_hold_chars == 256
    assert s.allow_insecure_dev_tokens is False


def test_settings_env_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CP_PRIMARY_TIMEOUT_SECONDS", "0.25")
    assert Settings().primary_timeout_seconds == 0.25


def test_settings_override_fixture_is_small(settings_override: Settings) -> None:
    assert settings_override.rate_limit_window_seconds < 60
    assert settings_override.primary_timeout_seconds < 3


def test_fake_clock(fake_clock: Any) -> None:
    t0 = fake_clock()
    fake_clock.advance(61)
    assert fake_clock() == t0 + 61


# --- JSON-RPC helpers ---------------------------------------------------------------------


def test_is_notification_distinguishes_null_id() -> None:
    assert jsonrpc.is_notification({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert not jsonrpc.is_notification({"jsonrpc": "2.0", "id": None, "method": "x"})
    assert not jsonrpc.is_notification([])


@pytest.mark.parametrize("id_", ["abc", 7, None, "7", 0])
def test_make_error_preserves_id_type(id_: Any) -> None:
    err = jsonrpc.make_error(id_, jsonrpc.ErrorCode.INVALID_PARAMS)
    wire = json.loads(json.dumps(err))
    assert wire["id"] == id_ and type(wire["id"]) is type(id_)
    assert wire["error"] == {"code": -32602, "message": "Invalid params"}


@pytest.mark.parametrize(
    ("msg", "expected_id"),
    [
        (42, None),
        ({"jsonrpc": "1.0", "id": 5, "method": "x"}, 5),
        ({"jsonrpc": "2.0", "id": "a"}, "a"),
        ({"jsonrpc": "2.0", "id": True, "method": "x"}, None),
        ({"jsonrpc": "2.0", "id": {"x": 1}, "method": "x"}, None),
        ({"jsonrpc": "2.0", "id": 1, "method": "x", "params": "s"}, 1),
    ],
)
def test_request_shape_error(msg: Any, expected_id: Any) -> None:
    err = jsonrpc.request_shape_error(msg)
    assert err is not None
    assert err["error"]["code"] == -32600 and err["id"] == expected_id


def test_request_shape_ok() -> None:
    assert jsonrpc.request_shape_error({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) is None
    assert jsonrpc.request_shape_error({"jsonrpc": "2.0", "method": "notifications/x"}) is None


def test_make_error_unknown_code_has_generic_message() -> None:
    assert jsonrpc.make_error(1, -31999)["error"]["message"] == "Error"
