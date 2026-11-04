"""Zero-trust MCP gateway: ``POST /mcp`` authenticates, authorizes per message, and proxies.

Messages stay plain dicts for the whole trip (see ``common/jsonrpc.py``), so ``"7"`` / ``7`` /
``null`` ids and the absent-``id`` notification case come out exactly as they went in.

Batches are split into per-message *slots*. Rejected messages get a local response, and the
downstream is never told about them. Allowed messages go downstream as a single batch with their
ids **rewritten to internal integers**. Responses are matched back by internal id, and each one
gets its caller's original id back from the slot, never from what the downstream echoed. So
duplicate client ids inside one batch can't cross over, and a downstream that coerces ids can't
change their type. Output follows slot order, and notifications are skipped. If nothing is left
to answer, the reply is 202 with an empty body.

Downstream failures become per-request ``-32603`` with HTTP 200 rather than a 502 for the whole
body. That way a batch that mixes local denials and forwarded calls still returns the denials.

Run standalone: ``python -m control_plane.task2_mcp_gateway.proxy`` (port 8100).
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from control_plane.common.correlation import CorrelationIdMiddleware, outbound_headers
from control_plane.common.errors import install_exception_handlers
from control_plane.common.jsonrpc import (
    ErrorCode,
    JsonRpcId,
    is_notification,
    is_valid_id,
    loads_strict,
    make_error,
    request_shape_error,
)
from control_plane.common.logging import audit, configure_logging, get_correlation_id, get_logger
from control_plane.common.settings import Settings
from control_plane.task2_mcp_gateway.auth import AuthError, Principal, authenticate
from control_plane.task2_mcp_gateway.downstream import (
    UPSTREAM_UNAVAILABLE,
    Downstream,
    DownstreamError,
    HttpDownstream,
)
from control_plane.task2_mcp_gateway.policy import (
    ROLE_GRANTS,
    TOOL_NAME_RE,
    ToolClass,
    classify,
    decide,
    denial_message,
    is_valid_tool_name,
)

_log = get_logger("task2.proxy")

ROLE_HEADER = "X-MCP-Caller-Role"
DECISION_HEADER = "X-MCP-Policy-Decision"
MASK_HEADER = "x-mask-unauthorized-tools"
_FORWARDED_REQUEST_HEADERS = {
    "mcp-session-id": "Mcp-Session-Id",
    "mcp-protocol-version": "MCP-Protocol-Version",
}


@dataclass(slots=True)
class _Slot:
    """One incoming message and, eventually, its single response (or none for notifications)."""

    id: JsonRpcId
    notification: bool
    method: str | None
    response: dict[str, Any] | None = None
    forward_msg: dict[str, Any] | None = None
    rejected: bool = False
    denied_by_rbac: bool = False

    def reject(self, response: dict[str, Any], *, rbac: bool = False) -> None:
        self.response = None if self.notification else response
        self.rejected = True
        self.denied_by_rbac = rbac


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


async def _read_limited(request: Request, limit: int) -> bytes | None:
    """Return the body, or None once it exceeds ``limit``. Reading stops at the limit instead of
    buffering an attacker-chosen size first."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        return None
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > limit:
            return None
    return bytes(buf)


def _id_if_single(body: bytes) -> JsonRpcId:
    try:
        payload = loads_strict(body)
    except ValueError:
        return None
    if isinstance(payload, dict):
        candidate = payload.get("id")
        if is_valid_id(candidate):
            return candidate
    return None


def _with_correlation_meta(msg: dict[str, Any]) -> dict[str, Any]:
    """MCP's ``params._meta`` is the reserved slot for out-of-band metadata. Copy, don't mutate."""
    cid = get_correlation_id()
    params = msg.get("params")
    if cid is None or not isinstance(params, dict):
        return msg
    meta = params.get("_meta")
    new_meta = {**meta, "correlationId": cid} if isinstance(meta, dict) else {"correlationId": cid}
    return {**msg, "params": {**params, "_meta": new_meta}}


def _classify(msg: Any, principal: Principal, started: float) -> _Slot:
    shape_error = request_shape_error(msg)
    if shape_error is not None:
        # Structurally invalid messages are always answered (JSON-RPC 2.0 §5), even without id.
        slot = _Slot(id=shape_error["id"], notification=False, method=None)
        slot.reject(shape_error)
        return slot

    method: str = msg["method"]
    id_: JsonRpcId = msg.get("id")
    slot = _Slot(id=id_, notification=is_notification(msg), method=method)
    tool_name: str | None = None
    if method == "tools/call":
        params = msg.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        if not isinstance(name, str):
            _audit_decision(principal, method, None, "deny", "missing_tool_name", started)
            slot.reject(
                make_error(id_, ErrorCode.INVALID_PARAMS, "Invalid params: 'name' must be a string")
            )
            return slot
        tool_name = name

    decision = decide(principal.role, method, tool_name)
    if method == "tools/call":
        verdict = "allow" if decision.allow else "deny"
        _audit_decision(principal, method, tool_name, verdict, decision.reason, started)
    if not decision.allow:
        if decision.error_code == ErrorCode.METHOD_NOT_FOUND:
            slot.reject(make_error(id_, ErrorCode.METHOD_NOT_FOUND))
        elif decision.error_code == ErrorCode.INVALID_PARAMS:
            message = f"Invalid params: tool name must match ^{TOOL_NAME_RE.pattern}$"
            slot.reject(make_error(id_, ErrorCode.INVALID_PARAMS, message))
        else:
            message = denial_message(principal.role, tool_name or method)
            slot.reject(make_error(id_, ErrorCode.UNAUTHORIZED_TOOL_CALL, message), rbac=True)
        return slot

    slot.forward_msg = _with_correlation_meta(msg) if method == "tools/call" else msg
    return slot


def _audit_decision(
    principal: Principal,
    method: str,
    tool_name: str | None,
    decision: str,
    reason: str,
    started: float,
) -> None:
    # Only names that passed the strict regex are logged verbatim; arguments never are.
    safe_tool = tool_name if tool_name is not None and is_valid_tool_name(tool_name) else None
    audit(
        "mcp_policy_decision",
        role=principal.role,
        token_kind=principal.token_kind,
        method=method,
        tool=safe_tool,
        decision=decision,
        reason=reason,
        latency_ms=_elapsed_ms(started),
    )


def _outbound_request_headers(request: Request, settings: Settings) -> dict[str, str]:
    """Allowlist, so hop-by-hop headers and the caller's ``Authorization`` are dropped by
    construction - the MCP spec forbids token passthrough."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    for lower, canonical in _FORWARDED_REQUEST_HEADERS.items():
        value = request.headers.get(lower)
        if value is not None:
            headers[canonical] = value
    headers.update(outbound_headers())
    if request.client is not None:
        headers["X-Forwarded-For"] = request.client.host
    if settings.t2_downstream_token:
        headers["Authorization"] = f"Bearer {settings.t2_downstream_token}"
    return headers


async def _forward(
    slots: list[_Slot],
    is_batch: bool,
    downstream: Downstream | None,
    headers: dict[str, str],
) -> str | None:
    """Send the allowed subset as one downstream call and merge replies into their slots.
    Returns the downstream ``Mcp-Session-Id`` if any."""
    outbound: list[dict[str, Any]] = []
    pending: dict[int, _Slot] = {}
    for slot in slots:
        if slot.forward_msg is None:
            continue
        msg = slot.forward_msg
        if not slot.notification:
            internal_id = len(pending)
            pending[internal_id] = slot
            msg = {**msg, "id": internal_id}
        outbound.append(msg)
    if not outbound:
        return None

    try:
        if downstream is None:
            raise DownstreamError("not_configured")
        reply = await downstream.send(outbound if is_batch else outbound[0], headers)
    except DownstreamError as exc:
        _log.warning(
            "downstream_unavailable",
            exc_info=(type(exc), exc, exc.__traceback__),
            extra={"fields": {"kind": exc.kind, "pending": len(pending)}},
        )
        for slot in pending.values():
            slot.response = make_error(slot.id, ErrorCode.INTERNAL_ERROR, UPSTREAM_UNAVAILABLE)
        return None

    body = reply.body
    items = body if isinstance(body, list) else [body] if isinstance(body, dict) else []
    for item in items:
        if not isinstance(item, dict):
            continue
        internal = item.get("id")
        if isinstance(internal, int) and not isinstance(internal, bool):
            slot_for = pending.get(internal)
            if slot_for is not None and slot_for.response is None:
                slot_for.response = {**item, "id": slot_for.id}
    for slot in pending.values():
        if slot.response is None:  # downstream dropped or garbled this one
            slot.response = make_error(slot.id, ErrorCode.INTERNAL_ERROR, UPSTREAM_UNAVAILABLE)
    return reply.session_id


def _mask_admin_tools(slots: list[_Slot]) -> None:
    for slot in slots:
        response = slot.response
        if slot.method != "tools/list" or response is None:
            continue
        result = response.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            continue
        kept = [
            tool
            for tool in result["tools"]
            if not (
                isinstance(tool, dict)
                and isinstance(tool.get("name"), str)
                and classify(tool["name"]) is ToolClass.ADMIN
            )
        ]
        slot.response = {**response, "result": {**result, "tools": kept}}


def _policy_decision(slots: list[_Slot]) -> str:
    rejected = any(s.rejected for s in slots)
    forwarded = any(s.forward_msg is not None for s in slots)
    if not rejected:
        return "allow"
    return "mixed" if forwarded else "deny"


def _json_rpc_response(
    content: Any, principal: Principal, decision: str, status_code: int = 200
) -> JSONResponse:
    return JSONResponse(
        content,
        status_code=status_code,
        headers={ROLE_HEADER: principal.role, DECISION_HEADER: decision},
    )


async def handle_mcp(request: Request) -> Response:
    started = time.perf_counter()
    settings: Settings = request.app.state.settings

    body = await _read_limited(request, settings.max_request_body_bytes)
    if body is None:
        audit("mcp_request_too_large", limit=settings.max_request_body_bytes)
        return JSONResponse(
            make_error(None, ErrorCode.INVALID_REQUEST, "Request too large"), status_code=413
        )

    try:
        credentials = request.headers.getlist("authorization")
        if len(credentials) > 1:
            # A front proxy may honour the last header while we'd honour the first.
            raise AuthError("duplicate_header")
        principal = authenticate(credentials[0] if credentials else None, settings)
    except AuthError as exc:
        audit("mcp_auth_failed", reason=exc.reason, latency_ms=_elapsed_ms(started))
        return JSONResponse(
            make_error(_id_if_single(body), ErrorCode.UNAUTHENTICATED),
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = loads_strict(body)
    except ValueError:  # JSONDecodeError, invalid UTF-8, NaN/Infinity, too deeply nested
        return _json_rpc_response(make_error(None, ErrorCode.PARSE_ERROR), principal, "deny")

    if isinstance(payload, dict):
        messages, is_batch = [payload], False
    elif isinstance(payload, list) and payload:
        messages, is_batch = payload, True
    else:  # scalars and the empty batch get one error object, not an array
        return _json_rpc_response(make_error(None, ErrorCode.INVALID_REQUEST), principal, "deny")

    if len(messages) > settings.mcp_max_batch_messages:
        # One POST must not fan out into an unbounded number of downstream tool executions.
        audit("mcp_batch_too_large", role=principal.role, messages=len(messages))
        return _json_rpc_response(
            make_error(None, ErrorCode.INVALID_REQUEST, "Batch too large"), principal, "deny"
        )

    slots = [_classify(m, principal, started) for m in messages]
    session_id = await _forward(
        slots,
        is_batch,
        request.app.state.downstream,
        _outbound_request_headers(request, settings),
    )

    wants_mask = (
        settings.mcp_mask_unauthorized_tools
        or request.headers.get(MASK_HEADER, "").strip().lower() == "true"
    )
    if wants_mask and ToolClass.ADMIN not in ROLE_GRANTS.get(principal.role, frozenset()):
        _mask_admin_tools(slots)

    decision = _policy_decision(slots)
    responses = [s.response for s in slots if s.response is not None]
    audit(
        "mcp_request",
        role=principal.role,
        messages=len(slots),
        forwarded=sum(s.forward_msg is not None for s in slots),
        rejected=sum(s.rejected for s in slots),
        decision=decision,
        latency_ms=_elapsed_ms(started),
    )

    headers = {ROLE_HEADER: principal.role, DECISION_HEADER: decision}
    if session_id is not None:
        headers["Mcp-Session-Id"] = session_id
    if not responses:
        return Response(status_code=202, headers=headers)
    if is_batch:
        return JSONResponse(responses, headers=headers)
    status = settings.t2_deny_http_status if slots[0].denied_by_rbac else 200
    return JSONResponse(responses[0], status_code=status, headers=headers)


def create_app(settings: Settings | None = None, downstream: Downstream | None = None) -> FastAPI:
    """``downstream`` is injectable so tests can wire the gateway to the mock in-process via
    ``httpx.ASGITransport``. That transport doesn't run lifespan, so an injected downstream is
    attached immediately. Otherwise lifespan owns one shared, pooled ``httpx.AsyncClient``."""
    resolved = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(resolved.log_level)
        resolved.warn_if_insecure()
        client: httpx.AsyncClient | None = None
        if app.state.downstream is None:
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=3.0),
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
                follow_redirects=False,
            )
            app.state.downstream = HttpDownstream(resolved.mcp_downstream_url, client)
        try:
            yield
        finally:
            if client is not None:
                await client.aclose()
                app.state.downstream = None

    app = FastAPI(title="MCP security gateway", lifespan=lifespan)
    app.state.settings = resolved
    app.state.downstream = downstream
    app.add_middleware(CorrelationIdMiddleware)
    install_exception_handlers(app)
    app.add_api_route("/mcp", handle_mcp, methods=["POST"])
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8100)
