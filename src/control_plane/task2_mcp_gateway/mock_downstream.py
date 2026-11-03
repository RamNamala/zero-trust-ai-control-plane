"""A deterministic MCP-over-HTTP server for testing the gateway without Task 1 or sockets.

It records what it *received* (call counters, last headers, last payload) because the gateway's
security claims are about what reaches the downstream: a denied call must leave the counter
untouched, the client's ``Authorization`` must be absent, and ``X-Correlation-ID`` must be
present.
State lives on ``app.state`` and is created in the factory, not in lifespan, because
``httpx.ASGITransport`` does not run lifespan events.

Run standalone: ``python -m control_plane.task2_mcp_gateway.mock_downstream`` (port 8101).
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from control_plane.common.jsonrpc import (
    ErrorCode,
    is_notification,
    make_error,
    make_result,
    request_shape_error,
)

_OBJECT_SCHEMA: dict[str, Any] = {"type": "object", "additionalProperties": False}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_customer_record",
        "description": "Fetch a customer record by id.",
        "inputSchema": {
            **_OBJECT_SCHEMA,
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
        },
    },
    {
        "name": "trigger_refund",
        "description": "Queue a refund for a customer.",
        "inputSchema": {
            **_OBJECT_SCHEMA,
            "properties": {
                "customer_id": {"type": "string"},
                "amount": {"type": "number"},
                "reason": {"type": "string"},
            },
            "required": ["customer_id", "amount", "reason"],
        },
    },
    {
        "name": "admin_reset_key",
        "description": "Rotate a tenant API key (administrative).",
        "inputSchema": {**_OBJECT_SCHEMA, "properties": {"tenant": {"type": "string"}}},
    },
]
_TOOL_NAMES = {tool["name"] for tool in TOOLS}


def _text_result(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "structuredContent": payload,
        "isError": False,
    }


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "get_customer_record":
        return _text_result({"customer_id": arguments.get("customer_id"), "tier": "gold"})
    if name == "trigger_refund":
        return _text_result({"refund_id": "RF-mock000001", "status": "queued"})
    return _text_result({"status": "key_rotated"})


def _handle(msg: Any, calls: Counter[str]) -> dict[str, Any] | None:
    shape_error = request_shape_error(msg)
    if shape_error is not None:
        return shape_error
    method: str = msg["method"]
    calls[method] += 1
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    if is_notification(msg):
        return None
    id_ = msg.get("id")
    if method == "initialize":
        return make_result(
            id_,
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mock-downstream", "version": "0.1.0"},
            },
        )
    if method == "tools/list":
        return make_result(id_, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        if not isinstance(name, str) or name not in _TOOL_NAMES:
            return make_error(id_, ErrorCode.INVALID_PARAMS, f"Unknown tool: {name}")
        calls[f"tools/call:{name}"] += 1
        arguments = params.get("arguments")
        return make_result(id_, _call_tool(name, arguments if isinstance(arguments, dict) else {}))
    return make_error(id_, ErrorCode.METHOD_NOT_FOUND)


def create_mock_app() -> FastAPI:
    app = FastAPI(title="Mock MCP downstream")
    app.state.calls = Counter()
    app.state.last_headers = {}
    app.state.last_payload = None

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        app.state.last_headers = {k.lower(): v for k, v in request.headers.items()}
        try:
            payload = json.loads(await request.body())
        except ValueError:
            return JSONResponse(make_error(None, ErrorCode.PARSE_ERROR))
        app.state.last_payload = payload
        if isinstance(payload, list):
            if not payload:
                return JSONResponse(make_error(None, ErrorCode.INVALID_REQUEST))
            responses = [r for m in payload if (r := _handle(m, app.state.calls)) is not None]
            return JSONResponse(responses) if responses else Response(status_code=202)
        response = _handle(payload, app.state.calls)
        return JSONResponse(response) if response is not None else Response(status_code=202)

    @app.get("/__stats")
    async def stats() -> dict[str, Any]:
        return {"calls": dict(app.state.calls), "last_headers": app.state.last_headers}

    return app


app = create_mock_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8101)
