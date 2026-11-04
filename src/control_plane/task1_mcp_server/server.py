"""Low-level MCP server for Task 1 with a hand-registered ``tools/call`` handler.

Why not ``@server.call_tool()``: that decorator catches every exception and turns it into
``CallToolResult(isError=True)``, so malformed arguments would look like a tool that ran and
failed. Task 1 needs the opposite split:

* malformed request (unknown tool, schema violation) -> JSON-RPC error ``-32602`` on the wire;
* well-formed request the business logic refuses (unknown customer) -> ``isError: true``.

The SDK's own fallback for an unexpected exception is ``ErrorData(code=0, message=str(err))``,
which would leak internals, so the handler maps anything unexpected to a generic ``-32603``.

mcp 1.x also answers a request whose method is not in its ``ClientRequest`` union with
``-32602 "Invalid request parameters"`` (it fails union validation before dispatch). JSON-RPC
says that is ``-32601``, so ``serve`` relays incoming messages and answers those itself.
"""

from __future__ import annotations

import json
import logging
import os
import time
import typing
from typing import Any

import anyio
import mcp.types as types
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import McpError
from mcp.shared.message import SessionMessage
from pydantic import BaseModel, ValidationError

from control_plane.common.correlation import is_valid_correlation_id
from control_plane.common.jsonrpc import ErrorCode
from control_plane.common.logging import (
    get_logger,
    log_event,
    reset_correlation_id,
    set_correlation_id,
)
from control_plane.task1_mcp_server import data
from control_plane.task1_mcp_server.schemas import (
    TOOL_DESCRIPTIONS,
    TOOL_INPUT_MODELS,
    GetCustomerRecordInput,
    TriggerRefundInput,
    tool_input_schema,
)

SERVER_NAME = "customer-service-mcp"
CHAOS_ENV = "CP_T1_CHAOS_STDOUT"

_log = get_logger("task1.server")

# Every request method the SDK can parse; anything else is an unknown method (-32601).
KNOWN_REQUEST_METHODS: frozenset[str] = frozenset(
    typing.get_args(request_type.model_fields["method"].annotation)[0]
    for request_type in typing.get_args(types.ClientRequest.model_fields["root"].annotation)
)


def chaos_enabled() -> bool:
    return os.environ.get(CHAOS_ENV) == "1"


def emit_chaos(where: str) -> None:
    """Deliberately write to every stdout path a careless dependency might use. With fd-level
    isolation in ``__main__`` all three must land on stderr; tests assert exactly that."""
    print(f"CHAOS-PRINT {where}")  # noqa: T201 - the whole point
    logging.getLogger().warning("CHAOS-LOG %s", where)
    os.write(1, f"CHAOS-FD1 {where}\n".encode())


def sanitize_validation_errors(exc: ValidationError) -> list[dict[str, Any]]:
    # loc/msg/type say *where* and *why*, never *what was sent*. An allow-list rather than
    # deleting input/url/ctx, so a key added by a future pydantic release cannot leak.
    return [
        {"loc": list(err["loc"]), "msg": err["msg"], "type": err["type"]}
        for err in exc.errors(include_url=False, include_input=False, include_context=False)
    ]


def _invalid_params(message: str, data_: Any = None) -> McpError:
    return McpError(
        types.ErrorData(code=int(ErrorCode.INVALID_PARAMS), message=message, data=data_)
    )


def _tool_error(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], isError=True
    )


def _tool_success(payload: dict[str, Any]) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload))],
        structuredContent=payload,
    )


def _run_tool(name: str, args: BaseModel) -> types.CallToolResult:
    """Pure dispatch. Error messages only echo validated identifiers, never free text."""
    try:
        if isinstance(args, GetCustomerRecordInput):
            return _tool_success(data.get_customer_record(args.customer_id))
        if isinstance(args, TriggerRefundInput):
            return _tool_success(data.trigger_refund(args.customer_id, args.amount, args.reason))
    except data.CustomerNotFoundError:
        return _tool_error(f"Customer not found: {args.customer_id}")  # type: ignore[attr-defined]
    except data.RefundRejectedError as exc:
        return _tool_error(f"Refund rejected: {exc}")
    raise AssertionError(f"no implementation for tool {name!r}")  # pragma: no cover


def _correlation_id_from_meta(params: types.CallToolRequestParams) -> str | None:
    meta = params.meta
    if meta is None:
        return None
    candidate = (meta.model_extra or {}).get("correlationId")
    return candidate if isinstance(candidate, str) and is_valid_correlation_id(candidate) else None


async def handle_call_tool(req: types.CallToolRequest) -> types.ServerResult:
    params = req.params
    token = set_correlation_id(_correlation_id_from_meta(params))
    started = time.perf_counter()
    outcome = "internal_error"
    known_tool = params.name in TOOL_INPUT_MODELS
    try:
        if chaos_enabled():
            emit_chaos("tools/call")
        if not known_tool:
            outcome = "unknown_tool"
            raise _invalid_params(f"Unknown tool: {params.name}")
        model = TOOL_INPUT_MODELS[params.name]
        try:
            args = model.model_validate(params.arguments or {})
        except ValidationError as exc:
            outcome = "invalid_params"
            raise _invalid_params("Invalid params", sanitize_validation_errors(exc)) from None
        result = _run_tool(params.name, args)
        outcome = "tool_error" if result.isError else "ok"
        return types.ServerResult(result)
    except McpError:
        raise
    except Exception:
        _log.exception("tool_call_crashed", extra={"fields": {"tool": params.name}})
        raise McpError(
            types.ErrorData(code=int(ErrorCode.INTERNAL_ERROR), message="Internal error")
        ) from None
    finally:
        log_event(
            _log,
            "tool_call",
            # An unknown name is attacker-controlled; log a bounded repr, not the raw string.
            tool=params.name if known_tool else repr(params.name[:64]),
            outcome=outcome,
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        reset_correlation_id(token)


def build_server() -> Server[Any, Any]:
    server: Server[Any, Any] = Server(SERVER_NAME)

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=name,
                description=TOOL_DESCRIPTIONS[name],
                inputSchema=tool_input_schema(model),
            )
            for name, model in TOOL_INPUT_MODELS.items()
        ]

    server.request_handlers[types.CallToolRequest] = handle_call_tool
    return server


def _method_not_found(request_id: types.RequestId) -> SessionMessage:
    error = types.JSONRPCError(
        jsonrpc="2.0",
        id=request_id,
        error=types.ErrorData(code=int(ErrorCode.METHOD_NOT_FOUND), message="Method not found"),
    )
    return SessionMessage(message=types.JSONRPCMessage(error))


class _NullIdError(types.JSONRPCMessage):
    """An error response with ``id: null``. mcp 1.x types can't express it (``JSONRPCError.id``
    is ``str | int``) and the stdio writer dumps with ``exclude_none=True``, which would drop
    the id entirely, so this message serializes itself."""

    def model_dump_json(self, **_: Any) -> str:
        error = self.root.error  # type: ignore[union-attr]
        return json.dumps(
            {"jsonrpc": "2.0", "id": None, "error": {"code": error.code, "message": error.message}}
        )


def _unparseable(exc: Exception) -> SessionMessage:
    """The SDK's stdio reader hands over a ``ValidationError`` for a line it couldn't turn into
    a message, and the server would answer it with a ``notifications/message`` log rather than
    a response, leaving the caller waiting (PITFALLS #50). JSON-RPC 2.0 owes an error with
    ``id: null``: -32700 for text that isn't JSON (incl. invalid UTF-8 and lone surrogates),
    -32600 for JSON that isn't a request."""
    not_json = not isinstance(exc, ValidationError) or any(
        err["type"] == "json_invalid" for err in exc.errors(include_url=False, include_input=False)
    )
    code = ErrorCode.PARSE_ERROR if not_json else ErrorCode.INVALID_REQUEST
    error = types.JSONRPCError.model_construct(
        jsonrpc="2.0",
        id=None,
        error=types.ErrorData(
            code=int(code), message="Parse error" if not_json else "Invalid Request"
        ),
    )
    return SessionMessage(message=_NullIdError.model_construct(root=error))


async def _relay_known_methods(
    source: MemoryObjectReceiveStream[SessionMessage | Exception],
    sink: MemoryObjectSendStream[SessionMessage | Exception],
    responses: MemoryObjectSendStream[SessionMessage],
) -> None:
    async with sink:
        async for message in source:
            if isinstance(message, Exception):
                log_event(_log, "unparseable_frame", logging.WARNING, kind=type(message).__name__)
                await responses.send(_unparseable(message))
                continue
            if isinstance(message, SessionMessage):
                root = message.message.root
                if (
                    isinstance(root, types.JSONRPCRequest)
                    and root.method not in KNOWN_REQUEST_METHODS
                ):
                    log_event(_log, "unknown_method", method=repr(root.method[:64]))
                    await responses.send(_method_not_found(root.id))
                    continue
            await sink.send(message)


async def serve(
    server: Server[Any, Any],
    read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
    write_stream: MemoryObjectSendStream[SessionMessage],
) -> None:
    """Run ``server`` over a transport, answering unknown methods with -32601 in front of it.
    The relay ends when the transport's read side closes, which in turn ends ``server.run``."""
    sink, filtered = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    async with anyio.create_task_group() as tg:
        tg.start_soon(_relay_known_methods, read_stream, sink, write_stream)
        await server.run(filtered, write_stream, server.create_initialization_options())
