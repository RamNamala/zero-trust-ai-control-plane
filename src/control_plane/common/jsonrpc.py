"""JSON-RPC 2.0 wire helpers shared by the MCP server, the gateway and the stdio downstream.

These operate on plain dicts on purpose. A Pydantic round-trip would coerce or drop the ``id``
(``"7"`` vs ``7`` vs ``null`` must survive byte-for-byte) and cannot express "key absent" versus
"key present with null" - which is exactly the request-vs-notification distinction.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any

JSONRPC_VERSION = "2.0"

JsonRpcId = str | int | None


class ErrorCode(IntEnum):
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    UNAUTHORIZED_TOOL_CALL = -32001  # gateway policy denial
    UNAUTHENTICATED = -32002  # gateway: missing/invalid bearer token


DEFAULT_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.PARSE_ERROR: "Parse error",
    ErrorCode.INVALID_REQUEST: "Invalid Request",
    ErrorCode.METHOD_NOT_FOUND: "Method not found",
    ErrorCode.INVALID_PARAMS: "Invalid params",
    ErrorCode.INTERNAL_ERROR: "Internal error",
    ErrorCode.UNAUTHORIZED_TOOL_CALL: "Unauthorized Tool Call",
    ErrorCode.UNAUTHENTICATED: "Unauthenticated",
}


def is_valid_id(value: object) -> bool:
    # bool is a subclass of int in Python but is not a valid JSON-RPC id.
    return (
        value is None
        or isinstance(value, str)
        or (isinstance(value, int) and not isinstance(value, bool))
    )


def is_notification(msg: object) -> bool:
    """``{"id": null}`` is a request (answer it with id null); only an absent ``id`` key makes
    a notification."""
    return isinstance(msg, dict) and "id" not in msg


def safe_id(msg: object) -> JsonRpcId:
    """The id to echo in an error for ``msg``: preserved if present and well-typed, else null."""
    if isinstance(msg, dict):
        candidate = msg.get("id")
        if is_valid_id(candidate):
            return candidate
    return None


def make_error(
    id_: JsonRpcId, code: int, message: str | None = None, data: Any = None
) -> dict[str, Any]:
    if message is None:
        try:
            message = DEFAULT_MESSAGES[ErrorCode(code)]
        except ValueError:  # `int in IntEnum` raises TypeError on 3.11, so look up instead
            message = "Error"
    error: dict[str, Any] = {"code": int(code), "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": JSONRPC_VERSION, "id": id_, "error": error}


def make_result(id_: JsonRpcId, result: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": id_, "result": result}


def request_shape_error(msg: object) -> dict[str, Any] | None:
    """Return a ``-32600`` error object if ``msg`` is not a structurally valid request or
    notification, else ``None``. Method-specific param checks belong to the caller."""
    if not isinstance(msg, dict):
        return make_error(None, ErrorCode.INVALID_REQUEST)
    if (
        msg.get("jsonrpc") != JSONRPC_VERSION
        or not isinstance(msg.get("method"), str)
        or ("id" in msg and not is_valid_id(msg["id"]))
        or ("params" in msg and not isinstance(msg["params"], dict | list))
    ):
        return make_error(safe_id(msg), ErrorCode.INVALID_REQUEST)
    return None
