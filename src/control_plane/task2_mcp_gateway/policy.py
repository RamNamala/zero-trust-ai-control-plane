"""RBAC policy: a pure function over a table, so it can be tested exhaustively without HTTP.

Tool names are validated before classification. A strict ASCII ``fullmatch`` blocks the
smuggling tricks a prefix check alone misses: a leading space (``" admin_reset_key"``), a
zero-width character, Unicode look-alikes, or a trailing newline (Python's ``$`` would accept it).
The ``admin_`` check is case-insensitive so ``Admin_reset_key`` can't slip past a downstream that
treats names case-insensitively. Unknown roles get nothing (default deny).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from control_plane.common.jsonrpc import ErrorCode

TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
ADMIN_PREFIX = "admin_"


class ToolClass(StrEnum):
    STANDARD = "standard"
    ADMIN = "admin"


ROLE_GRANTS: dict[str, frozenset[ToolClass]] = {
    "admin": frozenset({ToolClass.STANDARD, ToolClass.ADMIN}),
    "viewer": frozenset({ToolClass.STANDARD}),
}


@dataclass(frozen=True, slots=True)
class Decision:
    allow: bool
    reason: str
    error_code: int | None = None


def is_valid_tool_name(name: str) -> bool:
    return TOOL_NAME_RE.fullmatch(name) is not None


def classify(tool_name: str) -> ToolClass:
    return ToolClass.ADMIN if tool_name.lower().startswith(ADMIN_PREFIX) else ToolClass.STANDARD


def denial_message(role: str, tool_name: str) -> str:
    # Only called with names that passed TOOL_NAME_RE, so echoing them is safe.
    return (
        f"Unauthorized Tool Call: Role '{role}' is not permitted to invoke "
        f"administrative tool '{tool_name}'."
    )


def decide(role: str, method: str, tool_name: str | None = None) -> Decision:
    grants = ROLE_GRANTS.get(role)
    if grants is None:
        return Decision(False, "unknown_role", ErrorCode.UNAUTHORIZED_TOOL_CALL)
    if method != "tools/call":
        return Decision(True, "non_tool_method")
    if tool_name is None or not is_valid_tool_name(tool_name):
        return Decision(False, "invalid_tool_name", ErrorCode.INVALID_PARAMS)
    tool_class = classify(tool_name)
    if tool_class not in grants:
        return Decision(False, f"role_lacks_{tool_class}", ErrorCode.UNAUTHORIZED_TOOL_CALL)
    return Decision(True, f"role_grants_{tool_class}")
