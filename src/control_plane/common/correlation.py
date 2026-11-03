"""X-Correlation-ID middleware: validate or generate, store in a contextvar, echo on every response.

A pure ASGI middleware rather than ``BaseHTTPMiddleware`` because the latter buffers/wraps
streaming responses and breaks contextvar propagation into the body iterator - both fatal for
the Task 3 SSE path. Client-supplied IDs are accepted only if they match a conservative charset
(log-injection defense); anything else is silently replaced with a fresh uuid4.

The ID is also written into ``scope["state"]`` because Starlette's handler for bare ``Exception``
runs in ``ServerErrorMiddleware``, *outside* user middleware: by then the contextvar is reset and
our ``send`` wrapper is bypassed, so the error handler has to read it from the scope.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from control_plane.common.logging import (
    get_correlation_id,
    reset_correlation_id,
    set_correlation_id,
)

HEADER = "X-Correlation-ID"
_VALID = re.compile(r"[A-Za-z0-9._-]{8,128}")
STATE_KEY = "correlation_id"


def is_valid_correlation_id(value: str | None) -> bool:
    # fullmatch, not ``^...$``: Python's ``$`` also matches before a trailing newline.
    return value is not None and _VALID.fullmatch(value) is not None


def new_correlation_id() -> str:
    return str(uuid.uuid4())


def resolve_correlation_id(candidate: str | None) -> str:
    return (
        candidate
        if candidate is not None and is_valid_correlation_id(candidate)
        else (new_correlation_id())
    )


def correlation_id_from_scope(scope: Scope) -> str | None:
    state = scope.get("state")
    value = state.get(STATE_KEY) if isinstance(state, dict) else None
    return value if isinstance(value, str) else None


def outbound_headers() -> dict[str, str]:
    """Headers to attach to every outbound httpx call so the next hop logs the same ID."""
    cid = get_correlation_id()
    return {HEADER: cid} if cid else {}


class CorrelationIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw: str | None = None
        for name, value in scope.get("headers", []):
            if name.lower() == b"x-correlation-id":
                raw = value.decode("latin-1")
                break
        cid = resolve_correlation_id(raw)
        state: dict[str, Any] = scope.setdefault("state", {})
        state[STATE_KEY] = cid

        async def send_with_header(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)[HEADER] = cid
            await send(message)

        token = set_correlation_id(cid)
        try:
            await self.app(scope, receive, send_with_header)
        finally:
            reset_correlation_id(token)
