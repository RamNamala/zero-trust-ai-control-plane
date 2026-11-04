"""Request body cap for the JSON endpoints, enforced while the body is read.

FastAPI reads and parses the whole body before a route runs, so a size check inside the route
comes too late: a 50 MB ``padding`` field would already be in memory, and fields outside
``messages`` don't even show up in the token estimate. This middleware refuses an oversized
``Content-Length`` up front and, for chunked bodies, stops at the limit instead of buffering.

A pure ASGI middleware, like ``CorrelationIdMiddleware``, so streaming responses and contextvars
pass through untouched. Install it *before* the correlation middleware (Starlette's last-added
is outermost), so the 413 still carries the request's correlation ID.
"""

from __future__ import annotations

from collections.abc import Collection

from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from control_plane.common.errors import ErrorCode, error_response


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int, exclude_paths: Collection[str] = ()) -> None:
        self.app = app
        self.max_bytes = max_bytes
        # e.g. /mcp, which enforces the same limit itself and must answer in JSON-RPC shape
        self.exclude_paths = frozenset(exclude_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in self.exclude_paths:
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                declared = value.decode("latin-1")
                if declared.isdigit() and int(declared) > self.max_bytes:
                    response = error_response(ErrorCode.REQUEST_TOO_LARGE)
                    await response(scope, receive, send)
                    return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # FastAPI re-raises HTTPException from body reading; the app's handler
                    # turns it into the standard REQUEST_TOO_LARGE envelope.
                    raise HTTPException(status_code=413)
            return message

        await self.app(scope, limited_receive, send)
