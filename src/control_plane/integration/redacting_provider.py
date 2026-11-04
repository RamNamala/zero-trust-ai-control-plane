"""Task 3 as a T4 ``Provider`` wrapper, so every model answer is redacted whoever produced it.

The router relays provider bytes as they come and owns failover, so the guardrail can't sit in
front of it as a separate HTTP hop without buffering or duplicating that logic. Wrapping both
primary and backup puts the redactor on whichever one wins, and leaves the router unchanged.

Failover still has to work through the wrapper. The router fails over only if the stream
*raises* before its first chunk. The guardrail turns upstream errors into an ``event: error``
frame, which to the router would look like a successful first byte. So the wrapper pulls the
inner provider's first chunk itself, *outside* the guardrail, and errors up to that point
propagate untouched. After the first byte, a failure becomes the guardrail's sanitized error
frame, which is the only honest option once headers are on the wire.
"""

from __future__ import annotations

import time
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import aclosing

from control_plane.common.logging import audit, get_correlation_id
from control_plane.task3_streaming_guardrail.gateway import guard_events, redact_completion_body
from control_plane.task3_streaming_guardrail.sse import iter_lines, iter_sse
from control_plane.task4_resilient_router.providers import (
    ChatRequest,
    CompletionResult,
    Provider,
)


async def _prepend(first: bytes, rest: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    yield first
    async for chunk in rest:
        yield chunk


class RedactingProvider:
    def __init__(self, inner: Provider, max_hold: int) -> None:
        self.inner = inner
        self.name = inner.name
        self.max_hold = max_hold

    async def complete(self, req: ChatRequest) -> CompletionResult:
        started = time.perf_counter()
        result = await self.inner.complete(req)
        body = dict(result.body)  # don't mutate what the inner provider may still hold
        total = redact_completion_body(body)
        audit(
            "guardrail_completion",
            provider=self.name,
            pii_redactions=total,
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return CompletionResult(body=body, total_tokens=result.total_tokens)

    async def stream(self, req: ChatRequest) -> AsyncIterator[bytes]:
        source = self.inner.stream(req)
        try:
            # Errors before the first chunk propagate, so the router can fail over (see above).
            try:
                first = await anext(source)
            except StopAsyncIteration:
                return  # empty stream: the router reports "no first byte" itself
            events = iter_sse(iter_lines(_prepend(first, source)))
            frames = guard_events(events, self.max_hold, get_correlation_id())
            async with aclosing(frames):
                async for frame in frames:
                    yield frame
        finally:
            if isinstance(source, AsyncGenerator):
                await source.aclose()  # disconnect or failover -> the model stops generating
