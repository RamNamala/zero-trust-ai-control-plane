"""Server-Sent Events: a line parser over ``httpx.Response.aiter_lines()`` and an encoder.

The parser follows the WHATWG event-stream rules, not "every line is ``data: {json}``", because
real upstreams and proxies emit keep-alive comments (``: ping``), ``event:`` names, multi-line
``data:`` and a last frame without its trailing blank line. ``[DONE]`` is OpenAI's convention, not
SSE's, so it is returned as ordinary data and handled by the caller.
"""

from __future__ import annotations

from collections.abc import AsyncIterable, AsyncIterator
from dataclasses import dataclass

DONE = "[DONE]"


@dataclass(frozen=True, slots=True)
class SSEEvent:
    data: str
    event: str | None = None


async def iter_sse(lines: AsyncIterable[str]) -> AsyncIterator[SSEEvent]:
    """Yield one event per blank-line-terminated frame. Holds at most one frame in memory."""
    data: list[str] = []
    event: str | None = None
    async for raw in lines:
        line = raw.rstrip("\r\n")
        if line == "":
            if data:
                yield SSEEvent(data="\n".join(data), event=event)
            data, event = [], None
            continue
        if line.startswith(":"):
            continue
        field, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if field == "data":
            data.append(value)
        elif field == "event":
            event = value or None
        # "id", "retry" and unknown fields are ignored.
    if data:  # stream ended without the final blank line
        yield SSEEvent(data="\n".join(data), event=event)


def encode_event(data: str, event: str | None = None) -> bytes:
    """One frame. Embedded newlines become separate ``data:`` lines so they can't end the frame."""
    out = f"event: {event}\n" if event else ""
    out += "".join(f"data: {line}\n" for line in data.split("\n"))
    return (out + "\n").encode("utf-8")
