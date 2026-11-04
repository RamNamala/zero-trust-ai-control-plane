"""Server-Sent Events: a line parser over ``httpx.Response.aiter_lines()`` and an encoder.

The parser follows the WHATWG event-stream rules, not "every line is ``data: {json}``", because
real upstreams and proxies emit keep-alive comments (``: ping``), ``event:`` names, multi-line
``data:`` and a last frame without its trailing blank line. ``[DONE]`` is OpenAI's convention, not
SSE's, so it is returned as ordinary data and handled by the caller.
"""

from __future__ import annotations

import codecs
from collections.abc import AsyncIterable, AsyncIterator
from dataclasses import dataclass

DONE = "[DONE]"

# One frame (or one line) larger than this is not a chat-completion delta. The cap is what
# keeps memory per stream bounded against an upstream that never sends a newline or the blank
# line ending a frame (PITFALLS #51).
MAX_FRAME_CHARS = 1 << 20


class FrameTooLargeError(ValueError):
    """An SSE line or frame exceeded ``MAX_FRAME_CHARS``; framing can't be trusted after it."""


@dataclass(frozen=True, slots=True)
class SSEEvent:
    data: str
    event: str | None = None


async def iter_lines(
    chunks: AsyncIterable[bytes], max_chars: int = MAX_FRAME_CHARS
) -> AsyncIterator[str]:
    """Bytes -> text lines, holding at most one partial line (and a split UTF-8 sequence).
    Used instead of ``httpx.Response.aiter_lines()``, which buffers a line of any length."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    partial = ""
    async for chunk in chunks:
        partial += decoder.decode(chunk)
        *lines, partial = partial.split("\n")
        for line in lines:
            yield line
        if len(partial) > max_chars:
            raise FrameTooLargeError("SSE line too long")
    partial += decoder.decode(b"", final=True)
    if partial:
        yield partial


async def iter_sse(
    lines: AsyncIterable[str], max_chars: int = MAX_FRAME_CHARS
) -> AsyncIterator[SSEEvent]:
    """Yield one event per blank-line-terminated frame. Holds at most one frame in memory,
    and raises ``FrameTooLargeError`` rather than let that frame grow past ``max_chars``."""
    data: list[str] = []
    size = 0
    event: str | None = None
    async for raw in lines:
        line = raw.rstrip("\r\n")
        if line == "":
            if data:
                yield SSEEvent(data="\n".join(data), event=event)
            data, size, event = [], 0, None
            continue
        if line.startswith(":"):
            continue
        field, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if field == "data":
            size += len(value) + 1
            if size > max_chars:
                raise FrameTooLargeError("SSE frame too large")
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
