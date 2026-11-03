"""Streaming PII guardrail: ``POST /v1/chat/completions`` proxies an OpenAI-style SSE stream and
redacts SSNs, emails and Luhn-valid cards in ``delta.content`` on the fly.

Each frame is parsed, its content runs through that choice's ``StreamingPIIRedactor``, and the
frame is re-emitted straight away. Only the short tail that could still turn into PII is held
back, so TTFT stays close to the upstream's and memory per stream is O(max_hold), never
O(response).

Why things are shaped the way they are:

* **Count in a trailer, not a header.** Headers go out before the first byte, so the redaction
  count is sent as a final ``event: guardrail`` frame (and written to the audit log).
* **Flush before ``finish_reason``.** A client may stop reading at the finish frame, so held-back
  text for that choice is emitted in its own content frame *before* the finish frame.
* **One ``async with`` for the whole upstream lifetime.** When the client disconnects, Starlette
  cancels this generator (PITFALLS #42). The ``async with`` then closes the upstream response, so
  the model stops generating and billing. The cost is that a failure to *connect* surfaces as an
  ``event: error`` frame after a 200, not as a 502.
* **Upstream failures never reach the client verbatim.** Buffered text is flushed (redacted),
  then a sanitized error envelope is sent. The exception and traceback go to stderr only.

Run standalone: ``python -m control_plane.task3_streaming_guardrail.gateway`` (port 8200).
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import aclosing, asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict

from control_plane.common.correlation import (
    CorrelationIdMiddleware,
    correlation_id_from_scope,
    outbound_headers,
)
from control_plane.common.errors import (
    ErrorCode,
    GatewayError,
    build_envelope,
    install_exception_handlers,
)
from control_plane.common.logging import audit, configure_logging, get_logger
from control_plane.common.settings import Settings
from control_plane.task3_streaming_guardrail.patterns import redact
from control_plane.task3_streaming_guardrail.redactor import StreamingPIIRedactor
from control_plane.task3_streaming_guardrail.sse import DONE, SSEEvent, encode_event, iter_sse

_log = get_logger("task3.gateway")

GUARDRAIL_HEADER = "X-Guardrail"
GUARDRAIL_VERSION = "pii-redaction/v1"
REDACTIONS_HEADER = "X-Guardrail-Redactions"  # non-stream only; a stream uses the trailer
SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",  # NGINX: don't buffer this response (PITFALLS #19)
    GUARDRAIL_HEADER: GUARDRAIL_VERSION,
}
_FRAME_KEYS = ("id", "object", "created", "model")


class ChatCompletionRequest(BaseModel):
    """Only the fields the guardrail relies on are typed. Other OpenAI parameters
    (temperature, tools, ...) pass through untouched."""

    model_config = ConfigDict(extra="allow")

    model: str
    messages: list[dict[str, Any]]
    stream: bool = False
    max_tokens: int | None = None


class _UpstreamError(Exception):
    def __init__(self, kind: str) -> None:
        self.kind = kind
        super().__init__(kind)


class _ChoiceGuard:
    """Per-stream state: one redactor per choice index, so ``n > 1`` completions can't share a
    tail and leak a match across choices."""

    def __init__(self, max_hold: int) -> None:
        self.max_hold = max_hold
        self.redactors: dict[int, StreamingPIIRedactor] = {}
        self.template: dict[str, Any] = {}
        self.frames_out = 0

    def _redactor(self, index: int) -> StreamingPIIRedactor:
        if index not in self.redactors:
            self.redactors[index] = StreamingPIIRedactor(self.max_hold)
        return self.redactors[index]

    @property
    def redactions(self) -> int:
        return sum(r.redaction_count for r in self.redactors.values())

    @property
    def forced_flushes(self) -> int:
        return sum(r.forced_flushes for r in self.redactors.values())

    @property
    def peak_buffer_chars(self) -> int:
        return max((r.peak_buffer_chars for r in self.redactors.values()), default=0)

    def _encode(self, chunk: dict[str, Any]) -> bytes:
        self.frames_out += 1
        return encode_event(json.dumps(chunk, ensure_ascii=False))

    def _content_frame(self, index: int, content: str) -> bytes:
        choice = {"index": index, "delta": {"content": content}, "finish_reason": None}
        return self._encode({**self.template, "choices": [choice]})

    def process(self, chunk: dict[str, Any]) -> list[bytes]:
        if not self.template:
            self.template = {k: chunk[k] for k in _FRAME_KEYS if k in chunk}
        choices = chunk.get("choices")
        if not isinstance(choices, list) or not choices:
            return [self._encode(chunk)]  # e.g. a usage-only frame: nothing to redact

        out: list[bytes] = []
        kept: list[Any] = []
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            raw_index = choice.get("index", 0)
            index = raw_index if isinstance(raw_index, int) else 0
            delta = choice.get("delta")
            new_delta: dict[str, Any] = dict(delta) if isinstance(delta, dict) else {}
            redactor = self._redactor(index)
            had_content = isinstance(new_delta.get("content"), str)
            if had_content:
                new_delta["content"] = redactor.feed(new_delta["content"])

            if choice.get("finish_reason") is not None:
                pending = str(new_delta.pop("content", "")) + redactor.flush()
                if pending:
                    out.append(self._content_frame(index, pending))
            elif had_content and new_delta["content"] == "":
                del new_delta["content"]
                if not new_delta:
                    continue  # nothing left to say for this choice yet
            kept.append({**choice, "delta": new_delta})

        if kept or chunk.get("usage") is not None:
            out.append(self._encode({**chunk, "choices": kept}))
        return out

    def flush_all(self) -> list[bytes]:
        out: list[bytes] = []
        for index, redactor in sorted(self.redactors.items()):
            tail = redactor.flush()
            if tail:
                out.append(self._content_frame(index, tail))
        return out


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


def _upstream_headers() -> dict[str, str]:
    """Allowlist: the caller's Authorization and hop-by-hop headers never go upstream."""
    return {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        **outbound_headers(),
    }


async def guard_events(
    events: AsyncIterator[SSEEvent], max_hold: int, correlation_id: str | None
) -> AsyncGenerator[bytes, None]:
    """The guardrail proper, independent of where the events come from: this gateway feeds it
    from httpx, the integration app from a T4 provider's byte stream. Errors raised by
    ``events`` (connect, status, mid-stream) become a flushed tail plus a sanitized
    ``event: error`` frame."""
    started = time.perf_counter()
    guard = _ChoiceGuard(max_hold)
    outcome = "upstream_error"
    try:
        try:
            async for event in events:
                if event.data == DONE:
                    for frame in guard.flush_all():
                        yield frame
                    trailer = {
                        "pii_redactions": guard.redactions,
                        "forced_flushes": guard.forced_flushes,
                        "correlation_id": correlation_id,
                    }
                    yield encode_event(json.dumps(trailer), event="guardrail")
                    yield encode_event(DONE)
                    outcome = "ok"
                    return
                if event.event == "error":
                    raise _UpstreamError("upstream_error_event")  # its text is not forwarded
                try:
                    chunk = json.loads(event.data)
                except ValueError:
                    _log.warning("upstream_frame_unparseable")
                    continue
                if not isinstance(chunk, dict):
                    continue
                for frame in guard.process(chunk):
                    yield frame
            raise _UpstreamError("eof_without_done")
        except Exception as exc:
            kind = exc.kind if isinstance(exc, _UpstreamError) else type(exc).__name__
            _log.warning(
                "upstream_stream_failed",
                exc_info=(type(exc), exc, exc.__traceback__),
                extra={"fields": {"kind": kind}},
            )
            for frame in guard.flush_all():
                yield frame
            envelope = build_envelope(
                ErrorCode.GATEWAY_UPSTREAM_FAILURE, correlation_id=correlation_id
            )
            yield encode_event(json.dumps(envelope), event="error")
    except (asyncio.CancelledError, GeneratorExit):
        outcome = "client_disconnected"
        _log.info("client_disconnected", extra={"fields": {"frames_out": guard.frames_out}})
        raise
    finally:
        audit(
            "guardrail_stream",
            outcome=outcome,
            pii_redactions=guard.redactions,
            forced_flushes=guard.forced_flushes,
            peak_buffer_chars=guard.peak_buffer_chars,
            choices=len(guard.redactors),
            frames_out=guard.frames_out,
            latency_ms=_elapsed_ms(started),
        )


async def _guarded_stream(
    client: httpx.AsyncClient,
    url: str,
    payload: dict[str, Any],
    max_hold: int,
    correlation_id: str | None,
) -> AsyncIterator[bytes]:
    async def upstream_events() -> AsyncGenerator[SSEEvent, None]:
        # The whole upstream lifetime sits in this one ``async with``: a client disconnect
        # cancels whatever it is awaiting, and leaving the block closes the upstream response.
        async with client.stream("POST", url, json=payload, headers=_upstream_headers()) as resp:
            if resp.status_code != 200:
                raise _UpstreamError(f"status_{resp.status_code}")
            async for event in iter_sse(resp.aiter_lines()):
                yield event

    events = upstream_events()
    try:
        async with aclosing(guard_events(events, max_hold, correlation_id)) as frames:
            async for frame in frames:
                yield frame
    finally:
        await events.aclose()


def redact_completion_body(body: dict[str, Any]) -> int:
    """Redact every ``choices[].message.content`` in place; returns the redaction count."""
    total = 0
    choices = body.get("choices")
    for choice in choices if isinstance(choices, list) else []:
        message = choice.get("message") if isinstance(choice, dict) else None
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            message["content"], n = redact(message["content"])
            total += n
    return total


async def _complete(client: httpx.AsyncClient, url: str, payload: dict[str, Any]) -> JSONResponse:
    """Non-stream: the body is already complete, so redact each message once."""
    started = time.perf_counter()
    try:
        resp = await client.post(url, json=payload, headers=_upstream_headers())
        if resp.status_code != 200:
            raise _UpstreamError(f"status_{resp.status_code}")
        body = resp.json()
        if not isinstance(body, dict):
            raise _UpstreamError("non_object_body")
    except Exception as exc:
        _log.warning(
            "upstream_request_failed",
            exc_info=(type(exc), exc, exc.__traceback__),
        )
        raise GatewayError(ErrorCode.GATEWAY_UPSTREAM_FAILURE) from None

    total = redact_completion_body(body)
    audit(
        "guardrail_completion",
        pii_redactions=total,
        latency_ms=_elapsed_ms(started),
    )
    return JSONResponse(
        body,
        headers={GUARDRAIL_HEADER: GUARDRAIL_VERSION, REDACTIONS_HEADER: str(total)},
    )


async def chat_completions(request: Request, body: ChatCompletionRequest) -> Response:
    settings: Settings = request.app.state.settings
    client: httpx.AsyncClient = request.app.state.client
    payload = body.model_dump(mode="json", exclude_unset=True)
    if not body.stream:
        return await _complete(client, settings.llm_upstream_url, payload)
    return StreamingResponse(
        _guarded_stream(
            client,
            settings.llm_upstream_url,
            payload,
            settings.redactor_max_hold_chars,
            correlation_id_from_scope(request.scope),
        ),
        media_type="text/event-stream",
        headers=SSE_HEADERS,
    )


def create_app(
    settings: Settings | None = None, client: httpx.AsyncClient | None = None
) -> FastAPI:
    """``client`` is injectable so tests can point it at the mock LLM. An injected client is
    attached immediately because ``httpx.ASGITransport`` doesn't run lifespan (PITFALLS #39)."""
    resolved = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(resolved.log_level)
        owned: httpx.AsyncClient | None = None
        if app.state.client is None:
            # read= is the gap allowed *between* chunks, not a cap on the whole stream.
            owned = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=3.0, read=60.0, pool=5.0),
                limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
                follow_redirects=False,
            )
            app.state.client = owned
        try:
            yield
        finally:
            if owned is not None:
                await owned.aclose()
                app.state.client = None

    app = FastAPI(title="Streaming PII guardrail", lifespan=lifespan)
    app.state.settings = resolved
    app.state.client = client
    app.add_middleware(CorrelationIdMiddleware)
    install_exception_handlers(app)
    app.add_api_route("/v1/chat/completions", chat_completions, methods=["POST"])
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8200)
