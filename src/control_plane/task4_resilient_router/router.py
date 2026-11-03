"""Resilient router: ``POST /v1/chat/completions`` with a per-tenant token budget and
primary -> backup failover.

Flow: tenant -> reserve budget -> primary under ``primary_timeout_seconds`` -> on a
provider-side failure, backup within what's left of ``request_deadline_seconds`` -> reconcile
the reservation to real usage, or release it if nobody answered.

Why things are shaped the way they are:

* **Reserve before calling, reconcile after.** Checking the budget and charging it later would
  let N concurrent requests all pass the check. The pessimistic hold (prompt + ``max_tokens``)
  is refunded down to ``usage.total_tokens`` once the provider answers.
* **Fail over only when the backup could help.** Timeout, 429, 5xx, connection errors (and
  untyped provider crashes) say "this provider is unwell". Any other 4xx says "this request is
  bad", and the backup would reject it too, so it's returned (sanitized) without a second call.
* **``asyncio.wait_for`` really cancels.** The timed-out primary call is cancelled, not left
  running in the background. MockProvider records that so tests can prove it.
* **Streaming timeout = time to first byte.** Until the first chunk is in hand nothing has been
  sent, so failover is invisible. After that, headers are on the wire and a failure can only
  be reported as an SSE ``event: error`` frame.
* **Nothing internal leaves.** Provider errors (which may carry paths, SQL, URLs, keys) are
  logged to stderr with their traceback; the client gets the fixed envelope from
  ``common.errors``.

Run standalone: ``python -m control_plane.task4_resilient_router.router`` (port 8300).
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections.abc import AsyncGenerator, AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from control_plane.common.correlation import CorrelationIdMiddleware, correlation_id_from_scope
from control_plane.common.errors import (
    ErrorCode,
    GatewayError,
    build_envelope,
    install_exception_handlers,
)
from control_plane.common.logging import audit, configure_logging, get_logger
from control_plane.common.settings import Settings
from control_plane.task3_streaming_guardrail.sse import encode_event
from control_plane.task4_resilient_router.circuit_breaker import CircuitBreaker
from control_plane.task4_resilient_router.providers import (
    ChatRequest,
    CompletionResult,
    HttpProvider,
    Provider,
    ProviderClientError,
    ProviderConnectionError,
    ProviderRateLimited,
    ProviderServerError,
)
from control_plane.task4_resilient_router.rate_limiter import (
    RateLimitExceededError,
    RequestTooLargeError,
    SQLiteRateLimiter,
    hash_tenant,
)
from control_plane.task4_resilient_router.tokens import (
    estimate_prompt_tokens,
    estimate_text_tokens,
    reservation_tokens,
)

_log = get_logger("task4.router")

TENANT_HEADER = "X-Tenant-Key"
MAX_TENANT_KEY_LEN = 256
SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}

# X-Routed-Provider reports the role, not the vendor, so clients see a stable vocabulary.
ROLE_PRIMARY = "primary"
ROLE_BACKUP = "backup"

REASON_NONE = "none"
REASON_429 = "http_429"
REASON_5XX = "http_5xx"
REASON_CONNECT = "connect_error"
REASON_PROVIDER_ERROR = "provider_error"
REASON_CIRCUIT_OPEN = "circuit_open"


def timeout_reason(timeout_seconds: float) -> str:
    """Derived from the setting so the header never claims a timeout that wasn't applied."""
    return f"timeout_{round(timeout_seconds * 1000)}ms"


class _NoFirstByte(Exception):
    """Provider stream ended before producing anything."""


def _failover_reason(exc: BaseException, timeout_seconds: float) -> str | None:
    """None means "don't fail over": the error is about the request, not the provider."""
    if isinstance(exc, TimeoutError):
        return timeout_reason(timeout_seconds)
    if isinstance(exc, ProviderRateLimited):
        return REASON_429
    if isinstance(exc, ProviderServerError):
        return REASON_5XX
    if isinstance(exc, ProviderConnectionError):
        return REASON_CONNECT
    if isinstance(exc, ProviderClientError):
        return None
    # Untyped crash inside a provider client (bad upstream payload, SDK bug): a provider-side
    # fault, so the backup is worth trying.
    return REASON_PROVIDER_ERROR


def _fmt_seconds(value: float) -> str:
    return f"{value:g}"


@dataclass(frozen=True)
class RouteOutcome:
    provider: str  # ROLE_PRIMARY | ROLE_BACKUP
    reason: str


@dataclass
class _Context:
    settings: Settings
    limiter: SQLiteRateLimiter
    primary: Provider
    backup: Provider
    breaker: CircuitBreaker | None
    tenant: str
    req: ChatRequest
    reservation_id: int
    reserved: int  # tokens held by the reservation
    remaining: int  # tenant headroom while the reservation is held
    deadline: float  # time.monotonic() value

    def budget(self) -> float:
        return self.deadline - time.monotonic()

    def rate_headers(self, charged: int) -> dict[str, str]:
        """``charged`` is what this request ends up costing: the real usage after reconcile,
        the full hold while a stream is still running, or 0 once released."""
        remaining = self.remaining + self.reserved - charged
        return {
            "X-RateLimit-Limit": str(self.limiter.limit),
            "X-RateLimit-Remaining": str(max(0, min(self.limiter.limit, remaining))),
            "X-RateLimit-Window-Seconds": _fmt_seconds(self.limiter.window_seconds),
        }


def _log_provider_failure(provider: str, exc: BaseException, reason: str | None) -> None:
    # Full detail (incl. traceback) goes to stderr for operators; never into a response.
    _log.warning(
        "provider_failed",
        exc_info=(type(exc), exc, exc.__traceback__),
        extra={"fields": {"provider": provider, "failover_reason": reason}},
    )


def _audit_route(
    ctx: _Context,
    outcome: str,
    provider: str | None,
    reason: str,
    started: float,
    tokens: int | None,
) -> None:
    audit(
        "route_decision",
        tenant=hash_tenant(ctx.tenant)[:12],  # a prefix is enough to correlate; never the key
        outcome=outcome,
        routed_provider=provider,
        failover_reason=reason,
        tokens=tokens,
        latency_ms=round((time.perf_counter() - started) * 1000, 3),
    )


def _tenant_from(request: Request) -> str:
    tenant = request.headers.get(TENANT_HEADER, "").strip()
    if not tenant or len(tenant) > MAX_TENANT_KEY_LEN:
        raise GatewayError(ErrorCode.UNAUTHENTICATED, f"Missing or invalid {TENANT_HEADER}.")
    return tenant


async def _reserve(
    settings: Settings, limiter: SQLiteRateLimiter, tenant: str, req: ChatRequest
) -> tuple[int, int, int]:
    tokens = reservation_tokens(req.messages, req.max_tokens)
    base = {
        "X-RateLimit-Limit": str(limiter.limit),
        "X-RateLimit-Window-Seconds": _fmt_seconds(limiter.window_seconds),
    }
    try:
        reservation = await limiter.reserve(tenant, tokens)
    except RequestTooLargeError as exc:
        raise GatewayError(
            ErrorCode.REQUEST_TOO_LARGE,
            "The request's token estimate exceeds the per-window token limit; "
            "reduce max_tokens or the prompt size.",
            headers=base,
        ) from exc
    except RateLimitExceededError as exc:
        audit(
            "rate_limited",
            tenant=hash_tenant(tenant)[:12],
            requested=tokens,
            retry_after_ms=exc.retry_after_ms,
        )
        raise GatewayError(
            ErrorCode.RATE_LIMITED,
            headers={
                **base,
                "Retry-After": str(max(1, math.ceil(exc.retry_after_ms / 1000))),
                "X-RateLimit-Remaining": str(exc.remaining),
                "X-RateLimit-Retry-After-Ms": str(exc.retry_after_ms),
            },
        ) from exc
    return reservation.id, tokens, reservation.remaining


def _primary_allowed(ctx: _Context) -> bool:
    return ctx.breaker is None or ctx.breaker.allow_primary()


def _record_primary(ctx: _Context, ok: bool) -> None:
    if ctx.breaker is not None:
        if ok:
            ctx.breaker.record_success()
        else:
            ctx.breaker.record_failure()


async def _complete_with_failover(ctx: _Context) -> tuple[CompletionResult, RouteOutcome]:
    timeout = ctx.settings.primary_timeout_seconds
    reason = REASON_CIRCUIT_OPEN
    if _primary_allowed(ctx):
        try:
            result = await asyncio.wait_for(
                ctx.primary.complete(ctx.req), timeout=min(timeout, max(ctx.budget(), 0.0))
            )
        except Exception as exc:  # CancelledError is BaseException: never swallowed here
            maybe = _failover_reason(exc, timeout)
            _log_provider_failure(ctx.primary.name, exc, maybe)
            if maybe is None:
                raise GatewayError(
                    ErrorCode.INVALID_REQUEST,
                    "The model provider rejected the request.",
                    status_code=400,
                ) from exc
            _record_primary(ctx, ok=False)
            reason = maybe
        else:
            _record_primary(ctx, ok=True)
            return result, RouteOutcome(ROLE_PRIMARY, REASON_NONE)

    budget = ctx.budget()
    if budget <= 0:
        raise GatewayError(ErrorCode.GATEWAY_UPSTREAM_FAILURE)
    try:
        result = await asyncio.wait_for(ctx.backup.complete(ctx.req), timeout=budget)
    except Exception as exc:
        _log_provider_failure(ctx.backup.name, exc, None)
        raise GatewayError(ErrorCode.GATEWAY_UPSTREAM_FAILURE) from exc
    return result, RouteOutcome(ROLE_BACKUP, reason)


def _actual_tokens(req: ChatRequest, result: CompletionResult) -> int:
    if result.total_tokens is not None:
        return result.total_tokens
    text = ""
    for choice in result.body.get("choices") or []:
        if isinstance(choice, dict) and isinstance(choice.get("message"), dict):
            content = choice["message"].get("content")
            text += content if isinstance(content, str) else ""
    return estimate_prompt_tokens(req.messages) + estimate_text_tokens(text)


async def _open_stream(
    provider: Provider, req: ChatRequest, ttfb_budget: float
) -> tuple[AsyncIterator[bytes], bytes]:
    """Start a provider stream and wait for its first chunk within ``ttfb_budget`` (TTFB)."""
    it = provider.stream(req)
    try:
        first = await asyncio.wait_for(anext(it), timeout=ttfb_budget)
    except StopAsyncIteration as exc:
        raise _NoFirstByte from exc
    except BaseException:
        if isinstance(it, AsyncGenerator):
            await it.aclose()
        raise
    return it, first


async def _stream_with_failover(
    ctx: _Context,
) -> tuple[AsyncIterator[bytes], bytes, RouteOutcome]:
    timeout = ctx.settings.primary_timeout_seconds
    reason = REASON_CIRCUIT_OPEN
    if _primary_allowed(ctx):
        try:
            it, first = await _open_stream(
                ctx.primary, ctx.req, min(timeout, max(ctx.budget(), 0.0))
            )
        except Exception as exc:
            maybe = _failover_reason(exc, timeout)
            _log_provider_failure(ctx.primary.name, exc, maybe)
            if maybe is None:
                raise GatewayError(
                    ErrorCode.INVALID_REQUEST,
                    "The model provider rejected the request.",
                    status_code=400,
                ) from exc
            _record_primary(ctx, ok=False)
            reason = maybe
        else:
            _record_primary(ctx, ok=True)
            return it, first, RouteOutcome(ROLE_PRIMARY, REASON_NONE)

    budget = ctx.budget()
    if budget <= 0:
        raise GatewayError(ErrorCode.GATEWAY_UPSTREAM_FAILURE)
    try:
        it, first = await _open_stream(ctx.backup, ctx.req, budget)
    except Exception as exc:
        _log_provider_failure(ctx.backup.name, exc, None)
        raise GatewayError(ErrorCode.GATEWAY_UPSTREAM_FAILURE) from exc
    return it, first, RouteOutcome(ROLE_BACKUP, reason)


class _StreamMeter:
    """Counts completion characters (and picks up provider ``usage``) from SSE bytes as they
    pass, without holding more than one partial line."""

    MAX_LINE = 65_536

    def __init__(self) -> None:
        self._partial = b""
        self.chars = 0
        self.usage_total: int | None = None

    def feed(self, chunk: bytes) -> None:
        data = self._partial + chunk
        *lines, self._partial = data.split(b"\n")
        if len(self._partial) > self.MAX_LINE:
            self._partial = b""  # a line this long isn't a frame we can meter; drop it
        for line in lines:
            self._line(line.strip())

    def _line(self, line: bytes) -> None:
        if not line.startswith(b"data:"):
            return
        payload = line[5:].strip()
        if not payload or payload == b"[DONE]":
            return
        try:
            frame = json.loads(payload)
        except ValueError:
            return
        if not isinstance(frame, dict):
            return
        usage = frame.get("usage")
        if isinstance(usage, dict) and isinstance(usage.get("total_tokens"), int):
            self.usage_total = usage["total_tokens"]
        for choice in frame.get("choices") or []:
            delta = choice.get("delta") if isinstance(choice, dict) else None
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                self.chars += len(delta["content"])


async def _settle(limiter: SQLiteRateLimiter, reservation_id: int, tokens: int | None) -> None:
    """Reconcile (``tokens`` given) or release. Never raises: by now the client has its answer,
    and a bookkeeping hiccup must not turn it into an error. The stale hold simply ages out."""
    try:
        if tokens is None:
            await limiter.release(reservation_id)
        else:
            await limiter.reconcile(reservation_id, tokens)
    except Exception:
        _log.exception("reservation_settle_failed")


def _relay(
    ctx: _Context, it: AsyncIterator[bytes], first: bytes, outcome: RouteOutcome, started: float
) -> AsyncIterator[bytes]:
    async def gen() -> AsyncIterator[bytes]:
        meter = _StreamMeter()
        status = "client_disconnected"
        try:
            meter.feed(first)
            yield first
            try:
                async for chunk in it:
                    meter.feed(chunk)
                    yield chunk
                status = "ok"
            except Exception as exc:
                # Headers are long gone: report in-band, sanitized.
                status = "midstream_error"
                _log_provider_failure(outcome.provider, exc, None)
                envelope = build_envelope(ErrorCode.GATEWAY_UPSTREAM_FAILURE)
                yield encode_event(json.dumps(envelope), event="error")
        finally:
            if isinstance(it, AsyncGenerator):
                await it.aclose()  # disconnect -> upstream stops generating (and billing)
            tokens = meter.usage_total
            if tokens is None:
                tokens = estimate_prompt_tokens(ctx.req.messages) + math.ceil(meter.chars / 4)
            # The tenant is charged for what was actually generated, even on a broken stream.
            await _settle(ctx.limiter, ctx.reservation_id, tokens)
            _audit_route(ctx, status, outcome.provider, outcome.reason, started, tokens)

    return gen()


async def chat_completions(request: Request, body: ChatRequest) -> Response:
    started = time.perf_counter()
    state = request.app.state
    settings: Settings = state.settings
    if state.primary is None or state.backup is None:
        raise GatewayError(ErrorCode.INTERNAL_ERROR)  # providers are wired in lifespan
    tenant = _tenant_from(request)
    reservation_id, reserved, remaining = await _reserve(settings, state.limiter, tenant, body)
    ctx = _Context(
        settings=settings,
        limiter=state.limiter,
        primary=state.primary,
        backup=state.backup,
        breaker=state.breaker,
        tenant=tenant,
        req=body,
        reservation_id=reservation_id,
        reserved=reserved,
        remaining=remaining,
        deadline=time.monotonic() + settings.request_deadline_seconds,
    )
    handed_off = False
    try:
        if body.stream:
            it, first, outcome = await _stream_with_failover(ctx)
            headers = {
                **SSE_HEADERS,
                # e.g. X-Guardrail when the integration app wraps providers in the T3 redactor
                **getattr(state, "extra_stream_headers", {}),
                **ctx.rate_headers(charged=ctx.reserved),  # still held until the stream ends
                "X-Routed-Provider": outcome.provider,
                "X-Failover-Reason": outcome.reason,
            }
            response: Response = StreamingResponse(
                _relay(ctx, it, first, outcome, started),
                media_type="text/event-stream",
                headers=headers,
            )
            handed_off = True  # the relay generator now owns settling the reservation
            return response

        result, outcome = await _complete_with_failover(ctx)
        actual = _actual_tokens(body, result)
        await _settle(ctx.limiter, reservation_id, actual)
        handed_off = True
        content = dict(result.body)
        content["gateway"] = {
            "routed_provider": outcome.provider,
            "failover_reason": outcome.reason,
            "correlation_id": correlation_id_from_scope(request.scope),
        }
        _audit_route(ctx, "ok", outcome.provider, outcome.reason, started, actual)
        return JSONResponse(
            content=content,
            headers={
                **ctx.rate_headers(charged=actual),
                "X-Routed-Provider": outcome.provider,
                "X-Failover-Reason": outcome.reason,
            },
        )
    except GatewayError as exc:
        exc.headers = {**ctx.rate_headers(charged=0), **exc.headers}  # released in finally
        _audit_route(ctx, exc.code.value, None, "n/a", started, None)
        raise
    finally:
        if not handed_off:
            # Nobody answered (or the client went away first): don't charge the tenant.
            await _settle(ctx.limiter, reservation_id, None)


def create_app(
    settings: Settings | None = None,
    *,
    limiter: SQLiteRateLimiter | None = None,
    primary: Provider | None = None,
    backup: Provider | None = None,
    clock: Callable[[], float] = time.time,
    breaker: CircuitBreaker | None = None,
) -> FastAPI:
    """Everything is injectable; whatever is injected is attached immediately because
    ``httpx.ASGITransport`` doesn't run lifespan (PITFALLS #39). The limiter opens its
    connection lazily, so it works with or without lifespan."""
    resolved = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(resolved.log_level)
        owned: httpx.AsyncClient | None = None
        if app.state.primary is None or app.state.backup is None:
            owned = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=3.0, read=60.0, pool=5.0),
                limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
                follow_redirects=False,
            )
            app.state.primary = app.state.primary or HttpProvider(
                "primary", resolved.primary_provider_url, owned
            )
            app.state.backup = app.state.backup or HttpProvider(
                "backup", resolved.backup_provider_url, owned
            )
        await app.state.limiter.open()
        try:
            yield
        finally:
            await app.state.limiter.close()
            if owned is not None:
                await owned.aclose()

    if breaker is None and resolved.circuit_breaker_enabled:
        breaker = CircuitBreaker(
            resolved.circuit_breaker_threshold, resolved.circuit_breaker_cooldown_seconds
        )

    app = FastAPI(title="Resilient model router", lifespan=lifespan)
    app.state.settings = resolved
    app.state.limiter = limiter or SQLiteRateLimiter(
        resolved.rate_limit_db_path,
        limit=resolved.rate_limit_tokens_per_window,
        window_seconds=resolved.rate_limit_window_seconds,
        clock=clock,
    )
    app.state.primary = primary
    app.state.backup = backup
    app.state.breaker = breaker
    app.add_middleware(CorrelationIdMiddleware)
    install_exception_handlers(app)
    app.add_api_route("/v1/chat/completions", chat_completions, methods=["POST"])
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8300)
