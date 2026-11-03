"""The unified control plane: one FastAPI app, one correlation ID per request, every hop.

* ``POST /v1/chat/completions``: T4 router (token budget + failover) -> provider -> T3 redactor.
  Redaction wraps each provider (``RedactingProvider``), so it applies to whichever one answered.
* ``POST /mcp``: T2 gateway (authn, RBAC, JSON-RPC fidelity) -> ``StdioMcpDownstream`` -> T1,
  which runs as a real child process.

The routes reuse the T2/T4 handlers as-is, registered on one app rather than mounted as sub-apps,
so there is a single middleware stack, a single set of exception handlers and one lifespan. The
handlers only read ``request.app.state``, and this app's state is the union of what they need.

Lifespan owns the limiter connection and the T1 subprocess. T1 is started eagerly so a broken
deployment fails at boot, not on the first tool call. There is no outbound HTTP: the providers
are in-process mocks, so no httpx client is created.

Run: ``uvicorn control_plane.integration.app:app --port 8000``.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI

from control_plane.common.correlation import CorrelationIdMiddleware
from control_plane.common.errors import install_exception_handlers
from control_plane.common.logging import configure_logging, configure_root_logging
from control_plane.common.settings import Settings
from control_plane.integration.mock_agent_llm import AgentMockProvider
from control_plane.integration.redacting_provider import RedactingProvider
from control_plane.task2_mcp_gateway.downstream import StdioMcpDownstream
from control_plane.task2_mcp_gateway.proxy import handle_mcp
from control_plane.task3_streaming_guardrail.gateway import GUARDRAIL_HEADER, GUARDRAIL_VERSION
from control_plane.task4_resilient_router.circuit_breaker import CircuitBreaker
from control_plane.task4_resilient_router.providers import Provider
from control_plane.task4_resilient_router.rate_limiter import SQLiteRateLimiter
from control_plane.task4_resilient_router.router import chat_completions

# Past the default 3 s failover timeout, so the default deployment demonstrates failover.
DEFAULT_PRIMARY_DELAY_SECONDS = 3.2


def create_app(
    settings: Settings | None = None,
    *,
    primary: Provider | None = None,
    backup: Provider | None = None,
    downstream: StdioMcpDownstream | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    """Providers are given *unwrapped*; this function puts the guardrail around them, so a
    caller can't wire a path that skips redaction."""
    resolved = settings or Settings()
    raw_primary = primary or AgentMockProvider("primary", delay=DEFAULT_PRIMARY_DELAY_SECONDS)
    raw_backup = backup or AgentMockProvider("backup")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_root_logging()
        configure_logging(resolved.log_level)
        resolved.warn_if_insecure()
        await app.state.limiter.open()
        try:
            await app.state.downstream.start()
            yield
        finally:
            await app.state.downstream.close()
            await app.state.limiter.close()

    app = FastAPI(title="Zero-trust AI control plane", lifespan=lifespan)
    app.state.settings = resolved
    app.state.limiter = SQLiteRateLimiter(
        resolved.rate_limit_db_path,
        limit=resolved.rate_limit_tokens_per_window,
        window_seconds=resolved.rate_limit_window_seconds,
        clock=clock,
    )
    app.state.primary = RedactingProvider(raw_primary, resolved.redactor_max_hold_chars)
    app.state.backup = RedactingProvider(raw_backup, resolved.redactor_max_hold_chars)
    app.state.breaker = (
        CircuitBreaker(
            resolved.circuit_breaker_threshold, resolved.circuit_breaker_cooldown_seconds
        )
        if resolved.circuit_breaker_enabled
        else None
    )
    app.state.extra_stream_headers = {GUARDRAIL_HEADER: GUARDRAIL_VERSION}
    app.state.downstream = downstream or StdioMcpDownstream()
    app.add_middleware(CorrelationIdMiddleware)
    install_exception_handlers(app)
    app.add_api_route("/v1/chat/completions", chat_completions, methods=["POST"])
    app.add_api_route("/mcp", handle_mcp, methods=["POST"])
    return app


app = create_app()
