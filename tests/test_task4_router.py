"""Task 4 - rate limiter and failover router (acceptance contract - docs/ACCEPTANCE_MATRIX.md).

Limiter tests run against a real on-disk SQLite file (``tmp_db_path``) with an injected clock.
Router tests wire the FastAPI app to ``MockProvider``s through ``httpx.ASGITransport``. Timing
tests come in two flavours: fast variants with a 0.2 s primary timeout (default run), and the
real 3.0 s / 3.2 s / 2.9 s cases marked ``slow``.
"""

from __future__ import annotations

import asyncio
import json
import multiprocessing as mp
import sqlite3
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import FakeClock, JsonLogCapture

from control_plane.common.settings import Settings
from control_plane.task4_resilient_router.circuit_breaker import CircuitBreaker
from control_plane.task4_resilient_router.providers import MockProvider, Provider
from control_plane.task4_resilient_router.rate_limiter import (
    RateLimitExceededError,
    RequestTooLargeError,
    Reservation,
    SQLiteRateLimiter,
    hash_tenant,
)
from control_plane.task4_resilient_router.router import create_app

LIMIT = 50_000
LEAK_MARKERS = ("Traceback", "/srv/", "SELECT", "10.0.0.7", "sk-live", ".py")
TENANT = "tenant-alpha-key"
# reserve = ceil(len("hi") / 4) + 4 * 1 message + max_tokens 100 = 105; MockProvider reports 120
REQUEST: dict[str, Any] = {
    "model": "gpt-test",
    "messages": [{"role": "user", "content": "hi"}],
    "max_tokens": 100,
}
RESERVED = 105
USAGE = 120


def _limiter(path: Path, clock: FakeClock | None = None, window: float = 60.0) -> SQLiteRateLimiter:
    return SQLiteRateLimiter(
        path, limit=LIMIT, window_seconds=window, clock=clock if clock is not None else time.time
    )


def _ledger(path: Path) -> list[tuple[Any, ...]]:
    with sqlite3.connect(path) as conn:
        return conn.execute(
            "SELECT id, tenant_key, tokens, timestamp, status FROM token_usage"
        ).fetchall()


def _assert_no_leaks(text: str) -> None:
    for marker in LEAK_MARKERS:
        assert marker not in text, f"leaked {marker!r}: {text}"


@asynccontextmanager
async def router(
    settings: Settings,
    primary: Provider,
    backup: Provider,
    *,
    limiter: SQLiteRateLimiter | None = None,
    breaker: CircuitBreaker | None = None,
) -> AsyncIterator[tuple[httpx.AsyncClient, SQLiteRateLimiter]]:
    lim = limiter or SQLiteRateLimiter(
        settings.rate_limit_db_path,
        limit=settings.rate_limit_tokens_per_window,
        window_seconds=settings.rate_limit_window_seconds,
    )
    app = create_app(settings, limiter=lim, primary=primary, backup=backup, breaker=breaker)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://router") as client:
            yield client, lim
    finally:
        await lim.close()


async def _post(
    client: httpx.AsyncClient, body: dict[str, Any] | None = None, tenant: str | None = TENANT
) -> httpx.Response:
    headers = {"X-Tenant-Key": tenant} if tenant is not None else {}
    return await client.post("/v1/chat/completions", json=body or REQUEST, headers=headers)


def _fast(settings: Settings, **update: Any) -> Settings:
    return settings.model_copy(update={"primary_timeout_seconds": 0.2, **update})


def _real_timing(settings: Settings) -> Settings:
    return settings.model_copy(
        update={"primary_timeout_seconds": 3.0, "request_deadline_seconds": 15.0}
    )


# --------------------------------------------------------------------------- rate-limit state


async def test_wal_mode_and_pragmas_enabled(tmp_db_path: Path) -> None:
    assert not tmp_db_path.parent.exists()  # the limiter must create its own directory
    async with _limiter(tmp_db_path) as lim:
        pragmas = await lim.pragmas()
    assert pragmas == {"journal_mode": "wal", "synchronous": 1, "busy_timeout": 5000}
    with sqlite3.connect(tmp_db_path) as conn:
        index = conn.execute("PRAGMA index_list(token_usage)").fetchall()
        assert any(row[1] == "idx_tenant_time" for row in index)
        cols = [row[2] for row in conn.execute("PRAGMA index_info(idx_tenant_time)")]
        assert cols == ["tenant_key", "timestamp"]


async def test_limit_enforced_at_50000(tmp_db_path: Path, fake_clock: FakeClock) -> None:
    async with _limiter(tmp_db_path, fake_clock) as lim:
        r = await lim.reserve("exact", 50_000)
        assert r.remaining == 0
        with pytest.raises(RateLimitExceededError):
            await lim.reserve("exact", 1)

        await lim.reserve("edge", 49_999)
        last = await lim.reserve("edge", 1)  # exactly reaching the limit is allowed
        assert last.remaining == 0
        with pytest.raises(RateLimitExceededError) as exc_info:
            await lim.reserve("edge", 1)
        assert exc_info.value.remaining == 0
        assert await lim.usage("edge") == 50_000


async def test_concurrent_gather_cannot_overdraft(tmp_db_path: Path) -> None:
    async with _limiter(tmp_db_path) as lim:
        results = await asyncio.gather(
            *(lim.reserve("burst", 1_000) for _ in range(100)), return_exceptions=True
        )
    ok = [r for r in results if isinstance(r, Reservation)]
    refused = [r for r in results if isinstance(r, RateLimitExceededError)]
    assert len(ok) == 50
    assert len(refused) == 50  # nothing else (e.g. "transaction within a transaction")
    rows = _ledger(tmp_db_path)
    assert len(rows) == 50
    assert sum(row[2] for row in rows) == 50_000


def _mp_worker(db_path: str, n: int, barrier: Any, results: Any) -> None:
    """Runs in a spawned process with its own connection (and its own asyncio.Lock, which
    therefore protects nothing across processes - only BEGIN IMMEDIATE does)."""

    async def run() -> int:
        async with SQLiteRateLimiter(Path(db_path), limit=LIMIT, window_seconds=60.0) as lim:
            barrier.wait()  # all processes start hammering at the same moment
            out = await asyncio.gather(
                *(lim.reserve("shared-tenant", 1_000) for _ in range(n)), return_exceptions=True
            )
        unexpected = [r for r in out if not isinstance(r, Reservation | RateLimitExceededError)]
        if unexpected:
            raise RuntimeError(f"unexpected errors: {unexpected!r}")
        return sum(isinstance(r, Reservation) for r in out)

    results.put(asyncio.run(run()))


@pytest.mark.slow
@pytest.mark.subprocess
async def test_multiprocess_cannot_overdraft(tmp_db_path: Path) -> None:
    async with _limiter(tmp_db_path):
        pass  # create the file + schema once, as app startup would
    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(4)
    results = ctx.Queue()
    procs = [
        ctx.Process(target=_mp_worker, args=(str(tmp_db_path), 25, barrier, results))
        for _ in range(4)
    ]
    for p in procs:
        p.start()
    for p in procs:
        await asyncio.to_thread(p.join, 60)
    assert all(p.exitcode == 0 for p in procs), [p.exitcode for p in procs]
    successes = [results.get(timeout=5) for _ in procs]
    assert sum(successes) == 50, successes
    rows = _ledger(tmp_db_path)
    assert len(rows) == 50
    assert sum(row[2] for row in rows) == 50_000


async def test_sliding_window_expiry_restores_quota(
    tmp_db_path: Path, fake_clock: FakeClock
) -> None:
    async with _limiter(tmp_db_path, fake_clock) as lim:
        await lim.reserve(TENANT, 50_000)
        fake_clock.advance(59.999)
        with pytest.raises(RateLimitExceededError):
            await lim.reserve(TENANT, 1)
        fake_clock.advance(0.002)  # now past t0 + 60 s
        r = await lim.reserve(TENANT, 50_000)
        assert r.remaining == 0
        assert len(_ledger(tmp_db_path)) == 1  # expired row was evicted, not just ignored


async def test_partial_expiry_is_sliding_not_fixed(
    tmp_db_path: Path, fake_clock: FakeClock
) -> None:
    async with _limiter(tmp_db_path, fake_clock) as lim:
        t0 = fake_clock.now
        await lim.reserve(TENANT, 20_000)
        fake_clock.set(t0 + 30)
        await lim.reserve(TENANT, 30_000)
        fake_clock.set(t0 + 60.5)
        # A fixed window would have reset at t0+60 and allow 50,000. A sliding window only
        # forgets the 20k from t0; the 30k from t0+30 still counts until t0+90.
        r = await lim.reserve(TENANT, 20_000)
        assert r.remaining == 0
        with pytest.raises(RateLimitExceededError):
            await lim.reserve(TENANT, 1)
        fake_clock.set(t0 + 90.5)
        assert await lim.usage(TENANT) == 20_000


async def test_retry_after_ms_is_accurate(tmp_db_path: Path, fake_clock: FakeClock) -> None:
    async with _limiter(tmp_db_path, fake_clock) as lim:
        t0 = fake_clock.now
        await lim.reserve(TENANT, 10_000)
        fake_clock.set(t0 + 10)
        await lim.reserve(TENANT, 30_000)
        fake_clock.set(t0 + 20)
        await lim.reserve(TENANT, 10_000)
        fake_clock.set(t0 + 25)
        # Needs 15k: the t0 row frees 10k (not enough), the t0+10 row frees 30k more, so the
        # earliest success is t0+10+60 = t0+70, i.e. 45,000 ms from now.
        with pytest.raises(RateLimitExceededError) as exc_info:
            await lim.reserve(TENANT, 15_000)
        assert exc_info.value.retry_after_ms == 45_000
        assert exc_info.value.remaining == 0

        fake_clock.set(t0 + 25 + 44.999)
        with pytest.raises(RateLimitExceededError) as exc_info:
            await lim.reserve(TENANT, 15_000)
        assert exc_info.value.retry_after_ms == 1
        fake_clock.set(t0 + 70)
        await lim.reserve(TENANT, 15_000)


async def test_request_larger_than_limit_is_413_not_429(
    tmp_db_path: Path, fake_clock: FakeClock, settings_override: Settings
) -> None:
    async with _limiter(tmp_db_path, fake_clock) as lim:
        with pytest.raises(RequestTooLargeError):
            await lim.reserve(TENANT, 50_001)
        await lim.reserve(TENANT, 50_000)  # even with the window full it's still 413
        with pytest.raises(RequestTooLargeError):
            await lim.reserve(TENANT, 60_000)

    primary, backup = MockProvider("primary"), MockProvider("backup")
    async with router(settings_override, primary, backup) as (client, _):
        resp = await _post(client, {**REQUEST, "max_tokens": 60_000})
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "REQUEST_TOO_LARGE"
    assert "Retry-After" not in resp.headers  # retrying can never help
    assert primary.calls == backup.calls == 0


# --------------------------------------------------------------------------- token tracking


async def test_reconcile_refunds_unused_reservation(
    tmp_db_path: Path, fake_clock: FakeClock, settings_override: Settings
) -> None:
    async with _limiter(tmp_db_path, fake_clock) as lim:
        t0 = fake_clock.now
        r = await lim.reserve(TENANT, 5_000)
        fake_clock.set(t0 + 30)
        await lim.reconcile(r.id, 1_200)
        assert await lim.usage(TENANT) == 1_200
        (row,) = _ledger(tmp_db_path)
        assert row[3] == t0  # original timestamp kept (PITFALLS #27)
        assert row[4] == "settled"
        fake_clock.set(t0 + 60.001)
        assert await lim.usage(TENANT) == 0  # expires on the original schedule

    async with router(settings_override, MockProvider("p"), MockProvider("b")) as (client, lim):
        resp = await _post(client)
        assert resp.status_code == 200
        assert await lim.usage(TENANT) == USAGE  # charged real usage, not the 105 estimate
        assert resp.headers["X-RateLimit-Remaining"] == str(LIMIT - USAGE)


async def test_release_on_total_failure_does_not_charge_tenant(
    tmp_db_path: Path, settings_override: Settings
) -> None:
    async with _limiter(tmp_db_path) as lim:
        r = await lim.reserve(TENANT, 5_000)
        await lim.release(r.id)
        assert await lim.usage(TENANT) == 0

    primary = MockProvider("p", "http_500")
    backup = MockProvider("b", "http_500")
    async with router(settings_override, primary, backup) as (client, lim):
        resp = await _post(client)
        assert resp.status_code == 502
        assert await lim.usage(TENANT) == 0
    assert resp.headers["X-RateLimit-Remaining"] == str(LIMIT)  # reports post-release headroom
    assert _ledger(settings_override.rate_limit_db_path) == []


async def test_tenant_isolation(tmp_db_path: Path, fake_clock: FakeClock) -> None:
    async with _limiter(tmp_db_path, fake_clock) as lim:
        await lim.reserve("tenant-a", 50_000)
        with pytest.raises(RateLimitExceededError):
            await lim.reserve("tenant-a", 1)
        r = await lim.reserve("tenant-b", 50_000)
        assert r.remaining == 0
        assert await lim.usage("tenant-a") == await lim.usage("tenant-b") == 50_000


async def test_raw_tenant_key_not_stored(tmp_db_path: Path) -> None:
    raw = "sk-tenant-SUPERSECRET-0123456789"
    async with _limiter(tmp_db_path) as lim:
        r = await lim.reserve(raw, 100)
        await lim.reconcile(r.id, 90)
        rows = _ledger(tmp_db_path)
    assert rows and rows[0][1] == hash_tenant(raw)
    assert all(raw not in str(row) for row in rows)
    for path in tmp_db_path.parent.iterdir():  # main file plus any -wal / -shm
        assert raw.encode() not in path.read_bytes(), path.name


# --------------------------------------------------------------------------- timeout races


async def test_failover_on_primary_timeout_3200ms(settings_override: Settings) -> None:
    """Fast variant: 0.2 s timeout, primary needs 0.6 s. The 0.5 s bound leaves 300 ms for
    reserve + logging + backup under full-suite load, and still fails if we waited for it."""
    primary = MockProvider("p", delay=0.6)
    backup = MockProvider("b")
    async with router(_fast(settings_override), primary, backup) as (client, _):
        started = time.perf_counter()
        resp = await _post(client)
        elapsed = time.perf_counter() - started
    assert resp.status_code == 200
    assert resp.headers["X-Routed-Provider"] == "backup"
    assert resp.headers["X-Failover-Reason"] == "timeout_200ms"
    assert resp.json()["gateway"]["routed_provider"] == "backup"
    assert elapsed < 0.5  # failed over at the timeout, didn't wait for the slow primary


@pytest.mark.slow
async def test_failover_on_primary_timeout_3200ms_real_timing(settings_override: Settings) -> None:
    primary = MockProvider("p", delay=3.2)
    backup = MockProvider("b")
    async with router(_real_timing(settings_override), primary, backup) as (client, _):
        started = time.perf_counter()
        resp = await _post(client)
        elapsed = time.perf_counter() - started
    assert resp.status_code == 200
    assert resp.headers["X-Routed-Provider"] == "backup"
    assert resp.headers["X-Failover-Reason"] == "timeout_3000ms"
    assert 2.95 <= elapsed < 3.2
    assert primary.cancelled


async def test_timed_out_primary_task_is_cancelled(settings_override: Settings) -> None:
    primary = MockProvider("p", delay=0.35)
    backup = MockProvider("b")
    async with router(_fast(settings_override), primary, backup) as (client, _):
        resp = await _post(client)
        assert resp.status_code == 200
        await asyncio.sleep(0.3)  # long enough for a zombie primary to have finished
    assert primary.calls == 1
    assert primary.cancelled is True
    assert primary.completed == 0
    assert backup.completed == 1


async def test_primary_2900ms_is_not_failed_over(settings_override: Settings) -> None:
    """Fast variant: 0.2 s timeout, primary answers in 0.1 s (margin for Windows' ~16 ms
    timer granularity)."""
    primary = MockProvider("p", delay=0.1)
    backup = MockProvider("b")
    async with router(_fast(settings_override), primary, backup) as (client, _):
        resp = await _post(client)
    assert resp.status_code == 200
    assert resp.headers["X-Routed-Provider"] == "primary"
    assert resp.headers["X-Failover-Reason"] == "none"
    assert backup.calls == 0
    assert not primary.cancelled


@pytest.mark.slow
async def test_primary_2900ms_is_not_failed_over_real_timing(settings_override: Settings) -> None:
    primary = MockProvider("p", delay=2.9)
    backup = MockProvider("b")
    async with router(_real_timing(settings_override), primary, backup) as (client, _):
        resp = await _post(client)
    assert resp.status_code == 200
    assert resp.headers["X-Routed-Provider"] == "primary"
    assert resp.headers["X-Failover-Reason"] == "none"
    assert backup.calls == 0


# --------------------------------------------------------------------------- fallback


async def test_failover_on_429(settings_override: Settings) -> None:
    primary, backup = MockProvider("p", "http_429"), MockProvider("b")
    async with router(settings_override, primary, backup) as (client, _):
        resp = await _post(client)
    assert resp.status_code == 200
    assert resp.headers["X-Routed-Provider"] == "backup"
    assert resp.headers["X-Failover-Reason"] == "http_429"
    assert primary.calls == backup.calls == 1


async def test_failover_on_5xx(settings_override: Settings) -> None:
    primary, backup = MockProvider("p", "http_500"), MockProvider("b")
    async with router(settings_override, primary, backup) as (client, _):
        resp = await _post(client)
    assert resp.status_code == 200
    assert resp.headers["X-Routed-Provider"] == "backup"
    assert resp.headers["X-Failover-Reason"] == "http_5xx"


async def test_failover_on_connect_error(settings_override: Settings) -> None:
    primary, backup = MockProvider("p", "raise"), MockProvider("b")  # ProviderConnectionError
    async with router(settings_override, primary, backup) as (client, _):
        resp = await _post(client)
    assert resp.status_code == 200
    assert resp.headers["X-Failover-Reason"] == "connect_error"


async def test_no_failover_on_400_client_error(settings_override: Settings) -> None:
    primary, backup = MockProvider("p", "http_400"), MockProvider("b")
    async with router(settings_override, primary, backup) as (client, lim):
        resp = await _post(client)
        assert await lim.usage(TENANT) == 0  # rejected request isn't charged
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "INVALID_REQUEST"
    assert backup.calls == 0  # the backup would reject the same bad request
    _assert_no_leaks(resp.text)


async def test_diagnostic_headers_present(settings_override: Settings) -> None:
    settings = settings_override.model_copy(update={"rate_limit_window_seconds": 60.0})
    cid = "corr-t4-diagnostics"
    async with router(settings, MockProvider("p"), MockProvider("b")) as (client, _):
        resp = await client.post(
            "/v1/chat/completions",
            json=REQUEST,
            headers={"X-Tenant-Key": TENANT, "X-Correlation-ID": cid},
        )
    assert resp.status_code == 200
    h = resp.headers
    assert h["X-Routed-Provider"] == "primary"
    assert h["X-Failover-Reason"] == "none"
    assert h["X-RateLimit-Limit"] == "50000"
    assert h["X-RateLimit-Remaining"] == str(LIMIT - USAGE)
    assert h["X-RateLimit-Window-Seconds"] == "60"
    assert h["X-Correlation-ID"] == cid
    assert resp.json()["gateway"] == {
        "routed_provider": "primary",
        "failover_reason": "none",
        "correlation_id": cid,
    }


# --------------------------------------------------------------------------- sanitization


async def test_both_fail_returns_envelope_without_leaks(
    settings_override: Settings, caplog_json: JsonLogCapture
) -> None:
    primary = MockProvider("p", "leaky_exception")
    backup = MockProvider("b", "leaky_exception")
    async with router(settings_override, primary, backup) as (client, lim):
        resp = await _post(client)
        assert await lim.usage(TENANT) == 0
    assert resp.status_code == 502
    err = resp.json()["error"]
    assert err["code"] == "GATEWAY_UPSTREAM_FAILURE"
    assert err["message"] == (
        "The request could not be completed by primary or backup model providers."
    )
    assert set(err) == {"code", "message", "request_id", "correlation_id", "timestamp"}
    assert err["correlation_id"] == resp.headers["X-Correlation-ID"]
    _assert_no_leaks(resp.text)
    _assert_no_leaks(json.dumps(dict(resp.headers)))
    # Operators still get the detail - on stderr, not in the response.
    failures = caplog_json.events("provider_failed")
    assert len(failures) == 2
    assert "/srv/app/secrets.py" in failures[0]["traceback"]
    assert all(TENANT not in line for line in caplog_json.lines)


class _ExplodingLimiter(SQLiteRateLimiter):
    async def reserve(self, tenant: str, tokens: int) -> Reservation:
        raise RuntimeError(
            'File "/srv/app/limiter.py": SELECT * FROM token_usage via http://10.0.0.7:8080/v1 '
            "key=sk-live-abc123"
        )


async def test_unhandled_exception_handler_sanitizes(
    settings_override: Settings, caplog_json: JsonLogCapture
) -> None:
    limiter = _ExplodingLimiter(settings_override.rate_limit_db_path)
    async with router(settings_override, MockProvider("p"), MockProvider("b"), limiter=limiter) as (
        client,
        _,
    ):
        resp = await _post(client)
    assert resp.status_code == 500
    err = resp.json()["error"]
    assert err["code"] == "INTERNAL_ERROR"
    assert err["correlation_id"] == resp.headers["X-Correlation-ID"]
    _assert_no_leaks(resp.text)
    (logged,) = caplog_json.events("unhandled_exception")
    assert "Traceback" in logged["traceback"]


async def test_rate_limited_envelope_and_retry_after_header(
    settings_override: Settings, fake_clock: FakeClock
) -> None:
    settings = settings_override.model_copy(update={"rate_limit_window_seconds": 60.0})
    limiter = _limiter(settings.rate_limit_db_path, fake_clock)
    primary, backup = MockProvider("p"), MockProvider("b")
    async with router(settings, primary, backup, limiter=limiter) as (client, lim):
        await lim.reserve(TENANT, 50_000)
        fake_clock.advance(10.2)
        resp = await _post(client)
        other = await _post(client, tenant="tenant-other")
    assert resp.status_code == 429
    err = resp.json()["error"]
    assert err["code"] == "RATE_LIMITED"
    assert err["correlation_id"] == resp.headers["X-Correlation-ID"]
    assert resp.headers["Retry-After"] == "50"  # ceil(49.8 s): never tells a client "too soon"
    assert resp.headers["X-RateLimit-Retry-After-Ms"] == "49800"
    assert resp.headers["X-RateLimit-Limit"] == "50000"
    assert resp.headers["X-RateLimit-Remaining"] == "0"
    assert resp.headers["X-RateLimit-Window-Seconds"] == "60"
    _assert_no_leaks(resp.text)
    assert primary.calls == 1  # only the other tenant's request reached a provider
    assert other.status_code == 200


async def test_missing_tenant_key_is_401(settings_override: Settings) -> None:
    async with router(settings_override, MockProvider("p"), MockProvider("b")) as (client, _):
        resp = await _post(client, tenant=None)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHENTICATED"


# --------------------------------------------------------------------------- beyond the matrix


async def test_cancelled_reserve_leaves_connection_usable(tmp_db_path: Path) -> None:
    """A request cancelled mid-transaction must not leave the shared connection inside an
    open transaction, or every later BEGIN fails."""
    async with _limiter(tmp_db_path) as lim:
        tasks = [asyncio.create_task(lim.reserve(TENANT, 1_000)) for _ in range(20)]
        await asyncio.sleep(0)
        for task in tasks[::2]:
            task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        committed = sum(isinstance(r, Reservation) for r in results)
        assert await lim.usage(TENANT) == committed * 1_000
        await lim.reserve(TENANT, 1_000)  # still usable


def _sse_events(text: str) -> list[tuple[str | None, str]]:
    events: list[tuple[str | None, str]] = []
    for block in text.strip().split("\n\n"):
        event = None
        data = []
        for line in block.split("\n"):
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].strip())
        events.append((event, "\n".join(data)))
    return events


async def test_streaming_failover_before_first_byte(settings_override: Settings) -> None:
    primary = MockProvider("p", delay=0.35)  # TTFB beyond the 0.2 s timeout
    backup = MockProvider("b", chunks=["Hel", "lo"])
    async with router(_fast(settings_override), primary, backup) as (client, lim):
        resp = await _post(client, {**REQUEST, "stream": True})
        assert await lim.usage(TENANT) > 0  # reconciled from streamed content
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert resp.headers["X-Routed-Provider"] == "backup"
    assert resp.headers["X-Failover-Reason"] == "timeout_200ms"
    assert resp.headers["X-Accel-Buffering"] == "no"
    content = "".join(
        json.loads(data)["choices"][0]["delta"].get("content", "")
        for _, data in _sse_events(resp.text)
        if data and data != "[DONE]"
    )
    assert content == "Hello"
    assert primary.cancelled


async def test_streaming_midstream_failure_is_sse_error_frame(settings_override: Settings) -> None:
    primary = MockProvider("p", chunks=["one", "two", "three"], fail_after_chunks=1)
    backup = MockProvider("b")
    async with router(settings_override, primary, backup) as (client, _):
        resp = await _post(client, {**REQUEST, "stream": True})
    assert resp.status_code == 200  # headers were already sent
    assert resp.headers["X-Routed-Provider"] == "primary"
    events = _sse_events(resp.text)
    assert events[-1][0] == "error"
    assert json.loads(events[-1][1])["error"]["code"] == "GATEWAY_UPSTREAM_FAILURE"
    assert backup.calls == 0  # no transparent failover after the first byte
    _assert_no_leaks(resp.text)


async def test_circuit_breaker_skips_primary_when_open(settings_override: Settings) -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(threshold=2, cooldown_seconds=30.0, clock=clock)
    primary, backup = MockProvider("p", "http_500"), MockProvider("b")
    async with router(settings_override, primary, backup, breaker=breaker) as (client, _):
        for _ in range(2):
            assert (await _post(client)).headers["X-Failover-Reason"] == "http_5xx"
        skipped = await _post(client)
        assert skipped.headers["X-Failover-Reason"] == "circuit_open"
        assert primary.calls == 2
        clock.advance(30)
        primary.behavior = "ok"  # half-open probe succeeds -> breaker closes
        probe = await _post(client)
        assert probe.headers["X-Routed-Provider"] == "primary"
        assert (await _post(client)).headers["X-Routed-Provider"] == "primary"
