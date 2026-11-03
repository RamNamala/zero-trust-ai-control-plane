"""Per-tenant sliding-window token limiter on SQLite (WAL).

Why SQLite: the ledger must survive restarts and be shared by every worker process on the host
without a Redis dependency. Why a ledger of rows instead of a counter: a sliding window needs to
know *when* each token was spent so it can expire exactly ``window`` seconds later, and a fixed
bucket would let a tenant spend 2x the limit across a boundary.

Concurrency is split in two, and both halves are needed:

* **In-process:** aiosqlite runs one connection on one worker thread. Two coroutines issuing
  ``BEGIN`` on it collide ("cannot start a transaction within a transaction") or interleave
  statements in one transaction, so every transaction runs under an ``asyncio.Lock``.
* **Cross-process:** the lock is process-local. ``BEGIN IMMEDIATE`` takes SQLite's write lock
  *before* the ``SUM``, so no other connection can read-then-insert in between (no TOCTOU), and
  ``busy_timeout`` makes waiters queue instead of failing with ``SQLITE_BUSY``.

The clock is injected and is wall time, not monotonic, because separate processes must agree
on timestamps in the shared file. Clock skew between hosts would bend the window; this is a
single-host design (see DESIGN_NOTES).
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import sqlite3
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiosqlite

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS token_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_key TEXT NOT NULL,
        tokens INTEGER NOT NULL,
        timestamp REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'reserved'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_tenant_time ON token_usage(tenant_key, timestamp)",
)

BUSY_TIMEOUT_MS = 5000


class RateLimitError(Exception):
    """Base for limiter refusals. Messages are fixed strings; safe to log, never shown raw."""


class RequestTooLargeError(RateLimitError):
    """The request alone exceeds the whole window budget: retrying can never succeed (413)."""

    def __init__(self, requested: int, limit: int) -> None:
        self.requested = requested
        self.limit = limit
        super().__init__("request exceeds the per-window token limit")


class RateLimitExceededError(RateLimitError):
    def __init__(self, retry_after_ms: int, remaining: int, limit: int) -> None:
        self.retry_after_ms = retry_after_ms
        self.remaining = remaining
        self.limit = limit
        super().__init__("token budget exhausted for this window")


@dataclass(frozen=True)
class Reservation:
    id: int
    remaining: int
    limit: int
    reset_at: float  # when the oldest live row expires, i.e. when quota next grows


def hash_tenant(raw_key: str) -> str:
    """The raw API key never touches disk: a stolen DB file must not yield credentials."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class SQLiteRateLimiter:
    def __init__(
        self,
        db_path: Path,
        *,
        limit: int = 50_000,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db_path = db_path
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()
        self._open_lock = asyncio.Lock()

    async def open(self) -> None:
        async with self._open_lock:
            if self._conn is not None:
                return
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = await aiosqlite.connect(self.db_path, isolation_level=None)
            try:
                await conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
                await conn.execute("PRAGMA journal_mode=WAL")
                await conn.execute("PRAGMA synchronous=NORMAL")
                pragmas = await self._read_pragmas(conn)
                if pragmas["journal_mode"] != "wal":
                    # Silently running in rollback-journal mode would serialize readers
                    # behind writers; fail loudly at startup instead.
                    raise RuntimeError("SQLite WAL mode could not be enabled")
                for stmt in _SCHEMA:
                    await conn.execute(stmt)
            except BaseException:
                await conn.close()
                raise
            self._conn = conn

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def __aenter__(self) -> SQLiteRateLimiter:
        await self.open()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    @staticmethod
    async def _read_pragmas(conn: aiosqlite.Connection) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in ("journal_mode", "synchronous", "busy_timeout"):
            async with conn.execute(f"PRAGMA {name}") as cur:
                row = await cur.fetchone()
            out[name] = row[0] if row else None
        return out

    async def pragmas(self) -> dict[str, Any]:
        return await self._read_pragmas(await self._connection())

    async def _connection(self) -> aiosqlite.Connection:
        if self._conn is None:
            await self.open()
        assert self._conn is not None  # noqa: S101 - open() guarantees it
        return self._conn

    async def reserve(self, tenant: str, tokens: int) -> Reservation:
        """Evict, sum, check, insert: one ``BEGIN IMMEDIATE`` transaction, so the check and the
        reservation are atomic against every coroutine and every process."""
        if tokens > self.limit:
            # Checked before touching the DB: the answer doesn't depend on usage, and a 429
            # here would invite the client to retry forever.
            raise RequestTooLargeError(tokens, self.limit)
        key = hash_tenant(tenant)
        async with self._transaction() as conn:
            now = self._clock()
            window_start = now - self.window_seconds
            await conn.execute(
                "DELETE FROM token_usage WHERE tenant_key = ? AND timestamp <= ?",
                (key, window_start),
            )
            async with conn.execute(
                "SELECT COALESCE(SUM(tokens), 0), MIN(timestamp) FROM token_usage "
                "WHERE tenant_key = ? AND timestamp > ?",
                (key, window_start),
            ) as cur:
                row = await cur.fetchone()
            used = int(row[0]) if row else 0
            oldest = float(row[1]) if row and row[1] is not None else None
            if used + tokens > self.limit:
                retry_ms = await self._retry_after_ms(
                    conn, key, window_start, now, used + tokens - self.limit
                )
                raise RateLimitExceededError(retry_ms, max(0, self.limit - used), self.limit)
            cur = await conn.execute(
                "INSERT INTO token_usage (tenant_key, tokens, timestamp, status) "
                "VALUES (?, ?, ?, 'reserved')",
                (key, tokens, now),
            )
            reservation_id = cur.lastrowid
        assert reservation_id is not None  # noqa: S101 - INSERT always yields a rowid
        return Reservation(
            id=reservation_id,
            remaining=self.limit - used - tokens,
            limit=self.limit,
            reset_at=(oldest if oldest is not None else now) + self.window_seconds,
        )

    async def _retry_after_ms(
        self, conn: aiosqlite.Connection, key: str, window_start: float, now: float, excess: int
    ) -> int:
        """Walk live rows oldest-first until enough tokens would have expired to fit the
        request. That row's expiry is the earliest moment a retry can succeed."""
        freed = 0
        async with conn.execute(
            "SELECT tokens, timestamp FROM token_usage WHERE tenant_key = ? AND timestamp > ? "
            "ORDER BY timestamp ASC, id ASC",
            (key, window_start),
        ) as cur:
            async for tokens, ts in cur:
                freed += int(tokens)
                if freed >= excess:
                    return max(1, math.ceil((float(ts) + self.window_seconds - now) * 1000))
        return max(1, math.ceil(self.window_seconds * 1000))  # unreachable when tokens <= limit

    async def reconcile(self, reservation_id: int, actual_tokens: int) -> None:
        """Settle to the real usage. The timestamp is kept on purpose: re-stamping would hand
        a long-running request a fresh window (PITFALLS #27)."""
        await self._write(
            "UPDATE token_usage SET tokens = ?, status = 'settled' WHERE id = ?",
            (max(0, actual_tokens), reservation_id),
        )

    async def release(self, reservation_id: int) -> None:
        """Both providers failed: the tenant got nothing, so it isn't charged."""
        await self._write("DELETE FROM token_usage WHERE id = ?", (reservation_id,))

    async def usage(self, tenant: str) -> int:
        """Tokens currently counted against ``tenant`` (diagnostics and tests)."""
        conn = await self._connection()
        async with (
            self._lock,
            conn.execute(
                "SELECT COALESCE(SUM(tokens), 0) FROM token_usage "
                "WHERE tenant_key = ? AND timestamp > ?",
                (hash_tenant(tenant), self._clock() - self.window_seconds),
            ) as cur,
        ):
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    async def _write(self, sql: str, params: tuple[Any, ...]) -> None:
        async with self._transaction() as conn:
            await conn.execute(sql, params)

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        """``BEGIN IMMEDIATE`` ... ``COMMIT`` under the in-process lock; ``ROLLBACK`` on any
        exit that isn't clean, including ``CancelledError``.

        ``BEGIN`` is inside the guarded region on purpose: if the await is cancelled, the
        statement still runs on aiosqlite's worker thread. Requests on that thread are FIFO,
        so the ROLLBACK queued after it always lands after it. "No transaction is active"
        means BEGIN never ran, which is fine."""
        conn = await self._connection()
        async with self._lock:
            try:
                await conn.execute("BEGIN IMMEDIATE")
                yield conn
                await conn.execute("COMMIT")
            except BaseException:
                try:
                    await conn.execute("ROLLBACK")
                except sqlite3.OperationalError:
                    pass
                raise
