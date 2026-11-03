"""Transports from the gateway to the MCP server behind it.

The proxy speaks to a ``Downstream`` and never to httpx or pipes directly, so the same policy
and merge logic fronts an HTTP MCP server and the Task 1 stdio server. Every transport failure
becomes ``DownstreamError`` (or a per-message ``-32603``) with a fixed message: the URL, host,
command line or exception text would tell a caller about internal topology, so they go to the
operator log only.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from control_plane.common.correlation import is_valid_correlation_id
from control_plane.common.jsonrpc import ErrorCode, is_notification, make_error
from control_plane.common.logging import get_logger, log_event

JsonPayload = dict[str, Any] | list[Any]

UPSTREAM_UNAVAILABLE = "Upstream MCP server unavailable"
MCP_PROTOCOL_VERSION = "2025-06-18"
T1_COMMAND = (sys.executable, "-m", "control_plane.task1_mcp_server")

_log = get_logger("task2.stdio")
_child_log = get_logger("task2.stdio.child")


class DownstreamError(Exception):
    def __init__(self, kind: str) -> None:
        self.kind = kind  # transport | timeout | status | decode | spawn | handshake - for logs
        super().__init__(f"downstream {kind} failure")


@dataclass(frozen=True, slots=True)
class DownstreamReply:
    body: Any | None  # None when the downstream answered 202 / no content
    session_id: str | None = None


class Downstream(Protocol):
    async def send(self, payload: JsonPayload, headers: Mapping[str, str]) -> DownstreamReply: ...


class HttpDownstream:
    """POSTs JSON-RPC to an MCP server over HTTP using a shared, lifespan-owned client."""

    def __init__(self, url: str, client: httpx.AsyncClient) -> None:
        self._url = url
        self._client = client

    async def send(self, payload: JsonPayload, headers: Mapping[str, str]) -> DownstreamReply:
        try:
            response = await self._client.post(self._url, json=payload, headers=dict(headers))
        except (httpx.TimeoutException, TimeoutError) as exc:
            raise DownstreamError("timeout") from exc
        except httpx.HTTPError as exc:
            raise DownstreamError("transport") from exc
        session_id = response.headers.get("mcp-session-id")
        if response.status_code == 202 or (response.is_success and not response.content):
            return DownstreamReply(None, session_id)
        if not response.is_success:
            raise DownstreamError("status")
        try:
            return DownstreamReply(json.loads(response.content), session_id)
        except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError
            raise DownstreamError("decode") from exc


class _ChildGone(Exception):
    """The child died (or was never reachable) while a message was in flight."""


class StdioMcpDownstream:
    """Task 1 as a child process, shared by every gateway request.

    Why things are shaped the way they are:

    * **Ids are rewritten per hop (PITFALLS #13).** Concurrent callers all arrive with small ids
      (the proxy itself numbers each request's messages from 0), so on one shared pipe their
      replies would cross. Each request goes out with a fresh value from a monotonic counter, and
      its reply is matched by that value and given the caller's id back.
    * **One reader, one write lock.** A single task owns stdout and resolves futures, so nobody
      races over the next line. Writes are serialized so two frames never interleave.
    * **stderr is always drained (PITFALLS #14).** A full stderr pipe blocks the child on its next
      log line, which looks like a hang. Drained lines are re-logged under the child's own
      correlation ID, which is how one ID becomes greppable across every hop.
    * **Batches are fanned out.** mcp 1.x's stdio server rejects a JSON-RPC array (PITFALLS #44),
      so each message goes as its own line and the replies are gathered.
    * **A crash costs only the in-flight messages.** They get ``-32603``; the next call respawns
      the child and handshakes again. Respawning lazily (not from the reader) means a child that
      dies at startup can't spin in a restart loop while nobody is asking for it.
    """

    def __init__(
        self,
        cmd: Sequence[str] = T1_COMMAND,
        *,
        env: Mapping[str, str] | None = None,
        request_timeout: float = 30.0,
        startup_timeout: float = 10.0,
        shutdown_timeout: float = 3.0,
        line_limit: int = 1 << 20,
    ) -> None:
        self._cmd = list(cmd)
        self._env = {**os.environ, **env} if env is not None else None
        self._request_timeout = request_timeout
        self._startup_timeout = startup_timeout
        self._shutdown_timeout = shutdown_timeout
        self._line_limit = line_limit
        self._proc: asyncio.subprocess.Process | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._ids = itertools.count(1)
        self._dead = True
        self._start_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._spawns = 0
        self._forwarded = 0

    @property
    def process(self) -> asyncio.subprocess.Process | None:
        return self._proc

    @property
    def restarts(self) -> int:
        return max(0, self._spawns - 1)

    @property
    def forwarded(self) -> int:
        """Requests written to the child (handshakes excluded), so callers can prove a denied
        call never reached it."""
        return self._forwarded

    def _alive(self) -> bool:
        return self._proc is not None and self._proc.returncode is None and not self._dead

    async def start(self) -> None:
        async with self._start_lock:
            if self._alive():
                return
            await self._teardown()  # reap a dead child before replacing it
            await self._spawn()

    async def close(self) -> None:
        async with self._start_lock:
            await self._teardown()

    async def send(self, payload: JsonPayload, headers: Mapping[str, str]) -> DownstreamReply:
        # ``headers`` has no stdio equivalent: the correlation ID already travels in
        # ``params._meta``, and there is no Authorization to pass through, by construction.
        try:
            await self.start()
        except DownstreamError:
            raise
        except OSError as exc:  # executable missing, fd exhaustion, ...
            raise DownstreamError("spawn") from exc
        if isinstance(payload, list):
            replies = await asyncio.gather(*(self._send_one(m) for m in payload))
            body = [r for r in replies if r is not None]
            return DownstreamReply(body or None)
        return DownstreamReply(await self._send_one(payload))

    async def _send_one(self, msg: Any) -> dict[str, Any] | None:
        if not isinstance(msg, dict):
            return None
        if is_notification(msg):
            try:
                await self._write(msg)
            except _ChildGone:
                log_event(_log, "stdio_notification_dropped", logging.WARNING)
            return None

        original_id = msg.get("id")
        internal = next(self._ids)
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        # Registered before the write, so a crash at any later point fails this future.
        self._pending[internal] = future
        try:
            await self._write({**msg, "id": internal})
            self._forwarded += 1
            reply = await asyncio.wait_for(future, timeout=self._request_timeout)
        except (_ChildGone, TimeoutError) as exc:
            kind = "timeout" if isinstance(exc, TimeoutError) else "child_gone"
            log_event(_log, "stdio_request_failed", logging.WARNING, kind=kind)
            return make_error(original_id, ErrorCode.INTERNAL_ERROR, UPSTREAM_UNAVAILABLE)
        finally:
            self._pending.pop(internal, None)
        return {**reply, "id": original_id}

    async def _write(self, msg: dict[str, Any]) -> None:
        # json.dumps escapes newlines inside strings, so one message is always exactly one line.
        line = (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        async with self._write_lock:
            proc = self._proc
            if self._dead or proc is None or proc.stdin is None:
                raise _ChildGone
            try:
                proc.stdin.write(line)
                await proc.stdin.drain()
            except (OSError, RuntimeError) as exc:  # broken pipe / reset / transport closed
                self._mark_dead(proc, "write_failed")
                raise _ChildGone from exc

    async def _spawn(self) -> None:
        proc = await asyncio.create_subprocess_exec(
            *self._cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._env,
            limit=self._line_limit,
        )
        self._proc = proc
        self._dead = False
        self._spawns += 1
        self._tasks = [
            asyncio.create_task(self._read_loop(proc), name="t1-stdout-reader"),
            asyncio.create_task(self._drain_stderr(proc), name="t1-stderr-drain"),
        ]
        log_event(_log, "stdio_child_spawned", pid=proc.pid, restarts=self.restarts)
        try:
            await asyncio.wait_for(self._handshake(), timeout=self._startup_timeout)
        except (_ChildGone, TimeoutError, DownstreamError) as exc:
            log_event(_log, "stdio_handshake_failed", logging.ERROR, kind=type(exc).__name__)
            await self._teardown()
            raise DownstreamError("handshake") from exc

    async def _handshake(self) -> None:
        internal = next(self._ids)
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[internal] = future
        try:
            await self._write(
                {
                    "jsonrpc": "2.0",
                    "id": internal,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "control-plane-gateway", "version": "1.0"},
                    },
                }
            )
            reply = await future
        finally:
            self._pending.pop(internal, None)
        if "result" not in reply:
            raise DownstreamError("handshake")
        await self._write({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _mark_dead(self, proc: asyncio.subprocess.Process, reason: str) -> None:
        if proc is not self._proc or self._dead:
            return  # a stale task from an earlier child, or already handled
        self._dead = True
        level = logging.INFO if reason == "shutdown" else logging.WARNING
        log_event(_log, "stdio_child_lost", level, reason=reason, pending=len(self._pending))
        for future in self._pending.values():
            if not future.done():
                future.set_exception(_ChildGone())

    async def _read_loop(self, proc: asyncio.subprocess.Process) -> None:
        stdout = proc.stdout
        try:
            while stdout is not None:
                try:
                    line = await stdout.readline()
                except ValueError:  # a line over ``line_limit``: framing is lost
                    log_event(_log, "stdio_frame_too_large", logging.ERROR)
                    break
                if not line:
                    break
                self._dispatch(line)
        finally:
            self._mark_dead(proc, "eof")

    def _dispatch(self, line: bytes) -> None:
        try:
            msg = json.loads(line)
        except ValueError:
            log_event(_log, "stdio_frame_unparseable", logging.WARNING, size=len(line))
            return
        if not isinstance(msg, dict):
            return
        id_ = msg.get("id")
        if "method" in msg or not isinstance(id_, int) or isinstance(id_, bool):
            # Server notifications (e.g. notifications/message). T1 never sends server->client
            # requests; if one appeared it would be dropped here, logged by method name only.
            method = str(msg.get("method"))[:64]
            log_event(_log, "stdio_child_message_ignored", logging.DEBUG, method=method)
            return
        future = self._pending.get(id_)
        if future is None or future.done():
            log_event(_log, "stdio_reply_unmatched", logging.WARNING)
            return
        future.set_result(msg)

    async def _drain_stderr(self, proc: asyncio.subprocess.Process) -> None:
        stderr = proc.stderr
        while stderr is not None:
            try:
                raw = await stderr.readline()
            except ValueError:
                log_event(_child_log, "t1_stderr_line_too_long", logging.WARNING)
                continue
            if not raw:
                return
            _relay_child_line(raw.decode("utf-8", errors="replace").strip())

    async def _teardown(self) -> None:
        proc, tasks = self._proc, self._tasks
        if proc is None:
            return
        self._mark_dead(proc, "shutdown")  # no new writes; in-flight callers get -32603
        if proc.stdin is not None and not proc.stdin.is_closing():
            proc.stdin.close()  # EOF on stdin is T1's clean-shutdown signal
        try:
            await asyncio.wait_for(proc.wait(), timeout=self._shutdown_timeout)
        except TimeoutError:
            log_event(_log, "stdio_child_kill", logging.WARNING, pid=proc.pid)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
        # Both pipes hit EOF once the child is gone, so the tasks normally end on their own.
        if tasks:
            _, still_running = await asyncio.wait(tasks, timeout=1.0)
            for task in still_running:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        log_event(_log, "stdio_child_stopped", pid=proc.pid, returncode=proc.returncode)
        self._proc, self._tasks = None, []


def _relay_child_line(text: str) -> None:
    if not text:
        return
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict):
        # Not one of T1's JSON lines (e.g. a C-level write): bounded, logged as opaque text.
        log_event(_child_log, "t1_stderr_text", text=text[:500])
        return
    cid = parsed.get("correlation_id")
    level = logging.getLevelName(str(parsed.get("level", "INFO")))
    _child_log.log(
        level if isinstance(level, int) else logging.INFO,
        "t1_log",
        extra={
            # The drain task's own contextvar is stale; carry the child's ID instead.
            "correlation_id": cid
            if isinstance(cid, str) and is_valid_correlation_id(cid)
            else None,
            "fields": {"child": parsed},
        },
    )
