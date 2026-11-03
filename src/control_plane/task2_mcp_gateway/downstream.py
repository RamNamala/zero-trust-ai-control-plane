"""Transports from the gateway to the MCP server behind it.

The proxy speaks to a ``Downstream`` and never to httpx directly, so the same policy and merge
logic fronts an HTTP MCP server today and the Task 1 stdio server in Phase 5. Every transport
failure becomes ``DownstreamError`` with a fixed message: the URL, host or exception text would
tell a caller about internal topology, so they go to the operator log only.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

JsonPayload = dict[str, Any] | list[Any]


class DownstreamError(Exception):
    def __init__(self, kind: str) -> None:
        self.kind = kind  # transport | timeout | status | decode - for logs
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


class StdioMcpDownstream:
    """TODO(phase 5): spawn Task 1 with ``asyncio.create_subprocess_exec``, run ``initialize`` +
    ``notifications/initialized`` once, rewrite request ids to an internal counter and map
    replies back (PITFALLS #13), drain the child's stderr (PITFALLS #14), and fail pending
    futures with -32603 / restart when the child dies."""

    def __init__(self, cmd: list[str]) -> None:
        self._cmd = cmd

    async def send(self, payload: JsonPayload, headers: Mapping[str, str]) -> DownstreamReply:
        raise NotImplementedError("StdioMcpDownstream is implemented in phase 5")
