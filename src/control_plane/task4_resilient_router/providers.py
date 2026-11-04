"""Model providers behind the router, plus a fault-injecting mock.

Providers raise *typed* errors so the router can decide whether failing over could help:
429 / 5xx / connection trouble are about the provider, while other 4xx are about the request
and the backup would reject it too. Provider code must stay cancellation-safe (no
``except Exception`` around awaits that could swallow ``CancelledError``), otherwise
``asyncio.wait_for`` can't actually stop a timed-out call (PITFALLS #25).
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field

from control_plane.common.correlation import outbound_headers


class ChatRequest(BaseModel):
    """Only the fields the router relies on are typed; other OpenAI parameters pass through."""

    model_config = ConfigDict(extra="allow")

    model: str = Field(min_length=1, max_length=200)
    messages: list[dict[str, Any]] = Field(min_length=1)
    stream: bool = False
    # strict: ``true`` or ``"7"`` is a client bug, not a budget; coercing it would hide that.
    max_tokens: int | None = Field(default=None, gt=0, strict=True)


@dataclass(frozen=True)
class CompletionResult:
    body: dict[str, Any]
    total_tokens: int | None  # provider-reported usage; None if it didn't say


class ProviderError(Exception):
    """Base for provider failures. ``str()`` may contain upstream detail: log it, never return
    it to a client."""


class ProviderRateLimited(ProviderError):
    def __init__(self, retry_after: float | None = None) -> None:
        self.retry_after = retry_after
        super().__init__("provider rate limited")


class ProviderServerError(ProviderError):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"provider server error {status}")


class ProviderClientError(ProviderError):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"provider rejected request {status}")


class ProviderConnectionError(ProviderError):
    pass


class Provider(Protocol):
    name: str

    async def complete(self, req: ChatRequest) -> CompletionResult: ...

    def stream(self, req: ChatRequest) -> AsyncIterator[bytes]: ...


def _usage_tokens(body: dict[str, Any]) -> int | None:
    usage = body.get("usage")
    if isinstance(usage, dict) and isinstance(usage.get("total_tokens"), int):
        return int(usage["total_tokens"])
    return None


def _raise_for_status(status: int, headers: httpx.Headers) -> None:
    if status == 429:
        raw = headers.get("retry-after")
        try:
            retry = float(raw) if raw is not None else None
        except ValueError:
            retry = None
        raise ProviderRateLimited(retry)
    if status >= 500:
        raise ProviderServerError(status)
    if status >= 400:
        raise ProviderClientError(status)


class HttpProvider:
    """OpenAI-compatible ``/v1/chat/completions`` endpoint over a shared ``httpx.AsyncClient``.
    The caller's credentials are never forwarded; the gateway's own key (if any) is."""

    def __init__(
        self, name: str, url: str, client: httpx.AsyncClient, api_key: str | None = None
    ) -> None:
        self.name = name
        self.url = url
        self._client = client
        self._api_key = api_key

    def _headers(self, accept: str) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": accept, **outbound_headers()}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def complete(self, req: ChatRequest) -> CompletionResult:
        payload = req.model_dump(exclude_none=True) | {"stream": False}
        try:
            resp = await self._client.post(
                self.url, json=payload, headers=self._headers("application/json")
            )
        except httpx.TransportError as exc:
            raise ProviderConnectionError(type(exc).__name__) from exc
        _raise_for_status(resp.status_code, resp.headers)
        try:
            body = resp.json()
        except ValueError as exc:
            raise ProviderServerError(resp.status_code) from exc
        if not isinstance(body, dict):
            raise ProviderServerError(resp.status_code)
        return CompletionResult(body=body, total_tokens=_usage_tokens(body))

    async def stream(self, req: ChatRequest) -> AsyncIterator[bytes]:
        payload = req.model_dump(exclude_none=True) | {"stream": True}
        try:
            async with self._client.stream(
                "POST", self.url, json=payload, headers=self._headers("text/event-stream")
            ) as resp:
                _raise_for_status(resp.status_code, resp.headers)
                async for chunk in resp.aiter_raw():
                    yield chunk
        except httpx.TransportError as exc:
            raise ProviderConnectionError(type(exc).__name__) from exc


Behavior = Literal["ok", "http_429", "http_500", "http_400", "raise", "leaky_exception"]

LEAKY_MESSAGE = (
    'Traceback (most recent call last):\n  File "/srv/app/secrets.py", line 42\n'
    "psycopg.errors: SELECT * FROM users WHERE api_key='sk-live-abc123' "
    "via http://10.0.0.7:8080/v1"
)


def _completion_body(model: str, provider: str, content: str, total: int) -> dict[str, Any]:
    return {
        "id": f"chatcmpl-{provider}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": total // 2,
            "completion_tokens": total - total // 2,
            "total_tokens": total,
        },
    }


def _chunk(model: str, provider: str, delta: dict[str, Any], finish: str | None = None) -> bytes:
    frame = {
        "id": f"chatcmpl-{provider}",
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }
    return f"data: {json.dumps(frame)}\n\n".encode()


class MockProvider:
    """Scriptable provider. ``delay`` is slept *before* the behavior applies, which makes it the
    cancellation point that timeout tests probe. ``cancelled`` is set when that sleep (or the
    stream) is cancelled, proving ``wait_for`` really stopped the call (no zombie upstream).
    ``sleep`` from the spec is ``behavior="ok"`` with a ``delay``."""

    def __init__(
        self,
        name: str,
        behavior: Behavior = "ok",
        *,
        delay: float = 0.0,
        exc: BaseException | None = None,
        content: str = "Hello from the mock provider.",
        chunks: Sequence[str] | None = None,
        usage_tokens: int | None = 120,
        chunk_delay: float = 0.0,
        fail_after_chunks: int | None = None,
    ) -> None:
        self.name = name
        self.behavior = behavior
        self.delay = delay
        self.exc = exc
        self.content = content
        self.chunks = list(chunks) if chunks is not None else [content]
        self.usage_tokens = usage_tokens
        self.chunk_delay = chunk_delay
        self.fail_after_chunks = fail_after_chunks
        self.calls = 0
        self.cancelled = False
        self.completed = 0

    def _apply_behavior(self) -> None:
        if self.behavior == "http_429":
            raise ProviderRateLimited(1.0)
        if self.behavior == "http_500":
            raise ProviderServerError(500)
        if self.behavior == "http_400":
            raise ProviderClientError(400)
        if self.behavior == "raise":
            raise self.exc or ProviderConnectionError("mock connect error")
        if self.behavior == "leaky_exception":
            raise RuntimeError(LEAKY_MESSAGE)

    async def complete(self, req: ChatRequest) -> CompletionResult:
        self.calls += 1
        try:
            await asyncio.sleep(self.delay)
            self._apply_behavior()
            total = self.usage_tokens if self.usage_tokens is not None else 0
            body = _completion_body(req.model, self.name, self.content, total)
            if self.usage_tokens is None:
                body.pop("usage")
            self.completed += 1
            return CompletionResult(body=body, total_tokens=self.usage_tokens)
        except asyncio.CancelledError:
            self.cancelled = True
            raise

    async def stream(self, req: ChatRequest) -> AsyncIterator[bytes]:
        self.calls += 1
        try:
            await asyncio.sleep(self.delay)
            self._apply_behavior()
            yield _chunk(req.model, self.name, {"role": "assistant"})
            for i, text in enumerate(self.chunks):
                if self.fail_after_chunks is not None and i >= self.fail_after_chunks:
                    raise ProviderServerError(502)
                if self.chunk_delay:
                    await asyncio.sleep(self.chunk_delay)
                yield _chunk(req.model, self.name, {"content": text})
            yield _chunk(req.model, self.name, {}, finish="stop")
            yield b"data: [DONE]\n\n"
            self.completed += 1
        except (asyncio.CancelledError, GeneratorExit):
            self.cancelled = True
            raise
