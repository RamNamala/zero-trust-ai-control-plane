"""A deterministic "agent" model for the end-to-end chain.

It plays both sides of one agent turn so the whole pipeline can be shown without a real model:

* **Turn 1** (no ``role: "tool"`` message yet): ask for ``get_customer_record(CUST-10042)``.
* **Turn 2** (a tool result is present): summarize *that* result, including its email and SSN.
  The PII comes from what Task 1 actually returned, not from a constant, so the demo shows that
  record data travelled T1 -> T2 -> agent -> model and was redacted by T3 on the way out. The
  stream is cut so that both values straddle chunk boundaries (the case T3 exists for).

``model="mock-leaky"`` makes the provider fail with an exception whose text carries a fake path,
SQL, internal URL and key, so Scenario E can show that none of it reaches the client.

It satisfies the T4 ``Provider`` protocol, so the router can use it as primary (with ``delay``
past the failover timeout) and as backup. ``delay`` is slept first and is the cancellation
point, like ``MockProvider``'s.
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections.abc import AsyncIterator
from typing import Any

from control_plane.task4_resilient_router.providers import (
    LEAKY_MESSAGE,
    ChatRequest,
    CompletionResult,
)

LEAKY_MODEL = "mock-leaky"
TOOL_NAME = "get_customer_record"
TARGET_CUSTOMER = "CUST-10042"
TOOL_CALL_ID = "call_1"
_CHUNK_WIDTH = 16


def _tool_result(messages: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The latest tool message, parsed. ``{}`` means a tool answered but not with a record."""
    for message in reversed(messages):
        if message.get("role") != "tool":
            continue
        content = message.get("content")
        try:
            parsed = json.loads(content) if isinstance(content, str) else None
        except ValueError:
            parsed = None
        return parsed if isinstance(parsed, dict) else {}
    return None


def summary_text(record: dict[str, Any]) -> str:
    if not all(isinstance(record.get(k), str) for k in ("name", "email", "ssn")):
        return "I could not read the customer record, so there is nothing to summarize."
    return (
        f"Customer {record['name']} ({record.get('tier', 'unknown')} tier) can be reached at "
        f"{record['email']}; the SSN on file is {record['ssn']}. "
        f"Current balance: {record.get('balance', 'n/a')}."
    )


def chunk_text(text: str, secrets: list[str]) -> list[str]:
    """Fixed-width chunks plus a cut inside every secret, so no secret arrives in one piece."""
    cuts = set(range(_CHUNK_WIDTH, len(text), _CHUNK_WIDTH))
    for secret in secrets:
        start = text.find(secret)
        if start >= 0 and len(secret) > 3:
            cuts.update({start + 3, start + len(secret) // 2 + 1})
    bounds = [0, *sorted(c for c in cuts if 0 < c < len(text)), len(text)]
    return [text[a:b] for a, b in zip(bounds, bounds[1:], strict=False) if b > a]


def _tool_call() -> dict[str, Any]:
    return {
        "id": TOOL_CALL_ID,
        "type": "function",
        "function": {"name": TOOL_NAME, "arguments": json.dumps({"customer_id": TARGET_CUSTOMER})},
    }


def _sse(frame: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(frame)}\n\n".encode()


class AgentMockProvider:
    def __init__(self, name: str, *, delay: float = 0.0, chunk_delay: float = 0.0) -> None:
        self.name = name
        self.delay = delay
        self.chunk_delay = chunk_delay
        self.calls = 0
        self.cancelled = False
        self.completed = 0

    def _frame(self, req: ChatRequest, delta: dict[str, Any], finish: str | None) -> bytes:
        return _sse(
            {
                "id": f"chatcmpl-agent-{self.name}",
                "object": "chat.completion.chunk",
                "model": req.model,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            }
        )

    async def _wait(self, req: ChatRequest) -> None:
        self.calls += 1
        if req.model == LEAKY_MODEL:
            raise RuntimeError(LEAKY_MESSAGE)
        await asyncio.sleep(self.delay)

    async def complete(self, req: ChatRequest) -> CompletionResult:
        try:
            await self._wait(req)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        record = _tool_result(req.messages)
        message: dict[str, Any]
        if record is None:
            message = {"role": "assistant", "content": None, "tool_calls": [_tool_call()]}
            finish, completion_chars = "tool_calls", 64
        else:
            text = summary_text(record)
            message = {"role": "assistant", "content": text}
            finish, completion_chars = "stop", len(text)
        prompt = sum(len(str(m.get("content") or "")) for m in req.messages)
        usage = {
            "prompt_tokens": math.ceil(prompt / 4),
            "completion_tokens": math.ceil(completion_chars / 4),
        }
        usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
        body = {
            "id": f"chatcmpl-agent-{self.name}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.model,
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": usage,
        }
        self.completed += 1
        return CompletionResult(body=body, total_tokens=usage["total_tokens"])

    async def stream(self, req: ChatRequest) -> AsyncIterator[bytes]:
        try:
            await self._wait(req)
            yield self._frame(req, {"role": "assistant"}, None)
            record = _tool_result(req.messages)
            if record is None:
                yield self._frame(req, {"tool_calls": [{"index": 0, **_tool_call()}]}, None)
                yield self._frame(req, {}, "tool_calls")
            else:
                text = summary_text(record)
                secrets = [str(record.get("email", "")), str(record.get("ssn", ""))]
                for piece in chunk_text(text, secrets):
                    if self.chunk_delay:
                        await asyncio.sleep(self.chunk_delay)
                    yield self._frame(req, {"content": piece}, None)
                yield self._frame(req, {}, "stop")
            yield b"data: [DONE]\n\n"
            self.completed += 1
        except (asyncio.CancelledError, GeneratorExit):
            self.cancelled = True
            raise
