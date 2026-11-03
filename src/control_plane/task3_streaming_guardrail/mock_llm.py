"""A scriptable OpenAI-style SSE "LLM" for testing the guardrail without a real provider.

A script is a list of ``Step(delay, content, index)``. The mock sleeps for ``delay`` and then
emits one ``chat.completion.chunk`` frame. Pick a preset per request with
``model="mock-<preset>"``.

The mock also records what happened on its side of the wire, because the guardrail's robustness
claims are about the upstream:

* ``upstream_closed`` is set in the generator's ``finally``. It fires on normal completion and
  also when the gateway hangs up early, which is how the tests prove a client disconnect
  cancels the upstream instead of leaving it generating (and billing).
* ``completed`` is only true if the script ran to the end.
* ``chunks_sent`` shows how far the upstream got when the client saw its first byte.

State is created in the factory, not in lifespan, because ``httpx.ASGITransport`` doesn't run
lifespan (PITFALLS #39).

Run standalone: ``python -m control_plane.task3_streaming_guardrail.mock_llm`` (port 8201).
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse


@dataclass(frozen=True, slots=True)
class Step:
    delay: float
    content: str
    index: int = 0
    fail: bool = False  # raise instead of emitting: simulates the upstream dying mid-stream


def _steps(*chunks: str, delay: float = 0.0) -> list[Step]:
    return [Step(delay, c) for c in chunks]


_TEN_K_TEXT = (
    "Reach alice.smith@company.org, SSN 123-45-6789, card 4532 0151 1283 0366; order 98765. " * 120
)

PRESETS: dict[str, list[Step]] = {
    "ssn_split": _steps("My SSN is 123-", "45-67", "89. Thanks"),
    "email_split": _steps("Email alice.smi", "th@compa", "ny.org now"),
    "card_split": _steps("Card 4532-01", "51-1283-", "0366 ok"),
    "card_spaced_split": _steps("Card 4532 01", "51 1283 ", "0366 ok"),
    "slow_first_then_pause": [
        Step(0.0, "Hello there, "),
        Step(1.0, "your SSN 123-45-6789 is on file."),
    ],
    "slow_long": _steps(*(f"tick {i}; " for i in range(200)), delay=0.05),
    "ten_k": [Step(0.0, _TEN_K_TEXT[i]) for i in range(10_000)],
    "error_midstream": [
        Step(0.0, "Partial answer for bob@example.com "),
        Step(0.0, "see ticket 4532"),  # digit tail is still held back when the upstream dies
        Step(0.0, "", fail=True),
    ],
    "multi_choice": [
        Step(0.0, "A: card 4532-0151-", 0),
        Step(0.0, "B: mail carol@exa", 1),
        Step(0.0, "1283-0366 done.", 0),
        Step(0.0, "mple.net done.", 1),
    ],
}

DEFAULT_PRESET = "card_split"


class UpstreamFailure(RuntimeError):
    """Raised by a ``fail`` step. The message mimics the kind of internals a real error leaks."""


@dataclass
class MockLLMState:
    default_script: list[Step]
    upstream_closed: asyncio.Event = field(default_factory=asyncio.Event)
    completed: bool = False
    chunks_sent: int = 0
    requests: int = 0
    last_headers: dict[str, str] = field(default_factory=dict)


def _frame(model: str, index: int, delta: dict[str, Any], finish: str | None = None) -> bytes:
    chunk = {
        "id": "chatcmpl-mock",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": index, "delta": delta, "finish_reason": finish}],
    }
    return f"data: {json.dumps(chunk)}\n\n".encode()


def _script_for(state: MockLLMState, model: str) -> list[Step]:
    if model.startswith("mock-") and model[5:] in PRESETS:
        return PRESETS[model[5:]]
    return state.default_script


async def _stream(state: MockLLMState, script: list[Step], model: str) -> AsyncIterator[bytes]:
    indexes = sorted({s.index for s in script}) or [0]
    try:
        for i in indexes:
            yield _frame(model, i, {"role": "assistant"})
        for step in script:
            if step.delay:
                await asyncio.sleep(step.delay)
            if step.fail:
                raise UpstreamFailure(
                    "upstream crashed at /srv/llm/worker.py talking to 10.0.0.7 (sk-live-abc)"
                )
            yield _frame(model, step.index, {"content": step.content})
            state.chunks_sent += 1
        for i in indexes:
            yield _frame(model, i, {}, "stop")
        yield b"data: [DONE]\n\n"
        state.completed = True
    finally:
        state.upstream_closed.set()


async def chat_completions(request: Request) -> Response:
    state: MockLLMState = request.app.state.mock
    state.requests += 1
    state.last_headers = dict(request.headers)
    body = await request.json()
    model = str(body.get("model", "mock"))
    script = _script_for(state, model)
    if body.get("stream"):
        return StreamingResponse(_stream(state, script, model), media_type="text/event-stream")

    by_index: dict[int, str] = {}
    for step in script:
        by_index[step.index] = by_index.get(step.index, "") + step.content
    state.completed = True
    state.upstream_closed.set()
    return JSONResponse(
        {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": i,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
                for i, text in sorted(by_index.items())
            ],
        }
    )


def create_mock_llm(default_script: list[Step] | None = None) -> FastAPI:
    app = FastAPI(title="Mock streaming LLM")
    app.state.mock = MockLLMState(default_script=default_script or PRESETS[DEFAULT_PRESET])
    app.add_api_route("/v1/chat/completions", chat_completions, methods=["POST"])
    return app


app = create_mock_llm()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8201)
