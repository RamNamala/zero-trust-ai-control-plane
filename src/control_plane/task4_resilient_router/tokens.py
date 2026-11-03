"""Token estimates for reservation before the provider has told us the real usage.

The reservation is deliberately pessimistic (prompt estimate + the full ``max_tokens``): it is
better to briefly hold too much budget and refund it on ``reconcile()`` than to let a burst of
requests jointly overdraw the window. ``tiktoken`` is used when installed; the chars/4
heuristic is the fallback and is what tests rely on.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Sequence
from typing import Any

DEFAULT_MAX_TOKENS = 1024
PER_MESSAGE_OVERHEAD = 4  # role/separator framing tokens per chat message


def _load_tiktoken() -> Callable[[str], int] | None:
    try:
        import tiktoken  # type: ignore[import-not-found, unused-ignore]
    except ImportError:
        return None
    try:
        enc = tiktoken.get_encoding("cl100k_base")
    except Exception:  # encoding files may need network on first use; fall back quietly
        return None
    return lambda text: len(enc.encode(text))


_tiktoken_count = _load_tiktoken()


def _message_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if content is None:
        return ""
    return json.dumps(content, ensure_ascii=False)  # multi-part / tool content


def estimate_prompt_tokens(
    messages: Sequence[dict[str, Any]], *, use_tiktoken: bool = False
) -> int:
    texts = [_message_text(m) for m in messages]
    overhead = PER_MESSAGE_OVERHEAD * len(messages)
    if use_tiktoken and _tiktoken_count is not None:
        return sum(_tiktoken_count(t) for t in texts) + overhead
    return math.ceil(sum(len(t) for t in texts) / 4) + overhead


def estimate_text_tokens(text: str) -> int:
    return math.ceil(len(text) / 4)


def reservation_tokens(messages: Sequence[dict[str, Any]], max_tokens: int | None) -> int:
    return estimate_prompt_tokens(messages) + (
        max_tokens if max_tokens is not None else DEFAULT_MAX_TOKENS
    )
