"""Token estimates for reservation before the provider has told us the real usage.

The reservation is deliberately pessimistic (prompt estimate + the full ``max_tokens``): it is
better to briefly hold too much budget and refund it on ``reconcile()`` than to let a burst of
requests jointly overdraw the window. The estimate is chars/4: a real tokenizer would be
closer, but every reservation is reconciled to the provider's reported ``usage`` anyway, so
the estimate only has to be in the right range (see README, "Known limitations").
"""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from typing import Any

DEFAULT_MAX_TOKENS = 1024
PER_MESSAGE_OVERHEAD = 4  # role/separator framing tokens per chat message


def _message_text(message: dict[str, Any]) -> str:
    """Every field the model will read, not just ``content``: tool-call arguments, ``name``
    and multi-part content are prompt tokens too, and leaving them out would let a caller
    reserve almost nothing for a huge prompt."""
    parts: list[str] = []
    for key, value in message.items():
        if key == "role" or value is None:
            continue
        parts.append(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))
    return "".join(parts)


def estimate_prompt_tokens(messages: Sequence[dict[str, Any]]) -> int:
    chars = sum(len(_message_text(m)) for m in messages)
    return math.ceil(chars / 4) + PER_MESSAGE_OVERHEAD * len(messages)


def estimate_text_tokens(text: str) -> int:
    return math.ceil(len(text) / 4)


def reservation_tokens(messages: Sequence[dict[str, Any]], max_tokens: int | None) -> int:
    return estimate_prompt_tokens(messages) + (
        max_tokens if max_tokens is not None else DEFAULT_MAX_TOKENS
    )
