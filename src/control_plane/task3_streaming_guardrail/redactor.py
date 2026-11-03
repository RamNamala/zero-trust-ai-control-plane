"""Chunk-boundary-safe streaming redaction (algorithm contract: ``docs/reference/``).

The problem: an LLM stream may split ``123-45-6789`` as ``"123-"``, ``"45-67"``, ``"89"``. If
each delta were redacted on its own, no single piece would match. So the redactor keeps back
the end of the text that *could still turn into* PII, and emits only the prefix before it.

How much to keep back is decided per feed, not fixed:

* A fixed 36-char window leaks: emails can be up to 254 chars, and "hold back to the last
  whitespace" leaks spaced cards like ``4532 0151 1283 0366``.
* Instead the cut is the start of the longest trailing run of characters that could still be
  part of a match: email characters (``EMAIL_TAIL``) or a digit run with spaces/dashes
  (``NUM_TAIL``). The two classes can sit next to each other (``"...1283 0366."``: the ``.`` is
  an email char, the digits before it are a number run), so the cut moves left until neither
  class can extend it any more. That is the fixpoint loop in ``_safe_cut``.

Everything before the cut can't be affected by future text, so redacting it now gives the same
result as redacting the whole text at the end. This is property-tested over random chunkings.

Memory trade-off: the held tail is capped at ``max_hold`` chars (default 256). If a single
unbroken run is longer than that, its oldest part is redacted and emitted anyway, and
``forced_flushes`` counts it. Bounded memory per stream wins over perfect recall on a 300-char
token, and the counter makes the loss visible in the audit log instead of silent.
"""

from __future__ import annotations

from control_plane.task3_streaming_guardrail.patterns import EMAIL_TAIL, NUM_TAIL, redact

DEFAULT_MAX_HOLD = 256


class StreamingPIIRedactor:
    """One instance per stream (per choice). Not thread-safe; not meant to be shared."""

    def __init__(self, max_hold: int = DEFAULT_MAX_HOLD) -> None:
        if max_hold <= 0:
            raise ValueError("max_hold must be positive")
        self.max_hold = max_hold
        self._buf = ""
        self.redaction_count = 0
        self.peak_buffer_chars = 0
        self.forced_flushes = 0

    @property
    def buffered_chars(self) -> int:
        return len(self._buf)

    def _safe_cut(self) -> int:
        cut = len(self._buf)
        while True:  # fixpoint over adjacent PII-capable runs
            new = cut
            for rx in (EMAIL_TAIL, NUM_TAIL):
                m = rx.search(self._buf, 0, new) if new else None
                if m is not None and m.start() < new:
                    new = m.start()
            if new == cut:
                break
            cut = new
        if len(self._buf) - cut > self.max_hold:
            cut = len(self._buf) - self.max_hold
            self.forced_flushes += 1
        return cut

    def feed(self, delta: str) -> str:
        """Add ``delta`` and return the redacted text that is now safe to emit (may be empty)."""
        self._buf += delta
        self.peak_buffer_chars = max(self.peak_buffer_chars, len(self._buf))
        cut = self._safe_cut()
        safe, self._buf = self._buf[:cut], self._buf[cut:]
        out, n = redact(safe)
        self.redaction_count += n
        return out

    def flush(self) -> str:
        """End of stream: nothing more can arrive, so redact and return everything held back."""
        out, n = redact(self._buf)
        self.redaction_count += n
        self._buf = ""
        return out
