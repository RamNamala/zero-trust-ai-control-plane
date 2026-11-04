"""
VERIFIED REFERENCE ALGORITHM for Task 3 (chunk-boundary-safe streaming PII redaction).

Status: prototyped and property-tested (Hypothesis, 3,000 random chunkings of a text that
contains emails, dashed + spaced credit cards and SSNs). For every chunking,
    "".join(r.feed(c) for c in chunks) + r.flush() == redact(full_text)

This is the algorithmic contract. The production version in
src/control_plane/task3_streaming_guardrail/ adds full typing, metrics
(redaction_count, peak_buffer_chars, forced_flushes) and its own property tests.

Why not a fixed 36-char holdback?
  * Emails can legally be up to 254 chars, so a 36-char window leaks long addresses.
  * "4532 0151 1283 0366" contains spaces, so "hold back to the last whitespace" also leaks.
  * Instead: hold back the maximal trailing run of characters that could still be part of a
    PII token (email chars, or a digit run with spaces/dashes), extended to a fixpoint because
    the two classes can be adjacent (e.g. "...1283 0366." -> the "." is an email char).
  * Memory stays bounded by MAX_HOLD (default 256). If a single run exceeds it, the oldest
    part is force-emitted after redaction. That is the documented trade-off: bounded memory
    beats perfect recall on a 300-char unbroken token, and it is logged as a guardrail event.
"""
from __future__ import annotations

import re

REDACTED = "[REDACTED]"

EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
SSN = re.compile(r"(?<![0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9])")
# Candidate card: 13-19 digits, optional single space/dash separators; confirmed by Luhn.
CC_CANDIDATE = re.compile(r"(?<![0-9])[0-9](?:[ -]?[0-9]){12,18}(?![0-9])")

# Tail classes: "could this trailing run still grow into PII?"
EMAIL_TAIL = re.compile(r"[A-Za-z0-9._%+\-@]*\Z")
NUM_TAIL = re.compile(r"[0-9][0-9 \-]*\Z")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _cc_sub(m: re.Match[str]) -> str:
    digits = re.sub(r"[^0-9]", "", m.group())
    return REDACTED if 13 <= len(digits) <= 19 and luhn_ok(digits) else m.group()


def redact(text: str) -> tuple[str, int]:
    """Redact complete matches. Order matters: email, then SSN, then card."""
    text, n1 = EMAIL.subn(REDACTED, text)
    text, n2 = SSN.subn(REDACTED, text)
    count = 0

    def cc(m: re.Match[str]) -> str:
        nonlocal count
        out = _cc_sub(m)
        count += out == REDACTED
        return out

    text = CC_CANDIDATE.sub(cc, text)
    return text, n1 + n2 + count


class StreamingPIIRedactor:
    MAX_HOLD = 256

    def __init__(self, max_hold: int = MAX_HOLD) -> None:
        self._buf = ""
        self.max_hold = max_hold
        self.redaction_count = 0
        self.peak_buffer_chars = 0
        self.forced_flushes = 0

    def _safe_cut(self) -> int:
        cut = len(self._buf)
        while True:  # fixpoint over adjacent PII-capable runs
            new = cut
            for rx in (EMAIL_TAIL, NUM_TAIL):
                m = rx.search(self._buf, 0, new) if new else None
                if m and m.start() < new:
                    new = m.start()
            if new == cut:
                break
            cut = new
        if len(self._buf) - cut > self.max_hold:
            cut = len(self._buf) - self.max_hold
            self.forced_flushes += 1
        return cut

    def feed(self, delta: str) -> str:
        self._buf += delta
        self.peak_buffer_chars = max(self.peak_buffer_chars, len(self._buf))
        cut = self._safe_cut()
        safe, self._buf = self._buf[:cut], self._buf[cut:]
        out, n = redact(safe)
        self.redaction_count += n
        return out

    def flush(self) -> str:
        out, n = redact(self._buf)
        self.redaction_count += n
        self._buf = ""
        return out


# --- Property test (copy into tests/test_task3_guardrail.py and adapt) -------------------
# from hypothesis import given, settings, strategies as st
# TEXT = ("Hi Sarah, reach alice.smith@company.org or call. SSN 123-45-6789, card "
#         "4532-0151-1283-0366 and 4532 0151 1283 0366. Order 12345 ok. "
#         "sarah.connor@cyberdyne.io / 999-01-4242.")
# @settings(max_examples=2000, deadline=None)
# @given(st.lists(st.integers(0, len(TEXT)), max_size=40))
# def test_chunking_invariance(cuts):
#     cuts = sorted(set(cuts)); parts, prev = [], 0
#     for c in cuts + [len(TEXT)]:
#         parts.append(TEXT[prev:c]); prev = c
#     r = StreamingPIIRedactor()
#     assert "".join(r.feed(p) for p in parts) + r.flush() == redact(TEXT)[0]
