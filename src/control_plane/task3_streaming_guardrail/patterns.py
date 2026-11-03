"""PII patterns and the one-shot ``redact()`` the streaming redactor must agree with.

Ported from ``docs/reference/redactor_reference.py`` (the property-tested contract). Two choices
differ from the original blueprint on purpose:

* Cards: the blueprint's ``\\b(?:\\d[ -]*?){13,16}\\b`` matches any long digit run (order numbers,
  timestamps) and misses 17-19 digit PANs. Here a *candidate* is 13-19 digits with optional single
  space/dash separators, and it is only redacted if the digits pass Luhn.
* SSNs: anything SSN-shaped is redacted, including "invalid" areas (000, 666, 9xx). Failing closed
  costs a few false positives; filtering would leak the demo's ``999-01-4242``.

Order is email -> SSN -> card, so a digit run inside an address is consumed with the address.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
SSN = re.compile(r"(?<![0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9])")
CC_CANDIDATE = re.compile(r"(?<![0-9])[0-9](?:[ -]?[0-9]){12,18}(?![0-9])")

# Tail classes used by the streaming redactor: "could this trailing run still grow into PII?"
EMAIL_TAIL = re.compile(r"[A-Za-z0-9._%+\-@]*\Z")
NUM_TAIL = re.compile(r"[0-9][0-9 \-]*\Z")

_NON_DIGIT = re.compile(r"[^0-9]")


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


def _is_card(candidate: str) -> bool:
    digits = _NON_DIGIT.sub("", candidate)
    return 13 <= len(digits) <= 19 and luhn_ok(digits)


def redact(text: str) -> tuple[str, int]:
    """Redact complete matches in ``text``. Returns the new text and the number of redactions."""
    text, n_email = EMAIL.subn(REDACTED, text)
    text, n_ssn = SSN.subn(REDACTED, text)
    n_card = 0

    def card(m: re.Match[str]) -> str:
        nonlocal n_card
        if _is_card(m.group()):
            n_card += 1
            return REDACTED
        return m.group()

    text = CC_CANDIDATE.sub(card, text)
    return text, n_email + n_ssn + n_card
