"""Optional breaker in front of the primary provider (off unless ``circuit_breaker_enabled``).

Why bother: without it, every request during a primary outage pays the full primary timeout
(3 s) before failing over. After ``threshold`` consecutive failover-worthy failures the breaker
opens and requests go straight to the backup. After ``cooldown`` one request is let through as
a half-open probe: success closes the breaker, failure re-opens it for another cooldown. Only
provider-side failures count. A 400 says nothing about the primary's health.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from enum import StrEnum


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(
        self,
        threshold: int = 5,
        cooldown_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False

    @property
    def state(self) -> BreakerState:
        if self._opened_at is None:
            return BreakerState.CLOSED
        if self._clock() - self._opened_at >= self.cooldown_seconds:
            return BreakerState.HALF_OPEN
        return BreakerState.OPEN

    def allow_primary(self) -> bool:
        """Closed: yes. Open: no. Half-open: exactly one concurrent probe."""
        state = self.state
        if state is BreakerState.CLOSED:
            return True
        if state is BreakerState.HALF_OPEN and not self._probe_in_flight:
            self._probe_in_flight = True
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None
        self._probe_in_flight = False

    def record_failure(self) -> None:
        self._probe_in_flight = False
        if self._opened_at is not None:
            self._opened_at = self._clock()  # failed probe: another full cooldown
            return
        self._failures += 1
        if self._failures >= self.threshold:
            self._opened_at = self._clock()
