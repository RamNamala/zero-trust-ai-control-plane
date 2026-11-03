from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from control_plane.common.logging import ROOT_LOGGER, JsonFormatter, configure_logging
from control_plane.common.settings import Settings


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """On-disk SQLite path in a not-yet-existing subdir (the limiter must create parents)."""
    return tmp_path / "data" / "ratelimit.db"


@pytest.fixture
def settings_override(tmp_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Settings with small windows/timeouts so tests never sleep for real-world durations.
    Ambient CP_* env vars are cleared so a developer's shell can't change test outcomes."""
    for key in list(os.environ):
        if key.startswith("CP_"):
            monkeypatch.delenv(key)
    yield Settings(
        rate_limit_tokens_per_window=50_000,
        rate_limit_window_seconds=2.0,
        rate_limit_db_path=tmp_db_path,
        primary_timeout_seconds=0.3,
        request_deadline_seconds=2.0,
        jwt_hs256_secret="test-secret-at-least-32-bytes-long!!",  # noqa: S106
    )


class FakeClock:
    """Injectable wall clock: ``clock()`` returns the current fake time."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def set(self, value: float) -> None:
        self.now = value


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()


class JsonLogCapture(logging.Handler):
    """Collects our log records rendered by the production JsonFormatter, then parsed back,
    so assertions run against exactly what would hit stderr."""

    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(JsonFormatter())
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))

    @property
    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.lines]

    def events(self, name: str) -> list[dict[str, Any]]:
        return [r for r in self.records if r["event"] == name]

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


@pytest.fixture
def caplog_json() -> Iterator[JsonLogCapture]:
    configure_logging("DEBUG")
    logger = logging.getLogger(ROOT_LOGGER)
    previous = logger.level
    logger.setLevel(logging.DEBUG)
    handler = JsonLogCapture()
    logger.addHandler(handler)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)
