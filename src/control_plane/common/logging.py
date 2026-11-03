"""JSON-lines logging to stderr with a correlation ID on every line.

Why stderr: Task 1 reserves stdout for JSON-RPC frames, and using one sink everywhere means no
component can pollute stdout by accident. Why JSON: ``json.dumps`` escapes CR/LF, so a hostile
value can never forge an extra log line, and every hop's logs can be grepped by correlation ID.
The handler resolves ``sys.stderr`` at emit time so it follows fd redirection and test capture.
"""

from __future__ import annotations

import json
import logging
import sys
import traceback
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

ROOT_LOGGER = "control_plane"
AUDIT_LOGGER = "control_plane.audit"

_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def get_correlation_id() -> str | None:
    return _correlation_id.get()


def set_correlation_id(value: str | None) -> Any:
    """Returns the contextvar token so callers can ``reset_correlation_id`` it."""
    return _correlation_id.set(value)


def reset_correlation_id(token: Any) -> None:
    _correlation_id.reset(token)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", None) or get_correlation_id(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            for key, value in fields.items():
                entry.setdefault(key, value)
        if record.exc_info and record.exc_info[0] is not None:
            entry["exc_type"] = record.exc_info[0].__name__
            entry["traceback"] = "".join(traceback.format_exception(*record.exc_info))
        return json.dumps(entry, default=str, ensure_ascii=False)


class StderrHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stderr.write(self.format(record) + "\n")
            sys.stderr.flush()
        except Exception:  # logging must never take the process down
            self.handleError(record)


def configure_logging(level: str | int = "INFO", logger_name: str = ROOT_LOGGER) -> None:
    """Idempotent: safe to call from every entrypoint and from tests."""
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    if not any(isinstance(h, StderrHandler) for h in logger.handlers):
        handler = StderrHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False


class FirstLineOnlyFilter(logging.Filter):
    """Third-party libraries log whatever they like; mcp 1.x, for example, warns with a full
    pydantic error dump including ``input_value`` (i.e. raw, possibly PII-laden arguments).
    We keep the first line, which names the problem, and drop the rest plus any traceback."""

    max_chars = 200

    def filter(self, record: logging.LogRecord) -> bool:
        lines = record.getMessage().splitlines() or [""]
        record.msg = lines[0][: self.max_chars]
        record.args = None
        record.exc_info = None
        record.exc_text = None
        return True


def configure_root_logging(level: str | int = "WARNING") -> None:
    """Route the root logger (third-party libraries) through the same JSON-to-stderr handler,
    sanitized. Without a root handler, the first bare ``logging.warning()`` anywhere calls
    ``basicConfig`` implicitly and emits unformatted, unsanitized text."""
    root = logging.getLogger()
    root.setLevel(level)
    if not any(isinstance(h, StderrHandler) for h in root.handlers):
        handler = StderrHandler()
        handler.setFormatter(JsonFormatter())
        handler.addFilter(FirstLineOnlyFilter())
        root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name if name.startswith(ROOT_LOGGER) else f"{ROOT_LOGGER}.{name}")


def log_event(logger: logging.Logger, event: str, level: int = logging.INFO, **fields: Any) -> None:
    logger.log(level, event, extra={"fields": fields})


def audit(event: str, **fields: Any) -> None:
    """Security decisions only. Callers pass names, roles, decisions and counts - never raw
    tool arguments, results or PII; this function cannot tell the difference, so the rule is
    enforced at call sites and by tests that grep the audit stream."""
    log_event(logging.getLogger(AUDIT_LOGGER), event, **fields)
