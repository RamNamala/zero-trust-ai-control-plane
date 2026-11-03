"""All tunables in one place, overridable via ``CP_*`` environment variables.

Settings are constructed explicitly (in a FastAPI lifespan or a test fixture) rather than read
from a module-level singleton, so tests can shrink windows and timeouts without monkeypatching
globals. Defaults match the assessment brief exactly (50,000 tokens / 60 s / 3000 ms).
"""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_JWT_SECRET = "dev-only-change-me"  # noqa: S105 - sentinel; startup warns if still in use

_log = logging.getLogger("control_plane.settings")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CP_", extra="ignore")

    # Task 4 - rate limiter / router
    rate_limit_tokens_per_window: int = Field(default=50_000, gt=0)
    rate_limit_window_seconds: float = Field(default=60.0, gt=0)
    rate_limit_db_path: Path = Path("./data/gateway_ratelimit.db")
    primary_timeout_seconds: float = Field(default=3.0, gt=0)
    request_deadline_seconds: float = Field(default=15.0, gt=0)
    primary_provider_url: str = "http://127.0.0.1:8301/v1/chat/completions"
    backup_provider_url: str = "http://127.0.0.1:8302/v1/chat/completions"
    circuit_breaker_enabled: bool = False
    circuit_breaker_threshold: int = Field(default=5, gt=0)
    circuit_breaker_cooldown_seconds: float = Field(default=30.0, gt=0)

    # Task 3 - streaming guardrail
    redactor_max_hold_chars: int = Field(default=256, gt=0)
    llm_upstream_url: str = "http://127.0.0.1:8201/v1/chat/completions"

    # Task 2 - MCP gateway
    mcp_downstream_url: str = "http://127.0.0.1:8101/mcp"
    mcp_mask_unauthorized_tools: bool = False
    t2_deny_http_status: int = Field(default=200, ge=200, le=599)
    t2_downstream_token: str | None = None
    jwt_hs256_secret: str = DEFAULT_JWT_SECRET
    jwt_leeway_seconds: float = Field(default=30.0, ge=0)
    jwt_audience: str | None = None
    allow_insecure_dev_tokens: bool = False

    # Shared
    max_request_body_bytes: int = Field(default=1_048_576, gt=0)
    log_level: str = "INFO"

    def warn_if_insecure(self) -> None:
        """Log loudly at startup; insecure configs must never be silent."""
        if self.jwt_hs256_secret == DEFAULT_JWT_SECRET:
            _log.warning(
                "insecure_default_jwt_secret",
                extra={"fields": {"hint": "set CP_JWT_HS256_SECRET"}},
            )
        if self.allow_insecure_dev_tokens:
            _log.warning(
                "insecure_dev_tokens_enabled",
                extra={"fields": {"hint": "static and unsigned tokens are accepted"}},
            )
