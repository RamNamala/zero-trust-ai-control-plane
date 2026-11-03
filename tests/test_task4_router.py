"""Task 4 - rate limiter and failover router (acceptance contract - docs/ACCEPTANCE_MATRIX.md).

Placeholders until phase 4; names are the contract and must not be renamed.
"""

from __future__ import annotations

import pytest


def test_wal_mode_and_pragmas_enabled() -> None:
    """Rate-limit state"""
    pytest.skip("phase 4")


def test_limit_enforced_at_50000() -> None:
    """Rate-limit state"""
    pytest.skip("phase 4")


def test_concurrent_gather_cannot_overdraft() -> None:
    """Rate-limit state: 100 × 1,000-token reservations via `asyncio.gather` → exactly 50 succeed"""
    pytest.skip("phase 4")


def test_multiprocess_cannot_overdraft() -> None:
    """Rate-limit state: 4 processes, separate connections, same DB file"""
    pytest.skip("phase 4")


def test_sliding_window_expiry_restores_quota() -> None:
    """Rate-limit state: (injected clock)"""
    pytest.skip("phase 4")


def test_partial_expiry_is_sliding_not_fixed() -> None:
    """Rate-limit state"""
    pytest.skip("phase 4")


def test_retry_after_ms_is_accurate() -> None:
    """Rate-limit state"""
    pytest.skip("phase 4")


def test_request_larger_than_limit_is_413_not_429() -> None:
    """Rate-limit state"""
    pytest.skip("phase 4")


def test_reconcile_refunds_unused_reservation() -> None:
    """Token tracking"""
    pytest.skip("phase 4")


def test_release_on_total_failure_does_not_charge_tenant() -> None:
    """Token tracking"""
    pytest.skip("phase 4")


def test_tenant_isolation() -> None:
    """Token tracking"""
    pytest.skip("phase 4")


def test_raw_tenant_key_not_stored() -> None:
    """Token tracking"""
    pytest.skip("phase 4")


def test_failover_on_primary_timeout_3200ms() -> None:
    """Timeout races: (`X-Failover-Reason: timeout_3000ms`)"""
    pytest.skip("phase 4")


def test_timed_out_primary_task_is_cancelled() -> None:
    """Timeout races: mock `cancelled` flag set"""
    pytest.skip("phase 4")


def test_primary_2900ms_is_not_failed_over() -> None:
    """Timeout races"""
    pytest.skip("phase 4")


def test_failover_on_429() -> None:
    """Fallback"""
    pytest.skip("phase 4")


def test_failover_on_5xx() -> None:
    """Fallback"""
    pytest.skip("phase 4")


def test_no_failover_on_400_client_error() -> None:
    """Fallback"""
    pytest.skip("phase 4")


def test_diagnostic_headers_present() -> None:
    """Fallback"""
    pytest.skip("phase 4")


def test_both_fail_returns_envelope_without_leaks() -> None:
    """Sanitization: no `Traceback`, `/srv/`, `SELECT`, `10.0.0.7`, `sk-live`"""
    pytest.skip("phase 4")


def test_unhandled_exception_handler_sanitizes() -> None:
    """Sanitization"""
    pytest.skip("phase 4")


def test_rate_limited_envelope_and_retry_after_header() -> None:
    """Sanitization"""
    pytest.skip("phase 4")
