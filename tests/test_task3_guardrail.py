"""Task 3 - streaming PII guardrail (acceptance contract - docs/ACCEPTANCE_MATRIX.md).

Placeholders until phase 3; names are the contract and must not be renamed.
"""

from __future__ import annotations

import pytest


def test_ssn_split_across_three_chunks() -> None:
    """Regex over partial streams"""
    pytest.skip("phase 3")


def test_email_split_across_three_chunks() -> None:
    """Regex over partial streams"""
    pytest.skip("phase 3")


def test_credit_card_split_across_three_chunks() -> None:
    """Regex over partial streams: (dashed and spaced)"""
    pytest.skip("phase 3")


def test_chunking_invariance_property() -> None:
    """Regex over partial streams: (Hypothesis)"""
    pytest.skip("phase 3")


def test_non_luhn_digit_runs_not_redacted() -> None:
    """Regex over partial streams: order numbers, phone-like runs"""
    pytest.skip("phase 3")


def test_flush_emits_tail_and_resets() -> None:
    """Buffer state mgmt"""
    pytest.skip("phase 3")


def test_finish_reason_frame_flushes_before_forwarding() -> None:
    """Buffer state mgmt"""
    pytest.skip("phase 3")


def test_multi_choice_streams_have_independent_buffers() -> None:
    """Buffer state mgmt"""
    pytest.skip("phase 3")


def test_peak_buffer_bounded_over_10k_chunks() -> None:
    """Memory efficiency: `peak_buffer_chars <= max_hold + max_chunk_len`"""
    pytest.skip("phase 3")


def test_gateway_never_reads_full_upstream_body() -> None:
    """Memory efficiency: (mock asserts streaming consumption)"""
    pytest.skip("phase 3")


def test_first_safe_chunk_yielded_before_stream_ends() -> None:
    """Low latency: first content < 200 ms while upstream pauses 1 s"""
    pytest.skip("phase 3")


def test_sse_headers_disable_proxy_buffering() -> None:
    """Low latency"""
    pytest.skip("phase 3")


def test_client_disconnect_closes_upstream() -> None:
    """Robustness"""
    pytest.skip("phase 3")


def test_upstream_error_midstream_emits_sanitized_error_frame() -> None:
    """Robustness"""
    pytest.skip("phase 3")


def test_guardrail_trailer_reports_redaction_count() -> None:
    """Diagnostics"""
    pytest.skip("phase 3")
