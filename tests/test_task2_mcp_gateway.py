"""Task 2 - MCP security gateway (acceptance contract - docs/ACCEPTANCE_MATRIX.md).

Placeholders until phase 2; names are the contract and must not be renamed.
"""

from __future__ import annotations

import pytest


def test_tools_list_proxied_for_viewer_and_admin() -> None:
    """JSON-RPC parsing"""
    pytest.skip("phase 2")


def test_id_type_preserved() -> None:
    """JSON-RPC parsing: parametrize `"abc"`, `7`, `null`"""
    pytest.skip("phase 2")


def test_parse_error_returns_32700_null_id() -> None:
    """JSON-RPC parsing"""
    pytest.skip("phase 2")


def test_invalid_request_shapes_return_32600() -> None:
    """JSON-RPC parsing: non-object, missing method, wrong jsonrpc, empty batch `[]`"""
    pytest.skip("phase 2")


def test_notification_returns_202_empty_body() -> None:
    """JSON-RPC parsing"""
    pytest.skip("phase 2")


def test_batch_mixed_allow_deny_preserves_order() -> None:
    """JSON-RPC parsing: downstream gets only allowed subset"""
    pytest.skip("phase 2")


def test_batch_of_only_notifications_returns_202() -> None:
    """JSON-RPC parsing"""
    pytest.skip("phase 2")


def test_authorization_header_not_passed_downstream() -> None:
    """Proxy forwarding"""
    pytest.skip("phase 2")


def test_correlation_id_propagated_downstream_and_echoed() -> None:
    """Proxy forwarding"""
    pytest.skip("phase 2")


def test_downstream_unavailable_returns_sanitized_32603() -> None:
    """Proxy forwarding"""
    pytest.skip("phase 2")


def test_viewer_can_call_get_customer_record() -> None:
    """Authorization"""
    pytest.skip("phase 2")


def test_viewer_admin_tool_blocked_32001_exact_message() -> None:
    """Authorization"""
    pytest.skip("phase 2")


def test_blocked_call_never_reaches_downstream() -> None:
    """Authorization: counter unchanged"""
    pytest.skip("phase 2")


def test_admin_can_call_admin_reset_key() -> None:
    """Authorization"""
    pytest.skip("phase 2")


def test_tool_name_smuggling_rejected() -> None:
    """Authorization: `"Admin_reset_key"` (blocked as admin_), `" admin_reset_key"`, zero-width
    char → -32602
    """
    pytest.skip("phase 2")


def test_missing_or_malformed_bearer_401() -> None:
    """Authorization"""
    pytest.skip("phase 2")


def test_jwt_expired_and_clock_skew_leeway() -> None:
    """Authorization"""
    pytest.skip("phase 2")


def test_insecure_dev_tokens_disabled_by_default() -> None:
    """Authorization"""
    pytest.skip("phase 2")


def test_mask_admin_tools_for_viewer_when_header_set() -> None:
    """Defense in depth"""
    pytest.skip("phase 2")


def test_caller_role_and_policy_headers() -> None:
    """Diagnostics"""
    pytest.skip("phase 2")
