"""Task 1 - STDIO MCP server (acceptance contract - docs/ACCEPTANCE_MATRIX.md).

Placeholders until phase 1; names are the contract and must not be renamed.
"""

from __future__ import annotations

import pytest


def test_stdout_is_pure_jsonrpc_with_chaos_writers() -> None:
    """STDIO isolation: subprocess with `CP_T1_CHAOS_STDOUT=1`; every stdout line `json.loads` and
    has `jsonrpc=="2.0"`
    """
    pytest.skip("phase 1")


def test_chaos_output_lands_on_stderr() -> None:
    """STDIO isolation: chaos markers appear on stderr"""
    pytest.skip("phase 1")


def test_sdk_client_roundtrip() -> None:
    """STDIO isolation: official `mcp` `stdio_client` + `ClientSession` lists tools and calls one"""
    pytest.skip("phase 1")


def test_initialize_and_tools_list_schemas_are_strict() -> None:
    """Protocol compliance: `additionalProperties: false`, pattern present"""
    pytest.skip("phase 1")


def test_unknown_tool_returns_32602() -> None:
    """Protocol compliance"""
    pytest.skip("phase 1")


def test_unknown_method_returns_32601() -> None:
    """Protocol compliance"""
    pytest.skip("phase 1")


def test_error_preserves_string_and_int_ids() -> None:
    """Protocol compliance"""
    pytest.skip("phase 1")


def test_business_error_is_iserror_not_protocol_error() -> None:
    """Protocol compliance: well-formed unknown customer"""
    pytest.skip("phase 1")


def test_get_customer_record_valid() -> None:
    """Validation"""
    pytest.skip("phase 1")


def test_trigger_refund_valid() -> None:
    """Validation: (incl. integer amount `50`)"""
    pytest.skip("phase 1")


def test_invalid_customer_id_variants() -> None:
    """Validation: parametrize: `CUST-1234`, `CUST-123456`, `cust-12345`, `CUST-12345\\n`,
    `" CUST-12345"`, `CUST-١٢٣٤٥` (Arabic-Indic digits), `12345`, `None`, `12345` (int)
    """
    pytest.skip("phase 1")


def test_invalid_amount_variants() -> None:
    """Validation: `0`, `-5`, `"50"`, `true`, `NaN`/`inf` (if transportable), `10.999`, `> 10000`"""
    pytest.skip("phase 1")


def test_invalid_reason_variants() -> None:
    """Validation: `"short"`, `"         x"` (stripped < 10), missing"""
    pytest.skip("phase 1")


def test_extra_fields_rejected() -> None:
    """Validation"""
    pytest.skip("phase 1")


def test_validation_error_data_does_not_echo_input() -> None:
    """Validation"""
    pytest.skip("phase 1")
