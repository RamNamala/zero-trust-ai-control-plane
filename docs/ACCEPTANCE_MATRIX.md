# Acceptance Matrix

Every evaluation criterion from the brief maps to code and to named tests.
`uv run python scripts/check_matrix.py --run` verifies that each named test exists and passes.

## Task 1 — MCP server (`tests/test_task1_mcp_server.py`)

| Criterion | Test | Status |
|---|---|---|
| STDIO isolation | `test_stdout_is_pure_jsonrpc_with_chaos_writers` — subprocess with `CP_T1_CHAOS_STDOUT=1`; every stdout line `json.loads` and has `jsonrpc=="2.0"` | pass |
| STDIO isolation | `test_chaos_output_lands_on_stderr` — chaos markers appear on stderr | pass |
| STDIO isolation | `test_sdk_client_roundtrip` — official `mcp` `stdio_client` + `ClientSession` lists tools and calls one | pass |
| Protocol compliance | `test_initialize_and_tools_list_schemas_are_strict` — `additionalProperties: false`, pattern present | pass |
| Protocol compliance | `test_unknown_tool_returns_32602` | pass |
| Protocol compliance | `test_unknown_method_returns_32601` | pass |
| Protocol compliance | `test_error_preserves_string_and_int_ids` | pass |
| Protocol compliance | `test_business_error_is_iserror_not_protocol_error` — well-formed unknown customer | pass |
| Validation | `test_get_customer_record_valid` | pass |
| Validation | `test_trigger_refund_valid` (incl. integer amount `50`) | pass |
| Validation | `test_invalid_customer_id_variants` — parametrize: `CUST-1234`, `CUST-123456`, `cust-12345`, `CUST-12345\n`, `" CUST-12345"`, `CUST-١٢٣٤٥` (Arabic-Indic digits), `12345`, `None`, `12345` (int) | pass |
| Validation | `test_invalid_amount_variants` — `0`, `-5`, `"50"`, `true`, `NaN`/`inf` (if transportable), `10.999`, `> 10000` | pass |
| Validation | `test_invalid_reason_variants` — `"short"`, `"         x"` (stripped < 10), missing | pass |
| Validation | `test_extra_fields_rejected` | pass |
| Validation | `test_validation_error_data_does_not_echo_input` | pass |

## Task 2 — MCP gateway (`tests/test_task2_mcp_gateway.py`)

| Criterion | Test | Status |
|---|---|---|
| JSON-RPC parsing | `test_tools_list_proxied_for_viewer_and_admin` | pass |
| JSON-RPC parsing | `test_id_type_preserved` — parametrize `"abc"`, `7`, `null` | pass |
| JSON-RPC parsing | `test_parse_error_returns_32700_null_id` | pass |
| JSON-RPC parsing | `test_invalid_request_shapes_return_32600` — non-object, missing method, wrong jsonrpc, empty batch `[]` | pass |
| JSON-RPC parsing | `test_notification_returns_202_empty_body` | pass |
| JSON-RPC parsing | `test_batch_mixed_allow_deny_preserves_order` — downstream gets only allowed subset | pass |
| JSON-RPC parsing | `test_batch_of_only_notifications_returns_202` | pass |
| Proxy forwarding | `test_authorization_header_not_passed_downstream` | pass |
| Proxy forwarding | `test_correlation_id_propagated_downstream_and_echoed` | pass |
| Proxy forwarding | `test_downstream_unavailable_returns_sanitized_32603` | pass |
| Authorization | `test_viewer_can_call_get_customer_record` | pass |
| Authorization | `test_viewer_admin_tool_blocked_32001_exact_message` | pass |
| Authorization | `test_blocked_call_never_reaches_downstream` — counter unchanged | pass |
| Authorization | `test_admin_can_call_admin_reset_key` | pass |
| Authorization | `test_tool_name_smuggling_rejected` — `"Admin_reset_key"` (blocked as admin_), `" admin_reset_key"`, zero-width char → -32602 | pass |
| Authorization | `test_missing_or_malformed_bearer_401` | pass |
| Authorization | `test_jwt_expired_and_clock_skew_leeway` | pass |
| Authorization | `test_insecure_dev_tokens_disabled_by_default` | pass |
| Defense in depth | `test_mask_admin_tools_for_viewer_when_header_set` | pass |
| Diagnostics | `test_caller_role_and_policy_headers` | pass |

## Task 3 — Streaming guardrail (`tests/test_task3_guardrail.py`)

| Criterion | Test | Status |
|---|---|---|
| Regex over partial streams | `test_ssn_split_across_three_chunks` | pass |
| Regex over partial streams | `test_email_split_across_three_chunks` | pass |
| Regex over partial streams | `test_credit_card_split_across_three_chunks` (dashed and spaced) | pass |
| Regex over partial streams | `test_chunking_invariance_property` (Hypothesis) | pass |
| Regex over partial streams | `test_non_luhn_digit_runs_not_redacted` — order numbers, phone-like runs | pass |
| Buffer state mgmt | `test_flush_emits_tail_and_resets` | pass |
| Buffer state mgmt | `test_finish_reason_frame_flushes_before_forwarding` | pass |
| Buffer state mgmt | `test_multi_choice_streams_have_independent_buffers` | pass |
| Memory efficiency | `test_peak_buffer_bounded_over_10k_chunks` — `peak_buffer_chars <= max_hold + max_chunk_len` | pass |
| Memory efficiency | `test_gateway_never_reads_full_upstream_body` (mock asserts streaming consumption) | pass |
| Low latency | `test_first_safe_chunk_yielded_before_stream_ends` — first content < 200 ms while upstream pauses 1 s | pass |
| Low latency | `test_sse_headers_disable_proxy_buffering` | pass |
| Robustness | `test_client_disconnect_closes_upstream` | pass |
| Robustness | `test_upstream_error_midstream_emits_sanitized_error_frame` | pass |
| Diagnostics | `test_guardrail_trailer_reports_redaction_count` | pass |

## Task 4 — Router (`tests/test_task4_router.py`)

| Criterion | Test | Status |
|---|---|---|
| Rate-limit state | `test_wal_mode_and_pragmas_enabled` | pass |
| Rate-limit state | `test_limit_enforced_at_50000` | pass |
| Rate-limit state | `test_concurrent_gather_cannot_overdraft` — 100 × 1,000-token reservations via `asyncio.gather` → exactly 50 succeed | pass |
| Rate-limit state | `test_multiprocess_cannot_overdraft` — 4 processes, separate connections, same DB file | pass |
| Rate-limit state | `test_sliding_window_expiry_restores_quota` (injected clock) | pass |
| Rate-limit state | `test_partial_expiry_is_sliding_not_fixed` | pass |
| Rate-limit state | `test_retry_after_ms_is_accurate` | pass |
| Rate-limit state | `test_request_larger_than_limit_is_413_not_429` | pass |
| Token tracking | `test_reconcile_refunds_unused_reservation` | pass |
| Token tracking | `test_release_on_total_failure_does_not_charge_tenant` | pass |
| Token tracking | `test_tenant_isolation` | pass |
| Token tracking | `test_raw_tenant_key_not_stored` | pass |
| Timeout races | `test_failover_on_primary_timeout_3200ms` (`X-Failover-Reason: timeout_3000ms`) | pass |
| Timeout races | `test_timed_out_primary_task_is_cancelled` — mock `cancelled` flag set | pass |
| Timeout races | `test_primary_2900ms_is_not_failed_over` | pass |
| Fallback | `test_failover_on_429` | pass |
| Fallback | `test_failover_on_5xx` | pass |
| Fallback | `test_no_failover_on_400_client_error` | pass |
| Fallback | `test_diagnostic_headers_present` | pass |
| Sanitization | `test_both_fail_returns_envelope_without_leaks` — no `Traceback`, `/srv/`, `SELECT`, `10.0.0.7`, `sk-live` | pass |
| Sanitization | `test_unhandled_exception_handler_sanitizes` | pass |
| Sanitization | `test_rate_limited_envelope_and_retry_after_header` | pass |

## Integration (`tests/test_e2e_integration.py`)

| Criterion | Test | Status |
|---|---|---|
| Zero-trust chain | `test_scenario_a_confused_deputy_blocked` | pass |
| Zero-trust chain | `test_scenario_b_full_pipeline_failover_tool_call_redaction` | pass |
| Zero-trust chain | `test_scenario_c_validation_error_passes_through_gateway` | pass |
| Zero-trust chain | `test_scenario_d_runaway_tenant_rate_limited` | pass |
| Zero-trust chain | `test_scenario_e_total_failure_sanitized` | pass |
| Observability | `test_single_correlation_id_visible_in_all_hops` (headers + T1 stderr + gateway logs) | pass |
| Robustness | `test_stdio_downstream_id_rewriting_handles_concurrent_same_ids` | pass |
| Robustness | `test_stdio_downstream_recovers_after_child_crash` | pass |
| Demo | `test_e2e_demo_exits_zero` (runs `python -m control_plane.e2e_demo --fast`) | pass |

## Adversarial review (`tests/test_adversarial.py`)

Every test in this file failed before the hardening commit or is a probe that held; see PITFALLS #49–#55.

| Criterion | Test | Status |
|---|---|---|
| T1 protocol compliance | `test_t1_unparseable_frames_get_a_jsonrpc_error_response` (`-32700`/`-32600`, `id: null`) | pass |
| T1 validation | `test_t1_odd_json_types_are_32602_and_never_echoed` | pass |
| T1 stdio | `test_t1_concurrent_requests_on_one_session`, `test_t1_garbage_frames_do_not_kill_the_session` | pass |
| T2 parsing | `test_t2_non_standard_json_numbers_are_parse_errors`, `test_t2_deeply_nested_json_is_not_a_500` | pass |
| T2 authorization | `test_t2_method_spelling_variants_never_bypass_rbac`, `test_t2_non_string_tool_name_is_32602`, `test_t2_params_as_array_for_tools_call_is_32602` | pass |
| T2 authentication | `test_t2_duplicate_authorization_headers_are_rejected`, `test_t2_forged_jwts_are_401`, `test_t2_bearer_scheme_any_case` | pass |
| T2 limits | `test_t2_batch_of_1000_messages_is_rejected_without_forwarding`, `test_t2_batch_at_the_cap_is_answered_in_order`, `test_t2_2mb_chunked_body_is_413` | pass |
| T3 redaction | `test_t3_forced_flush_never_splits_pii`, `test_t3_edge_texts_match_one_shot_redaction` | pass |
| T3 redaction scope | `test_t3_pii_in_non_content_delta_fields_is_redacted`, `test_t3_non_stream_tool_calls_and_content_parts_are_redacted` | pass |
| T3 stream handling | `test_t3_empty_and_role_only_deltas_pass_through`, `test_t3_done_twice_yields_one_trailer`, `test_t3_missing_done_flushes_redacted_tail_then_error`, `test_t3_sse_parser_bounds_an_unterminated_frame` | pass |
| T4 limiter | `test_t4_two_tenants_hammering_concurrently`, `test_t4_reconcile_after_window_expiry_does_not_resurrect`, `test_t4_clock_going_backwards_two_seconds` | pass |
| T4 input | `test_t4_invalid_max_tokens_is_422_and_charges_nothing`, `test_t4_huge_max_tokens_is_413`, `test_t4_oversized_body_is_413_before_any_provider_call`, `test_t4_oversized_chunked_body_is_413`, `test_t4_estimate_counts_tool_calls_and_names` | pass |
| T4 resilience | `test_t4_primary_200_with_malformed_json_fails_over`, `test_t4_backup_hanging_forever_respects_total_deadline`, `test_t4_stream_that_stalls_after_first_byte_is_cut_off`, `test_t4_client_cancel_during_primary_wait_releases_reservation` | pass |
| No leaks | `test_source_has_no_leaky_idioms`, `test_integration_error_paths_leak_nothing` | pass |
