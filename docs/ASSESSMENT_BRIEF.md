# Assessment Brief (transcribed from "AI Field Developer Test")

**Target roles:** AI Field Developer / AI Solutions Engineer
**Core focus areas:** MCP Servers, MCP Gateways, LLM Gateways, Security Guardrails, System Integration

**Overview:** 4 practical technical tasks evaluating building MCP servers, implementing LLM &
MCP security proxy gateways, handling stream guardrails, managing model routing resilience,
and **troubleshooting zero-trust network deployments**.

> The last focus area, troubleshooting zero-trust deployments, has no task of its own. It is
> addressed by the end-to-end demo, the diagnostic headers, correlation IDs, and
> [`TROUBLESHOOTING.md`](../TROUBLESHOOTING.md).

---

## Task 1 — Custom MCP Server with Strict Validation & Transport Handling
Format: Take-home / 60-min live coding

Write a runnable MCP server (TypeScript or Python) using the official SDK that exposes:
1. `get_customer_record` — input `customer_id` string formatted as `CUST-XXXXX`.
2. `trigger_refund` — inputs `customer_id`, `amount` (positive float), `reason` (string, min length 10).

Requirements
- Strict input schema validation (Zod or Pydantic). Reject invalid formats with standard MCP JSON-RPC error codes.
- stdio transport. stdout strictly reserved for JSON-RPC; system/debug logs exclusively to stderr.

Evaluation criteria
- **STDIO Isolation:** stdout is pure JSON-RPC without accidental console.log/print.
- **Protocol Compliance:** standard JSON-RPC error mapping and execution flow.
- **Validation:** robust schema definitions and edge-case handling for malformed input fields.

## Task 2 — MCP Security Gateway Proxy (Tool Filtering & Auth)
Format: Take-home coding challenge

Lightweight HTTP/JSON-RPC reverse proxy between an AI agent client and a downstream mock MCP server.

Requirements
- Read `Bearer <token>` header; extract role (e.g. `admin` or `viewer`).
- Inspect the MCP JSON-RPC payload:
  - `tools/list` → forward transparently downstream.
  - `tools/call` → inspect `params.name`. If it starts with `admin_` (e.g. `admin_reset_key`), verify role is `admin`. If not authorized, intercept and return JSON-RPC error `-32001: Unauthorized Tool Call` **without calling the downstream server**.

Evaluation criteria
- Parsing JSON-RPC wire format structures correctly.
- Proxy middleware construction and HTTP request/response forwarding.
- Fine-grained, method-level authorization logic and clean error handling.

## Task 3 — LLM Gateway Streaming Guardrail (PII Redaction)
Format: Coding assessment

LLM Gateway proxy endpoint that routes generation requests to an LLM provider and streams the response back.

Requirements
- Intercept the response chunk stream in real time.
- Parse stream deltas; detect and redact Emails, SSNs, credit card numbers → `[REDACTED]`.
- Stay responsive without accumulating the full response in memory; minimize TTFT and overall latency.

Evaluation criteria
- Efficient async stream chunking and buffer state management.
- Performant string/regex matching over partial text streams.
- Memory efficiency and low-latency proxying design.

## Task 4 — Rate-Limiting & Model Fallback Router
Format: Architectural coding task

Resilient model-routing module for an LLM Gateway accepting completion requests.

Requirements
- Token-aware sliding-window rate limiter (e.g. max 50,000 tokens/minute per tenant API key).
- If the primary model returns **429** or **times out after 3000 ms**, automatically fail over to a secondary backup provider.
- Error responses return a standardized gateway error payload without leaking upstream stack traces or internals.
- **Use on-disk SQLite** for the database.

Evaluation criteria
- Async concurrency handling and timeout race conditions.
- Accurate rate-limiter state eviction and token tracking.
- Graceful fallback mechanics and standardized error sanitization.
