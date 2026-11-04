# Engineering Spec — Zero-Trust AI & MCP Control Plane

The design the code implements, module by module. Section numbers are referenced from code
docstrings and `ACCEPTANCE_MATRIX.md`; the traps behind several of these decisions are in
`PITFALLS.md`.

---

## 0. Repository layout

```text
zero-trust-ai-control-plane/
├── README.md                    # architecture, run instructions, design trade-offs
├── TROUBLESHOOTING.md           # field-engineer runbook (zero-trust deployment failures)
├── DESIGN_NOTES.md              # decisions, alternatives, what changes in production
├── pyproject.toml               # uv, hatchling, src layout, ruff, mypy, pytest config
├── Makefile                     # shortcuts for the uv commands
├── docs/                        # spec, acceptance matrix, pitfalls, brief, reference algorithms
├── scripts/
│   ├── bench.py                 # measures gateway overhead (feeds README numbers)
│   ├── check_matrix.py          # cross-checks ACCEPTANCE_MATRIX.md against pytest
│   └── dev_tokens.py            # prints HS256 JWTs for admin/viewer for curl demos
├── src/control_plane/
│   ├── __init__.py
│   ├── common/
│   │   ├── settings.py          # pydantic-settings; all tunables + env prefix CP_
│   │   ├── logging.py           # JSON-lines logger -> stderr, correlation_id contextvar
│   │   ├── correlation.py       # X-Correlation-ID middleware (validate/generate, propagate)
│   │   ├── errors.py            # GatewayError envelope + FastAPI exception handlers
│   │   └── jsonrpc.py           # JSON-RPC 2.0 models/helpers (request, notification, error codes)
│   ├── task1_mcp_server/
│   │   ├── __main__.py          # STDIO isolation FIRST, then import server and run
│   │   ├── schemas.py           # Pydantic v2 strict input models
│   │   ├── data.py              # deterministic fixture customers
│   │   └── server.py            # low-level mcp.server.Server, custom CallTool handler
│   ├── task2_mcp_gateway/
│   │   ├── auth.py              # Bearer parsing -> Principal(role, subject, token_kind)
│   │   ├── policy.py            # RBAC policy engine (pure functions, table-driven)
│   │   ├── downstream.py        # Downstream protocol: HttpDownstream, StdioMcpDownstream
│   │   ├── proxy.py             # FastAPI app: POST /mcp
│   │   └── mock_downstream.py   # mock MCP-over-HTTP server with call counters
│   ├── task3_streaming_guardrail/
│   │   ├── patterns.py          # compiled regexes, Luhn, redact()
│   │   ├── redactor.py          # StreamingPIIRedactor (feed/flush)
│   │   ├── sse.py               # SSE line parser/encoder (OpenAI-style chunks)
│   │   ├── gateway.py           # FastAPI app: POST /v1/chat/completions (stream)
│   │   └── mock_llm.py          # mock SSE LLM with scripted chunking, delays, disconnect probe
│   ├── task4_resilient_router/
│   │   ├── tokens.py            # prompt token estimate (chars/4)
│   │   ├── rate_limiter.py      # SQLite WAL sliding window, reserve/reconcile/release
│   │   ├── providers.py         # Provider protocol, HttpProvider, fault-injecting mocks
│   │   ├── circuit_breaker.py   # skips the primary while open
│   │   └── router.py            # failover routing, headers, sanitized errors
│   ├── integration/
│   │   ├── app.py               # unified gateway: /v1/chat/completions (T4+T3) and /mcp (T2->T1)
│   │   └── mock_agent_llm.py    # deterministic "LLM" that emits a tool_call then a PII-laden summary
│   └── e2e_demo.py              # python -m control_plane.e2e_demo
└── tests/
    ├── conftest.py
    ├── test_task1_mcp_server.py
    ├── test_task2_mcp_gateway.py
    ├── test_task3_guardrail.py
    ├── test_task4_router.py
    ├── test_e2e_integration.py
    └── test_adversarial.py
```

---

## 1. Cross-cutting (`common/`)

### 1.1 Settings (`settings.py`)
`pydantic-settings` `BaseSettings`, env prefix `CP_`. Defaults:

| Setting | Default |
|---|---|
| `rate_limit_tokens_per_window` | 50000 |
| `rate_limit_window_seconds` | 60.0 |
| `rate_limit_db_path` | `./data/gateway_ratelimit.db` |
| `primary_timeout_seconds` | 3.0 |
| `request_deadline_seconds` | 15.0 (total budget incl. backup) |
| `redactor_max_hold_chars` | 256 |
| `mcp_downstream_url` | `http://127.0.0.1:8101/mcp` |
| `mcp_mask_unauthorized_tools` | false (also toggled per request by header) |
| `jwt_hs256_secret` | `dev-only-change-me` (warn loudly at startup if default) |
| `jwt_leeway_seconds` | 30 |
| `allow_insecure_dev_tokens` | false (enables static + unsigned base64-JSON tokens) |
| `max_request_body_bytes` | 1_048_576 |

### 1.2 Correlation IDs (`correlation.py`)
- ASGI middleware. Read `X-Correlation-ID`; accept only `^[A-Za-z0-9._-]{8,128}$` (log-injection defense), else generate `uuid4`. Store in a `contextvars.ContextVar`.
- Echo `X-Correlation-ID` on **every** response, including errors and 202s.
- Propagate downstream: HTTP header on every outbound httpx call; for MCP `tools/call` forwarded to T1, inject into `params._meta["correlationId"]` (MCP's reserved metadata slot). T1 logs it.

### 1.3 Logging (`logging.py`)
- JSON lines to **stderr**: `ts, level, logger, event, correlation_id, ...fields`.
- `audit(event, **fields)` helper for security decisions. Never pass raw arguments/results/PII; log tool name, role, decision, latency, redaction counts.

### 1.4 Error envelope (`errors.py`)
```json
{"error": {"code": "GATEWAY_UPSTREAM_FAILURE",
           "message": "The request could not be completed by primary or backup model providers.",
           "request_id": "<uuid4>", "correlation_id": "<id>", "timestamp": "<ISO-8601 UTC>"}}
```
Codes: `RATE_LIMITED` (429 + `Retry-After`), `REQUEST_TOO_LARGE` (413 — request alone exceeds the limit), `INVALID_REQUEST` (400/422), `UNAUTHENTICATED` (401), `GATEWAY_UPSTREAM_FAILURE` (502), `GATEWAY_TIMEOUT` (504), `INTERNAL_ERROR` (500).
Register handlers for `HTTPException`, `RequestValidationError`, and bare `Exception`. The bare handler logs the exception (with traceback) to stderr and returns only the envelope. `RequestValidationError` details are reduced to field paths + messages (no input echo).

### 1.5 JSON-RPC helpers (`jsonrpc.py`)
Codes: `-32700` parse error, `-32600` invalid request, `-32601` method not found, `-32602` invalid params, `-32603` internal error, `-32001` unauthorized tool call (gateway), `-32002` unauthenticated (gateway). Helper `is_notification(msg) = isinstance(msg, dict) and "id" not in msg`. Note: `"id": null` is present → it is a request, not a notification; preserve the null.

---

## 2. Task 1 — STDIO MCP server

### 2.1 STDIO isolation (`__main__.py`)
First executable lines, before any other import (the pattern verified in `docs/reference/mcp_stdio_spike.py`):
```python
import os, sys
_REAL_STDOUT_FD = os.dup(1)
os.dup2(2, 1)
sys.stdout = sys.stderr
```
Then configure logging to stderr, import the server, and run `stdio_server(stdout=<anyio-wrapped TextIOWrapper over _REAL_STDOUT_FD>)`. This covers `print()`, mis-configured loggers, third-party import-time prints, C extensions, and child processes — not just Python-level `sys.stdout`.
- Chaos switch for tests: env `CP_T1_CHAOS_STDOUT=1` makes the server deliberately `print()`, `logging.getLogger().warning()`, and `os.write(1, ...)` at startup and in each tool call. Tests run with it ON and assert stdout stays pure.

### 2.2 Schemas (`schemas.py`)
```python
CustomerId = Annotated[str, StringConstraints(pattern=r"^CUST-[0-9]{5}$")]   # [0-9], NOT \d
class GetCustomerRecordInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    customer_id: CustomerId
class TriggerRefundInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    customer_id: CustomerId
    amount: Annotated[float, Field(gt=0, le=10_000, allow_inf_nan=False)]
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=500)]
```
- Strict mode: strings like `"50"` rejected for `amount`; `true` rejected; JSON integer `50` accepted (Pydantic strict float accepts int; a refund of 50 is legitimate). Add a validator rejecting more than 2 decimal places.
- `inputSchema` advertised in `tools/list` is generated from `model_json_schema()` so the contract and the validator never drift. Include `"additionalProperties": false`.

### 2.3 Request handling (`server.py`)
- Low-level `mcp.server.lowlevel.Server`. Register `tools/list` via `@server.list_tools()`. Register `tools/call` by assigning `server.request_handlers[types.CallToolRequest] = handler` (the decorator would swallow errors into `isError`).
- Unknown tool name → `McpError(ErrorData(code=-32602, message="Unknown tool: <name>"))` (this is what the MCP spec prescribes; `-32601` is for unknown *methods* and the SDK already produces it).
- `arguments` missing → treat as `{}` and let validation fail with -32602.
- `pydantic.ValidationError` → `McpError(ErrorData(code=-32602, message="Invalid params", data=[{"loc", "msg", "type"}...]))`. Strip `input` and `url` from each error dict so the server doesn't echo user input.
- Business outcome errors (unknown-but-well-formed customer, refund over balance) → `CallToolResult(isError=True, content=[TextContent(...)])` — tool execution error, not protocol error.
- Success → `CallToolResult` with `TextContent` (JSON string) **and** `structuredContent` (dict) for clients that support it.
- Fixtures (`data.py`): at least `CUST-10042` → Sarah Connor, `sarah.connor@cyberdyne.io`, SSN `999-01-4242`, tier, balance, last 3 orders; plus 2 others. `trigger_refund` returns a deterministic `refund_id` (e.g. `RF-` + sha256(customer_id|amount|reason)[:10]), status `queued`.
- Log every call to stderr with `correlation_id` from `params._meta.correlationId` if present, tool name, outcome, latency. Never log the reason text or record contents.

---

## 3. Task 2 — MCP security gateway

### 3.1 Authentication (`auth.py`)
Parse `Authorization: Bearer <token>` (case-insensitive scheme, exactly one token, no extra spaces). Resolution order:
1. **HS256 JWT** (PyJWT): require `role` claim ∈ {`admin`, `viewer`}, honor `exp`/`nbf` with `jwt_leeway_seconds` leeway (clock-skew tolerance), optional `aud`.
2. If `allow_insecure_dev_tokens`: static tokens `admin-secret-token`→admin, `viewer-secret-token`→viewer; and unsigned base64url JSON `{"role": "..."}`. Off by default; tests turn it on explicitly; startup log warns when on.
Failures: missing/malformed header or invalid token → HTTP **401**, `WWW-Authenticate: Bearer`, body is a JSON-RPC error `{"jsonrpc":"2.0","id":null,"error":{"code":-32002,"message":"Unauthenticated"}}` (id echoed if body parsed). Unknown role → treated as unauthenticated. Compare static tokens with `hmac.compare_digest`.

### 3.2 Policy (`policy.py`)
Pure, table-driven: `decide(principal, method, tool_name) -> Decision(allow, reason)`.
- `tools/call` with `tool_name.lower().startswith("admin_")` requires `admin`.
- Tool names must match `^[A-Za-z0-9_.-]{1,128}$`; otherwise `-32602` locally (blocks Unicode look-alike / whitespace smuggling like `" admin_reset_key"` or `"admin_reset_key​"`).
- Everything else allowed for both roles. Default-deny for unknown roles.

### 3.3 Proxy (`proxy.py`) — `POST /mcp`
Wire handling, in order:
1. Body > `max_request_body_bytes` → 413.
2. Authenticate (3.1).
3. Parse JSON. Failure → HTTP 200, `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,...}}`.
4. Body is an object → single; array → batch; anything else → `-32600`. Empty array → single `-32600` error object (not an array).
5. Per message: not an object or missing `jsonrpc:"2.0"`/`method` string → `-32600` (id preserved if present & valid type).
6. `tools/call`: `params` must be an object with string `name` → else `-32602` locally. Apply policy. Denied → local error, **downstream never called**:
   ```json
   {"jsonrpc":"2.0","id":<preserved>,"error":{"code":-32001,
    "message":"Unauthorized Tool Call: Role 'viewer' is not permitted to invoke administrative tool 'admin_reset_key'."}}
   ```
7. Allowed messages are forwarded. Batch: forward the allowed subset as one downstream batch; merge local + downstream responses back in **original order**; omit responses for notifications.
8. Response: if no response objects remain (all notifications) → **HTTP 202, empty body**. Else HTTP 200 with object (single) or array (batch). `-32001` uses HTTP 200 by default (`CP_T2_DENY_HTTP_STATUS=403` optional).
9. Optional masking: when `X-Mask-Unauthorized-Tools: true` (or setting on) and caller is not admin, remove `admin_*` tools from `tools/list` results.

Forwarding rules:
- Shared `httpx.AsyncClient` (created in lifespan, closed on shutdown), timeouts set, connection pool limits.
- **Do not forward the client's `Authorization` header** (MCP spec forbids token passthrough). Downstream gets the gateway's own credential (`CP_T2_DOWNSTREAM_TOKEN`) if configured.
- Forward `Content-Type`, `Accept` (`application/json, text/event-stream`), `Mcp-Session-Id`, `MCP-Protocol-Version`; add `X-Correlation-ID`, `X-Forwarded-For`. Strip hop-by-hop headers both ways.
- Downstream unreachable/timeout → per-request JSON-RPC `-32603` with generic message "Upstream MCP server unavailable" (no URL), HTTP 200.
- Response headers: `X-Correlation-ID`, `X-MCP-Caller-Role`, `X-MCP-Policy-Decision: allow|deny|mixed`.

### 3.4 Downstreams (`downstream.py`)
`class Downstream(Protocol): async def send(self, payload: dict | list) -> dict | list | None`
- `HttpDownstream(url, client)` — POST and return parsed JSON (or None on 202).
- `StdioMcpDownstream(cmd)` — spawns T1 via `asyncio.create_subprocess_exec`, performs `initialize` + `notifications/initialized` once, then forwards raw JSON-RPC lines. **Rewrite request ids** to an internal monotonic counter and map responses back to the caller's original id (prevents collisions between concurrent clients that both use `id: 1`). One reader task dispatches responses to waiting futures; a lock serializes writes. Handles subprocess death (fail pending futures with -32603, restart on next call). stderr of the child is drained into the gateway log (otherwise the pipe fills and the child blocks — classic EOF/hang bug).

### 3.5 Mock downstream (`mock_downstream.py`)
FastAPI app speaking plain JSON-RPC over HTTP: `initialize`, `tools/list` (returns `get_customer_record`, `trigger_refund`, `admin_reset_key`), `tools/call`, batches, notifications → 202. `app.state.calls: Counter[str]` and `GET /__stats`. Records last received headers so tests can assert `Authorization` was NOT passed through and `X-Correlation-ID` WAS.

---

## 4. Task 3 — Streaming PII guardrail

### 4.1 Patterns (`patterns.py`)
Exactly as in `docs/reference/redactor_reference.py`: email, SSN `(?<![0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9])`, card candidate `(?<![0-9])[0-9](?:[ -]?[0-9]){12,18}(?![0-9])` confirmed by Luhn and 13–19 digits. Order: email → SSN → card. Do **not** drop SSNs with "invalid" area numbers (9xx, 000, 666): fail closed; the demo uses `999-01-4242`.

### 4.2 Redactor (`redactor.py`)
`StreamingPIIRedactor(max_hold=256)` with `feed(delta) -> str`, `flush() -> str`, and metrics `redaction_count`, `peak_buffer_chars`, `forced_flushes`. Algorithm: append → find safe cut = start of the maximal trailing PII-capable run (fixpoint over email-tail and numeric-tail classes) → cap hold at `max_hold` → redact and emit the prefix → keep the tail. `flush()` redacts and emits the rest. Property: for any chunking, output == `redact(full_text)` (as long as no single run exceeds `max_hold`).

### 4.3 SSE plumbing (`sse.py`, `gateway.py`) — `POST /v1/chat/completions`
- Body: OpenAI-style `{model, messages, stream: true, max_tokens}`. Non-stream requests also supported (redact whole result; it's already complete).
- Upstream via shared `httpx.AsyncClient.stream(...)`; parse with `aiter_lines()` handling `data:` lines, multi-line data, `:` comments, blank-line frame ends, and `[DONE]`.
- For each `choices[i].delta.content`: run through a per-choice redactor (`dict[int, StreamingPIIRedactor]`). Re-emit the frame with redacted content. If redacted content is empty and the frame carries nothing else, skip it; frames with `role`/`finish_reason`/`tool_calls` are always forwarded (flush that choice's redactor **before** forwarding a `finish_reason` frame).
- On `[DONE]`: flush all redactors, emit one final metadata frame `event: guardrail` / `data: {"pii_redactions": N, "correlation_id": ...}`, then `data: [DONE]`.
- **Redaction count cannot be a response header** — headers are sent before the body. Use the trailer frame + audit log.
- Response headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`, `X-Correlation-ID`, `X-Guardrail: pii-redaction/v1`.
- **Client disconnect:** the generator wraps the upstream stream in `async with`; on `asyncio.CancelledError` / `GeneratorExit` it logs `client_disconnected`, closes the upstream response, and re-raises. Mock LLM sets an `upstream_closed` event in its own `finally` so tests can prove it.
- Upstream error mid-stream: flush (redacted) what is buffered, then emit an `event: error` frame with the sanitized envelope, then end.

### 4.4 Mock LLM (`mock_llm.py`)
Scriptable: list of `(delay_seconds, content_chunk)`; preset scripts include the adversarial 3-way splits:
- SSN: `"My SSN is 123-"`, `"45-67"`, `"89. Thanks"`
- Email: `"Email alice.smi"`, `"th@compa"`, `"ny.org now"`
- Card: `"Card 4532-01"`, `"51-1283-"`, `"0366 ok"`
Also a `slow_first_then_pause` script for TTFT and a 10k-chunk script for memory bound.

---

## 5. Task 4 — Rate limiter & failover router

### 5.1 Rate limiter (`rate_limiter.py`)
- `aiosqlite.connect(path, isolation_level=None)` (manual transactions). Create parent dir. On init: `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;` and verify WAL actually took effect (read back the pragma).
- Schema: `token_usage(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_key TEXT NOT NULL, tokens INTEGER NOT NULL, timestamp REAL NOT NULL, status TEXT NOT NULL DEFAULT 'reserved')` + `CREATE INDEX IF NOT EXISTS idx_tenant_time ON token_usage(tenant_key, timestamp)`.
- Store a **hash** of the tenant key (sha256), never the raw API key.
- `reserve(tenant, tokens) -> Reservation(id, remaining, limit, reset_at)` inside **one** `BEGIN IMMEDIATE ... COMMIT` (ROLLBACK on error):
  1. `DELETE FROM token_usage WHERE tenant_key=? AND timestamp <= ?` (window_start = now − window)
  2. `SELECT COALESCE(SUM(tokens),0) ... WHERE tenant_key=? AND timestamp > ?`
  3. If `tokens > limit` → `RequestTooLargeError` (413; retrying never helps).
  4. If `used + tokens > limit` → compute `retry_after_ms` by walking rows ordered by timestamp until enough expire; raise `RateLimitExceededError(retry_after_ms, remaining)`.
  5. Else `INSERT` and return the new row id.
- `reconcile(reservation_id, actual_tokens)` → `UPDATE ... SET tokens=?, status='settled' WHERE id=?` (keeps original timestamp so the window stays honest).
- `release(reservation_id)` → `DELETE` (both providers failed: tenant isn't charged).
- In-process concurrency: aiosqlite runs one connection on one thread; concurrent coroutines issuing `BEGIN IMMEDIATE` on the same connection collide ("cannot start a transaction within a transaction"). Guard each transaction with an `asyncio.Lock`. Cross-process correctness comes from `BEGIN IMMEDIATE` + `busy_timeout` — prove it with a multi-process test.
- Clock is injected (`clock: Callable[[], float] = time.time`). Wall clock (not monotonic) because multiple processes share the DB; note skew implications in DESIGN_NOTES.

### 5.2 Token accounting (`tokens.py`)
`estimate_prompt_tokens(messages) = ceil(total_chars / 4) + 4 * len(messages)`, counting every message field (tool calls, names, content parts). Reserve `prompt_estimate + max_tokens` (default `max_tokens` 1024 if absent). After completion, reconcile with provider `usage.total_tokens` (or estimate for streams lacking usage).

### 5.3 Providers (`providers.py`)
`class Provider(Protocol): name: str; async def complete(req) -> CompletionResult; async def stream(req) -> AsyncIterator[bytes]`
- `HttpProvider` (OpenAI-compatible base URL). Raises typed errors: `ProviderRateLimited(retry_after)`, `ProviderServerError(status)`, `ProviderClientError(status)`, `ProviderConnectionError`.
- `MockProvider(behavior=...)`: `ok`, `http_429`, `http_500`, `sleep(seconds)`, `raise(exc)`, `leaky_exception` (message containing a fake path `/srv/app/secrets.py`, SQL `SELECT * FROM users`, URL `http://10.0.0.7:8080/v1`, key `sk-live-abc123`). Tracks `calls` and `cancelled` (set in `finally` when cancelled).

### 5.4 Router (`router.py`) — `POST /v1/chat/completions` (non-stream and stream)
Flow:
1. Tenant from `X-Tenant-Key` (401 envelope if missing). Validate body (Pydantic).
2. `reserve()`; on `RateLimitExceededError` → 429 envelope, `Retry-After` (seconds, ceil), `X-RateLimit-*`.
3. Primary: `await asyncio.wait_for(primary.complete(req), timeout=primary_timeout_seconds)`. `wait_for` cancels the inner task on timeout — verify the mock observes cancellation (no zombie upstream call).
4. Failover triggers: `TimeoutError` → `timeout_3000ms`; `ProviderRateLimited` → `http_429`; `ProviderServerError` → `http_5xx`; `ProviderConnectionError` → `connect_error`. **Not** on `ProviderClientError` (4xx other than 429): return a sanitized 4xx — the backup would reject the same bad request.
5. Backup gets the remaining request deadline. If backup also fails → `release()` reservation → 502 `GATEWAY_UPSTREAM_FAILURE` envelope.
6. Success → `reconcile()`; response headers: `X-Routed-Provider: primary|backup`, `X-Failover-Reason: none|http_429|timeout_3000ms|http_5xx|connect_error`, `X-RateLimit-Limit: 50000`, `X-RateLimit-Remaining`, `X-RateLimit-Window-Seconds: 60`, `X-Correlation-ID`. Also put `routed_provider` in a `gateway` metadata field in the JSON body.
7. Streaming: the 3000 ms timeout applies to **time-to-first-byte** (headers + first chunk). Failover is only possible before the first byte reaches the client; after that, errors become an SSE `event: error` frame. Stream output is piped through the T3 redactor in the integration app.
8. Circuit breaker: after 5 consecutive primary failures, skip primary for 30s (half-open probe after). Header `X-Failover-Reason: circuit_open`.

---

## 6. Integration (`integration/app.py`, `e2e_demo.py`)

Unified FastAPI app mounting:
- `POST /v1/chat/completions` → T4 router (limiter + failover) → provider stream → T3 redactor → client.
- `POST /mcp` → T2 gateway → `StdioMcpDownstream` running T1 as a real subprocess.

`mock_agent_llm.py`: deterministic provider. Turn 1 (no tool result in messages): returns `tool_calls=[get_customer_record(CUST-10042)]`. Turn 2 (tool result present): streams a summary that includes the record's email and SSN split across chunks.

`e2e_demo.py` (rich output, one panel per hop showing headers and decisions):
- **Scenario A — Confused deputy blocked:** viewer token → `tools/call admin_reset_key` → `-32001`; prints downstream call count unchanged.
- **Scenario B — Full pipeline:** request passes limiter (shows remaining) → primary sleeps 3.2s → failover to backup (`X-Failover-Reason: timeout_3000ms`) → model asks for `get_customer_record` → T2 (viewer allowed) → T1 validates and returns record with raw PII → second model turn streams summary → T3 redacts split SSN/email → client sees `[REDACTED]`; prints redaction count from the trailer frame.
- **Scenario C — Validation:** `customer_id="CUST-12"` through the gateway → `-32602` from T1, passed through untouched.
- **Scenario D — Runaway agent:** burst of requests for one tenant → 429 with `Retry-After`; other tenant unaffected.
- **Scenario E — Total upstream failure:** both providers fail with leaky exceptions → sanitized envelope; demo asserts no secret substrings.
- One correlation ID per scenario, printed at the end with a `grep` hint showing it in T1 stderr, gateway logs, and response headers.
- Exit code non-zero if any scenario's assertion fails (so CI can run it).

---

## 7. Non-functional targets (measure, don't claim)
`scripts/bench.py` measures: T2 policy+parse overhead per request, T3 per-chunk redaction cost and TTFT delta vs. direct mock, T4 `reserve()` latency p50/p99 on disk. The README quotes only numbers produced by this script, with the hardware noted.
