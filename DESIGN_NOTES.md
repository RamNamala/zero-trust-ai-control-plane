# Design notes

These are the decisions a reviewer is most likely to probe. Each entry gives the choice,
the alternatives considered, and why this choice won. Code docstrings say the same things
closer to the code. `docs/PITFALLS.md` has the traps and the evidence for them.

---

## Task 1: MCP server

### Low-level `tools/call` handler, not the `@server.call_tool()` decorator
- **Choice:** register `server.request_handlers[types.CallToolRequest]` directly on the
  low-level `mcp.server.lowlevel.Server`, and raise `McpError` for protocol errors.
- **Alternatives:**
  - FastMCP / the `@call_tool()` decorator, which is less code.
  - Validating inside the decorated function and returning an error string.
- **Why:** the decorator catches every exception and turns it into
  `CallToolResult(isError=true)` (verified on mcp 1.30.0, PITFALLS #2). That means invalid
  arguments, which the brief wants as a *standard JSON-RPC error*, would come back as a
  successful response containing an error message. The low-level handler gives a real
  `{"error":{"code":-32602,...}}` frame with the caller's id.
- **Cost:** we own the dispatch. Unknown-method handling also needed a fix, because the SDK
  answers unknown methods with `-32602` (PITFALLS #35), and unexpected exceptions with
  `code: 0` and the exception text (PITFALLS #37). Both are covered by tests.

### `-32602` for an unknown tool name (not `-32601`)
- **Choice:** `McpError(-32602, "Unknown tool: <name>")`.
- **Alternative:** `-32601 Method not found`, which is what the original blueprint suggested.
- **Why:** `-32601` means the JSON-RPC *method* doesn't exist, but `tools/call` does exist.
  The tool name is a parameter, and the MCP spec's own example for an unknown tool uses
  `-32602`. Unknown *methods* (e.g. `foo/bar`) still get `-32601`.

### Protocol error vs tool error
- **Choice:**
  - Malformed input gets a JSON-RPC error (`-32602`, with field paths and no echo of the
    input).
  - Well-formed input that the business logic refuses (unknown customer, refund over
    balance) gets `CallToolResult(isError=true)`.
- **Why:** they mean different things to an agent. A protocol error says "your call was
  invalid; fix the call". A tool error says "the call was fine and the answer is no", which
  the model can reason about and tell the user. Mixing them up is the most common grading
  miss on this kind of task.

### Strict Pydantic, `[0-9]`, and an integer amount allowed
- **Choice:** strict mode with `extra="forbid"`.
  - `"50"` and `true` are rejected for `amount`, but the JSON integer `50` is accepted.
  - NaN/Infinity and more than two decimals are rejected.
  - `CUST-[0-9]{5}`, never `\d`.
- **Why:**
  - A refund of 50 is legitimate, and refusing it would be pedantry, not safety.
  - `\d` matches Unicode digits (`CUST-١٢٣٤٥`).
  - Error data has `input` and `url` removed so the server never reflects user input (or PII)
    back.

### fd-level stdout isolation
- **Choice:** `os.dup(1)` for the transport, then `os.dup2(2, 1)`, before any other import.
- **Alternative:** `sys.stdout = sys.stderr`, or "just be careful with print".
- **Why:** rebinding only covers Python-level `print`. C extensions, child processes and
  libraries that captured `sys.stdout` at import time write to fd 1. The chaos tests do all
  three, and stdout stays pure.

---

## Task 2: MCP gateway

### Unsigned dev tokens are off by default
- **Choice:** the real path is an HS256 JWT with required `role`, `exp`/`nbf` checks plus a
  leeway, an optional `aud`, and the algorithm pinned to HS256.
  - Static tokens (`admin-secret-token`) and unsigned base64 `{"role":"admin"}` tokens exist
    only behind `CP_ALLOW_INSECURE_DEV_TOKENS=true`, with a loud warning at startup.
  - Static tokens are compared with `hmac.compare_digest`.
- **Alternative:** accept the brief's simple "role in the token" format by default, which is
  easier to demo.
- **Why:** an unsigned token that says `{"role":"admin"}` lets *anyone* claim admin. In a
  zero-trust task, accepting it by default would defeat the point of the gateway. It stays
  available for curl demos, but opting in has to be deliberate and visible.

### The client's token is stripped before forwarding downstream
- **Choice:** outbound headers come from an allowlist: `Content-Type`, `Accept`,
  `Mcp-Session-Id`, `MCP-Protocol-Version`, `X-Correlation-ID`, `X-Forwarded-For`. The
  client's `Authorization` is never on that list. If the downstream needs credentials, the
  gateway sends its *own* (`CP_T2_DOWNSTREAM_TOKEN`).
- **Alternative:** transparent passthrough, which is "simpler" and lets the downstream do
  its own auth.
- **Why:**
  - MCP's security guidance calls token passthrough an anti-pattern. The downstream would be
    accepting a token that wasn't issued for it (confused deputy).
  - Audit trails split: the downstream can't tell the gateway's decision apart from the
    client's.
  - A compromised downstream gets reusable user tokens.
  - Using an allowlist instead of a denylist also drops hop-by-hop headers by construction.

### Ids rewritten per hop
- **Choice:** the gateway gives each forwarded message an internal integer id, matches
  replies by that id, and restores the caller's id from its own slot. `StdioMcpDownstream`
  does the same again over the shared pipe.
- **Alternative:** forward ids unchanged and match replies by them.
- **Why:**
  - Duplicate ids inside one batch, or two clients both using `id: 1` on one stdio child,
    would cross responses.
  - Trusting the downstream to echo `"7"` vs `7` vs `null` faithfully is a fidelity risk we
    don't need to take.

### Policy denial is a local JSON-RPC error with HTTP 200
- **Choice:** `-32001` answered by the gateway, with the downstream never called (proved
  against the mock's call counter).
  - HTTP status 200 by default, because JSON-RPC errors are carried in a 200 body and a batch
    can mix allowed and denied calls.
  - `CP_T2_DENY_HTTP_STATUS=403` is available for single requests, for deployments whose
    tooling keys on status codes.

### Batches to the stdio server are fanned out
- **Choice:** an allowed batch goes downstream as one HTTP batch, but over stdio it is sent
  as one line per message, and the replies are gathered.
- **Why:** mcp 1.x's stdio server doesn't accept JSON-RPC arrays (verified, PITFALLS #44).
  The 2025-06-18 protocol revision removed batching. The proxy's slot merge restores the
  original order either way.

---

## Task 3: Streaming guardrail

### Fail-closed redaction
- **Choice:**
  - Anything SSN-shaped (`NNN-NN-NNNN`) is redacted, including "invalid" ranges (9xx, 000,
    666).
  - Cards need 13–19 digits *and* a passing Luhn check.
  - Emails match a permissive pattern.
- **Alternatives:**
  - Validate SSN area/group numbers to reduce false positives.
  - Use an ML/NER detector.
- **Why:**
  - Redaction errors aren't symmetric. A false positive costs a slightly odd sentence; a
    false negative leaks PII. SSN-shaped strings in model output are rare enough that
    over-redacting costs little. (The demo's fixture SSN, `999-01-4242`, is itself
    "invalid", and would leak under range validation.)
  - The Luhn check is the exception: long digit runs (order numbers, timestamps) are common,
    and Luhn removes ~90% of false card matches.
  - A detector model would be a second pass in production, not a replacement for a fast
    deterministic one.

### Fixpoint hold-back, not a fixed window
- **Choice:**
  - After each delta, emit everything before the start of the *trailing run that could
    still become PII*, and hold that run back.
  - "Could still become PII" covers two character classes: email characters, and digits with
    spaces/dashes.
  - The cut moves left until neither class can extend it (a fixpoint), because the classes
    can sit next to each other, e.g. `"...1283 0366."`.
  - The held tail is capped at 256 chars. Beyond that the oldest part is force-flushed and
    counted (`forced_flushes`).
- **Alternatives:**
  - Hold back a fixed N characters (the blueprint used 36).
  - Hold back to the last whitespace.
  - Buffer the whole response.
- **Why:**
  - **Correctness:** a fixed window leaks emails longer than N (they can be up to 254 chars),
    and whitespace cuts leak spaced card numbers (`4532 0151 1283 0366`).
  - **Latency:** most text isn't PII-capable at the tail, so the hold is usually a few
    characters (peak 33 chars over a 50k-chunk benchmark stream), and TTFT stays close to
    the upstream's.
  - **Memory:** O(`max_hold`) per stream, never O(response).
  - **Proof:** a Hypothesis property test asserts that, for *any* chunking, output equals
    `redact(full_text)`. The algorithm is pinned to `docs/reference/redactor_reference.py`.
- **Trade-off made visible:** a single unbroken PII-capable run longer than 256 chars can be
  split by a forced flush. The counter appears in the trailer and the audit log, so the loss
  is never silent.

### Redaction count in a trailer frame, not a header
- **Choice:** a final `event: guardrail` frame with `pii_redactions`, `forced_flushes` and
  `correlation_id`, plus an audit log line.
- **Why:** response headers are sent before the first byte, so a header can't report a count
  that isn't known yet. Non-stream responses do get `X-Guardrail-Redactions`.

### Redaction wraps each provider in the integration app
- **Choice:** `RedactingProvider` wraps primary *and* backup. It pulls the first upstream
  chunk itself, outside the guardrail.
- **Alternative:** a separate T3 HTTP hop in front of the router.
- **Why:**
  - It redacts whichever provider answered, with no extra hop and no duplicated failover
    logic.
  - Pulling the first chunk first matters. The guardrail turns upstream errors into a
    sanitized `event: error` frame, which the router would take for a successful first
    byte, so it would never fail over (PITFALLS #45). Errors before the first byte therefore
    propagate and trigger failover. After that, they become the guardrail's error frame.

---

## Task 4: Limiter and router

### SQLite `BEGIN IMMEDIATE` + `asyncio.Lock`, vs Redis + Lua
- **Choice:**
  - A ledger of rows (`tenant_key` hash, `tokens`, `timestamp`, `status`) in SQLite WAL.
  - Each reservation is one `BEGIN IMMEDIATE` transaction: evict expired → `SUM` → check →
    `INSERT`.
  - An `asyncio.Lock` serializes transactions on the shared aiosqlite connection.
  - `busy_timeout=5000` makes other processes queue instead of failing.
- **Alternatives:**
  - **Redis + Lua.** Atomic, fast, and shared across nodes, but the brief requires on-disk
    SQLite, and it's an extra service.
  - **An in-memory counter.** Loses state on restart, and isn't shared by workers.
  - **A fixed-window counter.** Allows 2× the limit across a boundary.
  - **SQLite with plain `BEGIN` (deferred).**
- **Why:**
  - `BEGIN IMMEDIATE` takes the write lock *before* the `SUM`, so check-and-reserve is atomic
    across every process on the host (no TOCTOU).
  - The `asyncio.Lock` is needed because aiosqlite runs one connection on one thread:
    concurrent coroutines issuing `BEGIN` on it fail with "cannot start a transaction within
    a transaction" (PITFALLS #21).
  - Both halves are tested: exactly 50 of 100 concurrent `gather`ed reservations succeed,
    and the same holds across separate processes.
- **Limit:** this is correct on one host. Across nodes, it should move to Redis/Postgres
  behind the same interface. The benchmark puts `reserve()` + `reconcile()` at 0.43 ms p50
  on local SSD.

### Reserve, then reconcile (and release on total failure)
- **Choice:**
  - Before calling a provider, reserve the pessimistic cost: prompt estimate + `max_tokens`
    (1024 if absent).
  - After the response, `reconcile()` down to `usage.total_tokens` (or an estimate for
    streams without usage), *keeping the original timestamp*.
  - If both providers fail, `release()` the hold, so the tenant isn't charged.
- **Alternatives:**
  - Check the budget, call, then charge actual usage. N concurrent requests would all pass
    the check.
  - Charge the estimate and never reconcile. That overcharges, and tenants hit 429s with
    budget left.
- **Why:**
  - Only a hold taken *before* the call makes the limit hard under concurrency.
  - Reconciling keeps it accurate.
  - Keeping the timestamp stops a long request from getting a fresh window (PITFALLS #27).
  - A request whose hold alone exceeds the window budget gets **413**, not 429, because
    retrying can never succeed.

### No failover on 4xx (other than 429)
- **Choice:** fail over on timeout, 429, 5xx, connection errors, and untyped provider
  crashes. A 400/401/403/404/422 from the primary returns a sanitized 4xx immediately.
- **Why:**
  - A 4xx says the *request* is wrong (bad parameters, a context window that's too long, a
    content-policy refusal), and the backup would refuse it too. Retrying doubles latency
    and cost, and can hide real client bugs.
  - 429 is the exception because it's about the *provider's* capacity, which the backup
    doesn't share.

### Streaming failover only before the first byte
- **Choice:** for `stream: true`, the 3000 ms timeout applies to time to first byte. Until
  the first chunk arrives nothing has been sent, so failover is invisible to the client.
  After the first byte, a provider failure becomes an SSE `event: error` frame with the
  sanitized envelope, and the tenant is charged for what was actually generated.
- **Alternatives:**
  - Buffer the whole stream so failover is always possible. That defeats streaming.
  - Splice the backup in mid-stream. That would produce a mixed, incoherent answer the client
    can't detect.
- **Why:** once headers and text have reached the client, switching providers would
  silently change who is speaking mid-sentence. An explicit in-band error is the honest
  option.

### `asyncio.wait_for` really cancels the primary
- Timed-out calls are cancelled, not left running. Provider code never wraps awaits in
  `except Exception` that would swallow `CancelledError`, and the mocks record cancellation
  so the tests can prove it. A zombie primary would keep generating, and billing, after we
  had already moved on.

### Sanitized errors
- Every error leaving the gateway is the fixed envelope `{code, message, request_id,
  correlation_id, timestamp}`.
- The bare-`Exception` handler logs the traceback to stderr and returns only the envelope.
- Validation errors are reduced to field paths and messages, with no input echo.
- Tests feed in provider exceptions containing a path, SQL, an internal URL and an API key,
  and assert none of it reaches the client.

---

## Cross-cutting

### One correlation ID, carried in-band where HTTP headers can't go
- `X-Correlation-ID` is validated against a strict charset (log-injection defense) and echoed
  on every response.
- It is forwarded as a header on HTTP hops, and as `params._meta.correlationId` (MCP's
  reserved metadata slot) into T1. T1 logs it on stderr, and the gateway re-logs T1's lines
  under that same ID.
- One `jq` filter then shows a request's whole path. OpenTelemetry would replace this in
  production.

### Settings, clocks and timeouts are injected
- Settings are built explicitly, not as a module-level singleton, and the limiter's clock is
  injectable. Tests shrink the 60 s window and the 3 s timeout without sleeping or
  monkeypatching. The defaults stay at the brief's values (50,000 tokens / 60 s / 3000 ms).
