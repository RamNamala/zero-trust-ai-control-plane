# Troubleshooting runbook

How to diagnose this control plane, or any similar MCP and LLM gateway, in a customer's
zero-trust environment. Each entry follows the same shape:

- **Symptom**: how a customer describes it.
- **Confirm**: commands to run, and which header or log line to look at.
- **Root cause.**
- **Fix.**
- **What this repo does about it.**

All logs are JSON lines on **stderr**, one object per line. The fields are `ts`, `level`,
`logger`, `event` and `correlation_id`, plus event fields. When uvicorn's plain-text lines are
mixed in, filter with `jq -R 'fromjson? | ...'`, as in the examples below. Every command shown
was run against this repo (bash; on Windows, Git Bash).

## First five minutes

1. **Get the correlation ID.** Every response carries `X-Correlation-ID`, including 202s,
   401s and 5xx. It is also in every error envelope (`error.correlation_id`) and in the SSE
   trailer (`event: guardrail`). If the customer can't find it, have them resend with their
   own: `-H 'X-Correlation-ID: case-1234-repro'`. Allowed characters: `[A-Za-z0-9._-]`,
   8–128 chars. Anything else is replaced, not echoed.
2. **Pull every hop's lines for that ID:**
   ```bash
   jq -R -c --arg id "$CID" 'fromjson? | select(.correlation_id==$id) | {logger, event}' gateway.log
   ```
   A healthy agent turn shows, in order:
   - `route_decision` (T4)
   - `mcp_policy_decision` and `mcp_request` (T2)
   - `t1_log` with `child.event = tool_call` (T1, relayed from its stderr)
   - `guardrail_stream` (T3)

   **A hop that is missing is the hop that failed.**
3. **Read the diagnostic headers** without the body: `curl -s -D - -o /dev/null ...`. Check:
   - `X-Routed-Provider` / `X-Failover-Reason`: did the router fail over, and why?
   - `X-RateLimit-Remaining` / `Retry-After`: is the tenant out of budget?
   - `X-MCP-Caller-Role` / `X-MCP-Policy-Decision`: who did the gateway think you were, and
     what did it decide?
   - `X-Guardrail`: is the redactor actually in the path?
4. **Check the startup warnings:**
   - `insecure_default_jwt_secret`
   - `insecure_dev_tokens_enabled`
   - a startup failure `SQLite WAL mode could not be enabled`

   They explain a surprising number of "works on my laptop" cases.
5. **Prove the stack works on that host**, independent of their network:
   `uv run python -m control_plane.e2e_demo --fast` (exit 0 = every hop OK locally). If it
   passes there but not through their proxies, the problem is in the path: see §3, §4 and §6.

---

## 1. STDIO pipe corruption: "MCP server throws EOF" / "Unexpected token in JSON"

**Symptom.** The MCP Inspector, a desktop MCP host, or the customer's agent says the server
disconnected, or shows `Unexpected token 'S', "Server sta"... is not valid JSON`. It often
only happens on a code path that logs, or after someone adds a `print()` for debugging.

**Confirm.** Drive the server by hand and make every stdout line go through `jq`:
```bash
(cat scripts/handshake.jsonl; sleep 1) | uv run python -m control_plane.task1_mcp_server 2>/dev/null | jq -c .
```
- Every line must parse. A single non-JSON line fails like this:
  `jq: parse error: Invalid numeric literal at line 1, column 7` (that's what
  `Server starting...` on stdout produces).
- On Windows also check line endings, because strict clients reject `\r\n` framing:
  `... | tr -cd '\r' | wc -c` must print `0`.
- Keep stdin open (`; sleep 1`). With `< file`, stdin hits EOF straight away and the MCP SDK
  shuts the session down, dropping requests that are still in flight (PITFALLS #47). That
  looks like a missing response but isn't corruption.

**Root cause.** In MCP over stdio, stdout *is* the protocol. Any byte that isn't a JSON-RPC
frame breaks framing, from:
- a `print()`
- a logger configured with `StreamHandler(sys.stdout)`
- a library banner
- a C extension or subprocess writing to fd 1

Rebinding `sys.stdout` only catches the first one.

**Fix.** Isolate at the file-descriptor level before anything else is imported:
`os.dup(1)` keeps a private handle for the transport, `os.dup2(2, 1)` points fd 1 at
stderr, and all logging goes to stderr.

**This repo.**
- `task1_mcp_server/__main__.py` does exactly this as its first statements.
- `CP_T1_CHAOS_STDOUT=1` makes the server `print()`, log, and `os.write(1, …)` on purpose:
  ```bash
  (cat scripts/handshake.jsonl; sleep 1) | CP_T1_CHAOS_STDOUT=1 uv run python -m control_plane.task1_mcp_server 2>/dev/null | jq -c .
  ```
  Stdout stays clean, and the `CHAOS-*` markers appear on stderr.
- Tests: `test_stdout_is_pure_jsonrpc_with_chaos_writers`, `test_chaos_output_lands_on_stderr`,
  and the CRLF assertion (PITFALLS #30).

## 2. "The agent hangs on the MCP server" / tool calls return each other's results

**Symptom.** Tool calls work for a while, then every call hangs until the client times out.
Or, under load, one user's agent receives another user's tool result.

**Confirm.**
- Hang: look for the stdio downstream's own events.
  ```bash
  jq -R -c 'fromjson? | select(.event | startswith("stdio_")) | {ts, event, reason, kind}' gateway.log
  ```
  - `stdio_request_failed` with `kind: timeout` means the child accepted the request and
    never answered.
  - `stdio_child_lost` with `reason: eof` means it died.
  - If nothing is logged and the child process is alive, take a Python stack of the child
    (`py-spy dump --pid <child>`, if py-spy is installed). A child blocked in
    `write()` to fd 2 is the full-pipe case.
- Crossed results: compare the `id` the client sent with the result it got. With this gateway
  every caller gets its own id back. If the customer's own gateway shares one stdio child
  between clients without rewriting ids, two clients that both send `"id": 1` race for the
  same reply.

**Root cause.**
- **Full stderr pipe.** The parent spawned the server with `stderr=PIPE` and never reads it.
  Once the OS pipe buffer fills (64 KiB on Linux), the child's next log write blocks forever,
  mid-request.
- **Id collisions.** JSON-RPC ids are only unique per client, but the stdio pipe is shared.

**Fix.** Drain the child's stderr continuously in a background task. Rewrite every forwarded
request's id to a process-wide counter, and map replies back.

**This repo.** `StdioMcpDownstream`:
- has a dedicated stderr drain task, which re-logs each child line as `t1_log` under the
  child's own correlation ID
- uses a monotonic id counter with a `dict[int, Future]`
- has a single reader and a write lock
- fails in-flight calls with `-32603 "Upstream MCP server unavailable"` when the child dies
- respawns the child on the next call

Tests:
- `test_stdio_downstream_id_rewriting_handles_concurrent_same_ids` (20 concurrent calls, all
  `id: 1`)
- `test_stdio_downstream_recovers_after_child_crash`
- `test_single_correlation_id_visible_in_all_hops`

The PITFALLS entries are #13, #14 and #44 (batches are fanned out, because the SDK's stdio
server rejects JSON-RPC arrays).

## 3. Bearer / JWT failures in zero-trust setups

**Symptom.** "Every call is 401 Unauthenticated", "it works from my laptop but not from the
cluster", or "the downstream MCP server says we're not authenticated even though the gateway
accepted us".

**Confirm.** The gateway logs a fixed reason category, never the token:
```bash
jq -R -c 'fromjson? | select(.event=="mcp_auth_failed") | {ts, correlation_id, reason}' gateway.log
```
`reason` is one of:
- `missing`
- `malformed`: not exactly `Bearer <token>`
- `expired`
- `not_yet_valid`
- `invalid`: bad signature, wrong `aud`, wrong algorithm
- `bad_role`
- `dev_tokens_disabled`

Decode the claims locally. The signature isn't checked here, and the token doesn't leave the
machine:
```bash
uv run python -c "import jwt,sys,time; c=jwt.decode(sys.argv[1], options={'verify_signature': False}); print(c, 'exp_in_s=', c['exp']-int(time.time()))" "$TOKEN"
```
Then compare the clocks of the issuer and the gateway host (`date -u` on both).

**Root causes and fixes.**
- **Clock skew vs `exp`/`nbf`.** A token issued "now" by a host running 40 s fast is
  `not_yet_valid` on a host 10 s slow.
  - Fix NTP first.
  - `CP_JWT_LEEWAY_SECONDS` (default 30) absorbs small skew. Don't paper over minutes of
    drift with a large leeway.
- **Wrong audience.**
  - If `CP_JWT_AUDIENCE` is set, a token without that `aud` is `invalid`. Verified: a dev
    token with no `aud` against `CP_JWT_AUDIENCE=control-plane` gives `401`,
    `reason: invalid`.
  - The reverse also fails: a token that *has* an `aud` is rejected when the gateway has no
    audience configured.
  - Fix: align the IdP's audience with the setting.
- **"The downstream doesn't see our token". This is by design.**
  - The gateway never forwards the client's `Authorization` header. Passing tokens through is
    explicitly called out as an anti-pattern in the MCP security guidance: the downstream
    would accept a token that wasn't issued for it.
  - If the downstream needs credentials, give the gateway its own: `CP_T2_DOWNSTREAM_TOKEN`.
  - Confirm with the mock: `curl http://127.0.0.1:8101/__stats` shows `last_headers`
    without `authorization`, and with `x-correlation-id`.
- **mTLS terminates at the sidecar.**
  - In Istio, Linkerd or an Envoy front proxy, the client certificate is verified by the
    sidecar, and the app receives plain HTTP. It never sees the cert, and anything
    cert-based in app code silently does nothing.
  - Fix: either enforce identity at the mesh (e.g. Istio `AuthorizationPolicy` on the SPIFFE
    principal), or have the sidecar pass it in `X-Forwarded-Client-Cert` and make sure the
    sidecar *strips* any client-supplied copy before the app trusts it.
  - This gateway authenticates the bearer token at the application layer, which is
    independent of where TLS terminates.
- **Dev tokens in a real environment.**
  - `admin-secret-token` and unsigned base64 tokens only work with
    `CP_ALLOW_INSECURE_DEV_TOKENS=true`. Otherwise they are rejected with
    `reason: dev_tokens_disabled`. They should be off anywhere real.
  - `insecure_dev_tokens_enabled` at startup means someone turned them on.

**This repo.**
- Auth is tested for every reason category, for leeway on both sides of the boundary, for
  `alg: none` and forged signatures, and for the passthrough ban: see
  `tests/test_task2_mcp_gateway.py`.
- 401 responses carry `WWW-Authenticate: Bearer` and a JSON-RPC `-32002` body.

## 4. SSE "arrives all at once" (TTFT is fine locally, terrible in production)

**Symptom.** The UI shows nothing for seconds, then the whole answer at once. Or streams cut
off after ~15 s or a few minutes.

**Confirm.** Timestamp every line as it arrives, first direct to the service and then through
the customer's proxy chain:
```bash
curl -sN http://127.0.0.1:8200/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"mock-slow_long","messages":[{"role":"user","content":"hi"}],"stream":true}' \
  | while IFS= read -r line; do [ -n "$line" ] && printf '%s %s\n' "$(date +%T.%3N)" "${line:0:60}"; done
```
- Direct to the guardrail you get one frame every ~50 ms (`17:19:23.275`, `.328`, `.381`,
  `.444`, …).
- If the same command through their ingress shows all timestamps within a few milliseconds
  of each other, something in between is buffering.
- Check the response headers through the proxy too (`curl -sN -D - -o /dev/null ...`). A
  `content-encoding: gzip` or a missing `transfer-encoding: chunked` points at the culprit.

**Root cause.** A hop that buffers responses:
- **NGINX**: `proxy_buffering` defaults to on.
- **Compression middleware or filters**: gzip needs a block of data before emitting output.
- **CDNs and WAFs.**
- **Envoy route timeouts**: the default route `timeout` is 15 s for the *whole* response, and
  streams hit `stream_idle_timeout` and `idle_timeout`.

**Fix.**
- NGINX, for this location:
  - `proxy_buffering off;`
  - `proxy_cache off;`
  - `proxy_http_version 1.1;`
  - `gzip off;`
  - Respect `X-Accel-Buffering: no`, which this service sends (NGINX honors it when
    `proxy_ignore_headers` doesn't remove it).
  - Raise `proxy_read_timeout` above the longest gap between tokens.
- Envoy:
  - Route `timeout: 0s` (no whole-response cap) for streaming routes.
  - Set `stream_idle_timeout` and `idle_timeout` above the longest expected pause.
  - Exclude `text/event-stream` from the compressor filter.
- CDN: bypass caching and buffering for the streaming path.
- App-level gzip middleware must skip `text/event-stream`.

**This repo.**
- The guardrail sends `Cache-Control: no-cache` and `X-Accel-Buffering: no`, and emits each
  redacted frame as soon as it's safe. Only the possible-PII tail is held back.
- TTFT is tested under a real uvicorn server (`test_first_safe_chunk_yielded_before_stream_ends`).
  The test can't use ASGITransport, which buffers too (PITFALLS #41).
- Measured TTFT cost of the guardrail hop on loopback: ~3.6 ms p50 (README benchmarks).

## 5. `database is locked` / latency spikes in the rate limiter under load

**Symptom.** Intermittent `500 INTERNAL_ERROR`, or chat latency jumping by seconds under
load, and operator logs mentioning `database is locked`.

**Confirm.**
- Find the failing requests. The client got only the envelope; the operator log has the
  traceback:
  ```bash
  jq -R -r 'fromjson? | select((.traceback // "") | test("database is locked")) | [.ts, .event, .correlation_id] | @tsv' gateway.log
  ```
- Check the journal mode on the **live** database file. Read-only, so it can't create a
  file:
  ```bash
  uv run python -c "import sqlite3, sys; c = sqlite3.connect(f'file:{sys.argv[1]}?mode=ro', uri=True); print(c.execute('PRAGMA journal_mode').fetchone()[0])" data/gateway_ratelimit.db
  ```
  - It must print `wal`, and `-wal` and `-shm` files sit next to the database while it's in
    use.
  - If the gateway refused to start with `SQLite WAL mode could not be enabled`, the file is
    on a filesystem that can't do WAL.
- Compare `reserve()` latency with the baseline: p50 0.43 ms / p99 0.97 ms on the reference
  machine (`uv run python scripts/bench.py`).

**Root cause.**
- **WAL unavailable.** NFS, SMB and some container overlay or network volumes don't support
  the shared-memory index WAL needs. In rollback-journal mode, readers and writers block each
  other.
- **A long-held write transaction.** For example, someone ran `sqlite3` against the live
  file and left a `BEGIN` open, or a backup job locked it. Writers then wait out
  `busy_timeout` (5 s here) and fail.
- **Several hosts writing one file over a network share.** SQLite locking isn't reliable
  across machines.

**Fix.**
- Put the database on local disk (`CP_RATE_LIMIT_DB_PATH`).
- Never open the live file in read-write tools.
- Keep transactions short. This limiter's longest is one `DELETE`/`SUM`/`INSERT`.
- For **more than one node**, move the budget to a shared store (Redis or Postgres; see the
  README's production table). The same `reserve`/`reconcile`/`release` interface applies.

**This repo.**
- `PRAGMA journal_mode=WAL`, `synchronous=NORMAL` and `busy_timeout=5000` are set, and WAL is
  **read back and verified at startup** (fail loudly rather than run slowly).
- One `BEGIN IMMEDIATE` per reservation, plus an `asyncio.Lock` for coroutines sharing the
  connection (PITFALLS #21).
- Tests: `test_concurrent_gather_cannot_overdraft` (exactly 50 of 100 succeed) and
  `test_multiprocess_cannot_overdraft` (separate processes, one file).

## 6. Zombie upstream streams: tokens keep burning after users close the tab

**Symptom.** The provider bill or token usage is far above what users saw, especially for
long answers that users abandon. Provider dashboards show streams running to completion that
nobody read.

**Confirm.** Disconnect on purpose, then check that the gateway noticed and closed the
upstream:
```bash
curl -sN --max-time 0.5 http://127.0.0.1:8200/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"mock-slow_long","messages":[{"role":"user","content":"hi"}],"stream":true}' > /dev/null
jq -R -c 'fromjson? | select(.event=="client_disconnected" or (.event=="guardrail_stream" and .outcome=="client_disconnected"))' gateway.log
```
- Expected: `client_disconnected` with `frames_out`, and `guardrail_stream` with
  `outcome: client_disconnected`, under the same correlation ID.
- On the router path, the `route_decision` audit has `outcome: client_disconnected` and
  charges the tenant for what was actually generated.
- If the gateway shows the disconnect but the provider (or its access log) shows the request
  running to the end, the upstream connection wasn't closed.

**Root cause.**
- The proxy keeps reading upstream after the client is gone. Often a broad
  `except Exception:` swallows `CancelledError`, or the upstream response is opened outside
  any context manager.
- Or an intermediate proxy ignores client aborts: NGINX `proxy_ignore_client_abort on`.

**Fix.**
- Hold the upstream response in `async with` for the whole stream.
- Let `CancelledError` / `GeneratorExit` propagate after logging.
- Don't configure proxies to ignore client aborts on streaming routes.

**This repo.**
- `_guarded_stream` and `RedactingProvider.stream` close the upstream on cancel.
- The router closes the provider's stream in `finally`.
- `wait_for` cancels a timed-out primary for real.
- Tests:
  - `test_client_disconnect_closes_upstream`: the mock's `upstream_closed` fires within 1 s
    under real uvicorn.
  - the T4 cancellation tests: `MockProvider.cancelled`.
  - Scenario B asserts that the slow primary was cancelled.
- PITFALLS #20, #25 and #42.

## 7. Unexpected failover storms

**Symptom.** "Everything is going to the backup", "costs doubled", or "latency is 3 s worse
than the provider's own dashboard says".

**Confirm.** Get the distribution of failover reasons from the audit log:
```bash
jq -R -r 'fromjson? | select(.event=="route_decision") | .failover_reason' gateway.log | sort | uniq -c
```
Each reason means something different:
- **`timeout_3000ms` dominating.** The primary is slow, not necessarily down. Compare with
  the provider's p99 latency, and for streams with its time-to-first-token, because the
  timeout applies to the *first byte* of a stream.
- **`http_429`.** The *provider's* rate limit (shared org quota), not ours.
- **`http_5xx` / `connect_error`.** The provider or network really is failing.
  `connect_error` takes ~2 s to appear on Windows hosts, because refused localhost
  connections retry before failing.
- **`circuit_open`.** The breaker is skipping the primary on purpose.

`provider_failed` lines carry the full exception for each failed attempt (stderr only), under
the request's correlation ID.

**Root cause.** A fixed 3 s timeout is tighter than the primary's tail latency. Long prompts
or large `max_tokens` legitimately take longer to the first token. The result: healthy-but-slow
calls are abandoned and paid for twice (the cancelled primary may still bill for prompt
processing).

**Fix.**
- Tune `CP_PRIMARY_TIMEOUT_SECONDS` to the primary's measured p99 TTFT, not its median.
  `CP_REQUEST_DEADLINE_SECONDS` bounds the total.
- Enable the circuit breaker (`CP_CIRCUIT_BREAKER_ENABLED=true`,
  `CP_CIRCUIT_BREAKER_THRESHOLD`, `CP_CIRCUIT_BREAKER_COOLDOWN_SECONDS`). After N
  consecutive primary failures it skips the primary for the cooldown period and then probes
  it. This turns a storm of 3 s waits into immediate backup routing,
  `X-Failover-Reason: circuit_open`.
- Don't fail over on errors the backup would repeat. This router already returns a sanitized
  4xx for client errors instead of retrying them.

**This repo.**
- Failover classification is tested per reason, and `ProviderClientError` deliberately does
  not fail over.
- Failover is reflected in both `X-Routed-Provider` / `X-Failover-Reason` and the body's
  `gateway` field, so it's visible from the client side as well as in logs.
- The token reservation is shared by both attempts: one request, one charge.

---

## Reference: headers

| Header | Set by | Meaning |
|---|---|---|
| `X-Correlation-ID` | all routes | request ID; client-supplied if it matches `[A-Za-z0-9._-]{8,128}`, else a new uuid4. Echoed on every response, forwarded to every hop. |
| `X-Routed-Provider` | T4 | `primary` or `backup`: who answered |
| `X-Failover-Reason` | T4 | `none`, `timeout_<ms>ms`, `http_429`, `http_5xx`, `connect_error`, `provider_error`, `circuit_open` |
| `X-RateLimit-Limit` / `-Remaining` / `-Window-Seconds` | T4 | tenant budget (remaining reflects the real cost after reconcile; during a stream, the full hold) |
| `Retry-After`, `X-RateLimit-Retry-After-Ms` | T4 (429) | when enough budget frees up |
| `X-MCP-Caller-Role` | T2 | role the gateway resolved from the token |
| `X-MCP-Policy-Decision` | T2 | `allow`, `deny`, or `mixed` (batch with both) |
| `WWW-Authenticate: Bearer` | T2 (401) | authentication required |
| `X-Guardrail` | T3 | `pii-redaction/v1`: the redactor is in the path |
| `X-Guardrail-Redactions` | T3 (non-stream only) | redaction count; streams use the trailer frame instead |
| `X-Accel-Buffering: no`, `Cache-Control: no-cache` | T3/T4 streams | ask proxies not to buffer |

## Reference: log events

| Event | Logger | Key fields | Look here when |
|---|---|---|---|
| `route_decision` | audit | `tenant` (sha256 prefix), `outcome`, `routed_provider`, `failover_reason`, `tokens`, `latency_ms` | any chat request; failover analysis (§7) |
| `rate_limited` | audit | `tenant`, `requested`, `retry_after_ms` | 429s |
| `provider_failed` | task4.router | `provider`, `failover_reason`, `traceback` | why a provider attempt failed (§7) |
| `mcp_auth_failed` | audit | `reason` | 401s (§3) |
| `mcp_policy_decision` | audit | `role`, `token_kind`, `method`, `tool`, `decision`, `reason`, `latency_ms` | per tool call RBAC result |
| `mcp_request` | audit | `messages`, `forwarded`, `rejected`, `decision` | per HTTP request to `/mcp` |
| `downstream_unavailable` | task2.proxy | `kind` | HTTP downstream unreachable |
| `stdio_child_spawned` / `_lost` / `_stopped` | task2.stdio | `pid`, `reason`, `pending`, `restarts` | T1 lifecycle, crashes (§2) |
| `stdio_request_failed` | task2.stdio | `kind`: `timeout` or `child_gone` | hung or crashed T1 (§2) |
| `t1_log` | task2.stdio.child | `child` (T1's own JSON line) | what T1 did, under the same correlation ID |
| `tool_call` (inside `t1_log.child`) | task1.server | `tool`, `outcome`, `latency_ms` | T1 per-call result |
| `guardrail_stream` | audit | `outcome`, `pii_redactions`, `forced_flushes`, `peak_buffer_chars`, `frames_out` | redaction results, disconnects (§6) |
| `guardrail_completion` | audit | `pii_redactions` | non-stream redaction |
| `client_disconnected` | task3.gateway | `frames_out` | client went away mid-stream (§6) |
| `upstream_stream_failed` | task3.gateway | `kind`, `traceback` | upstream died mid-stream |
| `insecure_default_jwt_secret`, `insecure_dev_tokens_enabled` | settings | `hint` | startup misconfiguration |

No log line contains raw tool arguments, tool results, prompts, completions or tokens. Audit
calls carry names, roles, decisions and counts only, and tests check the log stream for PII.
