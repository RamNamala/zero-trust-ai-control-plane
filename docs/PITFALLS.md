# Pitfalls — where the original blueprint is wrong or incomplete

Each item: the trap, the fix, and the test that proves it. Several of these were confirmed by
spikes before writing this kit (marked **verified**).

## Task 1
1. **MCP SDK major version (verified).** `mcp` 2.x (current latest 2.3.0) replaced the low-level API (`on_call_tool=` constructor callbacks, `add_request_handler(method, params_type, handler)`, new runner). The 1.x pattern in the blueprint doesn't run on 2.x. → Pin `mcp>=1.27,<2`; verified on 1.30.0 in `docs/reference/mcp_stdio_spike.py`.
2. **The `@server.call_tool()` decorator swallows errors (verified).** It turns exceptions into `CallToolResult(isError=True)`. → Assign `server.request_handlers[types.CallToolRequest]` directly and raise `McpError`; this yields a real `{"error":{"code":-32602,...}}` frame.
3. **Rebinding `sys.stdout` isn't enough (verified).** C extensions, child processes, and code holding an early reference to the old stdout write to fd 1 directly. → `os.dup(1)` for the transport, `os.dup2(2, 1)` for everyone else, before other imports.
4. **Unknown tool code.** The blueprint says `-32601`. The MCP spec's own example for an unknown tool is `-32602` ("Unknown tool: …"); `-32601` is for unknown JSON-RPC *methods*. → `-32602` for unknown tools, let the SDK return `-32601` for unknown methods.
5. **Protocol error vs. tool error.** Malformed input → protocol error. Well-formed input that fails business logic (customer not found) → `isError: true`. Mixing these up is a common grading miss.
6. **`\d` matches Unicode digits in Python.** `CUST-١٢٣٤٥` passes `^CUST-\d{5}$` under Python `re`. → Use `[0-9]`. Also test a trailing `\n` (Python `$` matches before a final newline; Pydantic's Rust regex engine doesn't, but test it rather than rely on it).
7. **Strict float.** Pydantic strict mode accepts a JSON integer for a `float` field and rejects `"50"` and `true`. That is the right behavior for money; document it and test both ways. Add `allow_inf_nan=False` and a 2-decimal check.
8. **Echoing input in errors.** `ValidationError.errors()` includes `input` and `url`. Returning that in `data` reflects user input (and potentially PII) back. → Strip them.

## Task 2
9. **Notifications.** Requests without `id` get no response. A batch of only notifications → HTTP 202, empty body. `"id": null` is *not* a notification. Empty batch `[]` → one `-32600` error object.
10. **Unsigned base64 JSON "tokens" = anyone can be admin.** The blueprint accepts `{"role":"admin"}` base64. → Real path is HS256 JWT with `exp` + leeway; static and unsigned tokens only behind `CP_ALLOW_INSECURE_DEV_TOKENS=true` (off by default, warned at startup). This is literally the zero-trust point of the task.
11. **Token passthrough.** Forwarding the agent's `Authorization` header to the downstream MCP server is explicitly called out as an anti-pattern in the MCP security guidance. → Strip it; use a gateway-owned credential.
12. **Tool-name smuggling.** `" admin_reset_key"`, `"Admin_reset_key"`, zero-width characters. → Strict name regex + case-insensitive prefix check.
13. **Id collisions on a shared stdio downstream.** Two clients both send `id: 1` → responses get crossed. → Rewrite ids per hop and map back.
14. **Child stderr pipe filling up.** If the gateway spawns T1 with `stderr=PIPE` and never reads it, T1 blocks once the pipe buffer is full → "my agent hangs". → Drain stderr in a background task.

## Task 3
15. **A fixed 36-char holdback leaks (verified).** Emails can be up to 254 chars; spaced card numbers break the "hold to last whitespace" rule; `"...1283 0366."` mixes numeric and email-char classes. → Fixpoint tail hold-back, bounded by `max_hold`; property-tested in `docs/reference/redactor_reference.py`.
16. **Blueprint card regex** `\b(?:\d[ -]*?){13,16}\b` over-matches any long digit run and misses 17–19 digit PANs. → Candidate regex + Luhn + 13–19 digits.
17. **`X-PII-Redactions-Count` as a response header is impossible for a stream** — headers are flushed before the first byte. → Final `event: guardrail` SSE frame + audit log.
18. **Filtering "invalid" SSN ranges** (9xx area) would miss `999-01-4242` from the demo. → Fail closed; redact anything SSN-shaped.
19. **Proxy buffering.** NGINX/Envoy buffer SSE by default, killing TTFT even if your code is perfect. → `X-Accel-Buffering: no`, `Cache-Control: no-cache`; document the Envoy/NGINX config in TROUBLESHOOTING.
20. **Zombie upstreams.** Client disconnects but the upstream stream keeps generating (and billing). → `async with client.stream(...)`, handle `CancelledError`, test with a mock that records closure.

## Task 4
21. **aiosqlite + concurrent `BEGIN IMMEDIATE` on one connection** → "cannot start a transaction within a transaction". → `isolation_level=None`, an `asyncio.Lock` per connection around each transaction; `BEGIN IMMEDIATE` + `busy_timeout` for cross-process safety; test both.
22. **Request bigger than the whole budget** returns 429 forever. → 413 `REQUEST_TOO_LARGE`.
23. **Failing over on every error.** A 400 from primary will be a 400 from backup too. → Fail over only on 429 / 5xx / timeout / connection errors.
24. **Streaming failover.** Once the first byte is sent you can't switch providers transparently. → Timeout applies to time-to-first-byte; mid-stream failure → SSE error frame.
25. **`asyncio.wait_for` cancellation.** It cancels the inner task, but only if the provider code is cancellation-safe (no bare `except Exception` swallowing `CancelledError`). → Test that the mock observes cancellation.
26. **`asyncio.TimeoutError`** is an alias of builtin `TimeoutError` since 3.11 — catch `TimeoutError`.
27. **Reconcile must not move the timestamp**, or a long request gets a fresh 60s window.
28. **Storing raw tenant API keys** in SQLite. → Store sha256.

## Numbers to treat with care
29. The blueprint's cost and latency figures (model prices, "<3.5 ms total", "1,000+ concurrent streams per 2 vCPU", "~4 KB per stream") are unmeasured estimates, and some model names/prices in it may be wrong. Quote only numbers from `scripts/bench.py` on your machine, and say what hardware they came from.

## Discovered during build

30. **CRLF on Windows stdio (verified, phase 0, Windows 11 / Python 3.14 / mcp 1.30.0).** The spike's `io.TextIOWrapper(..., encoding="utf-8", write_through=True)` uses the default `newline=None`, which turns every `\n` into `\r\n` on Windows, so each JSON-RPC frame ends in `\r\n`. Lenient clients cope (`json.loads` ignores the `\r`); strict newline-delimited parsers don't. → Pass `newline="\n"` to the TextIOWrapper in `task1_mcp_server/__main__.py`; T1 tests should assert frames end in `b"\n"` and not `b"\r\n"`. Apart from that, fd isolation (`os.dup`/`os.dup2`) works the same on Windows: the stray `print()` and the raw `os.write(1, ...)` both landed on stderr.
31. **Starlette runs the bare-`Exception` handler outside user middleware (phase 0).** `ServerErrorMiddleware` is the outermost layer, so a pure-ASGI correlation middleware's `send` wrapper never sees the 500 response, and its contextvar has already been reset. → The middleware also stores the ID in `scope["state"]`; `errors.py` reads it from there and sets `X-Correlation-ID` on the envelope itself. Covered by `test_correlation_id_echoed_on_error_responses[...boom...]`. Tests that hit a 500 need `httpx.ASGITransport(raise_app_exceptions=False)`, because Starlette re-raises after sending the response.
32. **`ruff format` also formats Python code blocks inside Markdown (ruff 0.17, phase 0).** It rewrote the code blocks in `SPEC.md`. → `pyproject.toml` excludes `docs`, `prompts` and `*.md` from ruff.
33. **`int in IntEnum` raises `TypeError` on Python 3.11** (it only became a value check in 3.12). The project supports 3.11+, so `jsonrpc.make_error` looks the code up with try/except instead.
34. **Tooling on this machine.** `python3` is the Microsoft Store stub; the real interpreter is `python` (3.14.0). The `uv` install script (`irm | iex`) was blocked by a local policy, so uv 0.13.7 was installed with `python -m pip install --user uv` into `%APPDATA%\Python\Python314\Scripts`, which is **not on PATH**. Add that folder to PATH, or reinstall uv with the official installer, so that the plain `uv ...` commands in the README work.
