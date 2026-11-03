"""End-to-end demo: ``python -m control_plane.e2e_demo [--fast] [--log-file PATH]``.

Runs scenarios A-E (SPEC §6) against the unified control plane served by uvicorn on an ephemeral
loopback port inside this process, with Task 1 as a real child process. A real HTTP client and
server are used, rather than ASGITransport, so the SSE stream genuinely arrives in pieces
(ASGITransport buffers, PITFALLS #41).

Every assertion reads only what an operator could observe: status codes, JSON-RPC bodies,
response headers, SSE frames, the stdio downstream's forwarded-call counter, and the JSON log
lines that carry the scenario's correlation ID. Logs go to ``--log-file`` instead of the
terminal so the panels stay readable; the file is what the closing ``grep`` hint points at.

Exit code 0 only if every check passes, so CI can run it (``--fast`` shrinks the 3 s timeout
to 0.3 s and the primary's sleep from 3.2 s to 0.5 s).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import secrets
import sys
import tempfile
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import jwt
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from control_plane.common.logging import ROOT_LOGGER, JsonFormatter
from control_plane.common.settings import Settings
from control_plane.integration.app import create_app
from control_plane.integration.mock_agent_llm import LEAKY_MODEL, AgentMockProvider
from control_plane.task2_mcp_gateway.downstream import StdioMcpDownstream
from control_plane.task3_streaming_guardrail.patterns import REDACTED

SECRET_MARKERS = ("Traceback", "/srv/", "SELECT", "10.0.0.7", "sk-live")
RAW_EMAIL = "sarah.connor@cyberdyne.io"
RAW_SSN = "999-01-4242"
DIAGNOSTIC_HEADERS = (
    "X-Correlation-ID",
    "X-Routed-Provider",
    "X-Failover-Reason",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "Retry-After",
    "X-MCP-Caller-Role",
    "X-MCP-Policy-Decision",
    "X-Guardrail",
)
HOPS: dict[str, tuple[str, ...]] = {
    "T4 router": ("route_decision", "rate_limited", "provider_failed"),
    "T2 gateway": ("mcp_policy_decision", "mcp_request"),
    "T1 server (stderr, via drain)": ("t1_log",),
    "T3 guardrail": ("guardrail_stream", "guardrail_completion"),
}

console = Console(highlight=False)


# --- log capture -------------------------------------------------------------------------------


class LogSink(logging.Handler):
    """Every ``control_plane`` record, rendered by the production formatter and parsed back, so
    assertions run against exactly what the log file (the app's stderr) receives."""

    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(JsonFormatter())
        self.records: list[dict[str, Any]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(json.loads(self.format(record)))

    def for_id(self, cid: str) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("correlation_id") == cid]


# --- checks ------------------------------------------------------------------------------------


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class ScenarioResult:
    key: str
    title: str
    correlation_id: str
    checks: list[Check] = field(default_factory=list)

    def check(self, name: str, ok: bool, detail: Any = "") -> None:
        self.checks.append(Check(name, bool(ok), str(detail)))

    @property
    def passed(self) -> bool:
        return all(c.ok for c in self.checks)


@dataclass
class Demo:
    client: httpx.AsyncClient
    settings: Settings
    primary: AgentMockProvider
    downstream: StdioMcpDownstream
    logs: LogSink
    timeout_label: str

    def token(self, role: str) -> str:
        claims = {"role": role, "sub": f"demo-{role}", "exp": int(time.time()) + 600}
        return jwt.encode(claims, self.settings.jwt_hs256_secret, algorithm="HS256")

    async def mcp(self, message: dict[str, Any], role: str, cid: str) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token(role)}", "X-Correlation-ID": cid}
        return await self.client.post("/mcp", json=message, headers=headers)

    async def chat(
        self,
        messages: list[dict[str, Any]],
        cid: str,
        *,
        tenant: str,
        model: str = "agent-mock",
        max_tokens: int = 256,
    ) -> httpx.Response:
        body = {"model": model, "messages": messages, "max_tokens": max_tokens}
        headers = {"X-Tenant-Key": tenant, "X-Correlation-ID": cid}
        return await self.client.post("/v1/chat/completions", json=body, headers=headers)

    async def chat_stream(
        self, messages: list[dict[str, Any]], cid: str, *, tenant: str
    ) -> tuple[httpx.Response, list[tuple[str | None, str]], list[float]]:
        """Read the SSE stream as it arrives; returns frames and per-frame arrival times (ms)."""
        body = {"model": "agent-mock", "messages": messages, "stream": True, "max_tokens": 256}
        headers = {"X-Tenant-Key": tenant, "X-Correlation-ID": cid}
        frames: list[tuple[str | None, str]] = []
        arrivals: list[float] = []
        started = time.perf_counter()
        async with self.client.stream(
            "POST", "/v1/chat/completions", json=body, headers=headers
        ) as resp:
            event: str | None = None
            data: list[str] = []
            async for line in resp.aiter_lines():
                if line == "":
                    if data:
                        frames.append((event, "\n".join(data)))
                        arrivals.append((time.perf_counter() - started) * 1000)
                    event, data = None, []
                elif line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data.append(line[5:].strip())
        return resp, frames, arrivals


def tool_call(name: str, arguments: dict[str, Any], id_: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": id_,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def new_cid(key: str) -> str:
    return f"demo-{key}-{uuid.uuid4().hex[:12]}"


# --- rendering ---------------------------------------------------------------------------------


def hop_panel(title: str, request: str, decision: str, resp: httpx.Response | None) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(overflow="fold")
    table.add_row("request", request)
    table.add_row("decision", decision)
    if resp is not None:
        table.add_row("status", str(resp.status_code))
        for name in DIAGNOSTIC_HEADERS:
            if name in resp.headers:
                table.add_row(name, resp.headers[name])
    console.print(Panel(table, title=title, title_align="left", border_style="blue"))


def short(value: Any, limit: int = 160) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# --- scenarios ---------------------------------------------------------------------------------


async def scenario_a(demo: Demo) -> ScenarioResult:
    res = ScenarioResult("A", "Confused deputy blocked", new_cid("A"))
    before = demo.downstream.forwarded
    resp = await demo.mcp(
        tool_call("admin_reset_key", {"user": "sarah"}, "deputy-1"), "viewer", res.correlation_id
    )
    body = resp.json()
    error = body.get("error", {})
    hop_panel(
        "A | T2 gateway  POST /mcp",
        "viewer JWT -> tools/call admin_reset_key",
        f"JSON-RPC {error.get('code')}: {error.get('message')}",
        resp,
    )
    await asyncio.sleep(0.3)  # give the stderr drain a moment, so "no T1 line" means something
    after = demo.downstream.forwarded
    t1_lines = [r for r in demo.logs.for_id(res.correlation_id) if r["event"] == "t1_log"]
    console.print(f"  downstream forwarded-call counter: {before} -> {after}")
    res.check("error code -32001", error.get("code") == -32001, error.get("code"))
    res.check(
        "message names role and tool",
        error.get("message")
        == "Unauthorized Tool Call: Role 'viewer' is not permitted to invoke administrative "
        "tool 'admin_reset_key'.",
        short(error.get("message")),
    )
    res.check("id preserved", body.get("id") == "deputy-1", body.get("id"))
    res.check("policy header = deny", resp.headers.get("X-MCP-Policy-Decision") == "deny", "deny")
    res.check("T1 never called (counter unchanged)", after == before, f"{before} -> {after}")
    res.check("no T1 log line for this ID", not t1_lines, len(t1_lines))
    return res


async def scenario_b(demo: Demo) -> ScenarioResult:
    res = ScenarioResult("B", "Full pipeline: failover -> tool call -> redaction", new_cid("B"))
    cid, tenant = res.correlation_id, "acme-support"
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": "Summarize customer CUST-10042 for the support ticket."}
    ]

    started = time.perf_counter()
    turn1 = await demo.chat(messages, cid, tenant=tenant)
    elapsed = (time.perf_counter() - started) * 1000
    body1 = turn1.json()
    assistant = (body1.get("choices") or [{}])[0].get("message", {})
    calls = assistant.get("tool_calls") or []
    hop_panel(
        "B1 | T4 router  POST /v1/chat/completions (turn 1)",
        f"tenant={tenant}, stream=false, max_tokens=256",
        f"primary sleeps {demo.primary.delay:g}s -> failover after {elapsed:.0f} ms; "
        f"model asks for {short([c['function'] for c in calls])}",
        turn1,
    )
    res.check("turn 1 status 200", turn1.status_code == 200, turn1.status_code)
    res.check(
        "routed to backup",
        turn1.headers.get("X-Routed-Provider") == "backup",
        turn1.headers.get("X-Routed-Provider"),
    )
    res.check(
        f"failover reason {demo.timeout_label}",
        turn1.headers.get("X-Failover-Reason") == demo.timeout_label,
        turn1.headers.get("X-Failover-Reason"),
    )
    res.check("primary call was cancelled (no zombie)", demo.primary.cancelled, "cancelled")
    res.check(
        "limiter reports remaining budget",
        int(turn1.headers.get("X-RateLimit-Remaining", "50000")) < 50_000,
        turn1.headers.get("X-RateLimit-Remaining"),
    )
    res.check("model requested a tool", len(calls) == 1, len(calls))
    if not calls:
        return res

    call = calls[0]
    arguments = json.loads(call["function"]["arguments"])
    tool = await demo.mcp(tool_call(call["function"]["name"], arguments, "agent-1"), "viewer", cid)
    result = tool.json().get("result", {})
    record = result.get("structuredContent") or {}
    hop_panel(
        "B2 | T2 gateway -> T1 (stdio)  POST /mcp",
        f"viewer JWT -> tools/call {call['function']['name']}({short(arguments)})",
        f"allowed; T1 validated and returned the record (raw, as tools do): "
        f"email={record.get('email')}, ssn={record.get('ssn')}",
        tool,
    )
    res.check(
        "policy header = allow",
        tool.headers.get("X-MCP-Policy-Decision") == "allow",
        tool.headers.get("X-MCP-Policy-Decision"),
    )
    res.check(
        "T1 returned the record", record.get("customer_id") == "CUST-10042", short(record, 60)
    )

    messages += [
        {"role": "assistant", "content": None, "tool_calls": calls},
        {"role": "tool", "tool_call_id": call["id"], "content": result["content"][0]["text"]},
    ]
    turn2, frames, arrivals = await demo.chat_stream(messages, cid, tenant=tenant)
    content = ""
    for event, data in frames:
        if event is None and data != "[DONE]":
            for choice in json.loads(data).get("choices", []):
                content += choice.get("delta", {}).get("content") or ""
    trailers = [json.loads(d) for e, d in frames if e == "guardrail"]
    trailer = trailers[0] if trailers else {}
    hop_panel(
        "B3 | T4 router -> T3 redactor  POST /v1/chat/completions (turn 2, stream)",
        "tool result appended; stream=true",
        f"{len(frames)} SSE frames, first at {arrivals[0] if arrivals else 0:.0f} ms, "
        f"last at {arrivals[-1] if arrivals else 0:.0f} ms; "
        f"trailer: {short(trailer)}\n[bold]client saw:[/bold] {content}",
        turn2,
    )
    raw_seen = RAW_EMAIL in content or RAW_SSN in content
    res.check(
        "turn 2 streamed (text/event-stream)",
        "event-stream" in turn2.headers.get("content-type", ""),
        turn2.headers.get("content-type"),
    )
    res.check("stream also failed over", turn2.headers.get("X-Routed-Provider") == "backup", "")
    res.check("summary built from the tool result", "Sarah Connor" in content, "")
    res.check("raw email/SSN absent from client stream", not raw_seen, "")
    res.check(f"{REDACTED} present", content.count(REDACTED) >= 2, content.count(REDACTED))
    res.check(
        "trailer pii_redactions >= 2",
        trailer.get("pii_redactions", 0) >= 2,
        trailer.get("pii_redactions"),
    )
    res.check("trailer carries the correlation ID", trailer.get("correlation_id") == cid, "")
    res.check("stream ends with [DONE]", bool(frames) and frames[-1] == (None, "[DONE]"), "")

    await asyncio.sleep(0.3)  # let the T1 stderr drain catch up
    hops = {hop: [r for r in demo.logs.for_id(cid) if r["event"] in ev] for hop, ev in HOPS.items()}
    for hop, lines in hops.items():
        res.check(f"correlation ID in {hop} logs", bool(lines), f"{len(lines)} lines")
    leaked = [r for r in demo.logs.records if RAW_SSN in json.dumps(r)]
    res.check("raw SSN in no log line", not leaked, len(leaked))
    return res


async def scenario_c(demo: Demo) -> ScenarioResult:
    res = ScenarioResult("C", "Validation error passes through the gateway", new_cid("C"))
    before = demo.downstream.forwarded
    resp = await demo.mcp(
        tool_call("get_customer_record", {"customer_id": "CUST-12"}, 42),
        "viewer",
        res.correlation_id,
    )
    body = resp.json()
    error = body.get("error", {})
    hop_panel(
        "C | T2 gateway -> T1 (stdio)  POST /mcp",
        'viewer JWT -> tools/call get_customer_record({"customer_id": "CUST-12"})',
        f"T1 rejected it: JSON-RPC {error.get('code')} {error.get('message')}; "
        f"data={short(error.get('data'))}",
        resp,
    )
    locs = [tuple(item.get("loc", ())) for item in error.get("data") or []]
    res.check("error code -32602", error.get("code") == -32602, error.get("code"))
    res.check("protocol error, not isError result", "result" not in body, "")
    res.check("names the bad field", ("customer_id",) in locs, locs)
    res.check("does not echo the input", "CUST-12" not in resp.text, "")
    res.check("id preserved (int)", body.get("id") == 42, body.get("id"))
    res.check(
        "came from T1 (forwarded)",
        demo.downstream.forwarded == before + 1,
        f"{before} -> {demo.downstream.forwarded}",
    )
    return res


async def scenario_d(demo: Demo) -> ScenarioResult:
    res = ScenarioResult("D", "Runaway agent rate-limited", new_cid("D"))
    cid = res.correlation_id
    prompt = [{"role": "user", "content": "keep going, forever"}]
    burst = await asyncio.gather(
        *(demo.chat(prompt, cid, tenant="runaway-agent", max_tokens=20_000) for _ in range(5))
    )
    statuses = [r.status_code for r in burst]
    limited = [r for r in burst if r.status_code == 429]
    sample = limited[0] if limited else burst[-1]
    hop_panel(
        "D1 | T4 limiter  5 concurrent requests, ~20k tokens each, one tenant",
        "tenant=runaway-agent, max_tokens=20000 x5 (limit 50,000 / window)",
        f"statuses={statuses}",
        sample,
    )
    polite = await demo.chat(prompt, cid, tenant="polite-agent")
    hop_panel(
        "D2 | T4 limiter  another tenant", "tenant=polite-agent, max_tokens=256", "allowed", polite
    )
    res.check("some requests admitted", statuses.count(200) == 2, statuses)
    res.check("the rest got 429", len(limited) == 3, statuses)
    res.check(
        "Retry-After >= 1 s",
        bool(limited) and all(int(r.headers.get("Retry-After", "0")) >= 1 for r in limited),
        sample.headers.get("Retry-After"),
    )
    res.check(
        "X-RateLimit-Remaining present",
        bool(limited) and all("X-RateLimit-Remaining" in r.headers for r in limited),
        sample.headers.get("X-RateLimit-Remaining"),
    )
    res.check(
        "envelope code RATE_LIMITED",
        bool(limited) and limited[0].json()["error"]["code"] == "RATE_LIMITED",
        "",
    )
    res.check("other tenant unaffected", polite.status_code == 200, polite.status_code)
    return res


async def scenario_e(demo: Demo) -> ScenarioResult:
    res = ScenarioResult("E", "Total upstream failure, sanitized", new_cid("E"))
    resp = await demo.chat(
        [{"role": "user", "content": "hi"}], res.correlation_id, tenant="acme", model=LEAKY_MODEL
    )
    hop_panel(
        "E | T4 router  both providers raise exceptions full of secrets",
        f"model={LEAKY_MODEL}",
        f"client got: {short(resp.text, 240)}",
        resp,
    )
    found = [m for m in SECRET_MARKERS if m in resp.text]
    error = resp.json().get("error", {})
    res.check("HTTP 502", resp.status_code == 502, resp.status_code)
    res.check(
        "code GATEWAY_UPSTREAM_FAILURE",
        error.get("code") == "GATEWAY_UPSTREAM_FAILURE",
        error.get("code"),
    )
    res.check("no secret substrings in body", not found, found or "none of " + str(SECRET_MARKERS))
    res.check(
        "detail kept for operators (log)",
        any(r["event"] == "provider_failed" for r in demo.logs.for_id(res.correlation_id)),
        "provider_failed logged with traceback",
    )
    return res


SCENARIOS: tuple[Callable[[Demo], Awaitable[ScenarioResult]], ...] = (
    scenario_a,
    scenario_b,
    scenario_c,
    scenario_d,
    scenario_e,
)


# --- harness -----------------------------------------------------------------------------------


@asynccontextmanager
async def serve(app: Any) -> AsyncIterator[str]:
    config = uvicorn.Config(
        app, host="127.0.0.1", port=0, log_config=None, log_level="warning", lifespan="on"
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        async with asyncio.timeout(20):
            while not server.started:  # noqa: ASYNC110 - uvicorn exposes a flag, not an Event
                if task.done():
                    raise RuntimeError("control plane failed to start; see the log file")
                await asyncio.sleep(0.02)
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


def print_summary(results: list[ScenarioResult]) -> None:
    table = Table(title="Scenario checks", show_lines=False)
    table.add_column("scn")
    table.add_column("check")
    table.add_column("result")
    table.add_column("observed", overflow="fold")
    for res in results:
        for check in res.checks:
            mark = "[green]PASS[/green]" if check.ok else "[bold red]FAIL[/bold red]"
            table.add_row(res.key, check.name, mark, short(check.detail, 70))
    console.print(table)


def print_trace(result: ScenarioResult, logs: LogSink, log_file: Path) -> None:
    cid = result.correlation_id
    console.rule(f"Scenario {result.key} correlation ID: [bold]{cid}[/bold]")
    lines = logs.for_id(cid)
    for hop, events in HOPS.items():
        console.print(f"[bold cyan]{hop}[/bold cyan]")
        for record in (r for r in lines if r["event"] in events):
            shown = record.get("child", record) if record["event"] == "t1_log" else record
            shown = {k: v for k, v in shown.items() if k not in ("ts", "traceback", "exc_type")}
            console.print("  " + short(shown, 240), soft_wrap=True)
    console.print(
        f"\ngrep hint: grep {cid} {log_file}   "
        "(gateway + T4 + T3 audit lines, and T1's own stderr relayed by the drain)"
    )


async def run(fast: bool, log_file: Path) -> int:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp, log_file.open("w", encoding="utf-8") as stream:
        sink = LogSink()
        root = logging.getLogger(ROOT_LOGGER)
        root.addHandler(sink)
        # Our JSON handler (and third-party loggers) resolve sys.stderr at emit time: pointing it
        # at the log file keeps the panels readable and leaves the lines intact for ``grep``.
        real_stderr = sys.stderr
        sys.stderr = stream
        try:
            timeout = 0.3 if fast else 3.0
            settings = Settings(
                primary_timeout_seconds=timeout,
                rate_limit_db_path=Path(tmp) / "ratelimit.db",
                jwt_hs256_secret=secrets.token_urlsafe(32),
            )
            primary = AgentMockProvider("primary", delay=0.5 if fast else 3.2)
            # A small inter-chunk gap so the panel shows the stream arriving in pieces.
            backup = AgentMockProvider("backup", chunk_delay=0.05)
            downstream = StdioMcpDownstream()
            app = create_app(settings, primary=primary, backup=backup, downstream=downstream)
            results: list[ScenarioResult] = []
            async with (
                serve(app) as base_url,
                httpx.AsyncClient(base_url=base_url, timeout=30.0) as client,
            ):
                demo = Demo(
                    client,
                    settings,
                    primary,
                    downstream,
                    sink,
                    f"timeout_{round(timeout * 1000)}ms",
                )
                console.rule(
                    f"Zero-trust control plane e2e  ({'fast' if fast else 'full timings'}; "
                    f"failover timeout {timeout:g}s, primary sleep {primary.delay:g}s; "
                    f"T1 pid {downstream.process.pid if downstream.process else '?'})"
                )
                for scenario in SCENARIOS:
                    result = await scenario(demo)
                    results.append(result)
                    status = "[green]passed[/green]" if result.passed else "[red]FAILED[/red]"
                    console.print(f"Scenario {result.key}: {result.title} -> {status}\n")
        finally:
            sys.stderr = real_stderr
            root.removeHandler(sink)

        print_summary(results)
        print_trace(next(r for r in results if r.key == "B"), sink, log_file)
        failed = [r.key for r in results if not r.passed]
        if failed:
            console.print(f"[bold red]FAILED scenarios: {', '.join(failed)}[/bold red]")
            return 1
        console.print("[bold green]ALL SCENARIOS PASSED[/bold green]")
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m control_plane.e2e_demo")
    parser.add_argument("--fast", action="store_true", help="0.3 s timeout / 0.5 s primary sleep")
    parser.add_argument("--log-file", type=Path, default=Path("data/e2e_demo.log"))
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):  # Windows pipes default to a legacy code page
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    return asyncio.run(run(args.fast, args.log_file))


if __name__ == "__main__":
    sys.exit(main())
