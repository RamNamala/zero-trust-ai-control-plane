"""Integration - end-to-end zero-trust chain (acceptance contract - docs/ACCEPTANCE_MATRIX.md).

The unified app runs in-process over ``httpx.ASGITransport`` with its lifespan entered
explicitly (ASGITransport doesn't run it, PITFALLS #39). Task 1 runs as a real subprocess
behind ``StdioMcpDownstream``. Timeouts are shrunk by ``settings_override``: the primary
sleeps 0.5 s against a 0.3 s failover timeout, so every chat call fails over to the backup.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from conftest import JsonLogCapture
from fastapi import FastAPI

from control_plane.common.settings import Settings
from control_plane.integration.app import create_app
from control_plane.integration.mock_agent_llm import LEAKY_MODEL, AgentMockProvider
from control_plane.task1_mcp_server.data import make_refund_id
from control_plane.task2_mcp_gateway.downstream import UPSTREAM_UNAVAILABLE, StdioMcpDownstream

pytestmark = pytest.mark.subprocess

REPO_ROOT = Path(__file__).resolve().parents[1]
SECRET_MARKERS = ("Traceback", "/srv/", "SELECT", "10.0.0.7", "sk-live")
RAW_EMAIL = "sarah.connor@cyberdyne.io"
RAW_SSN = "999-01-4242"
CUSTOMERS = ("CUST-10042", "CUST-20017", "CUST-30555")


@dataclass
class Stack:
    app: FastAPI
    client: httpx.AsyncClient
    settings: Settings
    primary: AgentMockProvider
    backup: AgentMockProvider
    downstream: StdioMcpDownstream

    def token(self, role: str) -> str:
        claims = {"role": role, "sub": f"{role}-e2e", "exp": int(time.time()) + 300}
        return jwt.encode(claims, self.settings.jwt_hs256_secret, algorithm="HS256")

    async def mcp(
        self, message: dict[str, Any], role: str = "viewer", correlation_id: str | None = None
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token(role)}"}
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id
        return await self.client.post("/mcp", json=message, headers=headers)

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tenant: str = "tenant-e2e",
        stream: bool = False,
        model: str = "agent-mock",
        max_tokens: int = 256,
        correlation_id: str | None = None,
    ) -> httpx.Response:
        headers = {"X-Tenant-Key": tenant}
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id
        body = {"model": model, "messages": messages, "stream": stream, "max_tokens": max_tokens}
        return await self.client.post("/v1/chat/completions", json=body, headers=headers)


@pytest.fixture
async def stack(settings_override: Settings) -> AsyncIterator[Stack]:
    primary = AgentMockProvider("primary", delay=0.5)
    backup = AgentMockProvider("backup")
    downstream = StdioMcpDownstream(request_timeout=10.0)
    app = create_app(settings_override, primary=primary, backup=backup, downstream=downstream)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://control-plane") as c:
            yield Stack(app, c, settings_override, primary, backup, downstream)


def tool_call(name: str, arguments: dict[str, Any], id_: Any = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": id_,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def parse_sse(text: str) -> list[tuple[str | None, str]]:
    frames: list[tuple[str | None, str]] = []
    for block in text.split("\n\n"):
        event: str | None = None
        data: list[str] = []
        for line in block.splitlines():
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].strip())
        if data:
            frames.append((event, "\n".join(data)))
    return frames


def stream_content(frames: list[tuple[str | None, str]]) -> str:
    text = ""
    for event, data in frames:
        if event is None and data != "[DONE]":
            for choice in json.loads(data).get("choices", []):
                text += choice.get("delta", {}).get("content") or ""
    return text


def trailer(frames: list[tuple[str | None, str]]) -> dict[str, Any]:
    payloads = [json.loads(d) for e, d in frames if e == "guardrail"]
    assert len(payloads) == 1
    result: dict[str, Any] = payloads[0]
    return result


async def run_agent_turn(stack: Stack, correlation_id: str | None = None) -> dict[str, Any]:
    """Scenario B as an agent would drive it: model turn -> tool call -> streamed model turn."""
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": "Summarize customer CUST-10042 for the support ticket."}
    ]
    turn1 = await stack.chat(messages, correlation_id=correlation_id)
    assert turn1.status_code == 200, turn1.text
    assistant = turn1.json()["choices"][0]["message"]
    call = assistant["tool_calls"][0]
    arguments = json.loads(call["function"]["arguments"])

    tool = await stack.mcp(
        tool_call(call["function"]["name"], arguments, id_="agent-call-1"),
        correlation_id=correlation_id,
    )
    assert tool.status_code == 200, tool.text
    result = tool.json()["result"]
    tool_text = result["content"][0]["text"]

    messages += [
        {"role": "assistant", "content": None, "tool_calls": assistant["tool_calls"]},
        {"role": "tool", "tool_call_id": call["id"], "content": tool_text},
    ]
    turn2 = await stack.chat(messages, stream=True, correlation_id=correlation_id)
    assert turn2.status_code == 200, turn2.text
    frames = parse_sse(turn2.text)
    return {
        "turn1": turn1,
        "tool": tool,
        "tool_result": result,
        "turn2": turn2,
        "frames": frames,
        "arguments": arguments,
        "tool_name": call["function"]["name"],
    }


async def test_scenario_a_confused_deputy_blocked(stack: Stack) -> None:
    """Zero-trust chain"""
    before = stack.downstream.forwarded
    resp = await stack.mcp(tool_call("admin_reset_key", {"user": "sarah"}, id_="deputy-7"))
    assert resp.status_code == 200
    assert resp.headers["X-MCP-Policy-Decision"] == "deny"
    assert resp.headers["X-MCP-Caller-Role"] == "viewer"
    assert resp.json() == {
        "jsonrpc": "2.0",
        "id": "deputy-7",
        "error": {
            "code": -32001,
            "message": "Unauthorized Tool Call: Role 'viewer' is not permitted to invoke "
            "administrative tool 'admin_reset_key'.",
        },
    }
    assert stack.downstream.forwarded == before  # T1 never saw it

    # The same viewer is allowed through for a non-admin tool: denial is per tool, not per user.
    ok = await stack.mcp(tool_call("get_customer_record", {"customer_id": "CUST-20017"}))
    assert ok.json()["result"]["structuredContent"]["customer_id"] == "CUST-20017"
    assert stack.downstream.forwarded == before + 1


async def test_scenario_b_full_pipeline_failover_tool_call_redaction(stack: Stack) -> None:
    """Zero-trust chain"""
    run = await run_agent_turn(stack)
    turn1, turn2 = run["turn1"], run["turn2"]

    # T4: budget checked, primary timed out (and was really cancelled), backup answered.
    for resp in (turn1, turn2):
        assert resp.headers["X-Routed-Provider"] == "backup"
        assert resp.headers["X-Failover-Reason"] == "timeout_300ms"
        assert int(resp.headers["X-RateLimit-Remaining"]) < 50_000
    assert stack.primary.cancelled
    assert turn1.json()["gateway"]["routed_provider"] == "backup"

    # Model asked for the record; T2 allowed the viewer; T1 validated and returned raw PII.
    assert run["tool_name"] == "get_customer_record"
    assert run["arguments"] == {"customer_id": "CUST-10042"}
    assert run["tool"].headers["X-MCP-Policy-Decision"] == "allow"
    record = run["tool_result"]["structuredContent"]
    assert record["email"] == RAW_EMAIL
    assert record["ssn"] == RAW_SSN

    # T3: the streamed summary came through redacted, although both values were split.
    assert turn2.headers["content-type"].startswith("text/event-stream")
    assert turn2.headers["X-Guardrail"] == "pii-redaction/v1"
    text = stream_content(run["frames"])
    assert "Sarah Connor" in text  # the summary really was built from the tool result
    assert RAW_EMAIL not in turn2.text
    assert RAW_SSN not in turn2.text
    assert text.count("[REDACTED") >= 2
    assert trailer(run["frames"])["pii_redactions"] >= 2
    assert run["frames"][-1] == (None, "[DONE]")


async def test_scenario_c_validation_error_passes_through_gateway(stack: Stack) -> None:
    """Zero-trust chain"""
    before = stack.downstream.forwarded
    resp = await stack.mcp(tool_call("get_customer_record", {"customer_id": "CUST-12"}, id_=42))
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 42
    assert "result" not in body
    assert body["error"]["code"] == -32602
    # The structured detail is T1's (the gateway has no schema for tool arguments), and it
    # names the field without echoing the input.
    locs = [tuple(item["loc"]) for item in body["error"]["data"]]
    assert ("customer_id",) in locs
    assert "CUST-12" not in resp.text
    assert stack.downstream.forwarded == before + 1  # it reached T1, which rejected it


async def test_scenario_d_runaway_tenant_rate_limited(stack: Stack) -> None:
    """Zero-trust chain"""
    prompt = [{"role": "user", "content": "loop forever"}]
    # Each request reserves ~20k of the 50k window: two fit, the rest are refused atomically.
    burst = await asyncio.gather(
        *(stack.chat(prompt, tenant="runaway", max_tokens=20_000) for _ in range(5))
    )
    statuses = sorted(r.status_code for r in burst)
    assert statuses == [200, 200, 429, 429, 429]
    for resp in (r for r in burst if r.status_code == 429):
        assert int(resp.headers["Retry-After"]) >= 1
        assert resp.headers["X-RateLimit-Limit"] == "50000"
        assert "X-RateLimit-Remaining" in resp.headers
        assert resp.json()["error"]["code"] == "RATE_LIMITED"

    polite = await stack.chat(prompt, tenant="polite", max_tokens=256)
    assert polite.status_code == 200


async def test_scenario_e_total_failure_sanitized(stack: Stack) -> None:
    """Zero-trust chain"""
    prompt = [{"role": "user", "content": "hello"}]
    for stream in (False, True):
        resp = await stack.chat(prompt, model=LEAKY_MODEL, stream=stream)
        assert resp.status_code == 502
        error = resp.json()["error"]
        assert error["code"] == "GATEWAY_UPSTREAM_FAILURE"
        assert set(error) == {"code", "message", "request_id", "correlation_id", "timestamp"}
        for marker in SECRET_MARKERS:
            assert marker not in resp.text
    assert stack.primary.calls == 2
    assert stack.backup.calls == 2  # both were tried each time


async def _wait_for(predicate: Any, within: float = 3.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return bool(predicate())


async def test_single_correlation_id_visible_in_all_hops(
    stack: Stack, caplog_json: JsonLogCapture
) -> None:
    """Observability: (headers + T1 stderr + gateway logs)"""
    cid = "e2e-trace-0001-abcdef"
    run = await run_agent_turn(stack, correlation_id=cid)

    # Response headers on every hop the client talked to.
    for key in ("turn1", "tool", "turn2"):
        assert run[key].headers["X-Correlation-ID"] == cid
    assert trailer(run["frames"])["correlation_id"] == cid

    def mine(event: str) -> list[dict[str, Any]]:
        return [r for r in caplog_json.events(event) if r["correlation_id"] == cid]

    def t1_tool_calls() -> list[dict[str, Any]]:
        return [r for r in mine("t1_log") if r["child"].get("event") == "tool_call"]

    # T1's stderr arrives via the drain task, asynchronously.
    assert await _wait_for(lambda: bool(t1_tool_calls()))
    assert t1_tool_calls()[0]["child"]["correlation_id"] == cid
    assert t1_tool_calls()[0]["child"]["tool"] == "get_customer_record"

    assert len(mine("route_decision")) == 2  # T4, both model turns
    assert [r["decision"] for r in mine("mcp_policy_decision")] == ["allow"]  # T2
    assert len(mine("guardrail_stream")) == 1  # T3, the streamed turn
    assert mine("guardrail_stream")[0]["pii_redactions"] >= 2

    # No hop logged the PII that flowed through it.
    assert RAW_SSN not in caplog_json.text
    assert RAW_EMAIL not in caplog_json.text


async def test_stdio_downstream_id_rewriting_handles_concurrent_same_ids(stack: Stack) -> None:
    """Robustness"""
    reason = "Duplicate charge on the last order"
    requests: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for i in range(20):
        customer = CUSTOMERS[i % 3]
        if i % 2 == 0:
            msg = tool_call("get_customer_record", {"customer_id": customer}, id_=1)
            expected = {"customer_id": customer}
        else:
            amount = float(10 + i)
            msg = tool_call(
                "trigger_refund",
                {"customer_id": customer, "amount": amount, "reason": reason},
                id_=1,
            )
            expected = {"refund_id": make_refund_id(customer, amount, reason)}
        requests.append((msg, expected))

    before = stack.downstream.forwarded
    responses = await asyncio.gather(*(stack.mcp(msg) for msg, _ in requests))

    for resp, (_, expected) in zip(responses, requests, strict=True):
        body = resp.json()
        assert body["id"] == 1
        assert "error" not in body, body
        content = body["result"]["structuredContent"]
        for key, value in expected.items():
            assert content[key] == value
    assert stack.downstream.forwarded == before + 20
    assert stack.downstream.restarts == 0


async def test_stdio_downstream_recovers_after_child_crash(stack: Stack) -> None:
    """Robustness"""
    downstream = stack.downstream
    proc = downstream.process
    assert proc is not None
    old_pid = proc.pid
    msg = tool_call("get_customer_record", {"customer_id": "CUST-10042"}, id_="in-flight")

    # Test seam: holding the write lock parks the request after its future is registered but
    # before it is written, so the crash deterministically lands while it is in flight. A plain
    # kill-then-call would race with asyncio noticing the exit (and just respawn).
    async with downstream._write_lock:
        pending = asyncio.create_task(stack.mcp(msg))
        assert await _wait_for(lambda: bool(downstream._pending))
        proc.kill()
        await proc.wait()
    resp = await pending

    assert resp.status_code == 200
    assert resp.json() == {
        "jsonrpc": "2.0",
        "id": "in-flight",
        "error": {"code": -32603, "message": UPSTREAM_UNAVAILABLE},
    }
    assert str(old_pid) not in resp.text

    # The next call respawns the child, handshakes again, and succeeds.
    again = await stack.mcp(msg)
    assert again.json()["result"]["structuredContent"]["customer_id"] == "CUST-10042"
    assert downstream.restarts == 1
    assert downstream.process is not None and downstream.process.pid != old_pid


@pytest.mark.slow
def test_e2e_demo_exits_zero(tmp_path: Path) -> None:
    """Demo: (runs `python -m control_plane.e2e_demo --fast`)"""
    log_file = tmp_path / "e2e_demo.log"
    proc = subprocess.run(  # noqa: S603 - fixed argv, our own module
        [sys.executable, "-m", "control_plane.e2e_demo", "--fast", "--log-file", str(log_file)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-4000:]
    assert "ALL SCENARIOS PASSED" in proc.stdout
    assert log_file.exists() and log_file.stat().st_size > 0
