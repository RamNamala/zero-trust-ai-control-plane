"""Measures the numbers the README is allowed to quote (SPEC §7). Nothing here is a claim until
this script has printed it on the machine named in the output.

    uv run python scripts/bench.py            # full run, prints a markdown table
    uv run python scripts/bench.py --quick    # 10x fewer iterations, for a smoke check

What is measured, and how:

* **T2 gateway overhead.** p50/p99 of a ``tools/call`` sent straight to the mock MCP downstream,
  and of the same call through the gateway (JWT verify, RBAC, id rewrite, audit log, forward).
  Both run in-process over ``httpx.ASGITransport``, so the difference is the gateway's own cost,
  not network.
* **T3 redactor cost.** ``StreamingPIIRedactor.feed`` timed per chunk over a 50k-chunk stream of
  token-sized pieces (1-8 chars) with occasional PII. **TTFT delta**: time to the first content
  frame, direct from the mock LLM vs through the guardrail. Both run under uvicorn on loopback,
  because ASGITransport buffers whole responses (PITFALLS #41) and would hide TTFT.
* **T4 limiter.** ``reserve()`` + ``reconcile()`` latency on an on-disk WAL database, and
  throughput with 50 concurrent tasks sharing one limiter (one connection, serialized by its
  asyncio.Lock: this measures the in-process ceiling, not a multi-node store).

Audit logging is on throughout (JSON formatting included) but written to ``os.devnull``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import jwt
import uvicorn

from control_plane.common.logging import ROOT_LOGGER, JsonFormatter
from control_plane.common.settings import Settings
from control_plane.task2_mcp_gateway.downstream import HttpDownstream
from control_plane.task2_mcp_gateway.mock_downstream import create_mock_app
from control_plane.task2_mcp_gateway.proxy import create_app as create_gateway
from control_plane.task3_streaming_guardrail.gateway import create_app as create_guardrail
from control_plane.task3_streaming_guardrail.mock_llm import create_mock_llm
from control_plane.task3_streaming_guardrail.patterns import redact
from control_plane.task3_streaming_guardrail.redactor import StreamingPIIRedactor
from control_plane.task4_resilient_router.rate_limiter import SQLiteRateLimiter

BENCH_SECRET = "bench-secret-that-is-at-least-32-bytes!"  # noqa: S105 - local benchmark only

Row = tuple[str, str, str]


# --- helpers -----------------------------------------------------------------------------------


def pct(samples: list[float], p: float) -> float:
    ordered = sorted(samples)
    index = min(len(ordered) - 1, max(0, round(p / 100 * len(ordered)) - 1))
    return ordered[index]


def cpu_model() -> str:
    try:
        if sys.platform == "win32":
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        if sys.platform == "darwin":
            out = subprocess.run(  # noqa: S603 - fixed argv
                ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                check=True,
            )
            return out.stdout.strip()
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return platform.processor() or platform.machine()


def quiet_json_logging() -> None:
    """Keep the audit/JSON logging cost in the measurement, but send the lines nowhere."""
    logger = logging.getLogger(ROOT_LOGGER)
    logger.handlers.clear()
    handler = logging.StreamHandler(open(os.devnull, "w", encoding="utf-8"))  # noqa: SIM115
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


@asynccontextmanager
async def serve(app: Any) -> AsyncIterator[str]:
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error", lifespan="off")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        async with asyncio.timeout(10):
            while not server.started:  # noqa: ASYNC110 - uvicorn exposes a flag, not an Event
                await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
    finally:
        server.should_exit = True
        await task


async def timed(n: int, call: Callable[[int], Any], warmup: int = 50) -> list[float]:
    for i in range(warmup):
        await call(i)
    samples: list[float] = []
    for i in range(n):
        started = time.perf_counter()
        await call(i)
        samples.append((time.perf_counter() - started) * 1000)
    return samples


# --- T2 ----------------------------------------------------------------------------------------


async def bench_t2(calls: int) -> list[Row]:
    mock = create_mock_app()
    settings = Settings(jwt_hs256_secret=BENCH_SECRET, log_level="INFO")
    token = jwt.encode(
        {"role": "viewer", "sub": "bench", "exp": int(time.time()) + 3600},
        BENCH_SECRET,
        algorithm="HS256",
    )
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "get_customer_record", "arguments": {"customer_id": "CUST-10042"}},
    }
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=mock), base_url="http://mock") as d,
    ):
        gateway = create_gateway(settings, downstream=HttpDownstream("http://mock/mcp", d))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway), base_url="http://gw"
        ) as g:
            headers = {"Authorization": f"Bearer {token}"}

            async def direct(_: int) -> None:
                resp = await d.post("/mcp", json=message)
                assert resp.status_code == 200  # noqa: S101

            async def via_gateway(_: int) -> None:
                resp = await g.post("/mcp", json=message, headers=headers)
                assert resp.status_code == 200 and "result" in resp.json()  # noqa: S101

            direct_ms = await timed(calls, direct)
            gateway_ms = await timed(calls, via_gateway)
    d50, d99 = pct(direct_ms, 50), pct(direct_ms, 99)
    g50, g99 = pct(gateway_ms, 50), pct(gateway_ms, 99)
    return [
        (
            "T2",
            f"`tools/call` direct to mock, p50 / p99 ({calls:,} calls)",
            f"{d50:.3f} / {d99:.3f} ms",
        ),
        (
            "T2",
            f"`tools/call` via gateway, p50 / p99 ({calls:,} calls)",
            f"{g50:.3f} / {g99:.3f} ms",
        ),
        ("T2", "gateway overhead, p50 / p99 (difference)", f"{g50 - d50:.3f} / {g99 - d99:.3f} ms"),
    ]


# --- T3 ----------------------------------------------------------------------------------------

_PROSE = (
    "Thanks for reaching out about your order. ",
    "I checked the account history and the last three shipments arrived on time. ",
    "The refund policy allows returns within thirty days of delivery. ",
    "Your ticket number is 48213 and the order total was 129.99 dollars. ",
    "Let me know if there is anything else I can help with today. ",
)
_PII = (
    "You can reach the customer at sarah.connor@cyberdyne.io for follow-up. ",
    "The SSN on file is 999-01-4242. ",
    "The card ending block is 4532 0151 1283 0366. ",
)


def realistic_chunks(n: int, seed: int = 7) -> list[str]:
    rng = random.Random(seed)  # noqa: S311 - deterministic workload, not crypto
    text: list[str] = []
    while sum(map(len, text)) < n * 9:
        text.append(rng.choice(_PII) if rng.random() < 0.05 else rng.choice(_PROSE))
    full = "".join(text)
    chunks: list[str] = []
    pos = 0
    while len(chunks) < n:
        size = rng.randint(1, 8)  # token-sized deltas, as OpenAI-style streams send them
        chunks.append(full[pos : pos + size])
        pos += size
    return chunks


def bench_redactor(n: int) -> list[Row]:
    chunks = realistic_chunks(n)
    redactor = StreamingPIIRedactor(256)
    out: list[str] = []
    samples_us: list[float] = []
    for chunk in chunks:
        started = time.perf_counter_ns()
        out.append(redactor.feed(chunk))
        samples_us.append((time.perf_counter_ns() - started) / 1000)
    out.append(redactor.flush())
    expected, _ = redact("".join(chunks))
    if "".join(out) != expected:  # the measurement is worthless if the output is wrong
        raise SystemExit("redactor output diverged from redact(full_text)")
    chars = sum(map(len, chunks))
    return [
        (
            "T3",
            f"redactor `feed()` per chunk, mean / p50 / p99 ({n:,} chunks, {chars:,} chars)",
            f"{statistics.fmean(samples_us):.2f} / {pct(samples_us, 50):.2f} / "
            f"{pct(samples_us, 99):.2f} µs",
        ),
        (
            "T3",
            "redactor peak buffer / redactions in stream",
            f"{redactor.peak_buffer_chars} chars / {redactor.redaction_count}",
        ),
    ]


async def first_content_ms(client: httpx.AsyncClient, url: str) -> float:
    body = {
        "model": "mock-email_split",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": True,
    }
    started = time.perf_counter()
    async with client.stream("POST", url, json=body) as resp:
        async for line in resp.aiter_lines():
            if not line.startswith("data:") or line.endswith("[DONE]"):
                continue
            frame = json.loads(line[5:])
            if any(c.get("delta", {}).get("content") for c in frame.get("choices", [])):
                return (time.perf_counter() - started) * 1000
    raise RuntimeError("stream had no content")


async def bench_ttft(runs: int) -> list[Row]:
    async with serve(create_mock_llm()) as mock_url:
        upstream = f"{mock_url}/v1/chat/completions"
        async with httpx.AsyncClient(timeout=10.0) as gw_upstream:
            guardrail = create_guardrail(Settings(llm_upstream_url=upstream), client=gw_upstream)
            async with serve(guardrail) as gw_url, httpx.AsyncClient(timeout=10.0) as client:
                gateway = f"{gw_url}/v1/chat/completions"
                for _ in range(20):  # warm-up: connection pools on both hops
                    await first_content_ms(client, upstream)
                    await first_content_ms(client, gateway)
                direct, guarded = [], []
                for _ in range(runs):  # interleaved, so drift hits both sides equally
                    direct.append(await first_content_ms(client, upstream))
                    guarded.append(await first_content_ms(client, gateway))
    d50, g50 = pct(direct, 50), pct(guarded, 50)
    return [
        (
            "T3",
            f"TTFT direct to mock, p50 / p99 ({runs} runs, loopback)",
            f"{d50:.2f} / {pct(direct, 99):.2f} ms",
        ),
        (
            "T3",
            f"TTFT via guardrail, p50 / p99 ({runs} runs, loopback)",
            f"{g50:.2f} / {pct(guarded, 99):.2f} ms",
        ),
        ("T3", "TTFT delta added by guardrail hop, p50", f"{g50 - d50:.2f} ms"),
    ]


# --- T4 ----------------------------------------------------------------------------------------


async def bench_t4(calls: int, tasks: int, per_task: int) -> list[Row]:
    with tempfile.TemporaryDirectory() as tmp:
        async with SQLiteRateLimiter(Path(tmp) / "bench.db") as lim:
            for _ in range(50):  # warm-up: page cache, prepared statements
                await lim.reserve("warmup", 1)

            async def pair(i: int) -> None:
                # A fresh tenant every 40 calls keeps the window from filling, so every call
                # takes the full evict / sum / insert path and commits.
                reservation = await lim.reserve(f"tenant-{i // 40}", 1_000)
                await lim.reconcile(reservation.id, 600)

            samples = await timed(calls, pair, warmup=0)

            async def worker(w: int) -> None:
                for j in range(per_task):
                    reservation = await lim.reserve(f"conc-{w}", 100)
                    await lim.reconcile(reservation.id, 60)
                    del j

            started = time.perf_counter()
            await asyncio.gather(*(worker(w) for w in range(tasks)))
            elapsed = time.perf_counter() - started
    total = tasks * per_task
    return [
        (
            "T4",
            f"`reserve()` + `reconcile()` on disk, p50 / p99 ({calls:,} sequential pairs)",
            f"{pct(samples, 50):.3f} / {pct(samples, 99):.3f} ms",
        ),
        (
            "T4",
            f"throughput, {tasks} concurrent tasks x {per_task} pairs (one connection)",
            f"{total / elapsed:,.0f} pairs/s ({elapsed:.2f} s for {total:,})",
        ),
    ]


# --- main --------------------------------------------------------------------------------------


async def run_all(scale: int) -> list[Row]:
    rows: list[Row] = []
    rows += await bench_t2(2_000 // scale)
    rows += bench_redactor(50_000 // scale)
    rows += await bench_ttft(200 // scale)
    rows += await bench_t4(2_000 // scale, 50, 100 // scale)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure gateway, guardrail and limiter costs.")
    parser.add_argument("--quick", action="store_true", help="10x fewer iterations")
    args = parser.parse_args()
    quiet_json_logging()
    rows = asyncio.run(run_all(10 if args.quick else 1))
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(f"- **CPU:** {cpu_model()} ({os.cpu_count()} logical cores)")
    print(f"- **OS:** {platform.platform()}")
    print(f"- **Python:** {platform.python_version()} ({platform.python_implementation()})")
    print(f"- **Temp dir (SQLite file):** {tempfile.gettempdir()}")
    print()
    print("| Task | Measurement | Result |")
    print("|---|---|---|")
    for task, name, value in rows:
        print(f"| {task} | {name} | {value} |")


if __name__ == "__main__":
    main()
