"""Measures the numbers the README is allowed to quote (SPEC §7). Nothing here is a claim until
this script has printed it on the machine named in the output.

    uv run python scripts/bench.py [--reserve-calls 1000]

Sections so far: T4 ``reserve()`` latency on an on-disk WAL database. (T2 policy overhead and
T3 per-chunk redaction cost get added in their own sections.)
"""

from __future__ import annotations

import argparse
import asyncio
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

from control_plane.task4_resilient_router.rate_limiter import SQLiteRateLimiter


def _pct(sorted_ms: list[float], p: float) -> float:
    index = min(len(sorted_ms) - 1, max(0, round(p / 100 * len(sorted_ms)) - 1))
    return sorted_ms[index]


async def bench_reserve(calls: int) -> dict[str, float]:
    """Sequential calls, one tenant per 50 calls so the window never fills (every call does the
    full evict/sum/insert path and commits). Each sample includes the ``BEGIN IMMEDIATE``
    write-lock acquisition and the WAL commit with ``synchronous=NORMAL``."""
    with tempfile.TemporaryDirectory() as tmp:
        async with SQLiteRateLimiter(Path(tmp) / "bench.db") as lim:
            for _ in range(50):  # warm-up: page cache, prepared statement cache
                await lim.reserve("warmup", 1)
            samples: list[float] = []
            for i in range(calls):
                started = time.perf_counter()
                await lim.reserve(f"tenant-{i // 50}", 1_000)
                samples.append((time.perf_counter() - started) * 1000)
    samples.sort()
    return {
        "calls": calls,
        "p50_ms": _pct(samples, 50),
        "p99_ms": _pct(samples, 99),
        "mean_ms": statistics.fmean(samples),
        "max_ms": samples[-1],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reserve-calls", type=int, default=1_000)
    args = parser.parse_args()
    print(
        f"host: {platform.platform()} | {platform.processor() or platform.machine()} | "
        f"python {sys.version.split()[0]}"
    )
    r = asyncio.run(bench_reserve(args.reserve_calls))
    print(
        f"T4 reserve() on disk, {r['calls']:.0f} calls: p50 {r['p50_ms']:.3f} ms | "
        f"p99 {r['p99_ms']:.3f} ms | mean {r['mean_ms']:.3f} ms | max {r['max_ms']:.3f} ms"
    )


if __name__ == "__main__":
    main()
