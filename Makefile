# Thin wrappers over the uv commands in the README; every target runs the same thing by hand.
# `make` is not part of a Windows install: from Git Bash/PowerShell run the command shown.

UV ?= uv
PORT ?= 8000

.PHONY: help install test test-all lint demo demo-fast bench check-matrix run-gateway run-t1 clean

help:  ## list targets
	@grep -E "^[a-z-]+:.*## " $(MAKEFILE_LIST) | sed "s/:.*## /\t/"

install:  ## create .venv and install pinned deps from uv.lock
	$(UV) sync

test:  ## everything except the 4 real-timing / multi-process tests marked slow
	$(UV) run pytest -q -m "not slow"

test-all:  ## everything, including the real-timing and multi-process tests, plus the matrix check
	$(UV) run pytest -q
	$(UV) run python scripts/check_matrix.py

lint:  ## ruff + format check + mypy strict
	$(UV) run ruff check .
	$(UV) run ruff format --check .
	$(UV) run mypy src

demo:  ## scenarios A-E with real 3 s failover timing (~16 s); exit 0 = all passed
	$(UV) run python -m control_plane.e2e_demo

demo-fast:  ## same scenarios with a 0.3 s failover timeout
	$(UV) run python -m control_plane.e2e_demo --fast

bench:  ## T2/T3/T4 latency and throughput table (add ARGS=--quick for a 10x shorter run)
	$(UV) run python scripts/bench.py $(ARGS)

check-matrix:  ## every ACCEPTANCE_MATRIX row is pass and names a test that exists and passes
	$(UV) run python scripts/check_matrix.py --run

run-gateway:  ## unified control plane: /v1/chat/completions (T4+T3) and /mcp (T2 -> T1 child)
	$(UV) run uvicorn control_plane.integration.app:app --port $(PORT)

run-t1:  ## T1 MCP server on stdio (speak JSON-RPC on stdin; logs on stderr)
	$(UV) run python -m control_plane.task1_mcp_server

clean:  ## remove runtime data and caches (never touches .venv)
	rm -rf data .pytest_cache .mypy_cache .ruff_cache .hypothesis
