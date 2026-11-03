# ruff: noqa: E402, I001
"""Entrypoint: ``python -m control_plane.task1_mcp_server``.

The first three statements below must stay first. In MCP over STDIO, stdout *is* the wire, so a
single stray byte corrupts the client's framing. Rebinding ``sys.stdout`` only covers Python
``print()``; C extensions, child processes and anything holding the original stream write to
fd 1 directly. So we keep a private duplicate of fd 1 for JSON-RPC frames and point fd 1 itself
at stderr for everyone else, before any other import can capture the old stdout.
"""

import os
import sys

_REAL_STDOUT_FD = os.dup(1)  # private handle reserved for JSON-RPC frames
os.dup2(2, 1)  # fd 1 now points at stderr for everyone else
sys.stdout = sys.stderr  # Python-level print() also goes to stderr

import io

import anyio

from control_plane.common.logging import (
    configure_logging,
    configure_root_logging,
    get_logger,
    log_event,
)

configure_root_logging()
configure_logging(os.environ.get("CP_LOG_LEVEL", "INFO"))

from mcp.server.stdio import stdio_server

from control_plane.task1_mcp_server.server import build_server, chaos_enabled, emit_chaos, serve

_log = get_logger("task1.main")


def _transport_stdout() -> anyio.AsyncFile[str]:
    # newline="\n": the default (None) translates "\n" to "\r\n" on Windows, which breaks
    # strict newline-delimited JSON-RPC readers (PITFALLS #30).
    raw = os.fdopen(_REAL_STDOUT_FD, "wb", buffering=0)
    return anyio.wrap_file(
        io.TextIOWrapper(raw, encoding="utf-8", newline="\n", write_through=True)
    )


async def main() -> None:
    server = build_server()
    log_event(_log, "t1_server_started", chaos=chaos_enabled())
    if chaos_enabled():
        emit_chaos("startup")
    async with stdio_server(stdout=_transport_stdout()) as (read_stream, write_stream):
        await serve(server, read_stream, write_stream)
    log_event(_log, "t1_server_stopped")


if __name__ == "__main__":
    anyio.run(main)
