"""
VERIFIED SPIKE for Task 1 against mcp==1.30.0 (Python 3.13), 2026-11-03.

Observed on the wire (stdout), driven by a raw subprocess client:
  {"jsonrpc":"2.0","id":1,"result":{...initialize...}}
  {"jsonrpc":"2.0","id":"abc","error":{"code":-32602,"message":"Invalid params","data":[...]}}
  {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"fine"}],"isError":false}}
and the stray print() + raw os.write(1, ...) both landed on STDERR, not stdout.

Two facts this proves:
  1. Registering a handler directly in server.request_handlers[types.CallToolRequest] and
     raising McpError(ErrorData(code=-32602, ...)) produces a real JSON-RPC error frame.
     (The @server.call_tool() decorator, by contrast, catches exceptions and returns
     CallToolResult(isError=True) - a soft error, which is NOT what Task 1 asks for.)
  2. FD-level isolation works: dup the real fd 1 for the transport, then dup2(2, 1) so that
     *anything* writing to fd 1 (print, logging misconfig, C extensions, child processes)
     goes to stderr.

WARNING: mcp 2.x (2.0.0+) has a different low-level API (constructor callbacks
on_call_tool=..., add_request_handler(method, params_type, handler), a new runner).
This spike does NOT run on 2.x. The kit pins mcp>=1.27,<2. If you deliberately move to
2.x, re-run an equivalent spike first and update the pin in pyproject.toml.
"""
# ---- MUST be the first lines executed in the server entrypoint (__main__.py) ----
import os
import sys

_REAL_STDOUT_FD = os.dup(1)   # private handle reserved for JSON-RPC frames
os.dup2(2, 1)                 # fd 1 now points at stderr for everyone else
sys.stdout = sys.stderr       # Python-level print() also goes to stderr
# ---------------------------------------------------------------------------------

import io  # noqa: E402
import logging  # noqa: E402

import anyio  # noqa: E402

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

import mcp.types as t  # noqa: E402
from mcp.server.lowlevel import Server  # noqa: E402
from mcp.server.stdio import stdio_server  # noqa: E402
from mcp.shared.exceptions import McpError  # noqa: E402

server = Server("spike")


async def call_tool(req: t.CallToolRequest) -> t.ServerResult:
    print("STRAY PRINT")                 # proves isolation: goes to stderr
    os.write(1, b"RAW FD1 WRITE\n")      # proves fd-level isolation: goes to stderr
    if req.params.name != "ok":
        raise McpError(t.ErrorData(code=-32602, message="Invalid params",
                                   data=[{"loc": ["customer_id"]}]))
    return t.ServerResult(t.CallToolResult(content=[t.TextContent(type="text", text="fine")]))


server.request_handlers[t.CallToolRequest] = call_tool


@server.list_tools()
async def list_tools() -> list[t.Tool]:
    return [t.Tool(name="ok", inputSchema={"type": "object"})]


async def main() -> None:
    transport_out = anyio.wrap_file(
        io.TextIOWrapper(os.fdopen(_REAL_STDOUT_FD, "wb", buffering=0),
                         encoding="utf-8", write_through=True)
    )
    async with stdio_server(stdout=transport_out) as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
