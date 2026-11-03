#!/usr/bin/env bash
# Explore the Task 1 STDIO MCP server interactively in the MCP Inspector (documentation only;
# not run by tests or CI). Requires Node.js. The Inspector spawns the server as a child process
# and talks JSON-RPC over its stdin/stdout, exactly like any other MCP host.
#
#   ./scripts/inspect_t1.sh            # normal mode
#   CHAOS=1 ./scripts/inspect_t1.sh    # stray print()/logging/os.write(1) on every call;
#                                      # the Inspector should keep working (all of it goes to stderr)
#
# Things worth trying in the Inspector's Tools tab:
#   get_customer_record {"customer_id": "CUST-10042"}            -> success + structuredContent
#   get_customer_record {"customer_id": "CUST-99999"}            -> isError: true (business error)
#   get_customer_record {"customer_id": "CUST-1234"}             -> JSON-RPC error -32602
#   trigger_refund {"customer_id": "CUST-10042", "amount": "50", "reason": "damaged item"}
#                                                                -> -32602 (strict: string amount)
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${CHAOS:-0}" == "1" ]]; then
  export CP_T1_CHAOS_STDOUT=1
fi

exec npx @modelcontextprotocol/inspector uv run python -m control_plane.task1_mcp_server
