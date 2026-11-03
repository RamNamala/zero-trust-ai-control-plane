"""Task 1 - STDIO MCP server (acceptance contract - docs/ACCEPTANCE_MATRIX.md).

Most tests drive the real server as a subprocess over raw newline-delimited JSON-RPC, with the
chaos switch ON, so every assertion is made against exactly what a client would see on the wire.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import sys
from collections.abc import AsyncIterator
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import ValidationError

from control_plane.task1_mcp_server.data import make_refund_id
from control_plane.task1_mcp_server.schemas import TriggerRefundInput

MODULE = "control_plane.task1_mcp_server"
READ_TIMEOUT_S = 15.0
SECRET = "SECRET-ECHO-9f3a"  # noqa: S105 - echo sentinel, not a credential
VALID_REASON = "item arrived damaged"
_MISSING = object()

pytestmark = pytest.mark.subprocess


def _server_env(chaos: bool = True) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("CP_")}
    env["PYTHONIOENCODING"] = "utf-8"
    if chaos:
        env["CP_T1_CHAOS_STDOUT"] = "1"
    return env


class McpStdioProc:
    """Minimal raw JSON-RPC client over a child's stdio. Every read has a timeout so a broken
    server fails the test instead of hanging it, and stderr is drained continuously so the
    child can never block on a full pipe."""

    def __init__(self, proc: asyncio.subprocess.Process) -> None:
        self.proc = proc
        self.stdout_lines: list[bytes] = []
        self._stderr = bytearray()
        self._drain = asyncio.create_task(self._drain_stderr())
        self._next_id = 1000

    @classmethod
    async def start(cls, chaos: bool = True) -> McpStdioProc:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            MODULE,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_server_env(chaos),
        )
        return cls(proc)

    async def _drain_stderr(self) -> None:
        assert self.proc.stderr is not None
        while chunk := await self.proc.stderr.read(4096):
            self._stderr.extend(chunk)

    @property
    def stderr_text(self) -> str:
        return self._stderr.decode("utf-8", errors="replace")

    async def send_raw(self, line: bytes) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(line + b"\n")
        await self.proc.stdin.drain()

    async def send(self, message: dict[str, Any]) -> None:
        await self.send_raw(json.dumps(message).encode())

    async def recv(self) -> dict[str, Any]:
        assert self.proc.stdout is not None
        line = await asyncio.wait_for(self.proc.stdout.readline(), READ_TIMEOUT_S)
        if not line:
            raise AssertionError(f"server closed stdout; stderr:\n{self.stderr_text[-2000:]}")
        self.stdout_lines.append(line)
        message: dict[str, Any] = json.loads(line)
        return message

    async def recv_id(self, request_id: Any) -> dict[str, Any]:
        while True:
            message = await self.recv()
            if "id" in message and message["id"] == request_id:
                # == treats 7 and "7" as different, but True == 1; ids here are never bools.
                return message

    async def request(
        self, method: str, params: dict[str, Any] | None = None, request_id: Any = None
    ) -> dict[str, Any]:
        if request_id is None:
            self._next_id += 1
            request_id = self._next_id
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        await self.send(message)
        return await self.recv_id(request_id)

    async def call_tool(self, name: str, arguments: Any, **extra: Any) -> dict[str, Any]:
        return await self.request("tools/call", {"name": name, "arguments": arguments, **extra})

    async def handshake(self) -> dict[str, Any]:
        response = await self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0"},
            },
        )
        await self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return response

    async def shutdown(self) -> None:
        """Close stdin (the MCP stdio shutdown signal), collect any trailing stdout, and make
        sure the process is gone even if it ignores EOF."""
        try:
            if self.proc.stdin is not None and not self.proc.stdin.is_closing():
                self.proc.stdin.close()
            if self.proc.stdout is not None:
                rest = await asyncio.wait_for(self.proc.stdout.read(), 10)
                self.stdout_lines.extend(rest.splitlines(keepends=True))
            await asyncio.wait_for(self.proc.wait(), 10)
        except (TimeoutError, OSError):
            pass
        finally:
            if self.proc.returncode is None:
                self.proc.kill()
                await self.proc.wait()
            try:
                await asyncio.wait_for(self._drain, 5)
            except (TimeoutError, OSError):
                self._drain.cancel()


@pytest.fixture
async def t1() -> AsyncIterator[McpStdioProc]:
    server = await McpStdioProc.start(chaos=True)
    try:
        await server.handshake()
        yield server
    finally:
        await server.shutdown()


def _error(response: dict[str, Any]) -> dict[str, Any]:
    assert "result" not in response, response
    error: dict[str, Any] = response["error"]
    return error


def _result(response: dict[str, Any]) -> dict[str, Any]:
    assert "error" not in response, response
    result: dict[str, Any] = response["result"]
    return result


def _refund_args(**overrides: Any) -> dict[str, Any]:
    args: dict[str, Any] = {"customer_id": "CUST-10042", "amount": 25.5, "reason": VALID_REASON}
    args.update(overrides)
    return {k: v for k, v in args.items() if v is not _MISSING}


# --- STDIO isolation ----------------------------------------------------------------------------


async def test_stdout_is_pure_jsonrpc_with_chaos_writers() -> None:
    """STDIO isolation: subprocess with `CP_T1_CHAOS_STDOUT=1`; every stdout line `json.loads` and
    has `jsonrpc=="2.0"`
    """
    server = await McpStdioProc.start(chaos=True)
    try:
        await server.handshake()
        await server.request("tools/list")
        await server.call_tool("get_customer_record", {"customer_id": "CUST-10042"})
        await server.call_tool("get_customer_record", {"customer_id": "CUST-99999"})
        await server.call_tool("trigger_refund", _refund_args())
        await server.call_tool("trigger_refund", _refund_args(amount="50"))
        await server.call_tool("nope", {})
        await server.request("foo/bar")
        await server.request("ping")
    finally:
        await server.shutdown()

    assert len(server.stdout_lines) >= 9
    for line in server.stdout_lines:
        assert line.endswith(b"\n") and not line.endswith(b"\r\n"), line
        message = json.loads(line)
        assert isinstance(message, dict), line
        assert message["jsonrpc"] == "2.0", line
    assert b"CHAOS" not in b"".join(server.stdout_lines)


async def test_chaos_output_lands_on_stderr(t1: McpStdioProc) -> None:
    """STDIO isolation: chaos markers appear on stderr"""
    await t1.call_tool("get_customer_record", {"customer_id": "CUST-10042"})
    await t1.shutdown()
    stderr = t1.stderr_text
    for marker in ("CHAOS-PRINT", "CHAOS-LOG", "CHAOS-FD1"):
        assert f"{marker} startup" in stderr
        assert f"{marker} tools/call" in stderr
    assert "t1_server_started" in stderr


async def test_sdk_client_roundtrip() -> None:
    """STDIO isolation: official `mcp` `stdio_client` + `ClientSession` lists tools and calls one"""
    params = StdioServerParameters(command=sys.executable, args=["-m", MODULE], env=_server_env())
    async with asyncio.timeout(30):
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {t.name for t in tools.tools} == {"get_customer_record", "trigger_refund"}

            result = await session.call_tool("get_customer_record", {"customer_id": "CUST-10042"})
            assert result.isError is False
            assert result.structuredContent is not None
            assert result.structuredContent["name"] == "Sarah Connor"
            assert json.loads(result.content[0].text)["customer_id"] == "CUST-10042"  # type: ignore[union-attr]


# --- Protocol compliance ------------------------------------------------------------------------


async def test_initialize_and_tools_list_schemas_are_strict(t1: McpStdioProc) -> None:
    """Protocol compliance: `additionalProperties: false`, pattern present"""
    tools = {tool["name"]: tool for tool in _result(await t1.request("tools/list"))["tools"]}
    assert set(tools) == {"get_customer_record", "trigger_refund"}
    for tool in tools.values():
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert schema["properties"]["customer_id"]["pattern"] == "^CUST-[0-9]{5}$"
        assert "customer_id" in schema["required"]

    refund = tools["trigger_refund"]["inputSchema"]
    assert set(refund["required"]) == {"customer_id", "amount", "reason"}
    assert refund["properties"]["amount"]["exclusiveMinimum"] == 0
    assert refund["properties"]["amount"]["maximum"] == 10_000
    assert refund["properties"]["reason"]["minLength"] == 10
    assert refund["properties"]["reason"]["maxLength"] == 500


async def test_unknown_tool_returns_32602(t1: McpStdioProc) -> None:
    """Protocol compliance"""
    error = _error(await t1.call_tool("admin_reset_key", {}))
    assert error["code"] == -32602
    assert error["message"] == "Unknown tool: admin_reset_key"


async def test_unknown_method_returns_32601(t1: McpStdioProc) -> None:
    """Protocol compliance"""
    error = _error(await t1.request("tools/delete"))
    assert error["code"] == -32601
    assert error["message"] == "Method not found"
    # The session is still healthy afterwards.
    assert _result(await t1.request("ping")) == {}


@pytest.mark.parametrize("request_id", ["abc", 7, "7", 0, ""])
async def test_error_preserves_string_and_int_ids(t1: McpStdioProc, request_id: Any) -> None:
    """Protocol compliance"""
    params = {"name": "nope", "arguments": {}}
    await t1.send({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params})
    response = await t1.recv()
    assert response["id"] == request_id
    assert type(response["id"]) is type(request_id)
    assert _error(response)["code"] == -32602


async def test_business_error_is_iserror_not_protocol_error(t1: McpStdioProc) -> None:
    """Protocol compliance: well-formed unknown customer"""
    result = _result(await t1.call_tool("get_customer_record", {"customer_id": "CUST-99999"}))
    assert result["isError"] is True
    assert result["content"][0]["text"] == "Customer not found: CUST-99999"

    result = _result(await t1.call_tool("trigger_refund", _refund_args(amount=9_999)))
    assert result["isError"] is True
    assert "exceeds" in result["content"][0]["text"]


# --- Validation ---------------------------------------------------------------------------------


async def test_get_customer_record_valid(t1: McpStdioProc) -> None:
    """Validation"""
    result = _result(await t1.call_tool("get_customer_record", {"customer_id": "CUST-10042"}))
    assert result["isError"] is False
    record = result["structuredContent"]
    assert record["name"] == "Sarah Connor"
    assert record["email"] == "sarah.connor@cyberdyne.io"
    assert record["ssn"] == "999-01-4242"
    assert len(record["last_orders"]) == 3
    assert json.loads(result["content"][0]["text"]) == record


@pytest.mark.parametrize("amount", [50, 25.5, 0.01, 1250])
async def test_trigger_refund_valid(t1: McpStdioProc, amount: float) -> None:
    """Validation: (incl. integer amount `50`)"""
    result = _result(await t1.call_tool("trigger_refund", _refund_args(amount=amount)))
    assert result["isError"] is False
    refund = result["structuredContent"]
    assert refund["status"] == "queued"
    assert refund["refund_id"] == make_refund_id("CUST-10042", float(amount), VALID_REASON)
    assert refund["refund_id"].startswith("RF-") and len(refund["refund_id"]) == 13

    # Deterministic: the same request yields the same refund id.
    again = _result(await t1.call_tool("trigger_refund", _refund_args(amount=amount)))
    assert again["structuredContent"]["refund_id"] == refund["refund_id"]


@pytest.mark.parametrize(
    "customer_id",
    [
        "CUST-1234",
        "CUST-123456",
        "cust-12345",
        "CUST-12345\n",
        " CUST-12345",
        "CUST-١٢٣٤٥",  # Arabic-Indic digits: matched by \d, rejected by [0-9]
        "12345",
        None,
        12345,
    ],
    ids=repr,
)
async def test_invalid_customer_id_variants(t1: McpStdioProc, customer_id: Any) -> None:
    """Validation: parametrize: `CUST-1234`, `CUST-123456`, `cust-12345`, `CUST-12345\\n`,
    `" CUST-12345"`, `CUST-١٢٣٤٥` (Arabic-Indic digits), `12345`, `None`, `12345` (int)
    """
    for tool, args in (
        ("get_customer_record", {"customer_id": customer_id}),
        ("trigger_refund", _refund_args(customer_id=customer_id)),
    ):
        error = _error(await t1.call_tool(tool, args))
        assert error["code"] == -32602
        assert error["message"] == "Invalid params"
        assert [e["loc"] for e in error["data"]] == [["customer_id"]]


_RAW = "__RAW_JSON_TOKEN__"


@pytest.mark.parametrize(
    "amount",
    [0, -5, "50", True, 10.999, 10_000.01, 1e308, None, "NaN", "Infinity", "-Infinity"],
    ids=repr,
)
async def test_invalid_amount_variants(t1: McpStdioProc, amount: Any) -> None:
    """Validation: `0`, `-5`, `"50"`, `true`, `NaN`/`inf` (if transportable), `10.999`, `> 10000`"""
    if amount in ("NaN", "Infinity", "-Infinity"):
        # Not valid JSON, but Python's json module (and pydantic's parser) accept the bare
        # tokens, so a sloppy client can send them. Inject the bare token into the frame.
        frame = {
            "jsonrpc": "2.0",
            "id": 77,
            "method": "tools/call",
            "params": {"name": "trigger_refund", "arguments": _refund_args(amount=_RAW)},
        }
        await t1.send_raw(json.dumps(frame).replace(f'"{_RAW}"', amount).encode())
        error = _error(await t1.recv_id(77))
        assert error["code"] in (-32602, -32700, -32600)
        return
    error = _error(await t1.call_tool("trigger_refund", _refund_args(amount=amount)))
    assert error["code"] == -32602
    assert [e["loc"] for e in error["data"]] == [["amount"]]


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_amount_rejects_non_finite_in_model(value: float) -> None:
    """Covers ``allow_inf_nan=False`` independently of what the transport lets through."""
    with pytest.raises(ValidationError):
        TriggerRefundInput.model_validate(
            {"customer_id": "CUST-10042", "amount": value, "reason": VALID_REASON}
        )


@pytest.mark.parametrize("amount", [10.1, 10.25, 0.01, 50, 9_999.99])
def test_amount_two_decimals_accepted_in_model(amount: float) -> None:
    model = TriggerRefundInput.model_validate(
        {"customer_id": "CUST-10042", "amount": amount, "reason": VALID_REASON}
    )
    assert model.amount == amount


@pytest.mark.parametrize(
    "reason", ["short", "         x", "  123456789  ", "x" * 501, _MISSING, 42]
)
async def test_invalid_reason_variants(t1: McpStdioProc, reason: Any) -> None:
    """Validation: `"short"`, `"         x"` (stripped < 10), missing"""
    error = _error(await t1.call_tool("trigger_refund", _refund_args(reason=reason)))
    assert error["code"] == -32602
    assert [e["loc"] for e in error["data"]] == [["reason"]]


async def test_reason_is_stripped_before_length_check(t1: McpStdioProc) -> None:
    padded = f"   {VALID_REASON}   "
    result = _result(await t1.call_tool("trigger_refund", _refund_args(reason=padded)))
    assert result["structuredContent"]["refund_id"] == make_refund_id(
        "CUST-10042", 25.5, VALID_REASON
    )


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("get_customer_record", {"customer_id": "CUST-10042", "include_ssn": True}),
        ("trigger_refund", _refund_args(currency="USD")),
        ("trigger_refund", _refund_args(customer_id="CUST-10042", approved_by="admin")),
    ],
)
async def test_extra_fields_rejected(t1: McpStdioProc, tool: str, args: dict[str, Any]) -> None:
    """Validation"""
    error = _error(await t1.call_tool(tool, args))
    assert error["code"] == -32602
    assert [e["type"] for e in error["data"]] == ["extra_forbidden"]


async def test_missing_arguments_treated_as_empty_object(t1: McpStdioProc) -> None:
    response = await t1.request("tools/call", {"name": "get_customer_record"})
    error = _error(response)
    assert error["code"] == -32602
    assert error["data"] == [{"loc": ["customer_id"], "msg": "Field required", "type": "missing"}]


async def test_validation_error_data_does_not_echo_input(t1: McpStdioProc) -> None:
    """Validation"""
    args = {"customer_id": SECRET, "amount": SECRET, "reason": SECRET[:5], SECRET: SECRET}
    response = await t1.call_tool("trigger_refund", args)
    error = _error(response)
    assert error["code"] == -32602
    for item in error["data"]:
        assert set(item) == {"loc", "msg", "type"}
    # The extra key's *name* appears in loc (it's the location of the problem) - nothing else.
    raw = t1.stdout_lines[-1].decode()
    assert raw.count(SECRET) == 1
    assert {tuple(e["loc"]) for e in error["data"]} >= {("customer_id",), ("amount",), (SECRET,)}

    # Logs never carry arguments either.
    await t1.shutdown()
    assert SECRET not in t1.stderr_text
    assert VALID_REASON not in t1.stderr_text


async def test_malformed_params_do_not_leak_to_stderr(t1: McpStdioProc) -> None:
    """mcp 1.x logs a full pydantic dump (with input_value) when a request fails its own
    union validation; our root-log sanitizer must keep that out of stderr."""
    error = _error(await t1.request("tools/call", {"name": "trigger_refund", "arguments": SECRET}))
    assert error["code"] == -32602
    await t1.shutdown()
    assert "Failed to validate request" in t1.stderr_text
    assert SECRET not in t1.stderr_text


async def test_correlation_id_from_meta_is_logged(t1: McpStdioProc) -> None:
    correlation_id = "corr-t1-abcdef12"
    await t1.call_tool(
        "get_customer_record",
        {"customer_id": "CUST-10042"},
        _meta={"correlationId": correlation_id},
    )
    await t1.call_tool(
        "get_customer_record", {"customer_id": "CUST-10042"}, _meta={"correlationId": "bad\nid"}
    )
    await t1.shutdown()
    tool_logs = [
        json.loads(line)
        for line in t1.stderr_text.splitlines()
        if line.startswith("{") and '"event": "tool_call"' in line
    ]
    assert [log["correlation_id"] for log in tool_logs] == [correlation_id, None]
    assert all(log["outcome"] == "ok" for log in tool_logs)
    # Record contents never reach the log.
    assert "Sarah Connor" not in t1.stderr_text
    assert "999-01-4242" not in t1.stderr_text
