"""In-process contract tests for the JSON-RPC layer (the real-subprocess
conformance run is tests/integration/test_mcp_server.py, Task 4)."""
import json

from aramid import mcp


def _req(id_, method, params=None):
    m = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        m["params"] = params
    return m


def test_initialize_echoes_supported_version():
    out = mcp.handle_message(_req(1, "initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}), {})
    assert out == {"jsonrpc": "2.0", "id": 1, "result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}},
        "serverInfo": mcp.SERVER_INFO,
    }}


def test_initialize_unknown_version_answers_latest():
    out = mcp.handle_message(_req(1, "initialize", {
        "protocolVersion": "1999-01-01", "capabilities": {}}), {})
    assert out["result"]["protocolVersion"] == "2025-11-25"


def test_initialized_notification_returns_none():
    assert mcp.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}, {}) is None


def test_ping_returns_empty_result():
    assert mcp.handle_message(_req(7, "ping"), {}) == {
        "jsonrpc": "2.0", "id": 7, "result": {}}


def test_tools_list_renders_registry():
    tools = {"t1": {"description": "does t1",
                    "inputSchema": {"type": "object", "properties": {}},
                    "handler": lambda root, args: (0, "ok", "")}}
    out = mcp.handle_message(_req(2, "tools/list"), tools)
    assert out == {"jsonrpc": "2.0", "id": 2, "result": {"tools": [
        {"name": "t1", "description": "does t1",
         "inputSchema": {"type": "object", "properties": {}}}]}}


def test_unknown_method_is_32601():
    out = mcp.handle_message(_req(3, "prompts/list"), {})
    assert out == {"jsonrpc": "2.0", "id": 3, "error": {
        "code": -32601, "message": "Method not found: prompts/list"}}


def test_unknown_tool_is_32602():
    out = mcp.handle_message(_req(4, "tools/call",
                                  {"name": "nope", "arguments": {}}), {})
    assert out == {"jsonrpc": "2.0", "id": 4, "error": {
        "code": -32602, "message": "Unknown tool: nope"}}


def test_unknown_notification_is_silently_tolerated():
    assert mcp.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/cancelled",
         "params": {"id": 3}}, {}) is None


def test_handler_exception_becomes_internal_error_not_crash():
    def boom(root, args):
        raise RuntimeError("kaput")
    tools = {"t": {"description": "d",
                   "inputSchema": {"type": "object", "properties": {}},
                   "handler": boom}}
    out = mcp.handle_message(_req(5, "tools/call",
                                  {"name": "t", "arguments": {}}), tools)
    assert out["error"]["code"] == -32603
    assert "kaput" not in json.dumps(out)   # no internals leak to the wire
