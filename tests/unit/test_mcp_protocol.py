"""In-process contract tests for the JSON-RPC layer (the real-subprocess
conformance run is tests/integration/test_mcp_server.py, Task 4)."""
import io
import json
import os

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


def test_known_method_without_id_is_never_answered():
    """A message with no `id` is a notification by JSON-RPC's own definition,
    even when its method name looks like a request (`ping`, `initialize`,
    `tools/*`). Answering it would violate the module docstring's own claim
    ("a method without an id must never be answered")."""
    assert mcp.handle_message({"jsonrpc": "2.0", "method": "ping"}, {}) is None


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


def test_initialize_non_dict_params_defaults_gracefully():
    # A lenient handshake: garbage params must not crash, and default to
    # our latest supported version exactly like an unknown-version request.
    for bad in (5, "x", [1]):
        out = mcp.handle_message(_req(1, "initialize", bad), {})
        assert out == {"jsonrpc": "2.0", "id": 1, "result": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": mcp.SERVER_INFO,
        }}


def test_tools_call_non_dict_params_is_invalid_params():
    # C1 (measured): `params.get` on a bare list/str/int raised
    # AttributeError OUTSIDE this function's try/except and killed serve()'s
    # whole loop. Full-object assert on all three shapes from the brief.
    for bad in (5, "x", [1]):
        out = mcp.handle_message(_req(1, "tools/call", bad), {})
        assert out == {"jsonrpc": "2.0", "id": 1, "error": {
            "code": -32602,
            "message": "Invalid params: params must be an object"}}


def test_tools_call_non_string_name_is_invalid_params():
    # `tools.get(name)` raises TypeError for an unhashable name (dict/list)
    # -- guarded BEFORE the lookup, so the message names the offending
    # value via repr rather than crashing.
    out = mcp.handle_message(_req(1, "tools/call",
                                  {"name": {"a": 1}, "arguments": {}}), {})
    assert out == {"jsonrpc": "2.0", "id": 1, "error": {
        "code": -32602, "message": "Unknown tool: {'a': 1}"}}


def test_tools_call_non_dict_truthy_arguments_is_invalid_params():
    # Before this fix, `arguments = params.get("arguments") or {}` let a
    # truthy non-dict (the `or {}` only substitutes on FALSY values) reach
    # the handler and blow up as a dishonest -32603. Now it is caught here,
    # as an honest -32602, before the handler ever runs.
    tools = {"t1": {"description": "d",
                    "inputSchema": {"type": "object", "properties": {}},
                    "handler": lambda root, args: (0, "ok", "")}}
    out = mcp.handle_message(_req(1, "tools/call",
                                  {"name": "t1", "arguments": [1]}), tools)
    assert out == {"jsonrpc": "2.0", "id": 1, "error": {
        "code": -32602,
        "message": "Invalid params: arguments must be an object"}}


def test_serve_survives_malformed_params_and_keeps_answering(monkeypatch):
    """serve()-level proof that the malformed-params fix holds inside the
    real read loop, not just in handle_message calls made directly: a
    `params: [1]` frame answers -32602 and the NEXT request (ping) still
    gets answered. Driven with a monkeypatched sys.stdin/_protect_stdout
    rather than real pipes -- the real-subprocess conformance test in
    tests/integration/test_mcp_server.py is the load-bearing end-to-end
    proof."""

    class FakeStdin:
        buffer = io.BytesIO(
            b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":[1]}\n'
            b'{"jsonrpc":"2.0","id":3,"method":"ping"}\n')

    monkeypatch.setattr(mcp.sys, "stdin", FakeStdin())
    out = io.StringIO()
    monkeypatch.setattr(mcp, "_protect_stdout", lambda: out)

    rc = mcp.serve({})

    assert rc == 0
    frames = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert frames == [
        {"jsonrpc": "2.0", "id": 2, "error": {
            "code": -32602,
            "message": "Invalid params: params must be an object"}},
        {"jsonrpc": "2.0", "id": 3, "result": {}},
    ]


def test_serve_catches_any_handle_message_exception_and_continues(monkeypatch):
    """Belt-and-braces on serve() itself: even an UNMAPPED future defect in
    handle_message must not kill the loop. handle_message is monkeypatched
    to raise for one message so this test exercises serve()'s own
    try/except, independent of any specific guard inside handle_message."""

    class FakeStdin:
        buffer = io.BytesIO(
            b'{"jsonrpc":"2.0","id":1,"method":"boom"}\n'
            b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n')

    monkeypatch.setattr(mcp.sys, "stdin", FakeStdin())
    out = io.StringIO()
    monkeypatch.setattr(mcp, "_protect_stdout", lambda: out)

    real_handle_message = mcp.handle_message

    def flaky(msg, tools):
        if msg.get("method") == "boom":
            raise RuntimeError("simulated crash")
        return real_handle_message(msg, tools)

    monkeypatch.setattr(mcp, "handle_message", flaky)

    rc = mcp.serve({})

    assert rc == 0
    frames = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert frames == [
        {"jsonrpc": "2.0", "id": 1, "error": {
            "code": -32603, "message": "Internal error"}},
        {"jsonrpc": "2.0", "id": 2, "result": {}},
    ]


def test_write_frame_flushes_to_a_real_pipe():
    """`write_through=True` on the TextIOWrapper only bypasses ITS OWN text
    buffer -- the `os.fdopen(fd, "wb")` underneath is still a BufferedWriter,
    so a write with no explicit flush stays invisible to a reader on the
    other end of a real pipe. A live MCP client would hang on every request
    if `_write_frame` did not flush. Proven against an actual `os.pipe()`,
    not a mock, and read WITHOUT closing the writer -- closing would flush
    on its own and hide exactly the bug this test exists to catch."""
    r, w = os.pipe()
    try:
        wrapper = io.TextIOWrapper(os.fdopen(w, "wb"), encoding="utf-8",
                                   newline="\n", write_through=True)
        payload = {"jsonrpc": "2.0", "id": 1, "result": {}}
        mcp._write_frame(wrapper, payload)
        raw = os.read(r, 65536)
        assert raw.endswith(b"\n")
        assert json.loads(raw.decode("utf-8")) == payload
    finally:
        os.close(r)
        wrapper.close()
