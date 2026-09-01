"""aramid.mcp -- minimal stdio MCP server (spec §7), stdlib only.

`python -P -m aramid.mcp`, spoken by the .mcp.json entry agent_mcp.py
writes. In-house rather than an SDK dependency, per aramid's offline
discipline and the spec's explicit call ("a minimal in-house stdio
server ... rather than a new SDK dependency"); the tool surface is the
contract, this file is plumbing.

WIRE CONTRACT (measured against the working graphite precedent on this
machine -- mcp SDK 1.29.0, LATEST_PROTOCOL_VERSION 2025-11-25 -- and the
MCP spec): newline-delimited JSON-RPC 2.0 over stdio, UTF-8, one message
per line; `initialize` handshake (echo a supported requested version,
else answer our latest), `notifications/initialized` expected but not
required, `ping` -> {}, `tools/list` -> the registry in one page (cursor
ignored), `tools/call` -> {content: [{type: "text", ...}], isError}.
Unknown REQUESTS get -32601 (or -32602 for an unknown tool); unknown
NOTIFICATIONS are silently tolerated -- a method without an id must
never be answered.

STDOUT IS THE PROTOCOL CHANNEL. _protect_stdout() dups fd 1 for the
protocol and repoints fd 1 at stderr, so a subprocess spawned by a tool
(semgrep under cmd_check, git under status) that writes to its inherited
stdout lands on stderr instead of corrupting the stream. Tool handlers
additionally run under redirect_stdout/redirect_stderr capture
(Task 3). Handler exceptions become -32603 with a generic message --
internals never reach the wire.

INPUT SHAPES ARE NEVER TRUSTED, only the JSON-RPC envelope is (serve()
already rejects a non-dict message). `initialize`'s params default to
{} for any non-dict value (a lenient handshake -- an odd client that
sends garbage params still gets a version back). `tools/call` is
stricter, because its params are load-bearing (name/arguments dispatch
a handler): non-dict params, a non-string tool name, or truthy non-dict
arguments each answer -32602 rather than reaching `.get`/dict-dispatch
on a value that cannot support it -- a `"params": [1]` frame used to
raise AttributeError OUTSIDE the handler try/except and kill the
process (measured: the next request was never answered). serve() also
wraps the handle_message call itself in try/except as a last resort --
belt-and-braces for any future defect this file's own guards miss --
answering -32603 and continuing the loop rather than propagating.

`InvalidParams` (imported here as `_InvalidParams`) lives in
`aramid.mcp_errors`, not in this file -- see that module's docstring:
running this file as `__main__` (the real launch command above) and then
having `aramid.mcp_tools` import from `aramid.mcp` by its dotted name
loads this module TWICE as two independent objects, so a class defined
in this file would not `except`-match an instance raised through the
other copy.
"""
import io
import json
import os
import sys

from aramid import __version__
from aramid.mcp_errors import InvalidParams as _InvalidParams

SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")

SERVER_INFO = {"name": "aramid", "version": __version__}


def _result(id_, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _error(id_, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {
        "code": code, "message": message}}


def handle_message(msg: dict, tools: dict) -> dict | None:
    """One JSON-RPC message in, one response out (None for notifications).

    Pure protocol logic -- no I/O -- so the whole surface is testable
    in-process; serve() owns the pipes.
    """
    method = msg.get("method")
    id_ = msg.get("id")
    is_notification = "id" not in msg

    if is_notification:
        return None                       # tolerate every notification

    if method == "initialize":
        params = msg.get("params")
        if not isinstance(params, dict):
            params = {}
        requested = params.get("protocolVersion")
        version = (requested if requested in SUPPORTED_PROTOCOL_VERSIONS
                   else SUPPORTED_PROTOCOL_VERSIONS[0])
        return _result(id_, {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        })
    if method == "ping":
        return _result(id_, {})
    if method == "tools/list":
        return _result(id_, {"tools": [
            {"name": name, "description": spec["description"],
             "inputSchema": spec["inputSchema"]}
            for name, spec in tools.items()]})
    if method == "tools/call":
        params = msg.get("params")
        if not isinstance(params, dict):
            return _error(id_, -32602,
                          "Invalid params: params must be an object")
        name = params.get("name")
        if not isinstance(name, str):
            return _error(id_, -32602, f"Unknown tool: {name!r}")
        spec = tools.get(name)
        if spec is None:
            return _error(id_, -32602, f"Unknown tool: {name}")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return _error(id_, -32602,
                          "Invalid params: arguments must be an object")
        try:
            return _result(id_, spec["handler"](None, arguments))
        except _InvalidParams as exc:
            return _error(id_, -32602, str(exc))
        except Exception:
            return _error(id_, -32603,
                          "Internal error while executing the tool")
    return _error(id_, -32601, f"Method not found: {method}")


def _protect_stdout() -> io.TextIOWrapper:
    """Reserve the protocol channel: dup fd 1 for our frames, repoint
    fd 1 at stderr so stray writes (subprocesses included) cannot
    corrupt the stream. Returns a UTF-8 text wrapper over the dup."""
    proto_fd = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    return io.TextIOWrapper(os.fdopen(proto_fd, "wb"), encoding="utf-8",
                            newline="\n", write_through=True)


def _write_frame(out, obj: dict) -> None:
    """Write one JSON-RPC frame and flush it immediately.

    `write_through=True` on the TextIOWrapper only bypasses ITS OWN text
    buffer -- the underlying `os.fdopen(fd, "wb")` is still a BufferedWriter,
    so without an explicit flush a written frame stays invisible to the
    reader on the other end of the pipe until the buffer fills or the
    process exits. A live client would hang on every request.
    """
    out.write(json.dumps(obj) + "\n")
    out.flush()


def serve(tools: dict) -> int:
    out = _protect_stdout()
    for line in sys.stdin.buffer:
        try:
            msg = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _write_frame(out, _error(None, -32700, "Parse error"))
            continue
        if not isinstance(msg, dict):
            _write_frame(out, _error(None, -32600, "Invalid Request"))
            continue
        try:
            response = handle_message(msg, tools)
        except Exception:
            # Belt-and-braces: handle_message is guarded at every known
            # crash site (C1), but this loop is the process's only chance
            # to survive an UNKNOWN future defect too. `msg` is a dict here
            # (checked above), so `.get("id")` is always safe.
            _write_frame(out, _error(msg.get("id"), -32603, "Internal error"))
            continue
        if response is not None:
            _write_frame(out, response)
    return 0


def main() -> int:
    from aramid.mcp_tools import TOOLS
    return serve(TOOLS)


if __name__ == "__main__":
    raise SystemExit(main())
