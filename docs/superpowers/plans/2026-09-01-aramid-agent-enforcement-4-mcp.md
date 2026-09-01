# Agent Enforcement Sub-Project 4: MCP Server + .mcp.json Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `python -P -m aramid.mcp` — a dependency-free stdio MCP server exposing aramid's full loop (check/status/ledger/resolvers/override/mark-*) — plus the `.mcp.json` merge/grade/remove lifecycle with full-shape tampered grading from day one.

**Architecture:** A new `src/aramid/agent_mcp.py` owns the `.mcp.json` entry (same event-bound-era discipline as `agent_settings.py`: whitespace-normalized single-string command template, full-shape grading, foreign entries preserved, unparseable never written). A new `src/aramid/mcp.py` implements newline-delimited JSON-RPC over stdio in-house (initialize handshake, tools/list, tools/call; no SDK), with fd-1 hardening so subprocess leakage can never corrupt the protocol stream, and a tool layer that calls the same `cmd_*` internals the CLI uses under stdout/stderr capture. init/doctor/uninstall/status gain the `.mcp.json` wiring. `cli.py` is NOT touched (no new subcommand — the server is `-m aramid.mcp` directly), so the sub-3 hook fast path's latency is unaffected.

**Tech Stack:** Python stdlib only (`json`, `sys`, `os`, `io`, `contextlib`); pytest with real-subprocess conformance tests.

**Spec:** `docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md` §4 (config-merge plumbing), §7 (MCP server), §8 (lifecycle), §9 (security), §10 (testing). Carry list: memory `agent-enforcement-epic.md` "Sub-4 CARRY LIST".

## Global Constraints

- **Two-aramid discipline:** machine wheel is 0.7.2; run tests as `python -m pytest ...` from the repo root. NEVER `pip install -e .`. Any spawned `python -m aramid...` child in tests MUST use `tests/conftest.py`'s `checkout_env()` (plain function, line ~153) as its env, else it imports the wheel — which has no `aramid.mcp` — and every test is a false result.
- **Protocol contract (MEASURED, not inherited):** the initialize-handshake protocol, newline-delimited JSON-RPC over stdio, UTF-8, one message per line. Ground truth: graphite's working server on this machine rides mcp SDK 1.29.0, `LATEST_PROTOCOL_VERSION = "2025-11-25"`, `DEFAULT_NEGOTIATED_VERSION = "2025-03-26"`, and this session's Claude Code 2.1.252 connects to it. `SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")`; initialize echoes the client's requested version when in that set, else answers `"2025-11-25"`. A guide-agent claim of a "2026-07-28 no-initialize revision" was REFUTED against this precedent — do not implement `server/discover` or `_meta`-namespaced versioning.
- **Stdout is the protocol channel.** Nothing but protocol JSON lines may ever reach the real stdout. The server dup's fd 1 at startup, repoints fd 1 to stderr, and writes protocol frames to the dup — so even a subprocess spawned by `cmd_check` that writes to inherited fd 1 lands on stderr, never in the stream. Tool internals additionally run under `redirect_stdout`/`redirect_stderr` capture.
- **The .mcp.json template mirrors graphite's measured working entry** (no `"type"` key): server key `"aramid"`, value `{"command": "python", "args": ["-P", "-m", "aramid.mcp"]}`, derived from the single constant `MCP_COMMAND = "python -P -m aramid.mcp"` by `.split()` — the constant is one literal so `tests/unit/test_launch_shadowing.py` (AST literal scan) sees `-m aramid` guarded by `-P`. Include that test in EVERY task's green run.
- **Full-shape grading from day one** (sub-3 carry): the owned entry's value must equal the template exactly — keys ⊆ {`command`, `args`}, command/args matching the normalized template; anything else (extra keys, `env`, changed args, missing `-P`) grades `tampered`. Tampered moves doctor to exit 2, same as settings.
- **Fail directions (spec §9):** merge fails closed on unparseable JSON (report, never write); the server never crashes on bad input — protocol errors are JSON-RPC errors, application-state failures (not an onboarded repo, refused suppression) are `isError: true` tool results with a remedy named in the text. Ruling recorded: the spec §7 phrase "refuses (JSON-RPC error, not crash)" is an anti-crash requirement; `isError: true` is the MCP-idiomatic shape for application errors and is what the model can act on — initialize and tools/list succeed anywhere so discovery and approval never break; only tools/call refuses.
- **Suppression parity (spec §7):** `aramid_override`/`aramid_mark_*` call the same internals as the CLI, reason required non-empty (schema `minLength: 1` plus an explicit `-32602` on a missing/empty/whitespace reason); the ledger event is transport-independent.
- **`aramid_check` runs `record=False` always** (ruling): MCP is the consumer-measurement surface — the exact shape that motivated `--no-record` (683-row incident). The tool description states "read-only snapshot; nothing is written to the ledger". Gate recording stays with the git hooks and CLI.
- **Rendered strings/objects asserted in full**, never substrings. Machine isolation: tmp repos only; never touch this repo's own `.mcp.json` (it holds graphite's live entry), `~/.claude`, or the registry. No `aramid init .` dogfood run (post-promotion only).
- **Pre-commit gate** (`python -m aramid check --staged`) before every commit; NEVER `--no-verify`. Ledger baseline: exactly 3 open suppressed findings.
- **EVIDENCE PROTOCOL:** every cited pytest run captured to a log file in the SDD workspace, numbers pasted FROM the file; pytest FOREGROUND with generous timeout, never background-and-wait.

---

### Task 1: `agent_mcp.py` — the .mcp.json merge/grade/remove lifecycle

**Files:**
- Create: `src/aramid/agent_mcp.py`
- Test: `tests/unit/test_agent_mcp.py`

**Interfaces:**
- Consumes: nothing new (mirrors `agent_settings.py` discipline; read that file first for the house style).
- Produces (Tasks 4–5 rely on these): `MCP_REL = Path(".mcp.json")`; `MCP_SERVER_KEY = "aramid"`; `MCP_COMMAND = "python -P -m aramid.mcp"`; `MCP_STATES = ("ok", "absent", "stale", "tampered", "unparseable")`; `KNOWN_PRIOR_MCP_COMMANDS: tuple[str, ...] = ()`; `merge_mcp_json(root) -> str` (created/updated/unchanged/unparseable); `remove_mcp_json(root) -> str` (removed/absent/unparseable); `mcp_state(root) -> str`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_agent_mcp.py`:

```python
"""aramid's entry in a consumer's .mcp.json (spec §4/§7). The graphite
postmortem names .mcp.json the most serious agent surface -- a hijacked
launch means every non-Claude agent talks to whatever the repo planted --
so grading is full-shape from day one."""
import json
from pathlib import Path

from aramid import agent_mcp


def _write(root: Path, data) -> Path:
    p = root / ".mcp.json"
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return p


def _template_entry() -> dict:
    return {"command": "python", "args": ["-P", "-m", "aramid.mcp"]}


def test_command_constant_and_derivation():
    assert agent_mcp.MCP_COMMAND == "python -P -m aramid.mcp"
    assert agent_mcp.MCP_SERVER_KEY == "aramid"
    assert agent_mcp.KNOWN_PRIOR_MCP_COMMANDS == ()


def test_merge_creates_file(tmp_path):
    assert agent_mcp.merge_mcp_json(tmp_path) == "created"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data == {"mcpServers": {"aramid": _template_entry()}}


def test_merge_is_byte_idempotent(tmp_path):
    agent_mcp.merge_mcp_json(tmp_path)
    before = (tmp_path / ".mcp.json").read_bytes()
    assert agent_mcp.merge_mcp_json(tmp_path) == "unchanged"
    assert (tmp_path / ".mcp.json").read_bytes() == before


def test_merge_preserves_foreign_servers_byte_level(tmp_path):
    _write(tmp_path, {"mcpServers": {"graphite": {
        "command": "python", "args": ["-P", "-m", "graphite.mcp"]}}})
    assert agent_mcp.merge_mcp_json(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["graphite"] == {
        "command": "python", "args": ["-P", "-m", "graphite.mcp"]}
    assert data["mcpServers"]["aramid"] == _template_entry()


def test_merge_rewrites_tampered_own_entry(tmp_path):
    # The -P-stripping class, planted under our key.
    _write(tmp_path, {"mcpServers": {"aramid": {
        "command": "python", "args": ["-m", "aramid.mcp"]}}})
    assert agent_mcp.merge_mcp_json(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["aramid"] == _template_entry()


def test_merge_refuses_unparseable(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_text("{not json", encoding="utf-8")
    assert agent_mcp.merge_mcp_json(tmp_path) == "unparseable"
    assert p.read_text(encoding="utf-8") == "{not json"


def test_merge_refuses_wrong_shape(tmp_path):
    _write(tmp_path, {"mcpServers": ["not", "a", "dict"]})
    before = (tmp_path / ".mcp.json").read_bytes()
    assert agent_mcp.merge_mcp_json(tmp_path) == "unparseable"
    assert (tmp_path / ".mcp.json").read_bytes() == before


def test_state_ok_after_merge(tmp_path):
    agent_mcp.merge_mcp_json(tmp_path)
    assert agent_mcp.mcp_state(tmp_path) == "ok"


def test_state_absent_without_file_or_entry(tmp_path):
    assert agent_mcp.mcp_state(tmp_path) == "absent"
    _write(tmp_path, {"mcpServers": {"graphite": {
        "command": "python", "args": ["-P", "-m", "graphite.mcp"]}}})
    assert agent_mcp.mcp_state(tmp_path) == "absent"


def test_full_shape_grading_extra_key_is_tampered(tmp_path):
    entry = _template_entry()
    entry["env"] = {"X": "1"}
    _write(tmp_path, {"mcpServers": {"aramid": entry}})
    assert agent_mcp.mcp_state(tmp_path) == "tampered"


def test_dropped_dash_p_is_tampered(tmp_path):
    _write(tmp_path, {"mcpServers": {"aramid": {
        "command": "python", "args": ["-m", "aramid.mcp"]}}})
    assert agent_mcp.mcp_state(tmp_path) == "tampered"


def test_foreign_key_launching_aramid_mcp_is_tampered(tmp_path):
    # Ownership is the key OR the launch target: a second entry that
    # reaches aramid.mcp under another name is not a foreign server.
    _write(tmp_path, {"mcpServers": {
        "aramid": _template_entry(),
        "helpful-tools": {"command": "python", "args": ["-m", "aramid.mcp"]},
    }})
    assert agent_mcp.mcp_state(tmp_path) == "tampered"


def test_whitespace_respaced_args_still_ok(tmp_path):
    # args come as a list; normalization joins tokens -- a respaced but
    # token-identical entry grades ok.
    _write(tmp_path, {"mcpServers": {"aramid": {
        "command": "python", "args": ["-P", "-m", "aramid.mcp"]}}})
    assert agent_mcp.mcp_state(tmp_path) == "ok"


def test_state_unparseable(tmp_path):
    (tmp_path / ".mcp.json").write_text("{not json", encoding="utf-8")
    assert agent_mcp.mcp_state(tmp_path) == "unparseable"


def test_remove_deletes_entry_and_empty_file(tmp_path):
    agent_mcp.merge_mcp_json(tmp_path)
    assert agent_mcp.remove_mcp_json(tmp_path) == "removed"
    assert not (tmp_path / ".mcp.json").exists()


def test_remove_preserves_foreign_and_file(tmp_path):
    _write(tmp_path, {"mcpServers": {
        "aramid": _template_entry(),
        "graphite": {"command": "python", "args": ["-P", "-m", "graphite.mcp"]},
    }})
    assert agent_mcp.remove_mcp_json(tmp_path) == "removed"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data == {"mcpServers": {"graphite": {
        "command": "python", "args": ["-P", "-m", "graphite.mcp"]}}}


def test_remove_absent_and_unparseable(tmp_path):
    assert agent_mcp.remove_mcp_json(tmp_path) == "absent"
    (tmp_path / ".mcp.json").write_text("{not json", encoding="utf-8")
    assert agent_mcp.remove_mcp_json(tmp_path) == "unparseable"
    assert (tmp_path / ".mcp.json").read_text(encoding="utf-8") == "{not json"


def test_states_constant_is_exhaustive():
    assert set(agent_mcp.MCP_STATES) == {
        "ok", "absent", "stale", "tampered", "unparseable"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_agent_mcp.py -v > <SDD workspace>/task-1-red.log 2>&1`
Expected: FAIL — `ModuleNotFoundError: No module named 'aramid.agent_mcp'`. Paste FROM the log.

- [ ] **Step 3: Write the implementation**

Create `src/aramid/agent_mcp.py`:

```python
"""agent_mcp -- aramid's entry in a consumer's .mcp.json.

Spec: docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md
§4/§7. Same discipline as agent_settings.py, hardened the way sub-3's final
review demanded for settings from day one here: FULL-SHAPE grading. The
graphite postmortem ranks .mcp.json the most serious agent surface -- MCP
is how every non-Claude agent reaches the tool, so a hijacked launch means
the agent talks to whatever the repo planted -- and an entry that keeps
aramid's name while adding an env block, dropping -P, or swapping the
module is exactly that hijack. Anything but the exact template under our
key (or an entry under ANY key whose launch reaches aramid.mcp without
being the template under our key) grades "tampered".

The template mirrors graphite's measured working entry (no "type" key --
Claude Code treats stdio as the default for command entries). The command
lives in ONE single-string constant so tests/unit/test_launch_shadowing.py
sees the `-m aramid` literal with its `-P`; the JSON args list is derived
by .split().

A file that cannot be parsed -- or whose relevant shapes are not the
expected dicts -- is NEVER written: a merge that cannot read what it
merges into must not guess.
"""
import json
from pathlib import Path

MCP_REL = Path(".mcp.json")

MCP_SERVER_KEY = "aramid"

# ONE literal, split into the JSON shape -- never write the args list as
# separate string literals (the launch-shadowing guard scans literals, and
# ["-m", "aramid.mcp"] fragments would be invisible to it).
MCP_COMMAND = "python -P -m aramid.mcp"

# Commands an OLDER template wrote. Empty until the template first changes.
KNOWN_PRIOR_MCP_COMMANDS: tuple[str, ...] = ()

MCP_STATES = ("ok", "absent", "stale", "tampered", "unparseable")


def _template_entry() -> dict:
    parts = MCP_COMMAND.split()
    return {"command": parts[0], "args": parts[1:]}


def _entry_command(entry) -> str | None:
    """The launch a server entry performs, as one normalized string, or
    None for a shape that has no readable command."""
    if not isinstance(entry, dict):
        return None
    cmd = entry.get("command")
    args = entry.get("args", [])
    if not isinstance(cmd, str) or not isinstance(args, list):
        return None
    tokens = [cmd] + [str(a) for a in args]
    return " ".join(" ".join(tokens).split())


def _launches_aramid_mcp(entry) -> bool:
    joined = _entry_command(entry)
    return joined is not None and "aramid.mcp" in joined.split()


def _owned_key(name: str, entry) -> bool:
    return name == MCP_SERVER_KEY or _launches_aramid_mcp(entry)


def _shape_ok(entry) -> bool:
    """Full-shape grade: the entry must BE the template -- same keys, same
    command, token-identical args. An extra key (env, cwd, type, ...) is a
    behavior change wearing aramid's name."""
    if not isinstance(entry, dict) or set(entry) != {"command", "args"}:
        return False
    known = {MCP_COMMAND, *KNOWN_PRIOR_MCP_COMMANDS}
    return _entry_command(entry) in {" ".join(c.split()) for c in known}


def _load(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def merge_mcp_json(root: Path) -> str:
    """Register aramid's server entry; returns "created", "updated",
    "unchanged", or "unparseable" (refused, file untouched). Foreign
    servers are preserved byte-structurally; an owned entry (our key, or
    any entry launching aramid.mcp) is rewritten to the template under
    OUR key -- a generator fix reaches every consumer on the next init."""
    path = root / MCP_REL
    if path.is_file():
        original = path.read_bytes()
        data = _load(path)
        if data is None:
            return "unparseable"
        existed = True
    else:
        original = b""
        data = {}
        existed = False

    servers = data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        return "unparseable"
    for name in [n for n, e in servers.items() if _owned_key(n, e)]:
        del servers[name]
    servers[MCP_SERVER_KEY] = _template_entry()

    rendered = (json.dumps(data, indent=2) + "\n").encode("utf-8")
    if existed and rendered == original:
        return "unchanged"
    path.write_bytes(rendered)
    return "updated" if existed else "created"


def remove_mcp_json(root: Path) -> str:
    """Reverse of merge_mcp_json, for `aramid uninstall`. Returns
    "removed", "absent", or "unparseable". Foreign servers preserved; a
    file left holding nothing is deleted."""
    path = root / MCP_REL
    if not path.is_file():
        return "absent"
    data = _load(path)
    if data is None:
        return "unparseable"
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return "absent"
    owned = [n for n, e in servers.items() if _owned_key(n, e)]
    if not owned:
        return "absent"
    for name in owned:
        del servers[name]
    if not servers:
        del data["mcpServers"]
    if not data:
        path.unlink()
        return "removed"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return "removed"


def mcp_state(root: Path) -> str:
    """Read-only grade for `aramid doctor`. "ok" (exactly one owned entry,
    under our key, exactly the current template), "stale" (owned entry
    matches a KNOWN_PRIOR command in full shape), "tampered" (an owned
    entry -- our key or any entry launching aramid.mcp -- in any other
    shape, including one sitting under a foreign key), "absent",
    "unparseable". Never writes."""
    path = root / MCP_REL
    if not path.is_file():
        return "absent"
    data = _load(path)
    if data is None:
        return "unparseable"
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return "absent"
    owned = {n: e for n, e in servers.items() if _owned_key(n, e)}
    if not owned:
        return "absent"
    if set(owned) != {MCP_SERVER_KEY}:
        return "tampered"
    entry = owned[MCP_SERVER_KEY]
    if not _shape_ok(entry):
        return "tampered"
    if _entry_command(entry) == " ".join(MCP_COMMAND.split()):
        return "ok"
    return "stale"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_agent_mcp.py tests/unit/test_launch_shadowing.py -v > <SDD workspace>/task-1-green.log 2>&1`
Expected: all PASS. Paste FROM the log.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/agent_mcp.py tests/unit/test_agent_mcp.py
git commit -m "feat(mcp): .mcp.json lifecycle -- full-shape grading from day one, foreign servers preserved, unparseable never written"
```

---

### Task 2: `mcp.py` protocol core — framing, handshake, dispatch skeleton

**Files:**
- Create: `src/aramid/mcp.py`
- Test: `tests/unit/test_mcp_protocol.py`

**Interfaces:**
- Consumes: nothing (stdlib only; tool registry arrives in Task 3 — this task ships the core with an EMPTY registry the tests drive directly).
- Produces: `SUPPORTED_PROTOCOL_VERSIONS`, `SERVER_INFO`, `handle_message(msg: dict, tools: dict) -> dict | None` (None for notifications), `serve(tools: dict) -> int` (the blocking stdio loop), `main() -> int`, `_protect_stdout() -> "io.TextIOBase"` (fd-dup hardening), and the `TOOLS` import point Task 3 fills.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_mcp_protocol.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_mcp_protocol.py -v > <SDD workspace>/task-2-red.log 2>&1`
Expected: FAIL — no `aramid.mcp` module. Paste FROM the log.

- [ ] **Step 3: Write the implementation**

Create `src/aramid/mcp.py`:

```python
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
"""
import io
import json
import os
import sys

from aramid import __version__

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

    if method == "initialize":
        params = msg.get("params") or {}
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
        params = msg.get("params") or {}
        name = params.get("name")
        spec = tools.get(name)
        if spec is None:
            return _error(id_, -32602, f"Unknown tool: {name}")
        arguments = params.get("arguments") or {}
        try:
            return _result(id_, spec["handler"](None, arguments))
        except _InvalidParams as exc:
            return _error(id_, -32602, str(exc))
        except Exception:
            return _error(id_, -32603,
                          "Internal error while executing the tool")
    if is_notification:
        return None                       # tolerate every notification
    return _error(id_, -32601, f"Method not found: {method}")


class _InvalidParams(Exception):
    """Raised by tool handlers for missing/invalid arguments -> -32602."""


def _protect_stdout():
    """Reserve the protocol channel: dup fd 1 for our frames, repoint
    fd 1 at stderr so stray writes (subprocesses included) cannot
    corrupt the stream. Returns a UTF-8 text wrapper over the dup."""
    proto_fd = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    return io.TextIOWrapper(os.fdopen(proto_fd, "wb"), encoding="utf-8",
                            newline="\n", write_through=True)


def serve(tools: dict) -> int:
    out = _protect_stdout()
    for line in sys.stdin.buffer:
        try:
            msg = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            out.write(json.dumps(_error(None, -32700, "Parse error")) + "\n")
            continue
        if not isinstance(msg, dict):
            out.write(json.dumps(
                _error(None, -32600, "Invalid request")) + "\n")
            continue
        response = handle_message(msg, tools)
        if response is not None:
            out.write(json.dumps(response) + "\n")
    return 0


def main() -> int:
    from aramid.mcp_tools import TOOLS
    return serve(TOOLS)


if __name__ == "__main__":
    raise SystemExit(main())
```

NOTE for the implementer: the `handler` call passes `None` as the first argument today; Task 3's handlers derive the repo from `Path.cwd()` themselves (the signature keeps a `root` slot so tests can inject one). `aramid.mcp_tools` does not exist until Task 3 — `main()` imports it lazily so this task's tests (which drive `handle_message`/`serve` directly) pass without it.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_mcp_protocol.py tests/unit/test_launch_shadowing.py -v > <SDD workspace>/task-2-green.log 2>&1`
Expected: all PASS. Paste FROM the log.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/mcp.py tests/unit/test_mcp_protocol.py
git commit -m "feat(mcp): stdlib stdio server core -- initialize/tools handshake, fd-1 hardening, notifications tolerated, errors never crash"
```

---

### Task 3: `mcp_tools.py` — the seven tools over the CLI internals

**Files:**
- Create: `src/aramid/mcp_tools.py`
- Test: `tests/unit/test_mcp_tools.py`

**Interfaces:**
- Consumes: `cmd_check(root, gate: Gate, mode: str, strict=False, as_json=False, accept_degraded=None, record=True)` from `aramid.commands.check`; `cmd_status(root)`; `cmd_ledger_filter(root, tool=None, rule=None, status=None, severity=None, as_json=False)`, `cmd_ledger_mark_rotated(root, finding_id, reason)`, `cmd_ledger_mark_not_a_secret(root, finding_id, reason)` from `aramid.commands.ledger_cmd`; `cmd_override(root, finding_id, reason)` from `aramid.commands.override`; `cmd_resolvers(root, as_json=False)` from `aramid.commands.resolvers`; `Gate` from `aramid.models`; `mcp._InvalidParams`; `gitutil.repo_root`.
- Produces: `TOOLS: dict[str, dict]` — keys exactly `("aramid_check", "aramid_status", "aramid_ledger_filter", "aramid_resolvers", "aramid_override", "aramid_mark_not_a_secret", "aramid_mark_rotated")`, each `{"description", "inputSchema", "handler"}`; handlers return the MCP call-result dict `{"content": [{"type": "text", "text": ...}], "isError": bool}`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_mcp_tools.py`. Reuse the repo-building conventions from `tests/integration/test_agent_hook.py` (`_git`/`_repo` helpers) for an onboarded tmp repo — but since these are unit tests calling handlers in-process, build the minimal repo by hand: `git init`, write `aramid.toml` (`schema_version = 1\nsemgrep_block_armed = false\nagent_block_armed = false\n`), `monkeypatch.chdir` into it (handlers derive the repo from cwd):

```python
"""Tool handlers over the CLI internals -- same code path, captured
output, isError only when the OPERATION failed (not when a gate honestly
reports findings)."""
import json
import subprocess
from pathlib import Path

import pytest

from aramid import mcp_tools


def _repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True,
                   capture_output=True)
    (r / "aramid.toml").write_text(
        "schema_version = 1\nsemgrep_block_armed = false\n"
        "agent_block_armed = false\n", encoding="utf-8")
    return r


def test_tool_names_are_exactly_the_spec_seven():
    assert set(mcp_tools.TOOLS) == {
        "aramid_check", "aramid_status", "aramid_ledger_filter",
        "aramid_resolvers", "aramid_override", "aramid_mark_not_a_secret",
        "aramid_mark_rotated"}
    for spec in mcp_tools.TOOLS.values():
        assert set(spec) == {"description", "inputSchema", "handler"}
        assert spec["inputSchema"]["type"] == "object"


def test_status_returns_captured_text(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    out = mcp_tools.TOOLS["aramid_status"]["handler"](None, {})
    assert out["isError"] is False
    assert out["content"][0]["type"] == "text"
    assert "aramid status" in out["content"][0]["text"]


def test_not_onboarded_is_isError_with_remedy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)          # no git repo, no aramid.toml
    out = mcp_tools.TOOLS["aramid_status"]["handler"](None, {})
    assert out["isError"] is True
    assert out["content"] == [{"type": "text", "text":
        "aramid: this directory is not an onboarded repo (no aramid.toml"
        " at the git root) -- run `aramid init` there first."}]


def test_check_snapshot_never_writes_ledger(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    out = mcp_tools.TOOLS["aramid_check"]["handler"](
        None, {"gate": "pre-commit", "staged": True})
    assert out["isError"] is False
    assert not (r / ".aramid" / "ledger.db").exists()


def test_check_rejects_unknown_gate(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    from aramid.mcp import _InvalidParams
    with pytest.raises(_InvalidParams):
        mcp_tools.TOOLS["aramid_check"]["handler"](None, {"gate": "sneaky"})


def test_override_requires_nonempty_reason(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    from aramid.mcp import _InvalidParams
    for bad in ({}, {"id": "abc"}, {"id": "abc", "reason": ""},
                {"id": "abc", "reason": "   "}):
        with pytest.raises(_InvalidParams):
            mcp_tools.TOOLS["aramid_override"]["handler"](None, bad)


def test_override_unknown_finding_is_isError(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    out = mcp_tools.TOOLS["aramid_override"]["handler"](
        None, {"id": "0" * 64, "reason": "test reason"})
    assert out["isError"] is True


def test_ledger_filter_passes_filters(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    out = mcp_tools.TOOLS["aramid_ledger_filter"]["handler"](
        None, {"status": "open"})
    assert out["isError"] is False
```

Also pin every tool's full inputSchema object (one test, `assert mcp_tools.TOOLS["aramid_check"]["inputSchema"] == {...}` for each of the seven — exact values in Step 3).

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_mcp_tools.py -v > <SDD workspace>/task-3-red.log 2>&1`
Expected: FAIL — no `aramid.mcp_tools`. Paste FROM the log.

- [ ] **Step 3: Write the implementation**

Create `src/aramid/mcp_tools.py`:

```python
"""mcp_tools -- the seven MCP tools over the CLI internals (spec §7).

Tools call the SAME functions the CLI commands use -- no subprocess
self-reinvocation, one code path to test, and suppression over MCP
carries identical authority and audit trail to the CLI (the transport
changes, the ledger event does not).

Handlers run the internals under redirect_stdout/redirect_stderr into
buffers: the cmd_* functions speak through print(), and stdout belongs
to the protocol. The captured text IS the tool result. isError marks a
failed OPERATION -- not a gate honestly reporting findings: aramid_check
exiting 3 (blocking findings) did its job and returns isError False
with the report; an override the ledger REFUSED returns isError True.

aramid_check always runs record=False (a ledger SNAPSHOT): MCP is the
consumer-measurement surface, exactly the shape that motivated
`check --no-record` after a consumer's whole-tree look wrote 683 rows.
Recording gate runs stay with the git hooks and the CLI.
"""
import contextlib
import io
from pathlib import Path

from aramid.mcp import _InvalidParams


def _repo() -> Path | None:
    from aramid import gitutil
    try:
        repo = gitutil.repo_root(Path.cwd())
    except Exception:
        return None
    if not (repo / "aramid.toml").is_file():
        return None
    return repo


_NOT_ONBOARDED = (
    "aramid: this directory is not an onboarded repo (no aramid.toml"
    " at the git root) -- run `aramid init` there first.")


def _text_result(text: str, *, is_error: bool) -> dict:
    return {"content": [{"type": "text", "text": text}],
            "isError": is_error}


def _run(fn, *args, ok_codes=(0,), report_codes=(), **kwargs) -> dict:
    """Run a cmd_* internal with stdout+stderr captured; the combined
    text is the tool result. Exit codes in ok_codes and report_codes
    are isError False (report_codes are 'the command worked and is
    telling you something is wrong with the REPO'); everything else is
    isError True."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn(*args, **kwargs)
    text = out.getvalue()
    if err.getvalue():
        text += ("\n[stderr]\n" if text else "[stderr]\n") + err.getvalue()
    text += f"\n(exit code {rc})"
    return _text_result(text, is_error=rc not in (*ok_codes, *report_codes))


def _require_id_and_reason(args: dict) -> tuple[str, str]:
    fid = args.get("id")
    reason = args.get("reason")
    if not isinstance(fid, str) or not fid:
        raise _InvalidParams("`id` is required (a finding id string)")
    if not isinstance(reason, str) or not reason.strip():
        raise _InvalidParams(
            "`reason` is required and must be non-empty -- suppression"
            " without a reason is not recordable")
    return fid, reason


def _onboarded(handler):
    def wrapped(root, args):
        repo = _repo()
        if repo is None:
            return _text_result(_NOT_ONBOARDED, is_error=True)
        return handler(repo, args)
    return wrapped


@_onboarded
def _check(repo, args):
    from aramid.commands.check import cmd_check
    from aramid.models import Gate
    gate_raw = args.get("gate", "pre-commit")
    try:
        gate = Gate(gate_raw)
    except ValueError:
        raise _InvalidParams(
            f"`gate` must be one of pre-commit, pre-push, all"
            f" (got {gate_raw!r})") from None
    if args.get("staged", False):
        mode = "staged"
    elif gate is Gate.ALL:
        mode = "all"
    else:
        mode = "staged" if gate is Gate.PRE_COMMIT else "range"
    return _run(cmd_check, repo, gate, mode,
                strict=bool(args.get("strict", False)),
                record=False, report_codes=(2, 3))


@_onboarded
def _status(repo, args):
    from aramid.commands.status import cmd_status
    return _run(cmd_status, repo)


@_onboarded
def _ledger_filter(repo, args):
    from aramid.commands.ledger_cmd import cmd_ledger_filter
    return _run(cmd_ledger_filter, repo,
                tool=args.get("tool"), rule=args.get("rule"),
                status=args.get("status"), severity=args.get("severity"))


@_onboarded
def _resolvers(repo, args):
    from aramid.commands.resolvers import cmd_resolvers
    return _run(cmd_resolvers, repo)


@_onboarded
def _override(repo, args):
    from aramid.commands.override import cmd_override
    fid, reason = _require_id_and_reason(args)
    return _run(cmd_override, repo, fid, reason)


@_onboarded
def _mark_not_a_secret(repo, args):
    from aramid.commands.ledger_cmd import cmd_ledger_mark_not_a_secret
    fid, reason = _require_id_and_reason(args)
    return _run(cmd_ledger_mark_not_a_secret, repo, fid, reason)


@_onboarded
def _mark_rotated(repo, args):
    from aramid.commands.ledger_cmd import cmd_ledger_mark_rotated
    fid, reason = _require_id_and_reason(args)
    return _run(cmd_ledger_mark_rotated, repo, fid, reason)


_ID_REASON_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "minLength": 1,
               "description": "the finding id (from aramid_ledger_filter)"},
        "reason": {"type": "string", "minLength": 1,
                   "description": "why -- recorded in the ledger"},
    },
    "required": ["id", "reason"],
}

TOOLS: dict[str, dict] = {
    "aramid_check": {
        "description": (
            "Run aramid's security/quality gate against a read-only"
            " SNAPSHOT of the ledger (nothing is written). gate:"
            " pre-commit (default, staged scope), pre-push, or all."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "gate": {"type": "string",
                         "enum": ["pre-commit", "pre-push", "all"]},
                "staged": {"type": "boolean"},
                "strict": {"type": "boolean"},
            },
        },
        "handler": _check,
    },
    "aramid_status": {
        "description": "Live gate posture: open findings, bakes, streaks,"
                       " agent surfaces -- the same output as `aramid"
                       " status`.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": _status,
    },
    "aramid_ledger_filter": {
        "description": "Filter ledger findings (status/tool/rule/severity);"
                       " suppression notes included.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string"}, "tool": {"type": "string"},
                "rule": {"type": "string"}, "severity": {"type": "string"},
            },
        },
        "handler": _ledger_filter,
    },
    "aramid_resolvers": {
        "description": "Per-resolver yield report -- what each analyzer"
                       " actually produced here.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": _resolvers,
    },
    "aramid_override": {
        "description": "Suppress a WARN finding, reason required --"
                       " identical authority and ledger audit trail to"
                       " `aramid override`.",
        "inputSchema": _ID_REASON_SCHEMA,
        "handler": _override,
    },
    "aramid_mark_not_a_secret": {
        "description": "Mark a secret finding as not-a-secret, reason"
                       " required; ledger-logged.",
        "inputSchema": _ID_REASON_SCHEMA,
        "handler": _mark_not_a_secret,
    },
    "aramid_mark_rotated": {
        "description": "Mark a leaked secret as rotated, reason required;"
                       " ledger-logged.",
        "inputSchema": _ID_REASON_SCHEMA,
        "handler": _mark_rotated,
    },
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_mcp_tools.py tests/unit/test_mcp_protocol.py tests/unit/test_launch_shadowing.py -v > <SDD workspace>/task-3-green.log 2>&1`
Expected: all PASS. Paste FROM the log.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/mcp_tools.py tests/unit/test_mcp_tools.py
git commit -m "feat(mcp): seven tools over the CLI internals -- captured output, snapshot check, reason-required suppression"
```

---

### Task 4: Real-subprocess conformance test

**Files:**
- Create: `tests/integration/test_mcp_server.py`

**Interfaces:**
- Consumes: `checkout_env()` from `tests/conftest.py` (plain function — the child MUST import this checkout, the wheel has no `aramid.mcp`); the wire contract from Tasks 2–3.
- Produces: nothing (test-only).

- [ ] **Step 1: Write the test (red is expected only if earlier tasks broke something — this task is the conformance gate, not TDD-new-code)**

Create `tests/integration/test_mcp_server.py`:

```python
"""Spec §10 conformance smoke: spawn the real server, complete a real
initialize handshake, list tools, call aramid_status and one suppression
tool end-to-end against a scratch ledger, and prove stdout purity.

The child is spawned with checkout_env() -- without it the child imports
the installed wheel, which has no aramid.mcp, and every assertion here
would be measuring a different program.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from conftest import checkout_env  # noqa: E402


def _repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True,
                   capture_output=True)
    (r / "aramid.toml").write_text(
        "schema_version = 1\nsemgrep_block_armed = false\n"
        "agent_block_armed = false\n", encoding="utf-8")
    return r


class _Client:
    def __init__(self, cwd: Path):
        self.proc = subprocess.Popen(
            [sys.executable, "-P", "-m", "aramid.mcp"],
            cwd=cwd, env=checkout_env(), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._id = 0

    def request(self, method: str, params=None) -> dict:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        out = json.loads(line.decode("utf-8"))
        assert out["id"] == self._id
        return out

    def notify(self, method: str) -> None:
        self.proc.stdin.write(
            (json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
            .encode("utf-8"))
        self.proc.stdin.flush()

    def close(self) -> tuple[bytes, bytes]:
        self.proc.stdin.close()
        out = self.proc.stdout.read()
        err = self.proc.stderr.read()
        self.proc.wait(timeout=30)
        return out, err


@pytest.fixture
def client(tmp_path):
    c = _Client(_repo(tmp_path))
    yield c
    if c.proc.poll() is None:
        c.proc.kill()
        c.proc.wait(timeout=10)


def _handshake(c: _Client) -> dict:
    out = c.request("initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "conformance-test", "version": "0"}})
    c.notify("notifications/initialized")
    return out


def test_initialize_result_shape(client):
    out = _handshake(client)
    assert out["result"]["protocolVersion"] == "2025-06-18"
    assert out["result"]["capabilities"] == {"tools": {}}
    assert out["result"]["serverInfo"]["name"] == "aramid"


def test_tools_list_names(client):
    _handshake(client)
    out = client.request("tools/list")
    assert [t["name"] for t in out["result"]["tools"]] == [
        "aramid_check", "aramid_status", "aramid_ledger_filter",
        "aramid_resolvers", "aramid_override", "aramid_mark_not_a_secret",
        "aramid_mark_rotated"]


def test_status_call_end_to_end(client):
    _handshake(client)
    out = client.request("tools/call",
                         {"name": "aramid_status", "arguments": {}})
    result = out["result"]
    assert result["isError"] is False
    assert "aramid status" in result["content"][0]["text"]


def test_suppression_tool_end_to_end(client):
    # Unknown id against the scratch ledger: the OPERATION fails ->
    # isError True; the server survives and keeps answering.
    _handshake(client)
    out = client.request("tools/call", {
        "name": "aramid_override",
        "arguments": {"id": "0" * 64, "reason": "conformance probe"}})
    assert out["result"]["isError"] is True
    assert client.request("ping")["result"] == {}


def test_missing_reason_is_invalid_params(client):
    _handshake(client)
    out = client.request("tools/call", {
        "name": "aramid_override", "arguments": {"id": "0" * 64}})
    assert out["error"]["code"] == -32602


def test_unknown_method_and_tool(client):
    _handshake(client)
    assert client.request("prompts/list")["error"]["code"] == -32601
    out = client.request("tools/call", {"name": "nope", "arguments": {}})
    assert out["error"]["code"] == -32602


def test_stdout_is_pure_json_lines_and_eof_exits(tmp_path):
    # A fresh process whose ENTIRE stdout is captured in one read -- the
    # readline-per-request client would have consumed the very lines this
    # test exists to inspect, leaving the purity loop vacuous.
    r = _repo(tmp_path)
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "aramid_status", "arguments": {}}},
    ]
    payload = "".join(json.dumps(m) + "\n" for m in msgs).encode("utf-8")
    proc = subprocess.run(
        [sys.executable, "-P", "-m", "aramid.mcp"], cwd=r,
        env=checkout_env(), input=payload, capture_output=True, timeout=300)
    assert proc.returncode == 0               # EOF -> clean exit
    lines = proc.stdout.splitlines()
    parsed = [json.loads(ln.decode("utf-8")) for ln in lines]  # pure JSON
    assert [p["id"] for p in parsed] == [1, 2, 3]  # every response, in order
    assert parsed[2]["result"]["isError"] is False  # status ran inside


def test_not_onboarded_refuses_calls_but_completes_handshake(tmp_path):
    bare = tmp_path / "bare"
    bare.mkdir()
    c = _Client(bare)
    try:
        _handshake(c)
        assert c.request("tools/list")["result"]["tools"]  # discovery works
        out = c.request("tools/call",
                        {"name": "aramid_status", "arguments": {}})
        assert out["result"]["isError"] is True
        assert "not an onboarded repo" in out["result"]["content"][0]["text"]
    finally:
        c.proc.kill()
        c.proc.wait(timeout=10)
```

(If importing `conftest` that way trips the suite's import mode, move `checkout_env` usage to however existing subprocess tests import it — `tests/integration/test_agent_hook_cli.py` from sub-3 is the working precedent; follow it exactly and say so in the report.)

- [ ] **Step 2: Run the conformance suite**

Run: `python -m pytest tests/integration/test_mcp_server.py -v > <SDD workspace>/task-4-green.log 2>&1`
Expected: all PASS. Paste FROM the log. (If a test fails, the defect is in Task 2/3 code — fix it here with a covering commit, and say what changed.)

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_mcp_server.py
git commit -m "test(mcp): real-subprocess conformance -- handshake, tools, suppression, stdout purity, EOF exit"
```

---

### Task 5: init/doctor/uninstall/status wiring

**Files:**
- Modify: `src/aramid/commands/init.py`, `src/aramid/commands/doctor.py`, `src/aramid/commands/uninstall.py`, `src/aramid/commands/status.py`
- Test: `tests/unit/test_agent_mcp.py` (extend), `tests/integration/test_init.py` (extend), `tests/unit/test_launch_shadowing.py` (run)

**Interfaces:**
- Consumes: `merge_mcp_json`, `remove_mcp_json`, `mcp_state`, `MCP_STATES` (Task 1).
- Produces: `_AGENT_MCP_DETAIL` map in doctor (state-word prose, pinned exhaustive against `MCP_STATES`); `agent_mcp_lines(root)`; mcp tampered joins the exit-2 composite; `render_agent_mcp_notice(root, action)` in init; status agent-surfaces line gains `, mcp {state}`.

- [ ] **Step 1: Write the failing tests**

Extend `tests/unit/test_agent_mcp.py`:

```python
def test_every_mcp_state_has_a_doctor_detail():
    from aramid.commands import doctor
    assert set(doctor._AGENT_MCP_DETAIL) == set(agent_mcp.MCP_STATES)


def test_mcp_detail_prose_echoes_state_words():
    from aramid.commands import doctor
    for state, detail in doctor._AGENT_MCP_DETAIL.items():
        assert detail.startswith(f"{state}:")


def test_doctor_mcp_lines_render_ok_and_tampered(tmp_path):
    from aramid.commands import doctor
    agent_mcp.merge_mcp_json(tmp_path)
    assert doctor.agent_mcp_lines(tmp_path) == [
        "  OK   mcp        ok: aramid MCP server registered (.mcp.json,"
        " `python -P -m aramid.mcp`)"]
    _write(tmp_path, {"mcpServers": {"aramid": {
        "command": "python", "args": ["-m", "aramid.mcp"]}}})
    lines = doctor.agent_mcp_lines(tmp_path)
    assert lines[0].startswith("  WARN mcp        tampered:")
```

In `tests/integration/test_init.py`, extend the existing init/status/uninstall integration tests (find them by the `agent surfaces:` and settings-notice asserts):
- after `cmd_init`, `.mcp.json` exists and equals the template file shape; second init byte-idempotent (fold into the existing idempotence test if one pins the whole tree);
- the status line assert becomes `"agent surfaces: blocks 2/2, hooks ok, mcp ok | baking"` (and the armed variant `... | armed`);
- after `cmd_uninstall`, `.mcp.json` is gone (or foreign-only when a foreign server was present — mirror the settings uninstall test's shape);
- doctor exit-2 on a tampered `.mcp.json` in an otherwise-healthy repo — pin `doctor.editable_consumers_lines` to `lambda *a: []` (MANDATORY, CI installs -e) and assert rc 2 with the tampered stderr line rendered in full:
  `"aramid: doctor: .mcp.json carries an aramid-owned server entry whose shape differs from the template -- treat as tampering; re-run `aramid init` to rewrite it and investigate how it changed"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_agent_mcp.py tests/integration/test_init.py -v > <SDD workspace>/task-5-red.log 2>&1`
Expected: the new asserts FAIL (`_AGENT_MCP_DETAIL` missing, status line short, init writes no .mcp.json). Paste FROM the log.

- [ ] **Step 3: Implement**

1. `src/aramid/commands/doctor.py` — beside `_AGENT_SETTINGS_DETAIL` add:

```python
_AGENT_MCP_DETAIL = {
    "ok": "ok: aramid MCP server registered (.mcp.json,"
          " `python -P -m aramid.mcp`)",
    "absent": "absent: no aramid server entry in .mcp.json -- run"
              " `aramid init`",
    "stale": "stale: aramid's server entry matches an older template --"
             " re-run `aramid init`",
    "tampered": "tampered: an aramid-owned server entry differs from the"
                " template in shape -- treat as tampering; re-run"
                " `aramid init` to rewrite it and investigate how it"
                " changed",
    "unparseable": "unparseable: .mcp.json could not be parsed -- fix the"
                   " JSON, then run `aramid init`",
}


def agent_mcp_lines(root: Path) -> list[str]:
    """One line; tampered moves the exit code (handled in cmd_doctor --
    this renderer stays pure), same contract as agent_settings_lines."""
    from aramid import agent_mcp
    state = agent_mcp.mcp_state(root)
    tag = "OK  " if state == "ok" else "WARN"
    return [f"  {tag} {'mcp':<10} {_AGENT_MCP_DETAIL[state]}"]
```

   In `cmd_doctor`: print `agent_mcp_lines(root)` right after the `agent_settings_lines` loop (inside the same `not during_init` guard); extend the tampered composite — `mcp_tampered = (not during_init and agent_mcp_mod.mcp_state(root) == "tampered")`, print the full stderr line from Step 1's test when set, and `return 2` beside `settings_tampered` (same comment style).
2. `src/aramid/commands/init.py` — in the step that calls `merge_claude_settings`, also call `agent_mcp.merge_mcp_json(root)`; add `render_agent_mcp_notice(root, action)` (sibling of `render_agent_settings_notice`, same three rules: unparseable prints always — `"aramid: init: .mcp.json could not be parsed -- left untouched; fix the JSON and re-run `aramid init` to register aramid's MCP server"`; created/updated inside a work tree prints `"aramid: init: registered aramid's MCP server in .mcp.json -- MCP-capable agents get aramid_check/aramid_status/ledger tools:"` + the `git add .mcp.json && git commit -m "chore: aramid mcp server"` line); wire it into the step-9 notice loop.
3. `src/aramid/commands/uninstall.py` — call `remove_mcp_json`; stderr warning on "unparseable" (mirror the settings warning's wording with `.mcp.json`).
4. `src/aramid/commands/status.py` — `_agent_surfaces_line` renders `f"agent surfaces: blocks {ok}/{len(states)}, hooks {settings_state}, mcp {mcp_state} | {posture}"` (comma style — deliberate divergence from spec §8's "·" example, "e.g." licenses it; sub-3 shipped commas).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_agent_mcp.py tests/integration/test_init.py tests/integration/test_status.py tests/unit/test_agent_settings.py tests/unit/test_launch_shadowing.py -v > <SDD workspace>/task-5-green.log 2>&1`
Expected: all PASS (the green command includes every file this task's edits can affect). Paste FROM the log.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/init.py src/aramid/commands/doctor.py src/aramid/commands/uninstall.py src/aramid/commands/status.py tests/unit/test_agent_mcp.py tests/integration/test_init.py
git commit -m "feat(mcp): init/doctor/uninstall/status wiring -- mcp grades join the agent surfaces, tampered joins exit 2"
```

(Add `tests/integration/test_status.py` to git add if its asserts needed updating.)

---

### Task 6: Docs + CHANGELOG

**Files:**
- Modify: `docs/user-guide.md`, `CHANGELOG.md`, `ARAMID.md` template source if init renders it from code (check `render_aramid_md` — if ARAMID.md content lives in a renderer, add one MCP sentence there; if not, skip ARAMID.md)
- Test: run-only — the full agent-surface set

**Interfaces:** consumes everything shipped; produces no code.

- [ ] **Step 1: Write the docs**

1. `docs/user-guide.md`: in the agent-surfaces section (§6), after the pre-tool-use paragraph, add a paragraph in the guide's voice: `aramid init` also registers an MCP server entry in `.mcp.json` (`python -P -m aramid.mcp`) so MCP-capable agents — Claude Code and every non-Claude agent that speaks MCP — reach the same loop as tools: `aramid_check` (read-only ledger snapshot), `aramid_status`, `aramid_ledger_filter`, `aramid_resolvers`, and the suppression tools (`aramid_override`, `aramid_mark_not_a_secret`, `aramid_mark_rotated`; reason required, ledger-logged with identical authority to the CLI). Doctor grades the entry (`ok`/`stale`/`absent`/`tampered`/`unparseable`); a tampered entry exits 2 — it is the most serious agent surface, because a hijacked launch means the agent talks to whatever the repo planted. Note the status line now reads `agent surfaces: blocks 2/2, hooks ok, mcp ok | baking`.
2. `CHANGELOG.md` `[Unreleased]` `### Added`: `- `python -P -m aramid.mcp`: a dependency-free stdio MCP server exposing the full loop (aramid_check as a read-only snapshot, aramid_status, aramid_ledger_filter, aramid_resolvers, and reason-required suppression tools with the CLI's authority and audit trail); `aramid init` registers it in `.mcp.json` (foreign servers preserved; doctor grades the entry, tampered exits 2).`
3. If `ARAMID.md` is rendered by code (grep `render_aramid_md` in init.py): add one sentence to its agent section naming the MCP tools; update any test pinning that rendered content. If ARAMID.md is not renderer-owned, skip.

- [ ] **Step 2: Run the full agent-surface set green**

Run: `python -m pytest tests/unit/test_agent_mcp.py tests/unit/test_mcp_protocol.py tests/unit/test_mcp_tools.py tests/integration/test_mcp_server.py tests/integration/test_init.py tests/unit/test_agent_files.py tests/unit/test_agent_settings.py tests/unit/test_launch_shadowing.py -v > <SDD workspace>/task-6-green.log 2>&1`
Expected: all PASS. Paste FROM the log.

- [ ] **Step 3: Commit**

```bash
git add docs/user-guide.md CHANGELOG.md
git commit -m "docs(mcp): user-guide agent-surfaces MCP paragraph + changelog"
```

(Add ARAMID.md renderer + its tests to git add if step 1.3 applied.)

---

## After the last task

Hand back to the controller (full suite, then the integration menu — push only on the operator's word). Notes:

- **This completes the four-surface epic.** The next release ships sub-2 + sub-3 + sub-4; the announcement states the aramid version floor (both tracked files — `.claude/settings.json` with `pre-tool-use`, `.mcp.json` with `aramid.mcp` — outrun older wheels, which have neither the subcommand nor the module). After promotion: `aramid init .` here and in consumers; Claude Code will prompt users to approve the project-scope aramid MCP server on first connection.
- **Latency:** `cli.py` untouched; the sub-3 hook fast path is unaffected (no re-measure strictly needed, but the final review may spot-check).
- **Protocol contract is pinned to the measured 2025-11-25-family initialize handshake.** If a future harness moves to a discover-based revision, the server's unknown-method tolerance (-32601, notifications ignored) is the designed degradation; re-pin then, don't speculate now.
- **`aramid_check` snapshot semantics (`record=False` always) is a recorded ruling** — revisit only if a consumer asks for recording over MCP, and then as an explicit opt-in argument, never a default flip.
