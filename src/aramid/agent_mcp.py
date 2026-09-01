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
