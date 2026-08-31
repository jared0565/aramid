"""agent_settings -- aramid's entries in a consumer's .claude/settings.json.

Spec: docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md §4.

Own-entry-by-marker discipline, same as the git-hook installer's
chain-never-clobber and graphite's .mcp.json handling: an entry whose hook
command contains `-m aramid agent-hook` is aramid's and is rewritten to the
current template on every merge (a generator fix reaches every consumer on
their next `init`); every other entry is preserved structurally intact. A
file that cannot be parsed -- or whose relevant shapes are not the expected
dict/list -- is NEVER written: a merge that cannot read what it merges into
must not guess.

The template carries ONLY the SessionStart entry today. The PreToolUse
entry ships in sub-project 3 together with the subcommand that serves it --
init must never register a hook nothing can answer.

Hook commands never grow flags -- new behavior gets a new event name;
older binaries must no-op on newer commands.
"""
import json
from pathlib import Path

SETTINGS_REL = Path(".claude") / "settings.json"

_OWNED_MARK = "-m aramid agent-hook"

SESSION_START_COMMAND = "python -P -m aramid agent-hook session-start"

# Every command the CURRENT template writes.
TEMPLATE_COMMANDS: tuple[str, ...] = (SESSION_START_COMMAND,)

# Commands an OLDER template wrote. An owned entry matching one of these
# grades "stale" (advisory: re-run init); an owned entry matching neither
# set grades "tampered" (a security signal). Empty until the template
# first changes.
KNOWN_PRIOR_COMMANDS: tuple[str, ...] = ()


def _session_start_entry() -> dict:
    return {"hooks": [{"type": "command", "command": SESSION_START_COMMAND}]}


def _owned(entry) -> bool:
    if not isinstance(entry, dict):
        return False
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return False
    return any(isinstance(h, dict) and _OWNED_MARK in str(h.get("command", ""))
               for h in hooks)


def _owned_commands(data: dict) -> list[str]:
    """Every hook command in aramid-owned entries, across ALL hook events."""
    cmds: list[str] = []
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return cmds
    for arr in hooks.values():
        if not isinstance(arr, list):
            continue
        for entry in arr:
            if _owned(entry):
                for h in entry["hooks"]:
                    if isinstance(h, dict):
                        cmds.append(str(h.get("command", "")))
    return cmds


def _load(path: Path):
    """Parsed dict, or None for anything the merge must refuse to touch."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def merge_claude_settings(root: Path) -> str:
    """Register aramid's hook entries; returns "created" (file was absent),
    "updated", "unchanged", or "unparseable" (refused, file untouched)."""
    path = root / SETTINGS_REL
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

    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        return "unparseable"
    arr = hooks.setdefault("SessionStart", [])
    if not isinstance(arr, list):
        return "unparseable"

    hooks["SessionStart"] = [e for e in arr if not _owned(e)] + [_session_start_entry()]
    rendered = (json.dumps(data, indent=2) + "\n").encode("utf-8")
    if existed and rendered == original:
        return "unchanged"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(rendered)
    return "updated" if existed else "created"


# The full range settings_state can return; doctor's detail map is pinned
# against this in tests (same pattern as agent_files.AGENT_BLOCK_STATES).
SETTINGS_STATES = ("ok", "absent", "stale", "tampered", "unparseable")


def remove_claude_settings(root: Path) -> str:
    """Reverse of merge_claude_settings, for `aramid uninstall`.

    Sweeps EVERY hook-event array for aramid-owned entries (forward-compat:
    later sub-projects add more events), drops emptied structures, deletes a
    file left holding nothing -- and leaves `.claude/` itself in place,
    because other tools own files there. Returns "removed", "absent" (no
    file, or nothing of ours in it), or "unparseable" (refused, untouched).
    """
    path = root / SETTINGS_REL
    if not path.is_file():
        return "absent"
    data = _load(path)
    if data is None:
        return "unparseable"

    changed = False
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event in list(hooks):
            arr = hooks[event]
            if not isinstance(arr, list):
                continue
            kept = [e for e in arr if not _owned(e)]
            if kept != arr:
                changed = True
                if kept:
                    hooks[event] = kept
                else:
                    del hooks[event]
        if not hooks:
            del data["hooks"]
    if not changed:
        return "absent"
    if not data:
        path.unlink()
        return "removed"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return "removed"


def settings_state(root: Path) -> str:
    """Read-only grade of aramid's presence in .claude/settings.json.

    "ok" (owned commands are exactly the current template), "stale" (owned
    commands are all known -- current or prior template -- but not the
    current set), "tampered" (an owned command matches NO known template:
    the -P-stripping class of edit; doctor exits 2 on it), "absent",
    "unparseable". Never writes.
    """
    path = root / SETTINGS_REL
    if not path.is_file():
        return "absent"
    data = _load(path)
    if data is None:
        return "unparseable"
    cmds = _owned_commands(data)
    if not cmds:
        return "absent"
    known = set(TEMPLATE_COMMANDS) | set(KNOWN_PRIOR_COMMANDS)
    if any(c not in known for c in cmds):
        return "tampered"
    if set(cmds) == set(TEMPLATE_COMMANDS):
        return "ok"
    return "stale"
