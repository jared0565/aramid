"""agent_settings -- aramid's entries in a consumer's .claude/settings.json.

Spec: docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md §4.

Own-entry-by-marker discipline, same as the git-hook installer's
chain-never-clobber and graphite's .mcp.json handling: an entry whose hook
command contains `aramid agent-hook` is aramid's and is rewritten to the
current template on every merge (a generator fix reaches every consumer on
their next `init`); every other entry is preserved structurally intact. A
file that cannot be parsed -- or whose relevant shapes are not the expected
dict/list -- is NEVER written: a merge that cannot read what it merges into
must not guess.

The template carries the SessionStart and PreToolUse entries. Ownership and
grading are EVENT-BOUND: commands are compared against the template of the
event array they sit in, so an entry moved to a foreign event can never
grade ok, and the merge repairs every event it manages.

Hook commands never grow flags -- new behavior gets a new event name;
older binaries must no-op on newer commands.
"""
import json
from pathlib import Path

SETTINGS_REL = Path(".claude") / "settings.json"

# Deliberately WITHOUT the "-m " prefix: the bare token pair discriminates
# identically, and an "-m aramid" literal is indistinguishable from an
# unguarded launch to tests/unit/test_launch_shadowing.py (see its module
# docstring).
_OWNED_MARK = "aramid agent-hook"

SESSION_START_COMMAND = "python -P -m aramid agent-hook session-start"
PRE_TOOL_USE_COMMAND = "python -P -m aramid agent-hook pre-tool-use"

# Matcher for PreToolUse entries (SessionStart entries carry none). Pinned
# against Claude Code 2.1.252: PowerShell is a distinct tool on Windows.
PRE_TOOL_USE_MATCHER = "Bash|PowerShell"

# event -> commands the CURRENT template writes under that event. Grading
# is per event: a command is judged against the template of the array it
# actually sits in, never against a flat union (an armed rejector must not
# read "ok" because a DIFFERENT event's entry still matches).
TEMPLATE_COMMANDS: dict[str, tuple[str, ...]] = {
    "SessionStart": (SESSION_START_COMMAND,),
    "PreToolUse": (PRE_TOOL_USE_COMMAND,),
}

# event -> commands an OLDER template wrote under that event. An owned
# command matching only these grades "stale" (advisory: re-run init); one
# matching neither set grades "tampered". Empty: both current commands
# have never changed, and the session-start command deliberately stays
# current when new events ship (sub-2 "After the last task").
KNOWN_PRIOR_COMMANDS: dict[str, tuple[str, ...]] = {}


def _norm(cmd: str) -> str:
    """Whitespace-normalized command text: ownership and template grading
    both run on this, so a command respaced by another JSON tool is still
    ours (raw-substring matching read it as foreign, and then BOTH entries
    ran). Shell execution is whitespace-invariant for these commands, so
    normalizing cannot mistake a semantically different launch for ours."""
    return " ".join(cmd.split())


def _template_entry(event: str) -> dict:
    entry: dict = {}
    if event == "PreToolUse":
        entry["matcher"] = PRE_TOOL_USE_MATCHER
    entry["hooks"] = [{"type": "command", "command": c}
                      for c in TEMPLATE_COMMANDS[event]]
    return entry


def _owned(entry) -> bool:
    if not isinstance(entry, dict):
        return False
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return False
    return any(isinstance(h, dict)
               and _OWNED_MARK in _norm(str(h.get("command", "")))
               for h in hooks)


def _owned_commands_by_event(data: dict) -> dict[str, list[str]]:
    """Normalized hook commands in aramid-owned entries, keyed by the hook
    event array they sit in."""
    by_event: dict[str, list[str]] = {}
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return by_event
    for event, arr in hooks.items():
        if not isinstance(arr, list):
            continue
        for entry in arr:
            if _owned(entry):
                for h in entry["hooks"]:
                    if isinstance(h, dict):
                        by_event.setdefault(event, []).append(
                            _norm(str(h.get("command", ""))))
    return by_event


def _load(path: Path):
    """Parsed dict, or None for anything the merge must refuse to touch."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def merge_claude_settings(root: Path) -> str:
    """Register aramid's hook entries; returns "created" (file was absent),
    "updated", "unchanged", or "unparseable" (refused, file untouched).
    Writes every template event; sweeps aramid-owned entries out of every
    OTHER event first, so a hand-moved entry cannot keep firing beside the
    fresh ones."""
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
    for event in TEMPLATE_COMMANDS:
        if event in hooks and not isinstance(hooks[event], list):
            return "unparseable"

    for event in list(hooks):
        arr = hooks[event]
        if not isinstance(arr, list):
            continue                      # foreign shape, preserved as-is
        kept = [e for e in arr if not _owned(e)]
        if kept:
            hooks[event] = kept
        elif event in TEMPLATE_COMMANDS:
            hooks[event] = []
        else:
            del hooks[event]
    for event in TEMPLATE_COMMANDS:
        hooks.setdefault(event, []).append(_template_entry(event))

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

    "ok" (every template event's owned commands are exactly that event's
    current template), "stale" (every owned command is known FOR ITS EVENT
    -- current or prior template -- but the per-event sets differ from the
    current template, e.g. a sub-2 consumer missing the PreToolUse entry),
    "tampered" (an owned command matches no known template for the event it
    sits in: the -P-stripping class of edit, and equally an entry moved to
    a foreign event), "absent", "unparseable". Comparison is
    whitespace-normalized on both sides. Never writes.
    """
    path = root / SETTINGS_REL
    if not path.is_file():
        return "absent"
    data = _load(path)
    if data is None:
        return "unparseable"
    by_event = _owned_commands_by_event(data)
    if not by_event:
        return "absent"
    for event, cmds in by_event.items():
        known = ({_norm(c) for c in TEMPLATE_COMMANDS.get(event, ())}
                 | {_norm(c) for c in KNOWN_PRIOR_COMMANDS.get(event, ())})
        if any(c not in known for c in cmds):
            return "tampered"
    if all(set(by_event.get(event, ())) == {_norm(c) for c in cmds}
           for event, cmds in TEMPLATE_COMMANDS.items()):
        return "ok"
    return "stale"
