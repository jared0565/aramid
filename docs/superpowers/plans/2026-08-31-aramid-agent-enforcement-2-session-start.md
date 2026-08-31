# Agent Enforcement 2 — Session-Start Hook + Settings Merge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every Claude Code session in an onboarded repo starts with aramid's live posture injected as context: `aramid init` registers a `SessionStart` hook in `.claude/settings.json` (merge-preserving), a new `aramid agent-hook session-start` subcommand renders the posture, and uninstall/doctor/status learn the new surface — plus three fixes carried from sub-project 1's final review.

**Architecture:** Two new focused modules mirror sub-1's shape: `src/aramid/agent_settings.py` owns the `.claude/settings.json` merge/remove/state logic (own-entry-by-marker, foreign entries preserved, unparseable never written), and `src/aramid/commands/agent_hook.py` owns the hook endpoint (stdout is injected into session context; fail-open on absolutely everything). init/uninstall/doctor/status get thin wiring. The settings template carries ONLY the SessionStart entry — the PreToolUse entry ships in sub-project 3 with the subcommand that serves it, so init never writes a hook nothing can answer.

**Tech Stack:** Python ≥3.11, stdlib only (json, pathlib). Tests: pytest, existing `tests/unit/` + `tests/integration/` conventions.

**Spec:** `docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md` (§4 merge plumbing, §5 session-start, §8 lifecycle, §11 sub-project 2). Sub-project 2 of 4.

## Global Constraints

- **Fail-open is the session-start policy, stated everywhere it applies (spec §5):** outside an onboarded repo, on ANY internal error, or for an event name this version does not know, `agent-hook` exits 0 with no output. Only ever ONE print of a fully-built string, so a mid-build exception emits nothing.
- **Merge discipline (spec §4):** aramid's own entry is identified by the substring `-m aramid agent-hook` in a hook command and rewritten to the current template; every foreign entry is preserved structurally intact; a file that fails to parse as JSON (or has non-dict/list shapes where the merge needs them) is NEVER written — report and move on.
- **Tampered settings exit doctor 2 (spec §8);** absent/stale/unparseable are advisory. Agent-block states stay advisory (unchanged from sub-1).
- session-start reads only the local ledger and config — no scans, no network, no subprocesses; budget < 2 s; heavy imports live inside functions.
- ASCII `--` everywhere; `encoding="utf-8"` on every read/write; Write/Edit tools for file content, never bash heredoc.
- Every test runs in a tmp repo; the autouse conftest fixtures already isolate machine state — do not weaken them.
- Test command shape: `env -u PYTHONPATH python -P -m pytest <files> -v -o pythonpath=src` (forward slashes). `git add` before repo-wide checks; commit at the end of every task; NEVER `--no-verify`. TDD evidence must be VERBATIM pasted output.
- CHANGELOG is part of this sub-project (learned from sub-1's final review), included in Task 6.

---

### Task 1: Carried fixes from sub-project 1's final review

**Files:**
- Modify: `src/aramid/agent_files.py` (add `AGENT_BLOCK_STATES` constant)
- Modify: `src/aramid/commands/doctor.py` (`_AGENT_FILE_DETAIL` strings; `cmd_doctor` gains `during_init`)
- Modify: `src/aramid/commands/init.py` (`render_agent_blocks_notice` strings; `cmd_doctor` call site)
- Modify: `src/aramid/commands/uninstall.py` (warning strings)
- Modify: `tests/unit/test_agent_files.py` (updated pinned strings; exhaustiveness test)
- Modify: `tests/integration/test_init.py` (during-init suppression test)

**Interfaces:**
- Consumes: sub-1's `agent_files.agent_block_states`, doctor's `_AGENT_FILE_DETAIL`/`agent_files_lines`, init's `render_agent_blocks_notice`.
- Produces: `agent_files.AGENT_BLOCK_STATES = ("ok", "stale", "absent", "damaged", "unreadable")`; `cmd_doctor(root, fix=False, during_init=False)` — Task 5 relies on the `during_init` keyword existing.

Background: sub-1's fix wave widened what "damaged" means (unterminated OR duplicated begin marker) and guarded `(OSError, UnicodeDecodeError)`, but the operator-facing strings still describe only the narrow original causes; nothing pins that every `agent_block_states` value has a `_AGENT_FILE_DETAIL` key; and doctor's "run `aramid init`" remedy prints from INSIDE `aramid init` (init calls `cmd_doctor` at its step 3, before blocks are written).

- [ ] **Step 1: Write the failing tests**

In `tests/unit/test_agent_files.py`, UPDATE the pinned strings in the existing tests and ADD the exhaustiveness test. The three existing tests to update (find them by name) and their new expected values:

`test_notice_reports_damaged_even_outside_git` — new expectation:

```python
    assert notice == (
        "aramid: init: AGENTS.md has a damaged aramid fence (unterminated or"
        " duplicated begin marker) -- left untouched; repair or delete the"
        " fence and re-run `aramid init`")
```

`test_notice_reports_unreadable_even_outside_git` (added by sub-1's fix wave) — new expectation:

```python
    assert notice == (
        "aramid: init: AGENTS.md could not be read (not valid UTF-8, or an"
        " I/O error) -- left untouched; fix the file and re-run `aramid init`")
```

`test_doctor_lines_render_all_four_states` — RENAME to `test_doctor_lines_render_every_state` and replace its damaged-arm expectations; final form:

```python
def test_doctor_lines_render_every_state(tmp_path):
    agent_files.write_agent_blocks(tmp_path)
    stale = agent_files.render_block().replace(
        "security & quality gate", "old title")
    (tmp_path / "AGENTS.md").write_text(stale, encoding="utf-8")

    assert doctor_cmd.agent_files_lines(tmp_path) == [
        "  OK   CLAUDE.md  managed aramid block present",
        "  WARN AGENTS.md  aramid block differs from the current template"
        " -- re-run `aramid init`",
    ]

    (tmp_path / "CLAUDE.md").unlink()
    (tmp_path / "AGENTS.md").write_text(
        "<!-- aramid:begin -- x -->\nno end\n", encoding="utf-8")
    assert doctor_cmd.agent_files_lines(tmp_path) == [
        "  WARN CLAUDE.md  no managed aramid block -- run `aramid init`",
        "  WARN AGENTS.md  aramid fence is damaged (unterminated or"
        " duplicated begin marker) -- repair or delete the fence, then"
        " re-run `aramid init`",
    ]

    (tmp_path / "AGENTS.md").write_bytes(b"\xff\xfe garbage")
    lines = doctor_cmd.agent_files_lines(tmp_path)
    assert lines[1] == (
        "  WARN AGENTS.md  file could not be read (not valid UTF-8, or an"
        " I/O error) -- fix the file, then run `aramid init`")


def test_every_block_state_has_a_doctor_detail():
    # Exhaustiveness pin (sub-1 final review): a new state added to
    # agent_block_states without a detail entry must fail HERE, not as a
    # live KeyError inside `aramid doctor`.
    assert set(doctor_cmd._AGENT_FILE_DETAIL) == set(agent_files.AGENT_BLOCK_STATES)
    assert set(agent_files.AGENT_BLOCK_STATES) == {
        "ok", "stale", "absent", "damaged", "unreadable"}
```

In `tests/integration/test_init.py`, append (uses the existing `_repo`/`_fake_present` helpers and `doctor`/`init` imports):

```python
def test_init_suppresses_doctors_agent_sections(tmp_path, monkeypatch, capsys):
    # The step-3 doctor report inside `aramid init` must not tell the
    # operator to "run `aramid init`" about blocks init is about to write.
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    assert init.cmd_init(r) == 0
    out = capsys.readouterr().out
    assert "agent files:" not in out

    capsys.readouterr()
    doctor.cmd_doctor(r)
    assert "agent files:" in capsys.readouterr().out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py tests/integration/test_init.py -v -o pythonpath=src`
Expected: the updated pinned-string tests FAIL on the old wording; `test_every_block_state_has_a_doctor_detail` FAILS with `AttributeError: ... AGENT_BLOCK_STATES`; the suppression test FAILS because `cmd_init`'s doctor pass still prints `agent files:`.

- [ ] **Step 3: Implement**

a) `src/aramid/agent_files.py` — add below the `_END_MARKER` constant:

```python
# The full range agent_block_states can return. Doctor's detail map is
# pinned against this in tests, so a new state cannot ship unrendered.
AGENT_BLOCK_STATES = ("ok", "stale", "absent", "damaged", "unreadable")
```

b) `src/aramid/commands/doctor.py` — replace the `damaged` and `unreadable` values in `_AGENT_FILE_DETAIL`:

```python
    "damaged": "aramid fence is damaged (unterminated or duplicated begin"
               " marker) -- repair or delete the fence, then re-run"
               " `aramid init`",
    "unreadable": "file could not be read (not valid UTF-8, or an I/O"
                  " error) -- fix the file, then run `aramid init`",
```

c) `src/aramid/commands/doctor.py` — change `cmd_doctor`'s signature to `def cmd_doctor(root: Path, fix: bool = False, during_init: bool = False) -> int:` and wrap the agent-files section print in the guard, with a comment stating the policy:

```python
    if not during_init:
        # Suppressed during `aramid init`: this section's remedy is "run
        # `aramid init`", and init writes the blocks moments after this
        # report prints -- describing their pre-state mid-run misdirects.
        print("agent files:")
        for line in agent_files_lines(root):
            print(line)
```

Add one sentence to `cmd_doctor`'s docstring: `during_init suppresses the agent-surface sections whose remedy is the very init run that is printing this report.`

d) `src/aramid/commands/init.py` — in `_init_one`, change the step-3 call `cmd_doctor(root)` to `cmd_doctor(root, during_init=True)`. In `render_agent_blocks_notice`, replace the damaged and unreadable line bodies:

```python
        if action == "damaged":
            lines.append(
                f"aramid: init: {name} has a damaged aramid fence"
                f" (unterminated or duplicated begin marker) -- left"
                f" untouched; repair or delete the fence and re-run"
                f" `aramid init`")
        elif action == "unreadable":
            lines.append(
                f"aramid: init: {name} could not be read (not valid UTF-8,"
                f" or an I/O error) -- left untouched; fix the file and"
                f" re-run `aramid init`")
```

e) `src/aramid/commands/uninstall.py` — replace the two warning bodies:

```python
        if action == "damaged":
            print(f"aramid: uninstall: {name} has a damaged aramid fence"
                  f" (unterminated or duplicated begin marker) -- left"
                  f" untouched; remove the fence by hand.", file=sys.stderr)
        elif action == "unreadable":
            print(f"aramid: uninstall: {name} could not be read (not valid"
                  f" UTF-8, or an I/O error) -- left untouched; remove the"
                  f" fence by hand.", file=sys.stderr)
```

f) Sweep for stragglers: `grep -rn "no closing marker\|not valid UTF-8 -- fix the encoding" src/ tests/` — every hit must be one of the sites updated above or a test string you already updated; update any remaining hit to the new wording.

- [ ] **Step 4: Run tests to verify they pass**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py tests/integration/test_init.py tests/integration/test_doctor.py -v -o pythonpath=src`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/agent_files.py src/aramid/commands/doctor.py src/aramid/commands/init.py src/aramid/commands/uninstall.py tests/unit/test_agent_files.py tests/integration/test_init.py
git commit -m "fix(agent): widen damaged/unreadable operator strings, pin state-detail exhaustiveness, quiet doctor's agent sections during init"
```

---

### Task 2: `agent_settings.py` — settings merge

**Files:**
- Create: `src/aramid/agent_settings.py`
- Create: `tests/unit/test_agent_settings.py`

**Interfaces:**
- Consumes: nothing (stdlib json/pathlib).
- Produces (later tasks rely on these exact names):
  - `SETTINGS_REL` (a `Path(".claude") / "settings.json"`)
  - `SESSION_START_COMMAND = "python -P -m aramid agent-hook session-start"`
  - `TEMPLATE_COMMANDS: tuple[str, ...]` (currently just the one above)
  - `KNOWN_PRIOR_COMMANDS: tuple[str, ...]` (empty now; older template commands land here when the template changes, so they grade "stale" not "tampered")
  - `merge_claude_settings(root: Path) -> str` — returns one of `{"created", "updated", "unchanged", "unparseable"}`.

- [ ] **Step 1: Write the failing tests**

Write `tests/unit/test_agent_settings.py`:

```python
"""unit: agent_settings -- aramid's entries in .claude/settings.json.
Own-entry-by-marker merge: foreign hook entries are preserved structurally
intact, aramid's own entry is rewritten to the current template, and a file
that cannot be parsed is never written."""
import json

from aramid import agent_settings


def _read(tmp_path):
    return json.loads(
        (tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))


def _write(tmp_path, data):
    p = tmp_path / ".claude" / "settings.json"
    p.parent.mkdir(exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return p


GRAPHITE_PRE = {"matcher": "Grep|Glob|Bash|PowerShell", "hooks": [
    {"type": "command",
     "command": "python -P -m graphite agent-hook pre-tool-use --mode strict"}]}
GRAPHITE_SESSION = {"hooks": [
    {"type": "command",
     "command": "python -P -m graphite agent-hook session-start"}]}


def test_created_when_absent(tmp_path):
    assert agent_settings.merge_claude_settings(tmp_path) == "created"
    data = _read(tmp_path)
    assert data == {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command",
                    "command": agent_settings.SESSION_START_COMMAND}]}]}}


def test_merge_preserves_foreign_entries(tmp_path):
    _write(tmp_path, {"hooks": {"PreToolUse": [GRAPHITE_PRE],
                                "SessionStart": [GRAPHITE_SESSION]}})

    assert agent_settings.merge_claude_settings(tmp_path) == "updated"

    data = _read(tmp_path)
    assert data["hooks"]["PreToolUse"] == [GRAPHITE_PRE]
    assert data["hooks"]["SessionStart"][0] == GRAPHITE_SESSION
    assert data["hooks"]["SessionStart"][1]["hooks"][0]["command"] == (
        agent_settings.SESSION_START_COMMAND)


def test_second_merge_is_unchanged_and_byte_identical(tmp_path):
    agent_settings.merge_claude_settings(tmp_path)
    first = (tmp_path / ".claude" / "settings.json").read_bytes()

    assert agent_settings.merge_claude_settings(tmp_path) == "unchanged"
    assert (tmp_path / ".claude" / "settings.json").read_bytes() == first


def test_tampered_own_entry_is_rewritten(tmp_path):
    # The -P-stripping attack: an aramid-named entry whose command lost the
    # flag is rewritten to the template on the next init.
    _write(tmp_path, {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command",
                    "command": "python -m aramid agent-hook session-start"}]}]}})

    assert agent_settings.merge_claude_settings(tmp_path) == "updated"
    cmds = [h["command"]
            for e in _read(tmp_path)["hooks"]["SessionStart"]
            for h in e["hooks"]]
    assert cmds == [agent_settings.SESSION_START_COMMAND]


def test_unparseable_is_never_written(tmp_path):
    p = tmp_path / ".claude" / "settings.json"
    p.parent.mkdir()
    p.write_text("{not json", encoding="utf-8")

    assert agent_settings.merge_claude_settings(tmp_path) == "unparseable"
    assert p.read_text(encoding="utf-8") == "{not json"


def test_wrong_shape_is_never_written(tmp_path):
    p = _write(tmp_path, {"hooks": {"SessionStart": "a string, not a list"}})
    before = p.read_bytes()

    assert agent_settings.merge_claude_settings(tmp_path) == "unparseable"
    assert p.read_bytes() == before
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_settings.py -v -o pythonpath=src`
Expected: FAIL — `ModuleNotFoundError: No module named 'aramid.agent_settings'`.

- [ ] **Step 3: Write the implementation**

Write `src/aramid/agent_settings.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_settings.py -v -o pythonpath=src`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/agent_settings.py tests/unit/test_agent_settings.py
git commit -m "feat(agent): .claude/settings.json merge -- own-entry-by-marker, foreign-preserving, refuse-unparseable"
```

---

### Task 3: settings removal + state inspection

**Files:**
- Modify: `src/aramid/agent_settings.py` (append two functions)
- Modify: `tests/unit/test_agent_settings.py` (append tests)

**Interfaces:**
- Consumes: `_owned`, `_owned_commands`, `_load`, `TEMPLATE_COMMANDS`, `KNOWN_PRIOR_COMMANDS` from Task 2.
- Produces:
  - `remove_claude_settings(root: Path) -> str` — `{"removed", "absent", "unparseable"}`; a file left `{}` is deleted (the `.claude/` directory itself is left alone — other tools own files there).
  - `settings_state(root: Path) -> str` — `{"ok", "absent", "stale", "tampered", "unparseable"}`, read-only, for doctor/status.
  - `SETTINGS_STATES = ("ok", "absent", "stale", "tampered", "unparseable")` — exhaustiveness anchor, same pattern as `AGENT_BLOCK_STATES`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_agent_settings.py`:

```python
def test_remove_strips_only_aramid_entries(tmp_path):
    _write(tmp_path, {"hooks": {"PreToolUse": [GRAPHITE_PRE],
                                "SessionStart": [GRAPHITE_SESSION]}})
    agent_settings.merge_claude_settings(tmp_path)

    assert agent_settings.remove_claude_settings(tmp_path) == "removed"

    data = _read(tmp_path)
    assert data == {"hooks": {"PreToolUse": [GRAPHITE_PRE],
                              "SessionStart": [GRAPHITE_SESSION]}}


def test_remove_deletes_file_that_was_only_aramid(tmp_path):
    agent_settings.merge_claude_settings(tmp_path)

    assert agent_settings.remove_claude_settings(tmp_path) == "removed"
    assert not (tmp_path / ".claude" / "settings.json").exists()
    assert (tmp_path / ".claude").is_dir()  # the directory is not ours to delete


def test_remove_absent_and_unparseable(tmp_path):
    assert agent_settings.remove_claude_settings(tmp_path) == "absent"

    p = tmp_path / ".claude" / "settings.json"
    p.parent.mkdir()
    p.write_text("{not json", encoding="utf-8")
    assert agent_settings.remove_claude_settings(tmp_path) == "unparseable"
    assert p.read_text(encoding="utf-8") == "{not json"


def test_settings_state_grades_every_shape(tmp_path):
    assert agent_settings.settings_state(tmp_path) == "absent"

    agent_settings.merge_claude_settings(tmp_path)
    assert agent_settings.settings_state(tmp_path) == "ok"

    # tampered: aramid-named entry, command differs from every known template
    _write(tmp_path, {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command",
                    "command": "python -m aramid agent-hook session-start"}]}]}})
    assert agent_settings.settings_state(tmp_path) == "tampered"

    p = tmp_path / ".claude" / "settings.json"
    p.write_text("{not json", encoding="utf-8")
    assert agent_settings.settings_state(tmp_path) == "unparseable"


def test_settings_state_stale_via_known_prior(tmp_path, monkeypatch):
    # Simulate a future template change: the old command joins
    # KNOWN_PRIOR_COMMANDS and grades "stale", not "tampered".
    old = "python -P -m aramid agent-hook session-start --old-flag"
    monkeypatch.setattr(agent_settings, "KNOWN_PRIOR_COMMANDS", (old,))
    _write(tmp_path, {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command", "command": old}]}]}})

    assert agent_settings.settings_state(tmp_path) == "stale"


def test_settings_states_constant_is_exhaustive():
    assert set(agent_settings.SETTINGS_STATES) == {
        "ok", "absent", "stale", "tampered", "unparseable"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_settings.py -v -o pythonpath=src`
Expected: the 6 new tests FAIL with `AttributeError` on the new names; the Task 2 tests still pass.

- [ ] **Step 3: Write the implementation**

Append to `src/aramid/agent_settings.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_settings.py -v -o pythonpath=src`
Expected: 12 passed.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/agent_settings.py tests/unit/test_agent_settings.py
git commit -m "feat(agent): settings removal + tampered/stale/absent state grading"
```

---

### Task 4: `aramid agent-hook session-start`

**Files:**
- Create: `src/aramid/commands/agent_hook.py`
- Modify: `src/aramid/cli.py` (subparser + dispatch + import)
- Create: `tests/integration/test_agent_hook.py`

**Interfaces:**
- Consumes: `commands/status.py` private renderers `_open_counts_line(state)`, `_new_since_baseline_line(ledger, state)`, `_skip_streak_lines(ledger)`, `_bake_lines(cfg, state)` (spec §5 says reuse status internals); `gitutil.repo_root`; `Ledger`; `config.load_config`.
- Produces: `cmd_agent_hook(event: str, root: Path | None = None) -> int` in `commands/agent_hook.py` — Task 5's doctor/status do NOT call it; the generated settings command from Task 2 (`python -P -m aramid agent-hook session-start`) is what invokes it in production.

Protocol note (pinned here so the implementer doesn't research it): Claude Code runs SessionStart hooks with the project directory as cwd and **adds the hook's stdout to the session's context**; stdin carries a JSON event the hook may ignore. aramid ignores stdin entirely and prints a compact posture block. Exit code is 0 in every path — a context hook must never break session start; the git-hook gate beneath still enforces (spec §5, §9).

- [ ] **Step 1: Write the failing tests**

Write `tests/integration/test_agent_hook.py`:

```python
"""integration: `aramid agent-hook session-start` -- the SessionStart
context injector. Fail-open is the contract under test as much as the
happy path: non-repo, un-onboarded repo, unknown event, and an internal
error must all exit 0 with NOTHING printed."""
import subprocess
import sys
from pathlib import Path

from aramid.commands import agent_hook, doctor, init
from aramid.commands import status as status_mod


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _repo(tmp_path, name="repo") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "app.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    _git(r, "add", "app.py")
    _git(r, "commit", "-q", "-m", "seed")
    return r


def _fake_present(root):
    return {
        "gitleaks": doctor.ToolStatus("gitleaks", True, "8.21.2"),
        "semgrep": doctor.ToolStatus("semgrep", True, "1.100.0"),
        "ruff": doctor.ToolStatus("ruff", True, "0.6.0"),
        "pip-audit": doctor.ToolStatus("pip-audit", True, "2.7.0"),
        "interpreter": doctor.ToolStatus("interpreter", True, sys.executable),
    }


def test_session_start_prints_posture_in_onboarded_repo(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0
    capsys.readouterr()

    rc = agent_hook.cmd_agent_hook("session-start", root=r)

    out = capsys.readouterr().out
    assert rc == 0
    lines = out.splitlines()
    assert lines[0] == ("aramid: this repo is GATED (pre-commit + pre-push"
                        " hooks). Read ARAMID.md; NEVER pass --no-verify.")
    assert lines[1].startswith("aramid: open findings:")
    assert lines[-1] == ('aramid: commands: aramid check --staged | aramid'
                         ' ledger filter --status open | aramid override'
                         ' <id> --reason "..."')


def test_session_start_is_silent_outside_a_repo(tmp_path, capsys):
    assert agent_hook.cmd_agent_hook("session-start", root=tmp_path) == 0
    assert capsys.readouterr().out == ""


def test_session_start_is_silent_in_un_onboarded_repo(tmp_path, capsys):
    r = _repo(tmp_path)
    assert agent_hook.cmd_agent_hook("session-start", root=r) == 0
    assert capsys.readouterr().out == ""


def test_unknown_event_is_a_silent_noop(tmp_path, capsys):
    # Forward compatibility: a harness sending an event this aramid version
    # does not know must get a clean no-op, never an argparse error.
    assert agent_hook.cmd_agent_hook("post-tool-use", root=tmp_path) == 0
    assert capsys.readouterr().out == ""


def test_internal_error_fails_open_with_no_partial_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0
    capsys.readouterr()

    def boom(state):
        raise RuntimeError("injected")
    monkeypatch.setattr(status_mod, "_open_counts_line", boom)

    assert agent_hook.cmd_agent_hook("session-start", root=r) == 0
    # single-print design: an exception mid-build must emit NOTHING,
    # not a half-rendered context block.
    assert capsys.readouterr().out == ""


def test_cli_wires_agent_hook(tmp_path, monkeypatch, capsys):
    from aramid import cli
    monkeypatch.chdir(tmp_path)
    assert cli.main(["agent-hook", "session-start"]) == 0
    assert capsys.readouterr().out == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `env -u PYTHONPATH python -P -m pytest tests/integration/test_agent_hook.py -v -o pythonpath=src`
Expected: FAIL — `ImportError: cannot import name 'agent_hook'` (and the CLI test fails with exit 3 on the unknown command).

- [ ] **Step 3: Write the implementation**

Write `src/aramid/commands/agent_hook.py`:

```python
"""agent_hook -- aramid's endpoint for agent-harness hooks (Claude Code).

Spec: docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md §5.

`session-start` prints a compact live-posture block to stdout; Claude Code
adds a SessionStart hook's stdout to the session's context, so an agent
opens every session in an onboarded repo already knowing the gate exists,
what is open, and which commands to use. The stdin JSON the harness sends
is deliberately ignored -- everything needed is derived from the repo at
cwd, which is where the harness runs the hook.

FAIL-OPEN IS THE WHOLE CONTRACT (spec §5/§9, stated as policy): outside a
git repo, in a repo without aramid.toml, for an event name this version
does not know (forward compatibility with newer harness configs), and on
ANY internal error, exit 0 with no output. The block is built fully before
a single print so a mid-build exception can never emit a half-rendered
context. The git-hook gate beneath still enforces; this layer only informs.

Budget: < 2 s. Reads only the local ledger and config -- no scans, no
network, no subprocesses. Heavy imports stay inside functions so the
non-matching paths stay cheap.
"""
from pathlib import Path


def cmd_agent_hook(event: str, root: Path | None = None) -> int:
    try:
        if event != "session-start":
            return 0
        base = Path(root) if root is not None else Path.cwd()
        from aramid import gitutil
        try:
            repo = gitutil.repo_root(base)
        except Exception:
            return 0
        if not (repo / "aramid.toml").is_file():
            return 0
        print(_session_context(repo), end="")
        return 0
    except Exception:
        return 0


def _session_context(repo: Path) -> str:
    from aramid import config as config_mod
    from aramid.commands import status as status_mod
    from aramid.ledger import Ledger

    cfg = config_mod.load_config(repo)
    ledger = Ledger(repo / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        lines = [
            "aramid: this repo is GATED (pre-commit + pre-push hooks)."
            " Read ARAMID.md; NEVER pass --no-verify.",
            "aramid: " + status_mod._open_counts_line(state),
            "aramid: " + status_mod._new_since_baseline_line(ledger, state),
        ]
        streaks = status_mod._skip_streak_lines(ledger)
        if streaks:
            lines.append("aramid: per-tool skip streaks:")
            lines.extend("aramid:   " + s.strip() for s in streaks)
        lines.extend("aramid: " + b.strip()
                     for b in status_mod._bake_lines(cfg, state))
        lines.append(
            'aramid: commands: aramid check --staged | aramid ledger filter'
            ' --status open | aramid override <id> --reason "..."')
        return "\n".join(lines) + "\n"
    finally:
        ledger.close()
```

In `src/aramid/cli.py`:

a) Add the import beside the other `cmd_*` imports at the top of the file (match the existing import style there):

```python
from aramid.commands.agent_hook import cmd_agent_hook
```

b) In `build_parser()`, after the `p_rebaseline` block:

```python
    p_agent_hook = sub.add_parser(
        "agent-hook",
        help="agent-harness hook endpoint (Claude Code): session-start "
             "prints live gate posture for the session's context; any "
             "other event is a silent no-op")
    # Deliberately NOT choices=[...]: an event name from a newer template
    # must no-op (exit 0), never die in argparse -- fail-open.
    p_agent_hook.add_argument("event")
```

c) In `main()`, after the `status` dispatch:

```python
    if args.command == "agent-hook":
        return cmd_agent_hook(args.event, root)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `env -u PYTHONPATH python -P -m pytest tests/integration/test_agent_hook.py tests/integration/test_cli_dispatch.py -v -o pythonpath=src`
Expected: all pass (test_cli_dispatch.py included because it exercises the parser; if a test there enumerates the command set, extend its expectation with `agent-hook` and name that change in your report).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/agent_hook.py src/aramid/cli.py tests/integration/test_agent_hook.py
git commit -m "feat(agent): agent-hook session-start -- fail-open context injection from ledger posture"
```

---

### Task 5: init / uninstall / doctor / status wiring for the settings surface

**Files:**
- Modify: `src/aramid/commands/init.py` (merge call in step 4; `render_agent_settings_notice`; notice loop grows to four)
- Modify: `src/aramid/commands/uninstall.py` (removal call + warning + summary wording)
- Modify: `src/aramid/commands/doctor.py` (`_AGENT_SETTINGS_DETAIL`, `agent_settings_lines`, `agent hooks:` section, tampered exit 2)
- Modify: `src/aramid/commands/status.py` (`_agent_surfaces_line`)
- Modify: `tests/unit/test_agent_settings.py` (detail-map exhaustiveness + doctor-lines rendering)
- Modify: `tests/integration/test_init.py` (init/uninstall/doctor/status integration tests)

**Interfaces:**
- Consumes: `agent_settings.merge_claude_settings/remove_claude_settings/settings_state/SETTINGS_STATES` (Tasks 2-3), `cmd_doctor(..., during_init=...)` (Task 1).
- Produces: `render_agent_settings_notice(root: Path, action: str) -> str` (init.py); `agent_settings_lines(root: Path) -> list[str]` and `_AGENT_SETTINGS_DETAIL` (doctor.py); `_agent_surfaces_line(root: Path) -> str` (status.py).

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_agent_settings.py` (add `from aramid.commands import doctor as doctor_cmd` to its imports):

```python
def test_every_settings_state_has_a_doctor_detail():
    assert set(doctor_cmd._AGENT_SETTINGS_DETAIL) == set(agent_settings.SETTINGS_STATES)


def test_doctor_settings_lines_render_ok_and_tampered(tmp_path):
    agent_settings.merge_claude_settings(tmp_path)
    assert doctor_cmd.agent_settings_lines(tmp_path) == [
        "  OK   settings   aramid session-start hook registered"
        " (.claude/settings.json)",
    ]

    _write(tmp_path, {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command",
                    "command": "python -m aramid agent-hook session-start"}]}]}})
    assert doctor_cmd.agent_settings_lines(tmp_path) == [
        "  WARN settings   an aramid-named hook entry differs from the"
        " template -- treat as tampering; re-run `aramid init` to rewrite"
        " it and investigate how it changed",
    ]
```

Append to `tests/integration/test_init.py` (add `from aramid import agent_settings` and `import json` to its imports):

```python
def test_init_registers_session_start_hook_idempotently(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    assert init.cmd_init(r) == 0
    p = r / ".claude" / "settings.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    cmds = [h["command"] for e in data["hooks"]["SessionStart"] for h in e["hooks"]]
    assert cmds == [agent_settings.SESSION_START_COMMAND]
    first = p.read_bytes()

    assert init.cmd_init(r) == 0
    assert p.read_bytes() == first


def test_init_preserves_foreign_settings_and_uninstall_reverses(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    foreign = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": "python -P -m graphite agent-hook pre-tool-use"}]}]}}
    p = r / ".claude" / "settings.json"
    p.parent.mkdir()
    p.write_text(json.dumps(foreign, indent=2) + "\n", encoding="utf-8")

    assert init.cmd_init(r) == 0
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["hooks"]["PreToolUse"] == foreign["hooks"]["PreToolUse"]
    assert agent_settings.settings_state(r) == "ok"

    assert uninstall.cmd_uninstall(r) == 0
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data == foreign
    assert agent_settings.settings_state(r) == "absent"


def test_doctor_exits_2_on_tampered_settings(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0
    capsys.readouterr()
    rc_ok = doctor.cmd_doctor(r)

    p = r / ".claude" / "settings.json"
    text = p.read_text(encoding="utf-8")
    p.write_text(text.replace("python -P -m aramid", "python -m aramid"),
                 encoding="utf-8")
    capsys.readouterr()
    rc_tampered = doctor.cmd_doctor(r)
    err = capsys.readouterr().err

    assert rc_tampered == 2
    assert rc_tampered != rc_ok
    assert ("aramid: doctor: .claude/settings.json carries an aramid-named"
            " hook whose command differs from the template -- treat as"
            " tampering; re-run `aramid init` to rewrite it and investigate"
            " how it changed" in err)


def test_status_reports_agent_surfaces(tmp_path, monkeypatch, capsys):
    from aramid.commands.status import cmd_status
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0
    capsys.readouterr()

    assert cmd_status(r) == 0
    assert ("agent surfaces: blocks 2/2, session hook ok"
            in capsys.readouterr().out)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_settings.py tests/integration/test_init.py -v -o pythonpath=src`
Expected: the new tests FAIL (`_AGENT_SETTINGS_DETAIL`/`agent_settings_lines` missing; init writes no settings file; doctor rc unchanged on tamper; status lacks the line). Pre-existing tests still pass.

- [ ] **Step 3: Implement**

a) `src/aramid/commands/init.py` — in `_init_one` step 4, directly after `agent_actions = agent_files.write_agent_blocks(root)`:

```python
    settings_action = agent_settings.merge_claude_settings(root)
```

(add `agent_settings` to the module's `from aramid import ...` import). Add beside `render_agent_blocks_notice`:

```python
def render_agent_settings_notice(root: Path, action: str) -> str:
    """Sibling of the other init notices; same three rules. The unparseable
    line prints even outside a git work tree -- it reports a refused write,
    not a chore."""
    if action == "unparseable":
        return ("aramid: init: .claude/settings.json could not be parsed --"
                " left untouched; fix the JSON and re-run `aramid init` to"
                " register aramid's session-start hook")
    if action not in ("created", "updated"):
        return ""
    if gitutil._run(root, "rev-parse", "--is-inside-work-tree").returncode != 0:
        return ""
    return ("aramid: init: registered aramid's session-start hook in"
            " .claude/settings.json -- agent sessions start with live gate"
            " posture:\n"
            'aramid: init:       git add .claude/settings.json && git commit'
            ' -m "chore: aramid agent hooks"')
```

Extend the step-9 notice loop to four renderers:

```python
    for notice in (render_aramid_md_notice(root),
                   render_gitignore_notice(root, gi_added, gi_created),
                   render_agent_blocks_notice(root, agent_actions),
                   render_agent_settings_notice(root, settings_action)):
        if notice:
            print(notice, file=sys.stderr)
```

b) `src/aramid/commands/uninstall.py` — after the agent-blocks warning loop (add `agent_settings` to the import):

```python
    settings_action = agent_settings.remove_claude_settings(root)
    if settings_action == "unparseable":
        print("aramid: uninstall: .claude/settings.json could not be parsed"
              " -- left untouched; remove aramid's hook entry by hand.",
              file=sys.stderr)
```

and extend the summary print's artifact list to `"... agent blocks removed, agent hooks removed, gitignore entries removed. ..."` (one added phrase, rest of the sentence unchanged).

c) `src/aramid/commands/doctor.py` — beside `_AGENT_FILE_DETAIL`:

```python
_AGENT_SETTINGS_DETAIL = {
    "ok": "aramid session-start hook registered (.claude/settings.json)",
    "absent": "no aramid hook entry in .claude/settings.json -- run"
              " `aramid init`",
    "stale": "aramid hook entry matches an older template -- re-run"
             " `aramid init`",
    "tampered": "an aramid-named hook entry differs from the template --"
                " treat as tampering; re-run `aramid init` to rewrite it"
                " and investigate how it changed",
    "unparseable": ".claude/settings.json could not be parsed -- fix the"
                   " JSON, then run `aramid init`",
}


def agent_settings_lines(root: Path) -> list[str]:
    """One line; tampered is the only state that moves doctor's exit code
    (handled in cmd_doctor -- this renderer stays pure)."""
    from aramid import agent_settings
    state = agent_settings.settings_state(root)
    tag = "OK  " if state == "ok" else "WARN"
    return [f"  {tag} {'settings':<10} {_AGENT_SETTINGS_DETAIL[state]}"]
```

In `cmd_doctor`, inside the existing `if not during_init:` block, after the agent-files section:

```python
        print("agent hooks:")
        for line in agent_settings_lines(root):
            print(line)
```

and add the tampered gate. Compute after the section prints (import at use site, matching the file's lazy-import convention):

```python
    from aramid import agent_settings as agent_settings_mod
    settings_tampered = (not during_init
                         and agent_settings_mod.settings_state(root) == "tampered")
    if settings_tampered:
        print("aramid: doctor: .claude/settings.json carries an aramid-named"
              " hook whose command differs from the template -- treat as"
              " tampering; re-run `aramid init` to rewrite it and"
              " investigate how it changed", file=sys.stderr)
```

and in the exit chain, after the `editable_gate` return:

```python
    if settings_tampered:
        return 2                        # an edited aramid hook command is the -P-stripping class
```

(`during_init=True` skips the check on purpose: the merge init runs moments later rewrites the entry — gating onboarding on the thing onboarding fixes would deadlock it. Put that sentence in a comment.)

d) `src/aramid/commands/status.py` — add near the other line helpers:

```python
def _agent_surfaces_line(root: Path) -> str:
    from aramid import agent_files, agent_settings
    states = agent_files.agent_block_states(root)
    ok = sum(1 for _, s in states if s == "ok")
    return (f"agent surfaces: blocks {ok}/{len(states)}, "
            f"session hook {agent_settings.settings_state(root)}")
```

and in `cmd_status`, directly after `lines.extend(_bake_lines(cfg, state))`:

```python
        lines.append(_agent_surfaces_line(root))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_settings.py tests/unit/test_agent_files.py tests/integration/test_init.py tests/integration/test_doctor.py tests/integration/test_agent_hook.py -v -o pythonpath=src`
Expected: all pass (test_doctor.py catches report-shape pins; extend, never weaken, any that pin the full report).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/init.py src/aramid/commands/uninstall.py src/aramid/commands/doctor.py src/aramid/commands/status.py tests/unit/test_agent_settings.py tests/integration/test_init.py
git commit -m "feat(agent): wire settings surface into init/uninstall/doctor/status -- tampered exits doctor 2"
```

---

### Task 6: docs + CHANGELOG + dogfood

**Files:**
- Modify: `docs/user-guide.md` (§2: new list item + uninstall sentence; short paragraph after the hooks table in §2 or §3 about the session-start hook)
- Modify: `CHANGELOG.md` (`[Unreleased]` `### Added` — second bullet)
- Dogfood on this repo, with a deliberate revert of the live settings entry (see Step 3's ruling)

- [ ] **Step 1: Update the docs**

`docs/user-guide.md` §2, in the "What a single-repo `init` does" numbered list, insert AFTER the managed-blocks item (currently item 4) and renumber the rest:

```markdown
5. Registers aramid's `SessionStart` hook in `.claude/settings.json` (merging: entries belonging to other tools are preserved intact; aramid's own entry -- identified by `-m aramid agent-hook` in its command -- is rewritten to the current template; an unparseable file is reported and never written). Claude Code adds the hook's stdout to each session's context, so agent sessions in the repo open with live gate posture: open findings, skip streaks, bake states, and the commands to use. The hook is fail-open everywhere -- outside an onboarded repo, or on any internal error, it prints nothing and exits 0.
```

Extend the §2 uninstall sentence's artifact list with: `removes aramid's hook entries from .claude/settings.json (deleting the file if nothing else remains in it)`.

`CHANGELOG.md` — under `[Unreleased]` / `### Added`, append a second bullet after the managed-block bullet (match the existing bold-lead style):

```markdown
- **`aramid init` registers a session-start agent hook, and `aramid
  agent-hook session-start` renders live gate posture.** The hook entry in
  `.claude/settings.json` is merged own-entry-by-marker (foreign tools'
  entries preserved; an unparseable file refused and reported), and the
  subcommand prints open findings, skip streaks, and bake posture for the
  agent session's context -- fail-open in every path, so a session can
  never be broken by it. `aramid doctor` grades the entry
  (`ok`/`absent`/`stale`/`tampered`/`unparseable`); a tampered entry --
  an aramid-named hook whose command differs from the template -- exits
  doctor `2`. `aramid status` gains an `agent surfaces:` line.
```

- [ ] **Step 2: Dogfood — prove the treatment, run init, inspect**

```bash
env -u PYTHONPATH PYTHONPATH="$(pwd -W 2>/dev/null || pwd)/src" python -P -c "import aramid; print(aramid.__file__)"
```

Expected: a path ending `src\aramid\__init__.py`. If site-packages appears, STOP — report BLOCKED.

Confirm `.claude/settings.json` is committed-clean BEFORE init (`git status --porcelain .claude/settings.json` prints nothing) — the revert in Step 3 depends on it. Then:

```bash
env -u PYTHONPATH PYTHONPATH="$(pwd -W 2>/dev/null || pwd)/src" python -P -m aramid init .
git status --porcelain
git diff .claude/settings.json
```

Verify: graphite's PreToolUse/SessionStart/Stop entries survive byte-level in the diff (only additions touching aramid's entry); the init notice named the settings registration; CLAUDE.md/AGENTS.md unchanged (template untouched this sub-project).

- [ ] **Step 3: Revert the live settings entry (deliberate, ruled)**

Controller ruling, recorded in the SDD ledger: the machine's promoted aramid is 0.7.2, which has no `agent-hook` subcommand — a live SessionStart entry in THIS repo would error on every session start until the next release is promoted. The entry therefore lands here at the operator's post-promotion re-init, not now. The dogfood's purpose (prove the merge preserves graphite's entries on a real file) is served by the diff inspection in Step 2.

```bash
git checkout -- .claude/settings.json
git status --porcelain .claude/settings.json
```

(Safe precisely because Step 2 confirmed the file was committed-clean before init and the diff contained only aramid's entry — nothing uncommitted is lost.) Expected: no output from the status check.

- [ ] **Step 4: Run the affected suites one last time**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_settings.py tests/unit/test_agent_files.py tests/integration/test_agent_hook.py tests/integration/test_init.py tests/integration/test_doctor.py -q -o pythonpath=src`
Expected: all pass. Paste verbatim output.

- [ ] **Step 5: Commit**

```bash
git add docs/user-guide.md CHANGELOG.md
git commit -m "docs(agent): user-guide + changelog for the session-start surface; dogfood verified merge against graphite's settings"
```

---

## After the last task

Do NOT push as a plan step; hand back to the controller (full suite, then the integration menu). Sub-project 3 (pre-tool-use rejector + `arm --agent`) carries forward: adding its PreToolUse command to `TEMPLATE_COMMANDS` does NOT move this sub-project's session-start command to `KNOWN_PRIOR_COMMANDS` -- `SESSION_START_COMMAND` stays current and stays a member of `TEMPLATE_COMMANDS` unchanged. A consumer's entry grades "stale" for a simpler reason: its owned set (`{SESSION_START_COMMAND}` alone, until the repo re-runs `init`) no longer EQUALS the now-larger `TEMPLATE_COMMANDS` set (session-start plus the new PreToolUse command), even though every command it owns is still individually current -- `settings_state`'s own rule is "ok" only on set equality, "stale" once every owned command is still known but the sets differ. That is the designed rollout. Also carried to sub-3: restoring the "Armed repos reject the call outright." sentence to the instruction-block template.

Also carried forward, recorded hard requirements from this sub-project's final review:

- **Event-bound template grading.** Bind each command to the hook event it belongs to and grade per event, not as one flat set spanning every event -- the flat-set grading plus a merge that only ever rewrites the `SessionStart` array is not acceptable for an ARMED rejector: a tampered or missing PreToolUse entry could read "ok" so long as SessionStart alone still matches the template, and a SessionStart-only merge can never repair a PreToolUse array regardless of what it finds there.
- **The whitespace-variant ownership gap.** `_owned()`'s marker match (`-m aramid agent-hook` as a literal substring of the command) does not normalize whitespace, so a command respaced by another tool (extra or collapsed spaces, tabs) can still carry the marker text while failing an exact-template comparison, or the reverse. Close this before a PreToolUse entry's grading carries security weight.
- **The no-flags-in-hook-commands rule.** This sub-project fixed the CONSUMING half (an older `agent-hook` CLI must not die in argparse on a newer command line's trailing flags -- see F4 above, `nargs=argparse.REMAINDER` on the `event` positional). Sub-3 must uphold the PRODUCING half of the same rule: new behavior gets a new event name, hook commands never grow flags -- so the two halves of the contract cannot drift apart.
- **State an aramid version floor in the release announcement.** The tracked `.claude/settings.json` entry is committed and reaches every teammate and agent on the next pull, but it can outrun an older installed aramid wheel's understanding of it (a new event name; a REMAINDER-tolerant CLI on an install that predates F4). Name the minimum aramid version in the sub-3 release announcement so an under-versioned install is a known, named risk rather than a silent one.
