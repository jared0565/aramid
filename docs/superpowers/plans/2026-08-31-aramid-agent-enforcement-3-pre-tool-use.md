# Agent Enforcement Sub-Project 3: Pre-Tool-Use Rejector + `arm --agent` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `aramid agent-hook pre-tool-use` — a token-level git-bypass screener that advises while baking and rejects while armed — plus `aramid arm --agent`, the `agent_block_armed` config key, and event-bound grading of aramid's `.claude/settings.json` entries.

**Architecture:** A new pure-stdlib matcher module (`agent_bypass.py`) feeds a new `pre-tool-use` branch in `agent_hook.py` that renders Claude Code PreToolUse JSON (deny when armed, `additionalContext` advisory while baking). `agent_settings.py` is redesigned from a flat command set to an event-bound template (`{event: commands}`) with whitespace-normalized ownership, so a moved or edited entry grades `tampered` per event. `arm --agent` reuses the existing comment-preserving root-key machinery.

**Tech Stack:** Python 3.11+ stdlib only on the hook path (`shlex`, `json`); pytest; existing aramid modules (`config`, `gitutil`, `arm` machinery).

**Spec:** `docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md` (§6 rejector, §8 lifecycle, §9 security, §10 testing). Carried hard requirements: `docs/superpowers/plans/2026-08-31-aramid-agent-enforcement-2-session-start.md` § "After the last task".

## Global Constraints

- **Two-aramid discipline:** the machine wheel is 0.7.2; run tests as `python -m pytest ...` from the repo root (pyproject sets `pythonpath = ["src"]`). NEVER `pip install -e .`. When in doubt print `aramid.__file__` — it must resolve under `F:\Projects\aramid\src\`.
- **Fail-open is the hook contract (spec §6/§9):** internal error, unparseable stdin, non-matching command, non-repo, un-onboarded repo, unknown event → exit 0, no output. Only a positive match while armed denies. A hook crash must never take unrelated tool calls down.
- **Token-level matching, never substring (spec §6).** False negatives fail back to the status quo; false positives are the expensive direction and must be structurally hard.
- **Hook commands never grow flags** — new behavior gets a new event name. The new command is exactly `python -P -m aramid agent-hook pre-tool-use`.
- **Every generated launch carries `-P`** (`python -P -m aramid ...`). Include `tests/unit/test_launch_shadowing.py` in EVERY task's test run — a marker literal without `-P` escaped all sub-2 slices and went red only at the final full suite.
- **Harness contract pinned 2026-08-31 against Claude Code 2.1.252:** deny = stdout JSON `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": ...}}` with exit 0; advisory = stdout JSON `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": ...}}` with exit 0 (reaches the model; does NOT touch the permission decision — `permissionDecision: "allow"` is ruled out because it suppresses the user's permission prompt). Matcher string: `"Bash|PowerShell"`. The spec's "fallback exit 2 + stderr where JSON denial is unsupported" clause is unreachable on the pinned harness and is deliberately not implemented; an older harness that ignores the JSON fails open (advisory inert, deny inert) which is the spec's named degradation.
- **Rendered strings are asserted as FULL lines/objects, never substrings.**
- **Machine isolation:** every test runs in a tmp repo via existing fixtures; no test touches the real `~/.claude`, this repo's own `.claude/settings.json`, or the machine registry.
- **No dogfood `aramid init .` run in this sub-project.** This repo's settings entry stays absent until the next release promotes (the 0.7.2 wheel cannot serve `agent-hook`). The managed blocks here going stale against the new template is expected and stays until post-promotion re-init.
- **Never assert an absolute doctor exit code without `monkeypatch.setattr(doctor, "editable_consumers_lines", lambda *a: [])`** — CI installs `-e`, so healthy doctor exits 2 there with anything registered.
- **Latency (spec §6):** the non-matching pre-tool-use path imports stdlib + `aramid.agent_bypass` only (itself stdlib-only). `aramid.config`/`gitutil` load lazily inside the matched branch. Target < 500 ms non-matching.
- **Config:** `agent_block_armed` is additive, read `merged.get("agent_block_armed", False)` — NO `CURRENT_SCHEMA_VERSION` bump (config.py's mismatch rule only prints an advisory; pre-existing configs need no migration).

---

### Task 1: `agent_bypass.py` — token-level git bypass matcher

**Files:**
- Create: `src/aramid/agent_bypass.py`
- Test: `tests/unit/test_agent_bypass.py`

**Interfaces:**
- Consumes: nothing (pure stdlib).
- Produces: `find_bypass(command: str) -> Bypass | None`; `Bypass` frozen dataclass with fields `kind: str` (`"no-verify"` | `"hooks-path"`), `subcommand: str` (`"commit"` | `"push"`), `token: str` (the matched token or `-c` value, for messages). Task 4 imports both.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_agent_bypass.py`:

```python
"""Token-level git bypass detection (spec §6). Matching is on parsed
tokens, never substrings; false positives are the expensive direction."""
import pytest

from aramid.agent_bypass import Bypass, find_bypass


# ---- matches (spec §6 red-first cases) ----

def test_commit_no_verify_matches():
    assert find_bypass("git commit --no-verify -m x") == Bypass(
        "no-verify", "commit", "--no-verify")


def test_commit_short_n_matches():
    assert find_bypass("git commit -n -m x") == Bypass(
        "no-verify", "commit", "-n")


def test_push_no_verify_matches():
    assert find_bypass("git push --no-verify origin main") == Bypass(
        "no-verify", "push", "--no-verify")


def test_hookspath_wrapping_commit_matches():
    assert find_bypass('git -c core.hooksPath=/tmp/x commit -m x') == Bypass(
        "hooks-path", "commit", "core.hooksPath=/tmp/x")


def test_hookspath_case_insensitive_key():
    assert find_bypass("git -c CORE.HooksPath=/x push") == Bypass(
        "hooks-path", "push", "CORE.HooksPath=/x")


def test_hookspath_attached_spelling_matches():
    assert find_bypass("git -ccore.hookspath=/x commit") == Bypass(
        "hooks-path", "commit", "core.hookspath=/x")


def test_compound_command_tail_matches():
    assert find_bypass('pytest -q && git commit -n -m "wip"') == Bypass(
        "no-verify", "commit", "-n")


def test_piped_git_matches():
    assert find_bypass("echo hi | git push --no-verify") == Bypass(
        "no-verify", "push", "--no-verify")


def test_absolute_git_path_matches():
    assert find_bypass("/usr/bin/git commit -n") == Bypass(
        "no-verify", "commit", "-n")


def test_git_exe_matches():
    assert find_bypass("git.exe commit --no-verify") == Bypass(
        "no-verify", "commit", "--no-verify")


def test_global_dash_capital_c_arg_is_skipped_not_subcommand():
    assert find_bypass("git -C /some/path commit -n") == Bypass(
        "no-verify", "commit", "-n")


def test_git_dir_equals_form_is_skipped():
    assert find_bypass("git --git-dir=.git commit -n") == Bypass(
        "no-verify", "commit", "-n")


# ---- non-matches: the expensive direction, structurally excluded ----

def test_push_short_n_is_dry_run_not_bypass():
    assert find_bypass("git push -n origin main") is None


def test_plain_commit_and_push_allowed():
    assert find_bypass("git commit -m x") is None
    assert find_bypass("git push origin main") is None


def test_message_containing_flag_text_never_matches():
    assert find_bypass('git commit -m "do not pass --no-verify"') is None


def test_single_word_message_equal_to_flag_never_matches():
    # shlex strips the quotes, so only the -m arg-skip prevents this one.
    assert find_bypass('git commit -m "--no-verify"') is None


def test_pathspec_after_double_dash_never_matches():
    assert find_bypass("git commit -- --no-verify") is None


def test_other_subcommands_never_match():
    assert find_bypass("git log --no-verify") is None
    assert find_bypass("git merge --no-verify main") is None


def test_other_config_keys_never_match():
    assert find_bypass("git -c user.name=x commit -m y") is None


def test_hookspath_on_non_commit_push_never_matches():
    assert find_bypass("git -c core.hooksPath=/x status") is None


def test_no_git_in_command():
    assert find_bypass("pytest -q tests/unit") is None


def test_bundled_short_flags_are_a_documented_false_negative():
    # -an bundles -a and -n but is NOT expanded: at token level it cannot
    # be told apart from an attached-argument token. Pinned so the residual
    # is a choice, not an accident.
    assert find_bypass("git commit -an") is None


# ---- fail-open ----

def test_unbalanced_quote_fails_open():
    assert find_bypass('git commit -n "unclosed') is None


def test_non_string_fails_open():
    assert find_bypass(None) is None
    assert find_bypass(42) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_agent_bypass.py -v > task-1-red.log 2>&1`
Expected: FAIL — `ModuleNotFoundError: No module named 'aramid.agent_bypass'`. Paste evidence FROM the log file.

- [ ] **Step 3: Write the implementation**

Create `src/aramid/agent_bypass.py`:

```python
"""agent_bypass -- token-level detection of git hook-bypass invocations.

Spec: docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md §6.

Pure stdlib, imported by the pre-tool-use agent hook on EVERY Bash /
PowerShell tool call: no aramid imports, no I/O. Matching is on parsed
tokens, never substrings -- a commit message or filename that merely
CONTAINS "--no-verify" must not match, because that string never reaches
git as a flag token.

Best-effort by design (spec §6): a bypass this parser misses is caught by
nothing today, so a false NEGATIVE only fails back to the status quo; a
false POSITIVE while armed rejects a legitimate tool call, the expensive
direction. Every rule below is written to make false positives
structurally hard:

- tokens after a bare `--` are pathspecs, never flags -- not scanned;
- `-n` matches on `commit` only (`git push -n` is `--dry-run`, harmless);
- arguments of value-taking subcommand flags (`-m`, `-F`, `-o`, ...) are
  skipped, so a message that IS the literal flag text cannot match;
- bundled short flags (`git commit -an`) are NOT expanded -- a documented
  false-negative residual, indistinguishable at token level from an
  attached-argument token like `-mfix`.

Known residuals, all false-negative direction: bundled short flags, `git
config alias.*` indirection, commands built by shell variables or eval,
and PowerShell-only syntax shlex cannot lex (which fails open).
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass

# Characters shlex groups into operator tokens under punctuation_chars.
_PUNCT = set("();<>|&")

# Subcommand flags that take a SEPARATE value token: the value is skipped
# so it can never be read as a flag. `=`-attached forms are one token and
# self-contain their value, so they need no entry.
_ARG_FLAGS = {
    "commit": ("-m", "--message", "-F", "--file", "-t", "--template",
               "-C", "--reuse-message", "-c", "--reedit-message",
               "--fixup", "--squash", "--author", "--date", "--trailer"),
    "push": ("-o", "--push-option", "--receive-pack", "--exec", "--repo"),
}


@dataclass(frozen=True)
class Bypass:
    kind: str        # "no-verify" | "hooks-path"
    subcommand: str  # "commit" | "push"
    token: str       # the exact matched token / -c value, for messages


def _tokens(command: str) -> list[str] | None:
    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return None  # unbalanced quotes etc. -- fail open (spec §6)


def _segments(tokens: list[str]) -> list[list[str]]:
    """Split the token stream at shell operators (&&, ;, |, ...), so each
    simple command is scanned on its own."""
    segs: list[list[str]] = [[]]
    for tok in tokens:
        if tok and all(ch in _PUNCT for ch in tok):
            segs.append([])
        else:
            segs[-1].append(tok)
    return [s for s in segs if s]


def _is_git(token: str) -> bool:
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in ("git", "git.exe")


def _scan_one_git(seg: list[str], start: int) -> Bypass | None:
    """Scan the git invocation whose `git` token is seg[start]."""
    configs: list[str] = []
    i = start + 1
    subcommand = None
    while i < len(seg):
        tok = seg[i]
        if tok in ("-c", "-C"):
            if tok == "-c" and i + 1 < len(seg):
                configs.append(seg[i + 1])
            i += 2
            continue
        if tok.startswith("-c") and len(tok) > 2 and not tok.startswith("--"):
            configs.append(tok[2:])
            i += 1
            continue
        if tok.split("=", 1)[0] in ("--git-dir", "--work-tree",
                                    "--exec-path", "--namespace"):
            i += 1 if "=" in tok else 2
            continue
        if tok.startswith("-"):
            i += 1  # unknown global option; assume no separate argument
            continue
        subcommand = tok
        i += 1
        break
    if subcommand not in ("commit", "push"):
        return None
    for cfg in configs:
        if cfg.split("=", 1)[0].lower() == "core.hookspath":
            return Bypass("hooks-path", subcommand, cfg)
    skip = _ARG_FLAGS[subcommand]
    j = i
    while j < len(seg):
        tok = seg[j]
        if tok == "--":
            break
        if tok in skip:
            j += 2
            continue
        if tok == "--no-verify":
            return Bypass("no-verify", subcommand, tok)
        if tok == "-n" and subcommand == "commit":
            return Bypass("no-verify", subcommand, tok)
        j += 1
    return None


def find_bypass(command) -> Bypass | None:
    """The first git hook-bypass invocation in `command`, or None.

    Compound commands (&&, ;, |, ||) are scanned in full, not just the
    head (spec §6). One match is enough to decide the tool call.
    """
    if not isinstance(command, str) or "git" not in command.lower():
        return None
    tokens = _tokens(command)
    if tokens is None:
        return None
    for seg in _segments(tokens):
        for i, tok in enumerate(seg):
            if _is_git(tok):
                found = _scan_one_git(seg, i)
                if found is not None:
                    return found
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_agent_bypass.py tests/unit/test_launch_shadowing.py -v > task-1-green.log 2>&1`
Expected: all PASS. Paste the summary line FROM the log file.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/agent_bypass.py tests/unit/test_agent_bypass.py
git commit -m "feat(agent): token-level git bypass matcher -- --no-verify/-n/core.hooksPath, false positives structurally hard"
```

---

### Task 2: Event-bound settings template (`agent_settings.py`)

**Files:**
- Modify: `src/aramid/agent_settings.py`
- Test: `tests/unit/test_agent_settings.py`, `tests/integration/test_init.py`, `tests/unit/test_launch_shadowing.py` (run, not modify)

**Interfaces:**
- Consumes: nothing new.
- Produces (Tasks 4–6 rely on these): `PRE_TOOL_USE_COMMAND = "python -P -m aramid agent-hook pre-tool-use"`; `PRE_TOOL_USE_MATCHER = "Bash|PowerShell"`; `TEMPLATE_COMMANDS: dict[str, tuple[str, ...]]` keyed by hook event; `KNOWN_PRIOR_COMMANDS: dict[str, tuple[str, ...]]` (empty — the session-start command STAYS current; nothing joins the prior set); `merge_claude_settings(root) -> str` and `settings_state(root) -> str` with unchanged return vocabularies (`SETTINGS_STATES` unchanged).

**Why (carried hard requirements):** flat-set grading plus a SessionStart-only merge is unacceptable for an armed rejector — a tampered or missing PreToolUse entry could read "ok" while SessionStart matched, and the merge could never repair it. And `_owned`'s raw-substring marker meant a respaced command read as foreign (both entries then run). Both close here, BEFORE arming ships.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_agent_settings.py`. The file already has a `_write(tmp_path, data)` helper (writes `.claude/settings.json` from a dict) and imports `agent_settings` — reuse both; keep every existing test, updating the ones that pin the old flat template shape (see Step 3 notes):

```python
def test_template_covers_both_events():
    assert set(agent_settings.TEMPLATE_COMMANDS) == {"SessionStart", "PreToolUse"}
    assert agent_settings.TEMPLATE_COMMANDS["SessionStart"] == (
        agent_settings.SESSION_START_COMMAND,)
    assert agent_settings.TEMPLATE_COMMANDS["PreToolUse"] == (
        agent_settings.PRE_TOOL_USE_COMMAND,)
    assert (agent_settings.PRE_TOOL_USE_COMMAND
            == "python -P -m aramid agent-hook pre-tool-use")
    # Nothing joins the prior set for session-start: it stays current.
    assert agent_settings.KNOWN_PRIOR_COMMANDS == {}


def test_merge_writes_both_events(tmp_path):
    assert agent_settings.merge_claude_settings(tmp_path) == "created"
    data = json.loads((tmp_path / ".claude" / "settings.json")
                      .read_text(encoding="utf-8"))
    assert data["hooks"]["SessionStart"] == [
        {"hooks": [{"type": "command",
                    "command": agent_settings.SESSION_START_COMMAND}]}]
    assert data["hooks"]["PreToolUse"] == [
        {"matcher": "Bash|PowerShell",
         "hooks": [{"type": "command",
                    "command": agent_settings.PRE_TOOL_USE_COMMAND}]}]


def test_merge_repairs_entry_moved_to_wrong_event(tmp_path):
    """An owned entry hand-moved under a foreign event is swept, and the
    template entries land under their own events -- init repairs the move."""
    _write(tmp_path, {"hooks": {"Stop": [
        {"hooks": [{"type": "command",
                    "command": agent_settings.SESSION_START_COMMAND}]}]}})
    assert agent_settings.merge_claude_settings(tmp_path) == "updated"
    data = json.loads((tmp_path / ".claude" / "settings.json")
                      .read_text(encoding="utf-8"))
    assert "Stop" not in data["hooks"]          # emptied foreign array dropped
    assert set(data["hooks"]) == {"SessionStart", "PreToolUse"}


def test_sub2_consumer_grades_stale_not_ok_not_tampered(tmp_path):
    """The designed rollout: a repo that ran the sub-2 init has only the
    SessionStart entry -- every owned command is known for its event, the
    per-event sets differ -> stale (re-run init), never tampered."""
    _write(tmp_path, {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command",
                    "command": agent_settings.SESSION_START_COMMAND}]}]}})
    assert agent_settings.settings_state(tmp_path) == "stale"


def test_moved_entry_grades_tampered(tmp_path):
    """Event-bound grading: the session-start command sitting under
    PreToolUse matches no known template FOR THAT EVENT -> tampered."""
    _write(tmp_path, {"hooks": {"PreToolUse": [
        {"matcher": "Bash|PowerShell",
         "hooks": [{"type": "command",
                    "command": agent_settings.SESSION_START_COMMAND}]}]}})
    assert agent_settings.settings_state(tmp_path) == "tampered"


def test_respaced_owned_command_still_owned_and_ok(tmp_path):
    """Whitespace-variant ownership gap (carried hard requirement): a
    command respaced by another tool still carries the marker after
    normalization and grades against the template on normalized text."""
    _write(tmp_path, {"hooks": {
        "SessionStart": [{"hooks": [{
            "type": "command",
            "command": "python  -P  -m aramid   agent-hook session-start"}]}],
        "PreToolUse": [{"matcher": "Bash|PowerShell",
                        "hooks": [{
            "type": "command",
            "command": "python -P -m  aramid agent-hook  pre-tool-use"}]}],
    }})
    assert agent_settings.settings_state(tmp_path) == "ok"


def test_uninstall_sweeps_pre_tool_use_entry_too(tmp_path):
    agent_settings.merge_claude_settings(tmp_path)
    assert agent_settings.remove_claude_settings(tmp_path) == "removed"
    assert not (tmp_path / ".claude" / "settings.json").exists()
```

(Add `import json` at the top if not already present. The existing `test_state_ok`-style test and byte-idempotence test already cover "ok after merge" and "unchanged on second merge" — they stay and must still pass against the two-event template.)

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `python -m pytest tests/unit/test_agent_settings.py -v > task-2-red.log 2>&1`
Expected: new tests FAIL (`AttributeError: ... PRE_TOOL_USE_COMMAND` / dict-vs-tuple mismatches); pre-existing tests that pin the old flat template also fail — that is the signal to update them in Step 3. Paste FROM the log.

- [ ] **Step 3: Rewrite the template machinery**

In `src/aramid/agent_settings.py`, replace the section from `SESSION_START_COMMAND = ...` through `def _owned_commands(...)` (keep the module docstring's first two paragraphs; update its third paragraph — the "template carries ONLY the SessionStart entry today" sentence is now false, replace it with: `The template carries the SessionStart and PreToolUse entries. Ownership and grading are EVENT-BOUND: commands are compared against the template of the event array they sit in, so an entry moved to a foreign event can never grade ok, and the merge repairs every event it manages.`):

```python
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
```

Replace the body of `merge_claude_settings` (docstring: append the sentence `Writes every template event; sweeps aramid-owned entries out of every OTHER event first, so a hand-moved entry cannot keep firing beside the fresh ones.`):

```python
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
```

Replace the body of `settings_state` after the `_load` check (docstring: replace the grading sentences with: `"ok" (every template event's owned commands are exactly that event's current template), "stale" (every owned command is known FOR ITS EVENT -- current or prior template -- but the per-event sets differ from the current template, e.g. a sub-2 consumer missing the PreToolUse entry), "tampered" (an owned command matches no known template for the event it sits in: the -P-stripping class of edit, and equally an entry moved to a foreign event), "absent", "unparseable". Comparison is whitespace-normalized on both sides. Never writes.`):

```python
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
```

`remove_claude_settings`, `_load`, `_OWNED_MARK`, `SETTINGS_REL`, `SETTINGS_STATES` all stay; `_session_start_entry` is deleted (superseded by `_template_entry`). Update the existing tests that pin the old flat shapes — known instances (grep for others):

- `test_settings_state_stale_via_known_prior` monkeypatches `KNOWN_PRIOR_COMMANDS` with a tuple `(old,)` — change to the dict form `{"SessionStart": (old,)}`; the rest of that test stands.
- Tests asserting a merged file holds ONLY the SessionStart entry (e.g. the foreign-preservation and tampered-rewrite tests reading back `cmds`) now also see the PreToolUse entry — extend their expected values to the full two-event shape from `test_merge_writes_both_events`.
- The byte-idempotence test stays as-is (behavior unchanged).

Do not weaken any assert to a substring while updating.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_agent_settings.py tests/integration/test_init.py tests/unit/test_launch_shadowing.py -v > task-2-green.log 2>&1`
Expected: all PASS. Paste the summary line FROM the log.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/agent_settings.py tests/unit/test_agent_settings.py tests/integration/test_init.py
git commit -m "feat(agent): event-bound settings template -- per-event grading, whitespace-normalized ownership, merge repairs every managed event"
```

---

### Task 3: `agent_block_armed` config key + `aramid arm --agent`

**Files:**
- Modify: `src/aramid/config.py`, `src/aramid/data/defaults.toml`, `src/aramid/commands/arm.py`, `src/aramid/cli.py`
- Test: `tests/unit/test_arm_agent.py` (create), `tests/unit/test_launch_shadowing.py` (run)

**Interfaces:**
- Consumes: `_key_re`, `_arm_root_key`, `_write_armed`, `_report_misplaced`, `_root_span` (all existing in `arm.py`).
- Produces: `Config.agent_block_armed: bool` (default `False`) — Task 4 reads it; `cmd_arm(..., agent: bool = False)`; CLI flag `aramid arm --agent`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_arm_agent.py` (mirror the shape of `tests/unit/test_arm_shadow.py` — read it first and reuse its fixture/helper conventions for creating a repo with an `aramid.toml`):

```python
"""`aramid arm --agent` -- flips agent_block_armed (root table), the
pre-tool-use rejector's posture switch. Same comment-preserving machinery
as every other arm flag."""
from pathlib import Path

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def _repo(tmp_path: Path, toml_text: str) -> Path:
    (tmp_path / "aramid.toml").write_text(toml_text, encoding="utf-8")
    return tmp_path


def test_arm_agent_flips_the_key(tmp_path, capsys):
    root = _repo(tmp_path, "schema_version = 1\nagent_block_armed = false\n")
    assert cmd_arm(root, agent=True) == 0
    cfg = config_mod.load_config(root)
    assert cfg.agent_block_armed is True
    out = capsys.readouterr().out
    assert f"aramid: arm: agent_block_armed=true written to {root / 'aramid.toml'}\n" in out
    assert ("aramid: arm: agent bake ended -- the pre-tool-use hook now "
            "REJECTS git hook-bypass flags (--no-verify / core.hooksPath) "
            "in agent sessions; humans at a terminal are unaffected.\n") in out


def test_arm_agent_adds_key_when_absent(tmp_path):
    root = _repo(tmp_path, "schema_version = 1\n")
    assert cmd_arm(root, agent=True) == 0
    assert config_mod.load_config(root).agent_block_armed is True


def test_arm_agent_preserves_comments(tmp_path):
    root = _repo(tmp_path,
                 "# header comment\n"
                 "agent_block_armed = false  # inline note\n")
    assert cmd_arm(root, agent=True) == 0
    text = (root / "aramid.toml").read_text(encoding="utf-8")
    assert "# header comment" in text
    assert "agent_block_armed = true  # inline note" in text


def test_arm_agent_without_toml_refuses(tmp_path):
    assert cmd_arm(tmp_path, agent=True) == 3


def test_default_is_false_and_stub_carries_it(tmp_path):
    root = _repo(tmp_path, "schema_version = 1\n")
    assert config_mod.load_config(root).agent_block_armed is False
    stub = config_mod.render_repo_stub("python", "pip")
    assert "agent_block_armed = false\n" in stub


def test_agent_flag_is_recorded_in_arming_state(tmp_path):
    """The walk captures any Config bool ending _armed -- pinned here so
    the premise-recording behavior is a choice, not an accident. It cannot
    invalidate overrides: invalidation is classification-driven and this
    flag never moves a finding's tier."""
    root = _repo(tmp_path, "agent_block_armed = true\n")
    cfg = config_mod.load_config(root)
    assert config_mod.arming_state(cfg)["agent_block_armed"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_arm_agent.py -v > task-3-red.log 2>&1`
Expected: FAIL — `cmd_arm() got an unexpected keyword argument 'agent'`, `Config` has no `agent_block_armed`. Paste FROM the log.

- [ ] **Step 3: Implement**

`src/aramid/config.py`:
1. In the `Config` dataclass, add `agent_block_armed: bool = False` on the line after `tdd_block_armed: bool = False`. (It cannot sit literally beside `semgrep_block_armed` — that field has no default, and defaulted fields must follow non-defaulted ones.)
2. In `load_config`'s `Config(...)` call, add `agent_block_armed=merged.get("agent_block_armed", False),` after the `tdd_block_armed=...` line. No `CURRENT_SCHEMA_VERSION` bump.
3. In `render_repo_stub`, extend `body_dict` — after `"semgrep_block_armed": False,` add `"agent_block_armed": False,`.
4. In `arming_state`'s docstring, after the sentence about `[llm.autolearn].armed`, add: `agent_block_armed IS captured although it arms the agent pre-tool-use rejector rather than moving any finding's tier: recording it costs nothing as an override premise, and it cannot invalidate overrides -- invalidate_stale_overrides asks policy.classify, which never reads it.`

`src/aramid/data/defaults.toml`: after line 7 (`semgrep_block_armed = false`) add:

```toml
# `aramid arm --agent` flips this. Arms the agent pre-tool-use hook: a git
# commit/push carrying a hook bypass is REJECTED in agent sessions instead
# of advised against. Never affects finding tiers or humans at a terminal.
agent_block_armed = false
```

`src/aramid/commands/arm.py`:
1. Beside `_KEY_RE = _key_re("semgrep_block_armed")` add `_AGENT_KEY_RE = _key_re("agent_block_armed")`.
2. Add `agent: bool = False` to `cmd_arm`'s signature (after `shadow: bool = False`).
3. Before the `if tdd:` block, add:

```python
    if agent:
        new_text = _arm_root_key(text, _AGENT_KEY_RE, "agent_block_armed = true")
        if not _write_armed(toml_path, text, new_text, (), "agent_block_armed"):
            return 3
        _report_misplaced(text, _AGENT_KEY_RE, _root_span(text),
                          "agent_block_armed", "the root table")
        print(f"aramid: arm: agent_block_armed=true written to {toml_path}")
        # NOT "findings now BLOCK" like its siblings: this flag never moves
        # a finding's tier -- it changes what the agent pre-tool-use hook
        # does with a bypass-carrying tool call.
        print("aramid: arm: agent bake ended -- the pre-tool-use hook now "
              "REJECTS git hook-bypass flags (--no-verify / core.hooksPath) "
              "in agent sessions; humans at a terminal are unaffected.")
        return 0
```

`src/aramid/cli.py`:
1. In the `arm` parser help string, extend the parenthetical list with `, --agent for the agent pre-tool-use bypass rejector` (before the closing paren).
2. Add `arm_which.add_argument("--agent", action="store_true")` after the `--shadow` line.
3. In the `args.command == "arm"` dispatch, add `agent=args.agent` to the `cmd_arm(...)` call.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_arm_agent.py tests/integration/test_arm.py tests/unit/test_arm_selection.py tests/integration/test_override.py tests/unit/test_launch_shadowing.py -v > task-3-green.log 2>&1`
Expected: all PASS (`test_override.py` covers the walk-based arming-state pins; `test_arm_selection.py` covers the mutually-exclusive group). Paste FROM the log. If `test_arm_selection.py` pins the literal arm help text or flag list, update it to include `--agent` — full-line, not substring.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/config.py src/aramid/data/defaults.toml src/aramid/commands/arm.py src/aramid/cli.py tests/unit/test_arm_agent.py
git commit -m "feat(arm): --agent flips agent_block_armed -- additive config key, no schema bump, arming_state capture pinned as a choice"
```

---

### Task 4: `aramid agent-hook pre-tool-use`

**Files:**
- Modify: `src/aramid/commands/agent_hook.py`, `src/aramid/cli.py`
- Test: `tests/integration/test_agent_hook.py`, `tests/unit/test_launch_shadowing.py` (run)

**Interfaces:**
- Consumes: `find_bypass`/`Bypass` (Task 1), `Config.agent_block_armed` (Task 3).
- Produces: `cmd_agent_hook("pre-tool-use", root)` reading the hook JSON from stdin; stdout is either empty (allow), one advisory JSON line (baking), or one deny JSON line (armed); exit always 0.

- [ ] **Step 1: Write the failing tests**

Add to `tests/integration/test_agent_hook.py`. The file has no fixtures — its convention is module helpers `_repo(tmp_path)` / `_fake_present` plus `monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)` and `init.cmd_init(r)`, calling the hook as `agent_hook.cmd_agent_hook(...)`. Add at the top: `import io`, `import json`, and these helpers beside `_fake_present`:

```python
def _onboarded(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0
    return r


def _feed_stdin(monkeypatch, payload: dict) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))


def _hook_payload(command: str) -> dict:
    return {"session_id": "t", "cwd": ".", "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": command}}


def _arm_agent(r: Path) -> None:
    # NOT a raw append: init's stub already holds `agent_block_armed =
    # false`, and a duplicate key makes the TOML unparseable -- the hook
    # would then fail open and the armed tests would red for the wrong
    # reason. The real arm machinery rewrites the key in place.
    from aramid.commands.arm import cmd_arm
    assert cmd_arm(r, agent=True) == 0
```

New tests:

```python
def test_pre_tool_use_non_matching_command_is_silent(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload("pytest -q tests/unit"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    assert capsys.readouterr().out == ""


def test_pre_tool_use_baking_advisory_full_object(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload("git commit --no-verify -m x"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    out = capsys.readouterr().out
    assert json.loads(out) == {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "additionalContext": (
            "aramid: `git commit` carrying `--no-verify` bypasses this "
            "repo's gate. The bypass is ledger-visible, and the armed "
            "version of this hook rejects the call outright -- re-run "
            "without it; suppress a specific finding with `aramid override "
            "<id> --reason \"...\"` instead."),
    }}


def test_pre_tool_use_armed_denies_full_object(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    _arm_agent(r)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload("git push --no-verify"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    out = capsys.readouterr().out
    assert json.loads(out) == {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": (
            "aramid: `git push` carrying `--no-verify` bypasses the gate "
            "and is REJECTED in this repo (agent surface armed). Re-run "
            "without the bypass; to suppress a specific blocking finding "
            "use `aramid override <id> --reason \"...\"` after `aramid "
            "ledger filter --status open`."),
    }}


def test_pre_tool_use_armed_denies_hookspath_wrapper(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    _arm_agent(r)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload("git -c core.hooksPath=/tmp/x commit -m y"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert parsed["hookSpecificOutput"]["permissionDecisionReason"] == (
        "aramid: `git commit` under `-c core.hooksPath=/tmp/x` bypasses "
        "the gate and is REJECTED in this repo (agent surface armed). "
        "Re-run without the bypass; to suppress a specific blocking "
        "finding use `aramid override <id> --reason \"...\"` after "
        "`aramid ledger filter --status open`.")


def test_pre_tool_use_dry_run_push_allowed_even_armed(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    _arm_agent(r)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload("git push -n origin main"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    assert capsys.readouterr().out == ""


def test_pre_tool_use_message_containing_flag_allowed(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload('git commit -m "docs: explain --no-verify"'))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    assert capsys.readouterr().out == ""


def test_pre_tool_use_unparseable_stdin_fails_open(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    capsys.readouterr()
    monkeypatch.setattr("sys.stdin", io.StringIO("not json {"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    assert capsys.readouterr().out == ""


def test_pre_tool_use_outside_onboarded_repo_fails_open(tmp_path, monkeypatch, capsys):
    # A plain directory: no git repo, no aramid.toml -- even a matching
    # command allows silently.
    _feed_stdin(monkeypatch, _hook_payload("git commit --no-verify"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", tmp_path) == 0
    assert capsys.readouterr().out == ""
```

(The existing `test_unknown_event_is_a_silent_noop` already covers the unknown-event arm; it must still pass after the dispatch restructure.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration/test_agent_hook.py -v > task-4-red.log 2>&1`
Expected: new tests FAIL (silent exit 0, no output — because `pre-tool-use` is an unknown event today, the failures are empty-output asserts on the advisory/deny tests). Paste FROM the log.

- [ ] **Step 3: Implement**

In `src/aramid/commands/agent_hook.py`:

1. Update the module docstring: after the session-start paragraph add: `pre-tool-use screens each Bash/PowerShell tool call's command string for git hook-bypass invocations (aramid.agent_bypass, token-level). While baking it allows and surfaces an advisory through hookSpecificOutput.additionalContext; armed (agent_block_armed = true) it denies via permissionDecision: "deny". Contract pinned against Claude Code 2.1.252; both shapes ride stdout with exit 0, and a harness that ignores the JSON fails open. The non-matching path never imports aramid's heavy modules.`

2. Restructure `cmd_agent_hook` and add the helpers:

```python
def cmd_agent_hook(event: str, root: Path | None = None) -> int:
    try:
        if event == "session-start":
            return _session_start(root)
        if event == "pre-tool-use":
            return _pre_tool_use(root)
        return 0
    except Exception:
        return 0


def _repo_with_aramid(root: Path | None) -> Path | None:
    base = Path(root) if root is not None else Path.cwd()
    from aramid import gitutil
    try:
        repo = gitutil.repo_root(base)
    except Exception:
        return None
    if not (repo / "aramid.toml").is_file():
        return None
    return repo


def _session_start(root: Path | None) -> int:
    repo = _repo_with_aramid(root)
    if repo is None:
        return 0
    print(_session_context(repo), end="")
    return 0


def _pre_tool_use(root: Path | None) -> int:
    import json
    import sys
    try:
        payload = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return 0
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return 0
    from aramid.agent_bypass import find_bypass
    bypass = find_bypass(command)
    if bypass is None:
        return 0
    repo = _repo_with_aramid(root)
    if repo is None:
        return 0
    from aramid import config as config_mod
    cfg = config_mod.load_config(repo)
    print(_decision_json(bypass, armed=cfg.agent_block_armed))
    return 0


def _describe(bypass) -> str:
    if bypass.kind == "hooks-path":
        return f"`git {bypass.subcommand}` under `-c {bypass.token}`"
    return f"`git {bypass.subcommand}` carrying `{bypass.token}`"


def _decision_json(bypass, *, armed: bool) -> str:
    import json
    what = _describe(bypass)
    if armed:
        body = {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"aramid: {what} bypasses the gate and is REJECTED in this"
                f" repo (agent surface armed). Re-run without the bypass;"
                f" to suppress a specific blocking finding use `aramid"
                f" override <id> --reason \"...\"` after `aramid ledger"
                f" filter --status open`."),
        }
    else:
        body = {
            "hookEventName": "PreToolUse",
            "additionalContext": (
                f"aramid: {what} bypasses this repo's gate. The bypass is"
                f" ledger-visible, and the armed version of this hook"
                f" rejects the call outright -- re-run without it; suppress"
                f" a specific finding with `aramid override <id> --reason"
                f" \"...\"` instead."),
        }
    return json.dumps({"hookSpecificOutput": body})
```

The existing `cmd_agent_hook` body (repo detection + `print(_session_context(repo), end="")`) moves into `_session_start` unchanged; `_session_context` stays as-is. Note the whole dispatch stays inside the one outer `try/except Exception: return 0` — that IS the fail-open boundary, including a mid-`print` failure.

3. In `src/aramid/cli.py`, update the `agent-hook` parser help to:

```python
        help="agent-harness hook endpoint (Claude Code): session-start "
             "prints live gate posture for the session's context; "
             "pre-tool-use screens git commands for hook-bypass flags "
             "(advisory while baking, deny when armed); any other event "
             "is a silent no-op")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_agent_hook.py tests/unit/test_agent_bypass.py tests/unit/test_launch_shadowing.py -v > task-4-green.log 2>&1`
Expected: all PASS (session-start tests included — the restructure must not move them). Paste FROM the log.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/agent_hook.py src/aramid/cli.py tests/integration/test_agent_hook.py
git commit -m "feat(agent): pre-tool-use hook -- advisory while baking, deny when armed, fail-open everywhere else"
```

---

### Task 5: Doctor polish — state-word prose, two-hook detail, probe remedy, hermetic fixture

**Files:**
- Modify: `src/aramid/commands/doctor.py`, `tests/conftest.py`, `pyproject.toml`
- Test: `tests/unit/test_doctor_agent_probe.py` (create), existing doctor/agent full-line asserts (update), `tests/unit/test_launch_shadowing.py` (run)

**Interfaces:**
- Consumes: `settings_state` semantics from Task 2 (vocabulary unchanged).
- Produces: detail strings that echo their literal state word; a `real_interpreter_probe` pytest marker; an autouse fixture stubbing `doctor.agent_interpreter_lines` to `[]` suite-wide.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_doctor_agent_probe.py`:

```python
"""agent_interpreter_lines' probe arms, exercised hermetically (the
autouse conftest stub is bypassed via the real_interpreter_probe marker;
inside these tests the subprocess itself is monkeypatched)."""
import subprocess

import pytest

from aramid.commands import doctor


pytestmark = pytest.mark.real_interpreter_probe


def test_no_python_on_path(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert doctor.agent_interpreter_lines() == [
        "  WARN interpreter no `python` on PATH -- the generated"
        " agent-hook command cannot run; install one or adjust PATH"]


def test_probe_failure_names_a_remedy(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/x/python")
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="python", timeout=15)
    monkeypatch.setattr(doctor.subprocess, "run", _boom)
    assert doctor.agent_interpreter_lines() == [
        "  WARN interpreter `python` on PATH (/x/python) could not be"
        " probed -- run `/x/python -P -c \"import aramid\"` yourself; if"
        " it fails, `pip install aramid` into that interpreter or fix"
        " PATH"]


def test_import_failure_line(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/x/python")
    class _P:
        returncode = 1
    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: _P())
    assert doctor.agent_interpreter_lines() == [
        "  WARN interpreter `python` on PATH (/x/python) cannot import"
        " aramid -- the agent-hook entry in .claude/settings.json will"
        " error at every session start; `pip install aramid` into that"
        " interpreter or fix PATH"]


def test_healthy_probe_is_silent(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/x/python")
    class _P:
        returncode = 0
    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: _P())
    assert doctor.agent_interpreter_lines() == []
```

NOTE: these tests monkeypatch `doctor.shutil` / `doctor.subprocess`, which requires Step 3's change hoisting the function's imports to module scope (they are currently function-local). Also add to the exhaustiveness pins wherever `_AGENT_FILE_DETAIL` / `_AGENT_SETTINGS_DETAIL` are pinned today (in the existing agent doctor tests): an assert that every detail string starts with its own state word:

```python
def test_detail_prose_echoes_state_words():
    from aramid.commands import doctor
    for state, detail in doctor._AGENT_FILE_DETAIL.items():
        assert detail.startswith(f"{state}:")
    for state, detail in doctor._AGENT_SETTINGS_DETAIL.items():
        assert detail.startswith(f"{state}:")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_doctor_agent_probe.py -v > task-5-red.log 2>&1`
Expected: FAIL — marker unknown is tolerated but the remedy-verb assert and the `doctor.shutil` attribute do not exist yet. Paste FROM the log.

- [ ] **Step 3: Implement**

`src/aramid/commands/doctor.py`:

1. `agent_interpreter_lines`: delete the function-local `import shutil` / `import subprocess` (both are ALREADY imported at module scope — verify at the top of the file; `shutil` is, `subprocess` is; if either is missing, add it). Change the could-not-be-probed return to:

```python
        return [f"  WARN interpreter `python` on PATH ({exe}) could not be"
                f" probed -- run `{exe} -P -c \"import aramid\"` yourself; if"
                f" it fails, `pip install aramid` into that interpreter or"
                f" fix PATH"]
```

2. Replace `_AGENT_FILE_DETAIL` with (each detail now echoes its literal state word — grep-able against doctor output, and the word is what every other surface calls the state):

```python
_AGENT_FILE_DETAIL = {
    "ok": "ok: managed aramid block present",
    "stale": "stale: aramid block differs from the current template"
             " -- re-run `aramid init`",
    "absent": "absent: no managed aramid block -- run `aramid init`",
    "damaged": "damaged: aramid fence is damaged (unterminated or"
               " duplicated begin marker) -- repair or delete the fence,"
               " then re-run `aramid init`",
    "unreadable": "unreadable: file could not be read (not valid UTF-8, or"
                  " an I/O error) -- fix the file, then run `aramid init`",
}
```

3. Replace `_AGENT_SETTINGS_DETAIL` with:

```python
_AGENT_SETTINGS_DETAIL = {
    "ok": "ok: aramid agent hooks registered (SessionStart + PreToolUse,"
          " .claude/settings.json)",
    "absent": "absent: no aramid hook entry in .claude/settings.json --"
              " run `aramid init`",
    "stale": "stale: aramid's hook entries are known but not current (an"
             " older template, or a missing event) -- re-run `aramid"
             " init`",
    "tampered": "tampered: an aramid-named hook entry differs from the"
                " template for its event -- treat as tampering; re-run"
                " `aramid init` to rewrite it and investigate how it"
                " changed",
    "unparseable": "unparseable: .claude/settings.json could not be parsed"
                   " -- fix the JSON, then run `aramid init`",
}
```

4. Update every existing full-line assert that pins the OLD detail strings (grep tests for `managed aramid block present` and `session-start hook registered` to find them) to the new strings. Do not weaken to substrings.

`tests/conftest.py` — add (beside the existing machine-isolation fixtures):

```python
@pytest.fixture(autouse=True)
def _stub_agent_interpreter_probe(request, monkeypatch):
    """doctor.agent_interpreter_lines spawns a real subprocess against
    PATH's python -- machine state, not repo state. Stubbed suite-wide so
    doctor-reaching tests are hermetic; the probe's own tests opt out with
    @pytest.mark.real_interpreter_probe and stub the subprocess instead."""
    if "real_interpreter_probe" in request.keywords:
        yield
        return
    from aramid.commands import doctor
    monkeypatch.setattr(doctor, "agent_interpreter_lines", lambda: [])
    yield
```

`pyproject.toml` — in `[tool.pytest.ini_options]` add:

```toml
markers = [
    "real_interpreter_probe: opt out of the autouse agent_interpreter_lines stub (the probe's own tests)",
]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_doctor_agent_probe.py tests/integration/test_doctor.py tests/integration/test_init.py tests/unit/test_launch_shadowing.py -v > task-5-green.log 2>&1`
Expected: all PASS. Paste FROM the log.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/doctor.py tests/conftest.py pyproject.toml tests/unit/test_doctor_agent_probe.py
git commit -m "fix(doctor): state-word prose in agent details, probe-failure remedy verb, suite-wide hermetic probe stub"
```

(Also `git add` whichever existing test files had their full-line asserts updated in Step 3.4.)

---

### Task 6: Status posture, block-template sentence, init notice, docs

**Files:**
- Modify: `src/aramid/commands/status.py`, `src/aramid/agent_files.py`, `src/aramid/commands/init.py`, `docs/user-guide.md`, `CHANGELOG.md`
- Test: `tests/integration/test_init.py` (holds `test_status_reports_agent_surfaces` at ~line 869), `tests/unit/test_agent_files.py`, `tests/unit/test_launch_shadowing.py` (run)

**Interfaces:**
- Consumes: `settings_state` (Task 2), `Config.agent_block_armed` (Task 3).
- Produces: `_agent_surfaces_line(root, cfg) -> str` (signature gains `cfg`).

- [ ] **Step 1: Write the failing tests**

In `tests/integration/test_init.py`, `test_status_reports_agent_surfaces` currently ends:

```python
    assert cmd_status(r) == 0
    assert ("agent surfaces: blocks 2/2, session hook ok"
            in capsys.readouterr().out)
```

Replace those two lines and extend the test to cover both postures:

```python
    assert cmd_status(r) == 0
    assert ("agent surfaces: blocks 2/2, hooks ok | baking"
            in capsys.readouterr().out)

    from aramid.commands.arm import cmd_arm
    assert cmd_arm(r, agent=True) == 0
    capsys.readouterr()
    assert cmd_status(r) == 0
    assert ("agent surfaces: blocks 2/2, hooks ok | armed"
            in capsys.readouterr().out)
```

In `tests/unit/test_agent_files.py`, update the template-pinning asserts for the new block text (Step 3.2). In `tests/integration/test_init.py`, update the settings-notice assert for the new wording (Step 3.3).

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration/test_init.py::test_status_reports_agent_surfaces tests/unit/test_agent_files.py -v > task-6-red.log 2>&1`
Expected: the updated asserts FAIL against current output. Paste FROM the log.

- [ ] **Step 3: Implement**

1. `src/aramid/commands/status.py` — replace `_agent_surfaces_line` with:

```python
def _agent_surfaces_line(root: Path, cfg: config_mod.Config) -> str:
    from aramid import agent_files, agent_settings
    states = agent_files.agent_block_states(root)
    ok = sum(1 for _, s in states if s == "ok")
    posture = "armed" if cfg.agent_block_armed else "baking"
    return (f"agent surfaces: blocks {ok}/{len(states)}, "
            f"hooks {agent_settings.settings_state(root)} | {posture}")
```

and pass `cfg` at its call site in `cmd_status` (the caller already holds the loaded config; thread it through).

2. `src/aramid/agent_files.py` — in `_BLOCK`, extend the `--no-verify` bullet (carried hard requirement: restore the armed sentence; consumer blocks going stale → refresh on next init is the designed rollout):

```python
- NEVER pass `--no-verify` (or `-n`) to `git commit`, or `--no-verify` to
  `git push` -- it disables secret scanning along with everything else.
  Armed repos reject the call outright.
```

3. `src/aramid/commands/init.py` — `render_agent_settings_notice`: change the unparseable line's tail from `" register aramid's session-start hook"` to `" register aramid's agent hooks"`, and the success text to:

```python
    return ("aramid: init: registered aramid's agent hooks (SessionStart +"
            " PreToolUse) in .claude/settings.json -- sessions start with"
            " live gate posture and git bypass flags are screened:\n"
            'aramid: init:       git add .claude/settings.json && git commit'
            ' -m "chore: aramid agent hooks"')
```

4. `docs/user-guide.md`: in the agent-surfaces paragraph (§6), append: the `pre-tool-use` hook screens each agent tool call for `git commit`/`git push` carrying `--no-verify`/`-n` or a `-c core.hooksPath=...` wrapper — advisory while baking, rejected once the repo runs `aramid arm --agent`; humans at a real terminal are untouched. In the arm section's flag list, add `--agent` with one line: ends the agent-surface bake; the pre-tool-use hook then rejects bypass-carrying tool calls. In the §2 exit-code / posture material, no changes (tampered already listed in sub-2).

5. `CHANGELOG.md` `[Unreleased]`:
   - under `### Added`: `- `aramid agent-hook pre-tool-use`: token-level screening of agent tool calls for git hook-bypass invocations (`--no-verify`/`-n`, `-c core.hooksPath=...`) -- advisory while baking, denied once armed via `aramid arm --agent` (new root config key `agent_block_armed`, default false).`
   - under `### Changed` (create the heading if absent): `- .claude/settings.json template now registers a PreToolUse entry beside SessionStart, and grading is event-bound and whitespace-normalized: an aramid entry moved to a foreign event or edited grades tampered (doctor exit 2); a sub-2-era file with only the SessionStart entry grades stale -- re-run `aramid init`. The managed CLAUDE.md/AGENTS.md block gained "Armed repos reject the call outright." (existing blocks go stale until re-init; by design).`

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_status.py tests/unit/test_agent_files.py tests/integration/test_init.py tests/unit/test_launch_shadowing.py -v > task-6-green.log 2>&1`
Expected: all PASS. Paste FROM the log.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/status.py src/aramid/agent_files.py src/aramid/commands/init.py docs/user-guide.md CHANGELOG.md tests/unit/test_agent_files.py tests/integration/test_init.py
git commit -m "feat(agent): status posture, armed sentence in the managed block, two-hook init notice, docs + changelog"
```

(Also `git add tests/integration/test_status.py` if Step 4 forced assert updates there.)

---

## After the last task

Do NOT push as a plan step; hand back to the controller (full suite, then the integration menu). Notes for the controller and for sub-project 4 (MCP):

- **Release gating unchanged:** the next release ships sub-2 AND sub-3. The release announcement MUST state the aramid version floor — the tracked `.claude/settings.json` now carries a `pre-tool-use` event that pre-sub-2 wheels would die on in argparse (post-F4 wheels no-op). No dogfood `aramid init .` until post-promotion.
- **Sub-4 carries:** `.mcp.json` merge/grading should mirror the event-bound, whitespace-normalized discipline shipped here (entry graded against the template for the slot it occupies); the MCP command joins the generated-launch family and `tests/unit/test_launch_shadowing.py` applies to it; `aramid status`'s agent-surfaces line gains `mcp <state>` (spec §8's example); doctor's settings section gains the `.mcp.json` grades.
- **Baking advisory rendering is harness-pinned (2.1.252, `additionalContext`).** If a future harness stops rendering it, the degradation is automatic allow — re-pin at the next sub-project, do not add version sniffing.
- **`KNOWN_PRIOR_COMMANDS` stays empty** until a template command actually changes; the sub-2→sub-3 transition is expressed entirely as per-event set inequality (stale), never as a prior command.
