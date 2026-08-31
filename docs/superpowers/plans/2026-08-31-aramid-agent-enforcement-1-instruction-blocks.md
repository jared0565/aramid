# Agent Enforcement 1 — Managed Instruction Blocks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `aramid init` writes a marker-fenced, aramid-managed instruction block into CLAUDE.md and AGENTS.md (creating the files when absent, never touching content outside the fence); `uninstall` removes it; `doctor` reports its state.

**Architecture:** One new focused module, `src/aramid/agent_files.py`, owns the block template and all fence-scoped read/write/remove logic. `commands/init.py`, `commands/uninstall.py`, and `commands/doctor.py` each consume it with thin wiring — the same shape as the existing ARAMID.md/gitignore helpers, except shared across three commands, which is why it gets its own module instead of living in `init.py`. (The spec sketches the writer inside `init.py`; the standalone module implements identical semantics and is the refinement, not a deviation — uninstall and doctor need the same fence parser.)

**Tech Stack:** Python ≥3.11, stdlib only (pathlib). No new dependencies. Tests: pytest, existing `tests/unit/` + `tests/integration/` conventions.

**Spec:** `docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md` (§3 blocks, §8 lifecycle, §10 testing). Sub-project 1 of 4.

## Global Constraints

- Content outside the fence is NEVER touched; a file whose fence is damaged (begin marker without end marker) is NEVER written — report, don't guess (spec §4 rule applied to blocks).
- The blocks carry only durable instructions — no counts, dates, or posture (spec §3 static/live division).
- Generated text uses ASCII `--`, never em-dashes (house style, matches ARAMID.md).
- All file writes `encoding="utf-8"`, text mode (matches `_write_aramid_md`).
- init notices follow the house three rules (see `render_gitignore_notice` docstring): name the artifact, give the command rather than a complaint, stay silent when git cannot answer.
- Every test runs in a tmp repo; the autouse conftest fixtures (`_isolated_registry`, `_isolated_user_config`, `_isolated_tools_dir`, `_isolated_git_template`) already isolate machine state — do not weaken them.
- Test/impl files containing `\n` string literals are written with the Write tool, never via bash heredoc (heredoc bodies mangle backslashes on this machine).
- `git add` new files before running any repo-wide guard; commit at the end of every task (pre-commit gate runs gitleaks+ruff, ~5s).

---

### Task 1: `agent_files.py` — template + fence-scoped writer

**Files:**
- Create: `src/aramid/agent_files.py`
- Create: `tests/unit/test_agent_files.py`

**Interfaces:**
- Consumes: nothing (stdlib only).
- Produces (later tasks rely on these exact names):
  - `AGENT_FILES: tuple[str, str] = ("CLAUDE.md", "AGENTS.md")`
  - `render_block() -> str` — the full fenced block, trailing newline.
  - `write_agent_blocks(root: Path) -> list[tuple[str, str]]` — `[(filename, action)]`, action ∈ `{"created", "appended", "replaced", "unchanged", "damaged"}`.

- [ ] **Step 1: Write the failing tests**

Write `tests/unit/test_agent_files.py`:

```python
"""unit: agent_files -- the managed block aramid owns inside CLAUDE.md and
AGENTS.md. Fence-scoped writes: content outside the markers is untouchable,
and a damaged fence (begin without end) refuses the write entirely."""
from aramid import agent_files


def test_created_when_absent(tmp_path):
    actions = agent_files.write_agent_blocks(tmp_path)

    assert actions == [("CLAUDE.md", "created"), ("AGENTS.md", "created")]
    for name in ("CLAUDE.md", "AGENTS.md"):
        assert (tmp_path / name).read_text(encoding="utf-8") == agent_files.render_block()


def test_appended_preserves_existing_content_byte_for_byte(tmp_path):
    user_text = "# My project\n\nDo the thing.\n"
    (tmp_path / "CLAUDE.md").write_text(user_text, encoding="utf-8")

    actions = agent_files.write_agent_blocks(tmp_path)

    assert ("CLAUDE.md", "appended") in actions
    text = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert text == user_text + "\n" + agent_files.render_block()


def test_replaced_touches_only_the_fence(tmp_path):
    before = "# Mine\n"
    stale = ("<!-- aramid:begin -- old header -->\nOLD CONTENT\n"
             "<!-- aramid:end -->\n")
    after = "\n# Also mine\n"
    (tmp_path / "CLAUDE.md").write_text(before + stale + after, encoding="utf-8")

    actions = agent_files.write_agent_blocks(tmp_path)

    assert ("CLAUDE.md", "replaced") in actions
    text = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert text == before + agent_files.render_block() + after


def test_second_run_is_unchanged_and_byte_identical(tmp_path):
    agent_files.write_agent_blocks(tmp_path)
    first = (tmp_path / "CLAUDE.md").read_bytes()

    actions = agent_files.write_agent_blocks(tmp_path)

    assert actions == [("CLAUDE.md", "unchanged"), ("AGENTS.md", "unchanged")]
    assert (tmp_path / "CLAUDE.md").read_bytes() == first


def test_damaged_fence_is_never_written(tmp_path):
    damaged = "# Mine\n<!-- aramid:begin -- managed -->\nno end marker here\n"
    (tmp_path / "AGENTS.md").write_text(damaged, encoding="utf-8")

    actions = agent_files.write_agent_blocks(tmp_path)

    assert ("AGENTS.md", "damaged") in actions
    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == damaged


def test_block_content_names_the_commands():
    block = agent_files.render_block()
    assert block.startswith("<!-- aramid:begin")
    assert block.endswith("<!-- aramid:end -->\n")
    for needle in ("ARAMID.md", "aramid check --staged",
                   "aramid ledger filter --status open", "--no-verify",
                   "aramid override"):
        assert needle in block
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py -v -o pythonpath=src`
Expected: FAIL — `ModuleNotFoundError: No module named 'aramid.agent_files'` (or ImportError). Note: `pyproject.toml` already sets `pythonpath = ["src"]` for pytest; the `-o` override is belt-and-braces so the checkout, not the promoted wheel, is under test. If collection errors mention the wheel path, stop and fix the environment first — print `python -c "import aramid; print(aramid.__file__)"`.

- [ ] **Step 3: Write the implementation**

Write `src/aramid/agent_files.py`:

```python
"""agent_files -- the managed instruction block aramid owns inside a
consumer's agent instruction files (CLAUDE.md, AGENTS.md).

Spec: docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md §3.

The block is regenerated wholesale on every `init`, like ARAMID.md -- but
unlike ARAMID.md these files are SHARED with the operator and other tools,
so every write is fence-scoped: content outside the markers is never
touched, and a file whose fence is damaged (a begin marker with no end
marker) is never written at all. A splice that cannot see where the fence
ends would eat whatever follows it, so refusing is the only safe write.

Only durable instructions belong in the block -- no counts, dates, or
posture. Live state is the session-start agent hook's job (spec §5); a
tracked file must not be able to go stale against the ledger.
"""
from pathlib import Path

AGENT_FILES = ("CLAUDE.md", "AGENTS.md")

_BEGIN_PREFIX = "<!-- aramid:begin"
_END_MARKER = "<!-- aramid:end -->"

_BLOCK = """\
<!-- aramid:begin -- managed by `aramid init`; hand-edits inside the fence are overwritten -->
## Aramid (security & quality gate)

This repo is gated by aramid. Read `ARAMID.md` before your first commit.

- Before committing: run `aramid check --staged`. Read findings with
  `aramid ledger filter --status open`.
- NEVER pass `--no-verify` (or `-n`) to `git commit`, or `--no-verify` to
  `git push` -- it disables secret scanning along with everything else.
- To suppress a WARN finding, use `aramid override <id> --reason "..."`
  (ledger-logged); never edit findings away by hand.
<!-- aramid:end -->
"""


def render_block() -> str:
    return _BLOCK


def _find_fence(lines: list[str]) -> tuple[int | None, int | None]:
    """Indexes of the begin and end marker lines, either possibly None."""
    begin = end = None
    for i, line in enumerate(lines):
        if begin is None and line.lstrip().startswith(_BEGIN_PREFIX):
            begin = i
        elif begin is not None and line.strip() == _END_MARKER:
            end = i
            break
    return begin, end


def write_agent_blocks(root: Path) -> list[tuple[str, str]]:
    """Write/refresh the managed block in each of AGENT_FILES.

    Returns [(filename, action)]; action is one of "created" (file was
    absent), "appended" (file had no fence), "replaced" (fence refreshed),
    "unchanged" (fence already current), "damaged" (begin marker without an
    end marker -- file left untouched, caller must report it).
    """
    actions: list[tuple[str, str]] = []
    for name in AGENT_FILES:
        path = root / name
        if not path.is_file():
            path.write_text(_BLOCK, encoding="utf-8")
            actions.append((name, "created"))
            continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        begin, end = _find_fence(lines)
        if begin is not None and end is None:
            actions.append((name, "damaged"))
            continue
        if begin is None:
            sep = ("" if text.endswith("\n\n")
                   else "\n" if text.endswith("\n") else "\n\n")
            path.write_text(text + sep + _BLOCK, encoding="utf-8")
            actions.append((name, "appended"))
            continue
        new = "".join(lines[:begin]) + _BLOCK + "".join(lines[end + 1:])
        if new == text:
            actions.append((name, "unchanged"))
        else:
            path.write_text(new, encoding="utf-8")
            actions.append((name, "replaced"))
    return actions
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py -v -o pythonpath=src`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/agent_files.py tests/unit/test_agent_files.py
git commit -m "feat(agent): managed instruction block writer -- fence-scoped, damage-refusing"
```

---

### Task 2: removal + state inspection

**Files:**
- Modify: `src/aramid/agent_files.py` (append two functions)
- Modify: `tests/unit/test_agent_files.py` (append tests)

**Interfaces:**
- Consumes: `_find_fence`, `_BLOCK`, `AGENT_FILES` from Task 1.
- Produces:
  - `remove_agent_blocks(root: Path) -> list[tuple[str, str]]` — action ∈ `{"removed", "deleted", "absent", "damaged"}` (`"deleted"` = only the block remained, file unlinked).
  - `agent_block_states(root: Path) -> list[tuple[str, str]]` — state ∈ `{"ok", "stale", "absent", "damaged"}`; read-only.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_agent_files.py`:

```python
def test_remove_strips_fence_and_keeps_user_content(tmp_path):
    user_text = "# My project\n\nDo the thing.\n"
    (tmp_path / "CLAUDE.md").write_text(user_text, encoding="utf-8")
    agent_files.write_agent_blocks(tmp_path)

    actions = agent_files.remove_agent_blocks(tmp_path)

    assert ("CLAUDE.md", "removed") in actions
    # append inserted one "\n" separator; removal strips only fence lines.
    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == user_text + "\n"


def test_remove_deletes_file_that_was_only_the_block(tmp_path):
    agent_files.write_agent_blocks(tmp_path)

    actions = agent_files.remove_agent_blocks(tmp_path)

    assert actions == [("CLAUDE.md", "deleted"), ("AGENTS.md", "deleted")]
    assert not (tmp_path / "CLAUDE.md").exists()
    assert not (tmp_path / "AGENTS.md").exists()


def test_remove_reports_absent_and_damaged(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("no fence here\n", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text(
        "<!-- aramid:begin -- x -->\nno end\n", encoding="utf-8")

    actions = agent_files.remove_agent_blocks(tmp_path)

    assert actions == [("CLAUDE.md", "absent"), ("AGENTS.md", "damaged")]
    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == (
        "<!-- aramid:begin -- x -->\nno end\n")


def test_states_ok_stale_absent_damaged(tmp_path):
    agent_files.write_agent_blocks(tmp_path)                       # CLAUDE ok
    stale = agent_files.render_block().replace(
        "security & quality gate", "old title")
    (tmp_path / "AGENTS.md").write_text(stale, encoding="utf-8")   # stale

    states = dict(agent_files.agent_block_states(tmp_path))
    assert states == {"CLAUDE.md": "ok", "AGENTS.md": "stale"}

    (tmp_path / "CLAUDE.md").unlink()
    (tmp_path / "AGENTS.md").write_text(
        "<!-- aramid:begin -- x -->\nno end\n", encoding="utf-8")
    states = dict(agent_files.agent_block_states(tmp_path))
    assert states == {"CLAUDE.md": "absent", "AGENTS.md": "damaged"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py -v -o pythonpath=src`
Expected: the 4 new tests FAIL with `AttributeError: ... has no attribute 'remove_agent_blocks'`; the 6 from Task 1 still pass.

- [ ] **Step 3: Write the implementation**

Append to `src/aramid/agent_files.py`:

```python
def remove_agent_blocks(root: Path) -> list[tuple[str, str]]:
    """Reverse of write_agent_blocks, for `aramid uninstall`.

    Returns [(filename, action)]; "removed" strips the fence, "deleted"
    unlinks a file that held nothing but the block, "absent" means no file
    or no fence, "damaged" means an unterminated fence -- untouched, same
    refusal as the writer and for the same reason.
    """
    actions: list[tuple[str, str]] = []
    for name in AGENT_FILES:
        path = root / name
        if not path.is_file():
            actions.append((name, "absent"))
            continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        begin, end = _find_fence(lines)
        if begin is None:
            actions.append((name, "absent"))
            continue
        if end is None:
            actions.append((name, "damaged"))
            continue
        rest = "".join(lines[:begin]) + "".join(lines[end + 1:])
        if rest.strip():
            path.write_text(rest, encoding="utf-8")
            actions.append((name, "removed"))
        else:
            path.unlink()
            actions.append((name, "deleted"))
    return actions


def agent_block_states(root: Path) -> list[tuple[str, str]]:
    """Read-only state per agent file, for `aramid doctor`.

    States: "ok" (fence matches the current template), "stale" (fence
    present but differs), "absent" (no file or no fence), "damaged"
    (unterminated fence). Doctor reports; it never rewrites.
    """
    block_lines = _BLOCK.splitlines(keepends=True)
    states: list[tuple[str, str]] = []
    for name in AGENT_FILES:
        path = root / name
        if not path.is_file():
            states.append((name, "absent"))
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        except OSError:
            states.append((name, "absent"))
            continue
        begin, end = _find_fence(lines)
        if begin is None:
            states.append((name, "absent"))
        elif end is None:
            states.append((name, "damaged"))
        elif lines[begin:end + 1] == block_lines:
            states.append((name, "ok"))
        else:
            states.append((name, "stale"))
    return states
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py -v -o pythonpath=src`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/agent_files.py tests/unit/test_agent_files.py
git commit -m "feat(agent): block removal + doctor-facing state inspection"
```

---

### Task 3: init wiring + notice

**Files:**
- Modify: `src/aramid/commands/init.py` (import; call in step 4 at ~line 452; new `render_agent_blocks_notice`; notice loop at ~line 487)
- Modify: `tests/unit/test_agent_files.py` (notice unit tests — the notice lives in init.py but is tested beside the module it reports on)
- Modify: `tests/integration/test_init.py` (two integration tests)

**Interfaces:**
- Consumes: `agent_files.write_agent_blocks`, `agent_files.render_block` (Task 1).
- Produces: `render_agent_blocks_notice(root: Path, actions: list[tuple[str, str]]) -> str` in `commands/init.py` (Task 4's uninstall does NOT use it; listed for reviewers).

- [ ] **Step 1: Write the failing integration tests**

Append to `tests/integration/test_init.py` (uses the existing `_repo`, `_fake_present` helpers and `doctor`/`init` imports already at the top of that file; add `from aramid import agent_files` to its imports):

```python
# --- managed agent instruction blocks (agent-enforcement sub-project 1) -----

def test_init_writes_agent_blocks_and_reinit_is_byte_stable(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    assert init.cmd_init(r) == 0

    for name in ("CLAUDE.md", "AGENTS.md"):
        assert (r / name).read_text(encoding="utf-8") == agent_files.render_block()
    first = (r / "CLAUDE.md").read_bytes()

    assert init.cmd_init(r) == 0
    assert (r / "CLAUDE.md").read_bytes() == first


def test_init_appends_to_user_authored_claude_md(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    user_text = "# House rules\n\nAlways run the linter.\n"
    (r / "CLAUDE.md").write_text(user_text, encoding="utf-8")

    assert init.cmd_init(r) == 0

    text = (r / "CLAUDE.md").read_text(encoding="utf-8")
    assert text == user_text + "\n" + agent_files.render_block()
```

And append notice tests to `tests/unit/test_agent_files.py` (add `from aramid.commands.init import render_agent_blocks_notice` and `import subprocess` to its imports):

```python
def _git_repo(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True,
                   capture_output=True)
    return tmp_path


def test_notice_names_changed_files_and_gives_the_command(tmp_path):
    root = _git_repo(tmp_path)
    notice = render_agent_blocks_notice(
        root, [("CLAUDE.md", "created"), ("AGENTS.md", "appended")])
    assert notice == (
        "aramid: init: wrote the managed agent block into CLAUDE.md, AGENTS.md"
        " -- agent coders read these files from the repo:\n"
        'aramid: init:       git add CLAUDE.md AGENTS.md && '
        'git commit -m "chore: aramid agent block"')


def test_notice_silent_when_unchanged(tmp_path):
    root = _git_repo(tmp_path)
    assert render_agent_blocks_notice(
        root, [("CLAUDE.md", "unchanged"), ("AGENTS.md", "unchanged")]) == ""


def test_notice_reports_damaged_even_outside_git(tmp_path):
    notice = render_agent_blocks_notice(tmp_path, [("AGENTS.md", "damaged")])
    assert notice == (
        "aramid: init: AGENTS.md has an aramid fence with no closing marker"
        " -- left untouched; restore the `<!-- aramid:end -->` line (or"
        " delete the fence) and re-run `aramid init`")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py tests/integration/test_init.py -v -o pythonpath=src`
Expected: the 3 notice tests FAIL on ImportError (`render_agent_blocks_notice` missing); the 2 integration tests FAIL on the block-content asserts (init doesn't write the files yet). Pre-existing tests still pass.

- [ ] **Step 3: Wire init**

In `src/aramid/commands/init.py`:

a) Add to the module's imports: `from aramid import agent_files`

b) After the `_write_aramid_md(root, stack, pkg_mgr)` call (~line 452), insert:

```python
    agent_actions = agent_files.write_agent_blocks(root)
```

c) Add the notice renderer next to `render_gitignore_notice` (~line 242):

```python
def render_agent_blocks_notice(root: Path,
                               actions: list[tuple[str, str]]) -> str:
    """Sibling of render_aramid_md_notice / render_gitignore_notice; same
    three rules for the changed-files line. The damaged line is different in
    kind: it reports a REFUSED write (an unterminated aramid fence), which
    is worth saying even outside a git work tree -- it is a defect in the
    file, not a housekeeping chore."""
    lines: list[str] = []
    for name, action in actions:
        if action == "damaged":
            lines.append(
                f"aramid: init: {name} has an aramid fence with no closing"
                f" marker -- left untouched; restore the"
                f" `<!-- aramid:end -->` line (or delete the fence) and"
                f" re-run `aramid init`")
    changed = [n for n, a in actions
               if a in ("created", "appended", "replaced")]
    if changed and gitutil._run(
            root, "rev-parse", "--is-inside-work-tree").returncode == 0:
        names = ", ".join(changed)
        lines.append(
            f"aramid: init: wrote the managed agent block into {names}"
            f" -- agent coders read these files from the repo:")
        lines.append(
            f'aramid: init:       git add {" ".join(changed)} && '
            f'git commit -m "chore: aramid agent block"')
    return "\n".join(lines)
```

d) Extend the notice loop at ~line 487 to a three-tuple:

```python
    for notice in (render_aramid_md_notice(root),
                   render_gitignore_notice(root, gi_added, gi_created),
                   render_agent_blocks_notice(root, agent_actions)):
        if notice:
            print(notice, file=sys.stderr)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py tests/integration/test_init.py -v -o pythonpath=src`
Expected: all pass (13 in test_agent_files, existing + 2 new in test_init).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/init.py tests/unit/test_agent_files.py tests/integration/test_init.py
git commit -m "feat(init): write managed agent blocks into CLAUDE.md/AGENTS.md with house notice"
```

---

### Task 4: uninstall wiring

**Files:**
- Modify: `src/aramid/commands/uninstall.py`
- Modify: `tests/integration/test_init.py` (uninstall round-trip test)

**Interfaces:**
- Consumes: `agent_files.remove_agent_blocks` (Task 2).
- Produces: nothing new — behavior only.

- [ ] **Step 1: Write the failing test**

Append to `tests/integration/test_init.py` (add `from aramid.commands import uninstall` to its imports):

```python
def test_uninstall_reverses_agent_blocks(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    user_text = "# House rules\n\nAlways run the linter.\n"
    (r / "CLAUDE.md").write_text(user_text, encoding="utf-8")
    assert init.cmd_init(r) == 0

    assert uninstall.cmd_uninstall(r) == 0

    # user-authored file: block stripped, user content intact.
    assert (r / "CLAUDE.md").read_text(encoding="utf-8") == user_text + "\n"
    # init-created file: nothing but the block, so deleted outright.
    assert not (r / "AGENTS.md").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `env -u PYTHONPATH python -P -m pytest tests/integration/test_init.py::test_uninstall_reverses_agent_blocks -v -o pythonpath=src`
Expected: FAIL — CLAUDE.md still contains the block after uninstall.

- [ ] **Step 3: Wire uninstall**

In `src/aramid/commands/uninstall.py`:

a) Add to imports: `from aramid import agent_files`

b) After the `ARAMID.md` unlink block (`md_path.unlink()`), insert:

```python
    agent_actions = agent_files.remove_agent_blocks(root)
    for name, action in agent_actions:
        if action == "damaged":
            print(f"aramid: uninstall: {name} has an aramid fence with no"
                  f" closing marker -- left untouched; remove the fence by"
                  f" hand.", file=sys.stderr)
```

c) Update the final summary print to name the new artifact:

```python
    print(f"aramid: uninstall: {root} -- hooks removed, ARAMID.md removed, agent "
          f"blocks removed, gitignore entries removed. The ledger (.aramid/) is "
          f"KEPT -- delete it by hand if you also want to discard finding/security "
          f"history.")
```

Also update the module docstring's first sentence to include the agent blocks: `"""uninstall -- reverse exactly what `init` installed: git hook shims, ARAMID.md, the managed agent blocks (CLAUDE.md/AGENTS.md), and the gitignore entries it appended. ...`

- [ ] **Step 4: Run tests to verify they pass**

Run: `env -u PYTHONPATH python -P -m pytest tests/integration/test_init.py -v -o pythonpath=src`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/uninstall.py tests/integration/test_init.py
git commit -m "feat(uninstall): reverse the managed agent blocks, fence-scoped"
```

---

### Task 5: doctor advisory section

**Files:**
- Modify: `src/aramid/commands/doctor.py` (new `agent_files_lines`; wiring in `cmd_doctor` after the `autolearn:` section, ~line 978)
- Modify: `tests/integration/test_init.py` (capsys test — it already has `_repo`/`_fake_present`)
- Modify: `tests/unit/test_agent_files.py` (exact-line rendering test)

**Interfaces:**
- Consumes: `agent_files.agent_block_states` (Task 2).
- Produces: `agent_files_lines(root: Path) -> list[str]` in `commands/doctor.py`.

Spec §8: absent/stale blocks are ADVISORY — `cmd_doctor`'s exit code must not change for any block state. (The tampered/exit-2 rule applies to the settings/mcp entries of sub-projects 2 and 4, not to blocks.)

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_init.py`:

```python
def test_doctor_reports_agent_file_states_without_changing_exit(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0
    capsys.readouterr()

    rc_ok = doctor.cmd_doctor(r)
    out_ok = capsys.readouterr().out
    assert "agent files:" in out_ok
    assert "  OK   CLAUDE.md  managed aramid block present" in out_ok
    assert "  OK   AGENTS.md  managed aramid block present" in out_ok

    (r / "AGENTS.md").unlink()
    rc_absent = doctor.cmd_doctor(r)
    out_absent = capsys.readouterr().out
    assert ("  WARN AGENTS.md  no managed aramid block -- run `aramid init`"
            in out_absent)
    # advisory only: block state must never move doctor's exit code.
    assert rc_absent == rc_ok
```

And a unit test appended to `tests/unit/test_agent_files.py` (add `from aramid.commands import doctor as doctor_cmd` to its imports):

```python
def test_doctor_lines_render_all_four_states(tmp_path):
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
        "  WARN AGENTS.md  aramid fence has no closing marker -- restore"
        " `<!-- aramid:end -->` and re-run `aramid init`",
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py tests/integration/test_init.py -v -o pythonpath=src`
Expected: new tests FAIL — `agent_files_lines` undefined / "agent files:" absent from doctor output.

- [ ] **Step 3: Implement**

In `src/aramid/commands/doctor.py`:

a) Add near `_report_line` (~line 639):

```python
_AGENT_FILE_DETAIL = {
    "ok": "managed aramid block present",
    "stale": "aramid block differs from the current template"
             " -- re-run `aramid init`",
    "absent": "no managed aramid block -- run `aramid init`",
    "damaged": "aramid fence has no closing marker -- restore"
               " `<!-- aramid:end -->` and re-run `aramid init`",
}


def agent_files_lines(root: Path) -> list[str]:
    """Advisory only, by design (spec section 8): a missing or stale block
    means agents are under-informed, not that the gate is off -- the git
    hooks still run. Doctor reports; `aramid init` is the fix. Never
    contributes to doctor's exit code."""
    from aramid import agent_files
    lines = []
    for name, state in agent_files.agent_block_states(root):
        tag = "OK  " if state == "ok" else "WARN"
        lines.append(f"  {tag} {name:<10} {_AGENT_FILE_DETAIL[state]}")
    return lines
```

b) In `cmd_doctor`, after the `autolearn:` section (the `print(_autolearn_probe_line())` line, ~978), insert:

```python
    print("agent files:")
    for line in agent_files_lines(root):
        print(line)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py tests/integration/test_init.py tests/integration/test_doctor.py -v -o pythonpath=src`
Expected: all pass (test_doctor.py included to catch any output-shape assert its existing tests make about doctor's full report; if one pins the full report text, extend its expectation with the new `agent files:` section rather than weakening the pin).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/doctor.py tests/unit/test_agent_files.py tests/integration/test_init.py
git commit -m "feat(doctor): report managed agent block states -- advisory, never exit-moving"
```

---

### Task 6: docs + dogfood on this repo

**Files:**
- Modify: `docs/user-guide.md` (section 2, "What a single-repo `init` does" list — add the blocks step; the uninstall paragraph — add the blocks)
- Modify: this repo's own `CLAUDE.md` / `AGENTS.md` (via the real command, not by hand)

- [ ] **Step 1: Update the user guide**

In `docs/user-guide.md` §2, insert into the numbered "What a single-repo `init` does" list, after the "Always regenerates `ARAMID.md`" item:

```markdown
4. Writes a marker-fenced, aramid-managed instruction block into `CLAUDE.md` and `AGENTS.md` (creating them when absent) so agent coders meet the gate before their first commit, not at their first blocked push. Content outside the `<!-- aramid:begin -->`/`<!-- aramid:end -->` fence is never touched; a damaged fence (no closing marker) refuses the write with a notice. Both files are tracked, so teammates' agents inherit the block on pull.
```

(then renumber the following items), and extend the uninstall sentence at the end of §2 to include: `removes the managed agent blocks from CLAUDE.md/AGENTS.md (deleting a file that held nothing but the block)`.

- [ ] **Step 2: Dogfood — run the real init on this repo**

First prove the treatment will apply to the checkout, not the promoted wheel:

```bash
env -u PYTHONPATH PYTHONPATH="$(pwd -W 2>/dev/null || pwd)/src" python -P -c "import aramid; print(aramid.__file__)"
```

Expected: a path ending in `src\aramid\__init__.py` (the checkout). If it prints the Roaming site-packages path, STOP — the dogfood would exercise 0.7.2, which does not have this code.

Then:

```bash
env -u PYTHONPATH PYTHONPATH="$(pwd -W 2>/dev/null || pwd)/src" python -P -m aramid init .
```

Expected: init completes rc 0; the notice names CLAUDE.md and AGENTS.md; `git status --porcelain` shows modified `CLAUDE.md` (block appended after the existing graphite section), new `AGENTS.md`, and possibly a regenerated `ARAMID.md`.

- [ ] **Step 3: Review the dogfood diff before committing**

Run: `git diff CLAUDE.md; git status --porcelain`
Verify: the CLAUDE.md diff is ONLY the appended fenced block — the graphite section above it is byte-identical. AGENTS.md contains exactly `render_block()`. If ARAMID.md changed, that is the template regeneration being honest — include it.

- [ ] **Step 4: Run the affected suite slices one last time**

Run: `env -u PYTHONPATH python -P -m pytest tests/unit/test_agent_files.py tests/integration/test_init.py tests/integration/test_doctor.py -q -o pythonpath=src`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add docs/user-guide.md CLAUDE.md AGENTS.md ARAMID.md
git commit -m "docs+chore: user-guide init step for agent blocks; dogfood the blocks into aramid's own repo"
```

(If ARAMID.md is unchanged, drop it from the add list.)

---

## After the last task

Do NOT push as a plan step. The push runs the ~20-minute pre-push gate; hand back to the operator (or run it backgrounded per house practice, reading PUSH_RC from a log file) and then re-check `aramid ledger filter --status open` — new WARN-tier findings from the llm reviewer land at gate time and must be read, not just survived. Sub-project 2 (session-start + settings merge) gets its own plan once this one is merged and green.
