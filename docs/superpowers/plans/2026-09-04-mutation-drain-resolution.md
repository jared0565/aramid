# Mutation Consumer: Root-Anchored Commands, Honest Baseline Notes, Verdict-Based Scores Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A repo-relative test command works in the drain wherever it works at the gate; a baseline that never started says so instead of "baseline failing"; a failing baseline records its exit code and last output line; and a mutant's score counts only mutants that reached a verdict.

**Architecture:** Three independent defects found while answering interop round 174 (posted as round 175), fixed at their sources. (1) `runners.tests._argv` gains a `root` and anchors a relative argv[0] that contains a path separator to it, so both the gate's `run_custom` and the consumer's `_full_argv` launch an absolute path; `toolpath.resolve` stops returning a relative hit unabsolutized. (2) `consumers.mutation.consume` gets a third baseline note family for `ToolState.MISSING` (repo-scoped give-up like the timeout family, release valve = argv[0] in the prefix) and appends `-- rc N: <last line>` to the failing note plus a tail log under `.aramid/logs/`. (3) Per-target score counters distinguish confirmed survivors from stage-1-only ones: `killed_s2` and `unconfirmed` are added, confirm-stage timeouts/errors move out of `survived_s1`, and `mutation_score.TargetScore.rate` becomes the kill rate over mutants with a verdict.

**Tech Stack:** Python 3.12+ stdlib; pytest with the existing fixture repos in `tests/integration/test_mutation_consumer.py` (real git worktrees + real pytest) and the event fixtures in `tests/unit/test_mutation_score.py`.

**Spec:** Interop rounds 174 (graphite-agent's questions and evidence) and 175 (aramid's answer, which names the three defects and promises these fixes). No design spec file: each fix is a bug fix against an existing contract documented in the code it touches (`_full_argv`'s docstring, `timeout_note_prefix`/`failing_note_prefix`, `_finalize_scores`).

## Global Constraints

1. **Fail-open in the drain.** `consume` must not raise out of its seam for any of these paths; a log write that fails costs nothing but the log.
2. **Note strings are load-bearing.** `prior_note_count` and `note_count_any_item` match by `str.startswith(prefix)`. A suffix appended AFTER `failing_note_prefix(head)` is safe; the prefix itself must stay byte-identical (`test_note_families_are_pinned_to_their_literal_wording`). The new MISSING family gets its own prefix function and its own pin in that test.
3. **Additive JSON.** `mutation_scores.schema` stays `1`; new per-target keys `killed_s2` and `unconfirmed` are read with `.get(key, 0)` so rows written by older versions still parse (`test_iter_skips_target_missing_subscripted_key` pins which keys are subscripted: `killed_s1`, `survived_s1`, `fully_mutated` only).
4. **Stage 1 keeps using `sys.executable`.** Only argv[0] of the CONFIGURED command is anchored; nothing about which interpreter runs stage 1 changes.
5. **Test commands** run as `python -m pytest <path> -q -p no:cacheprovider` from the repo root. Never `pip install -e .`.
6. **Every commit goes through the gate:** `python -P -m aramid check --staged` before `git commit`, never `--no-verify`; after every gate, `python -P -m aramid ledger filter --status open`. Commit messages via `git commit -F <scratchpad file>`, ending with:
    ```
    Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
    Claude-Session: https://claude.ai/code/session_01Swr1yPAqMtUnH36YVhune9
    ```
7. **Heredoc bodies mangle backslashes on this machine.** Any file content with a backslash goes through the Write/Edit tools.
8. **Stay inside this repository.** graphite's ledger and repo are not read; the reproduction uses fixture repos under `tmp_path`.

---

## File Structure

- Modify `src/aramid/runners/tests.py` -- `_argv(command, root=None)`, `run_custom` passes `ctx.root`.
- Modify `src/aramid/commands/doctor.py` -- `_configured_argv0(command, root=None)`, `probe_tests` passes `root` (graphite `callers _argv`: doctor, mutation, run_custom, toolset; toolset only takes `Path(argv[0]).name`, unchanged by anchoring).
- Modify `src/aramid/toolpath.py` -- `resolve` returns absolute paths.
- Modify `src/aramid/consumers/mutation.py` -- `_full_argv(cfg, root=None)`, `_stage1_argv(..., root=None)`, `consume` anchors on `ctx.root`; `missing_note_prefix`; failing-note suffix + tail log; per-target `killed_s2`/`unconfirmed` bookkeeping in `_new_target`, `_mutate`, `_finalize_scores`.
- Modify `src/aramid/mutation_score.py` -- `TargetScore.killed_s2`, `rate`.
- Modify `src/aramid/commands/mutation_score.py` -- JSON gains `killed_s2`; the text line's denominator counts both kill stages.
- Tests: `tests/unit/test_tests_argv.py` (new), `tests/unit/test_toolpath.py`, `tests/integration/test_mutation_consumer.py`, `tests/unit/test_mutation_score.py`.
- Docs: `CHANGELOG.md` (Fixed x3).

---

### Task 1: A repo-relative test command resolves in the drain

**Files:**
- Modify: `src/aramid/runners/tests.py:235-262` (`_argv`, `run_custom`)
- Modify: `src/aramid/toolpath.py:181-202` (`resolve`)
- Modify: `src/aramid/consumers/mutation.py` (`_stage1_argv`, `_full_argv`, the three call sites in `consume`)
- Test: `tests/unit/test_tests_argv.py` (new), `tests/unit/test_toolpath.py`, `tests/integration/test_mutation_consumer.py`

**Interfaces:**
- Produces: `tests_runner._argv(command, root: Path | None = None) -> list[str]`; `mutation._full_argv(cfg=None, root: Path | None = None)`; `mutation._stage1_argv(wt, rel, cfg=None, root=None)`; `toolpath.resolve(name)` always returns an absolute `Path` or `None`.

- [ ] **Step 1: Write the failing unit tests**

Create `tests/unit/test_tests_argv.py` (Write tool: the Windows launcher body carries no backslash, but the file is new):

```python
"""`[tests].command` argv: a relative argv[0] with a path separator is
anchored to the repo root (interop round 174: the scheduled drain runs with
no Start In, so `../.venvs/x/Scripts/python.exe` resolved against the
drain's cwd, found nothing, and reported `baseline failing` for 43 runs)."""
import os
from pathlib import Path

from aramid.runners import tests as tests_runner


def _launcher(root: Path) -> str:
    d = root / "tools"
    d.mkdir()
    if os.name == "nt":
        p = d / "py.cmd"
        p.write_text("@echo off\r\npython %*\r\n", encoding="utf-8")
    else:
        p = d / "py"
        p.write_text("#!/bin/sh\nexec python \"$@\"\n", encoding="utf-8")
        p.chmod(0o755)
    return "tools/" + p.name


def test_relative_argv0_with_a_separator_is_anchored_to_root(tmp_path, monkeypatch):
    rel = _launcher(tmp_path)
    monkeypatch.chdir(tmp_path / "tools")          # a cwd where the relative path does NOT resolve
    argv = tests_runner._argv([rel, "-m", "pytest"], tmp_path)
    assert argv[0] == str((tmp_path / rel).resolve())
    assert argv[1:] == ["-m", "pytest"]


def test_bare_names_and_absolute_paths_are_left_alone(tmp_path):
    assert tests_runner._argv(["python", "-m", "pytest"], tmp_path) == ["python", "-m", "pytest"]
    absolute = str((tmp_path / "somewhere" / "python").resolve())
    assert tests_runner._argv([absolute, "-q"], tmp_path) == [absolute, "-q"]


def test_a_relative_path_that_does_not_exist_under_root_is_left_for_resolve(tmp_path):
    # MISSING is the runner's verdict to give; anchoring must not invent a file.
    assert tests_runner._argv("./nope/python -q", tmp_path) == ["./nope/python", "-q"]


def test_without_a_root_the_old_behaviour_holds(tmp_path):
    rel = _launcher(tmp_path)
    assert tests_runner._argv([rel, "-q"]) == [rel, "-q"]
```

Append to `tests/unit/test_toolpath.py`:

```python
def test_resolve_returns_an_absolute_path_for_a_relative_hit(tmp_path, monkeypatch):
    """A relative argv[0] that resolves against the cwd used to come back
    relative, and was then launched with a DIFFERENT cwd (the mutation
    worktree), where it no longer resolved. Absolutize at resolution."""
    d = tmp_path / "tools"
    d.mkdir()
    p = d / ("py.cmd" if os.name == "nt" else "py")
    p.write_text("@echo off\r\n" if os.name == "nt" else "#!/bin/sh\n", encoding="utf-8")
    if os.name != "nt":
        p.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    got = toolpath.resolve("tools/" + p.name)
    assert got is not None and got.is_absolute() and got == p.resolve()
```

(Check the file's imports: it needs `import os` and `from aramid import toolpath`; add whichever is missing.)

- [ ] **Step 2: Run them, read the failures**

Run: `python -m pytest tests/unit/test_tests_argv.py tests/unit/test_toolpath.py -q -p no:cacheprovider`
Expected: `TypeError: _argv() takes 1 positional argument but 2 were given` on three tests; `test_without_a_root_the_old_behaviour_holds` passes already (it pins the fallback); the toolpath test fails on `is_absolute()`.

- [ ] **Step 3: Implement**

`src/aramid/runners/tests.py`:

```python
def _argv(command: str | list, root: Path | None = None) -> list[str]:
    """A repo's configured `[tests].command` -> argv for run_subprocess.

    A list/tuple is taken verbatim, which sidesteps shell quoting entirely
    and is the form to prefer on Windows: POSIX splitting eats backslashes,
    so `tests\\unit` written as a string would lose its separator. A string
    is split POSIX-style, which is what nearly every real command
    ("pytest -q tests/unit") needs.

    With `root`, a relative argv[0] that contains a path separator is
    anchored to it and made absolute. The gate happens to run with the repo
    root as its cwd, so `../.venvs/dev/Scripts/python.exe` worked there by
    accident; the drain runs from wherever the scheduler started it and
    launches into a throwaway worktree, and the same command resolved
    against neither (interop round 174: 43 "baseline failing" rows that
    never started a process). A path that does not exist under `root` is
    left alone -- `run_subprocess` reports it MISSING, which is the verdict
    a misconfiguration deserves.

    Note there is no shell anywhere in this path -- run_subprocess execs the
    argv directly, so a command is exactly as trusted as the repo's own test
    suite, which the gate already runs.
    """
    argv = ([str(c) for c in command] if isinstance(command, (list, tuple))
            else shlex.split(command))
    if argv and root is not None:
        head = argv[0]
        if ("/" in head or os.sep in head) and not Path(head).is_absolute():
            anchored = Path(root) / head
            if anchored.is_file():
                argv[0] = str(anchored.resolve())
    return argv
```

(add `import os` if absent) and `run_custom`: `argv = _argv(command, ctx.root)`.

`src/aramid/commands/doctor.py`: `_configured_argv0(command, root: Path | None = None)` calls `_argv(command, root)`; `probe_tests` calls `_configured_argv0(command, root)`. Doctor's verdict on a configured command must be the drain's verdict (its own docstring: one parsing rule, never a second implementation). Test, appended to `tests/integration/test_doctor.py`:

```python
def test_probe_tests_resolves_a_repo_relative_command_from_a_foreign_cwd(tmp_path, monkeypatch):
    """doctor and the drain must agree on whether `[tests].command` resolves
    (round 174: the drain said MISSING for a command doctor called present)."""
    root = _repo(tmp_path)
    d = root / "tools"
    d.mkdir()
    p = d / ("py.cmd" if sys.platform == "win32" else "py")
    p.write_text("@echo off\r\n" if sys.platform == "win32" else "#!/bin/sh\n", encoding="utf-8")
    if sys.platform != "win32":
        p.chmod(0o755)
    (root / "aramid.toml").write_text(
        f'schema_version = 1\n[tests]\ncommand = ["tools/{p.name}", "-m", "pytest"]\n',
        encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    statuses = doctor.probe_tests(root, config_mod.load_config(root))
    assert len(statuses) == 1 and statuses[0].present, statuses[0].detail
```

`src/aramid/toolpath.py`, inside `resolve`'s `try`: replace `return Path(exe)` with

```python
            p = Path(exe)
            return p if p.is_absolute() else p.resolve()
```

and `return direct` with `return direct.resolve()`.

`src/aramid/consumers/mutation.py`: `_full_argv(cfg=None, root: Path | None = None)` passes `root` to `tests_runner._argv(command, root)`; `_stage1_argv(wt, rel, cfg=None, root=None)` forwards `root` to its `_full_argv` fallback; in `consume`, `full_argv = _full_argv(ctx.cfg, ctx.root)` and `s1_argv = _stage1_argv(wt, rel, ctx.cfg, ctx.root)`.

- [ ] **Step 4: Unit tests green**

Run: `python -m pytest tests/unit/test_tests_argv.py tests/unit/test_toolpath.py -q -p no:cacheprovider`
Expected: all pass.

- [ ] **Step 5: The end-to-end reproduction, failing first**

Append to `tests/integration/test_mutation_consumer.py`:

```python
# ------------------------- a repo-relative command in the drain (round 174) ---

def _repo_relative_launcher(r):
    """A `[tests].command` whose argv[0] is a repo-relative script, the shape
    graphite's dev-venv interpreter takes. Runs the real pytest."""
    d = r / "tools"
    d.mkdir()
    if os.name == "nt":
        p = d / "py.cmd"
        p.write_text("@echo off\r\npython %*\r\n", encoding="utf-8")
    else:
        p = d / "py"
        p.write_text("#!/bin/sh\nexec python \"$@\"\n", encoding="utf-8")
        p.chmod(0o755)
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "launcher")
    return "tools/" + p.name


def test_repo_relative_test_command_runs_from_any_drain_cwd(tmp_path, monkeypatch):
    r, base, _ = _repo(tmp_path, WEAK_TEST)
    rel = _repo_relative_launcher(r)
    head = _sha(r)
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\n"
        f"[tests]\ncommand = [\"{rel}\", \"-m\", \"pytest\", \"-q\"]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)               # the scheduled drain's cwd is never the repo root
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert not res.note.startswith("baseline"), res.note
    assert res.state == "ok" and res.extra["tested"] >= 1
```

Run: `python -m pytest tests/integration/test_mutation_consumer.py -q -p no:cacheprovider -k repo_relative`
Expected before Step 3's consumer edits: fails with a `baseline ...` note. (Write this test before touching `consumers/mutation.py`; then apply that file's part of Step 3.)

- [ ] **Step 6: Consumer test green, whole consumer file green**

Run: `python -m pytest tests/integration/test_mutation_consumer.py tests/unit/test_tests_gate.py -q -p no:cacheprovider`
Expected: all pass.

- [ ] **Step 7: Gate and commit**

`git add src/aramid/runners/tests.py src/aramid/toolpath.py src/aramid/consumers/mutation.py tests/unit/test_tests_argv.py tests/unit/test_toolpath.py tests/integration/test_mutation_consumer.py`, gate, ledger, commit: `fix(drain): a repo-relative test command is anchored to the repo root, so it resolves from the drain's cwd (round 174 Q1)`.

---

### Task 2: A baseline that never started says so; a failing one says why

**Files:**
- Modify: `src/aramid/consumers/mutation.py` (`missing_note_prefix`, `_MISSING_GIVE_UP`, the MISSING branch, the failing branch, `_tail_log`)
- Test: `tests/integration/test_mutation_consumer.py`

**Interfaces:**
- Produces: `mutation.missing_note_prefix(argv0: str) -> str` = `f"baseline command not found: {argv0}"`; the emitted MISSING note = prefix + `f" (resolved from {cwd}; set [mutation].test_command or [tests].command to a name on PATH, an absolute path, or a repo-relative path)"`; give-up note `f"mutation giving up: {argv0} not found after {_MISSING_GIVE_UP} attempts -- fix [mutation].test_command / [tests].command"`; the failing note = `failing_note_prefix(head) + f" -- rc {rc}: {last_line}"`; log file `.aramid/logs/mutation-baseline-{item.id}-{head[:12]}.log`.

- [ ] **Step 1: Failing tests**

Append to `tests/integration/test_mutation_consumer.py`:

```python
# --------------------- the baseline that never started (round 174 s1, s4) ---

def _with_missing_command(r):
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\n"
        "[tests]\ncommand = [\"./nope/python\", \"-m\", \"pytest\"]\n", encoding="utf-8")


def test_missing_baseline_command_is_named_not_reported_as_failing(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _with_missing_command(r)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    assert res.note.startswith(mut_consumer.missing_note_prefix("./nope/python"))
    assert "baseline failing" not in res.note
    assert "[mutation].test_command" in res.note


def test_missing_command_gives_up_after_three_across_items(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _with_missing_command(r)
    for i in range(3):
        assert _consume(r, base, head, monkeypatch, tmp_path, item_id=f"q{i}").state == "degraded"
    res = _consume(r, base, head, monkeypatch, tmp_path, item_id="q9")
    assert res.state == "ok"
    assert res.note.startswith("mutation giving up: ./nope/python not found after 3 attempts")


def test_failing_baseline_note_carries_rc_and_last_line_and_a_log(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, "def test_always_fails():\n    assert False\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    assert res.note.startswith(mut_consumer.failing_note_prefix(head) + " -- rc 1: ")
    assert "1 failed" in res.note
    log = r / ".aramid" / "logs" / f"mutation-baseline-q1-{head[:12]}.log"
    assert log.is_file() and "test_always_fails" in log.read_text(encoding="utf-8")
```

And in `test_note_families_are_pinned_to_their_literal_wording`, add:

```python
    assert mut_consumer.missing_note_prefix("./nope/python") == \
        "baseline command not found: ./nope/python"
```

- [ ] **Step 2: Run, read the failures**

Run: `python -m pytest tests/integration/test_mutation_consumer.py -q -p no:cacheprovider -k "missing or carries_rc or pinned"`
Expected: `AttributeError: module ... has no attribute 'missing_note_prefix'` on three; the rc test fails on the note suffix.

- [ ] **Step 3: Implement**

In `src/aramid/consumers/mutation.py`, after `failing_note_prefix`:

```python
_MISSING_GIVE_UP = 3    # repo-scoped like the timeout family: no commit fixes a command


def missing_note_prefix(argv0: str) -> str:
    """The note family for "the baseline command could not be resolved".

    Distinct from `failing_note_prefix` because the two demand opposite
    responses: a red suite is fixed at a commit, a command that does not
    resolve is fixed in `aramid.toml`. They shared one note for three weeks
    (interop round 174: 43 rows of `baseline failing` in 2-7 s, none of which
    started a process). Repo-scoped, with argv[0] in the prefix as the
    release valve: change the command and the count falls to zero.
    """
    return f"baseline command not found: {argv0}"
```

In `consume`, beside the timeout give-up (before the failing-baseline give-up):

```python
    if base.note_count_any_item(
            ctx.ledger, NAME, missing_note_prefix(full_argv[0])) >= _MISSING_GIVE_UP:
        return ConsumerResult(
            consumer=NAME, state="ok",
            note=(f"mutation giving up: {full_argv[0]} not found after "
                  f"{_MISSING_GIVE_UP} attempts -- fix [mutation].test_command / "
                  f"[tests].command"))
```

After the baseline run, before the TIMEOUT branch:

```python
        if base_res.state is ToolState.MISSING:
            return ConsumerResult(
                consumer=NAME, state="degraded",
                note=(f"{missing_note_prefix(full_argv[0])} (resolved from {Path.cwd()}; "
                      "set [mutation].test_command or [tests].command to a name on PATH, "
                      "an absolute path, or a repo-relative path)"),
                duration_s=time.monotonic() - started)
```

The failing branch becomes:

```python
        if base_res.state is not ToolState.OK or base_res.returncode != 0:
            # Note text is load-bearing: the give-up counter matches its PREFIX
            # (`failing_note_prefix`, both ends), so the suffix is free to say
            # what the counter never needed: the exit code and the last line.
            _tail_log(ctx.root, item, head=item.head, res=base_res)
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=(f"{failing_note_prefix(item.head)} -- rc "
                                        f"{base_res.returncode}: {_last_line(base_res)}"),
                                  duration_s=time.monotonic() - started)
```

with two helpers near `_is_test_file`:

```python
_LOG_TAIL_LINES = 60


def _last_line(res) -> str:
    """The last non-empty line of stderr, else of stdout, else a marker.
    pytest puts its summary on stdout, so stderr alone is often empty."""
    for text in (res.stderr or "", res.raw or ""):
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if lines:
            return lines[-1][:160]
    return "(no output)"


def _tail_log(root: Path, item, *, head: str, res) -> None:
    """The last `_LOG_TAIL_LINES` of stdout and stderr, under `.aramid/logs/`
    beside the gate's own logs. Best effort: a log that cannot be written
    costs nothing but the log (spec section 9 fail-open)."""
    try:
        logs = root / ".aramid" / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        out = "\n".join((res.raw or "").splitlines()[-_LOG_TAIL_LINES:])
        err = "\n".join((res.stderr or "").splitlines()[-_LOG_TAIL_LINES:])
        body = f"--- stdout (tail) ---\n{out}\n--- stderr (tail) ---\n{err}\n"
        (logs / f"mutation-baseline-{item.id}-{head[:12]}.log").write_text(body, encoding="utf-8")
    except Exception:
        pass
```

- [ ] **Step 4: Green**

Run: `python -m pytest tests/integration/test_mutation_consumer.py -q -p no:cacheprovider`
Expected: all pass, including the pre-existing failing-baseline tests (they assert `startswith(failing_note_prefix(head))`).

- [ ] **Step 5: Gate and commit**

Commit: `fix(mutation): a baseline command that does not resolve is named as such, and a red baseline records rc and its last line (round 174 s4)`.

---

### Task 3: Scores count verdicts, not stage-1 guesses

**Files:**
- Modify: `src/aramid/consumers/mutation.py` (`_new_target`, `_finalize_scores`, the confirm branches in `_mutate`)
- Modify: `src/aramid/mutation_score.py` (`TargetScore`)
- Modify: `src/aramid/commands/mutation_score.py` (JSON + text line)
- Test: `tests/unit/test_mutation_score.py`, `tests/integration/test_mutation_consumer.py`

**Interfaces:**
- Produces: per-target keys `killed_s2` (survived stage 1, killed by the full suite) and `unconfirmed` (survived stage 1, the confirm never ran: `confirm_cap`); `survived_s1` now means "survived stage 1 and the full suite passed on it" for rows written from here on; `timeouts`/`errors` also count confirm-stage outcomes. `stats["survived"]` (the item-level putative stage-1 count, documented as such at the branch) is unchanged. `TargetScore.killed_s2: int = 0`; `rate = (killed_s1 + killed_s2) / (killed_s1 + killed_s2 + survived_s1)` or `None`; `fully_mutated = killed_s1 + killed_s2 + survived_s1 == generated`.

- [ ] **Step 1: Failing unit tests for the analyzer**

In `tests/unit/test_mutation_score.py`, extend `_crf` with `killed_s2=None` (omit the key when None, so old-row parsing stays covered) and append:

```python
def test_rate_counts_a_full_suite_kill_as_a_kill():
    events = [_crf(0, "f.py::g", 1, 1, True, killed_s2=2)]
    s = mutation_score.iter_target_scores(events)[0]
    assert s.killed_s2 == 2
    assert s.rate == 3 / 4


def test_rows_without_killed_s2_keep_the_old_rate():
    events = [_crf(0, "f.py::g", 2, 1, True)]
    s = mutation_score.iter_target_scores(events)[0]
    assert s.killed_s2 == 0 and s.rate == 2 / 3
```

Run: `python -m pytest tests/unit/test_mutation_score.py -q -p no:cacheprovider`
Expected: `TypeError: TargetScore.__init__() got an unexpected keyword argument` or `AttributeError: killed_s2`.

- [ ] **Step 2: Analyzer**

`src/aramid/mutation_score.py`: add `killed_s2: int = 0` as the LAST field of `TargetScore`; `iter_target_scores` passes `killed_s2=int(t.get("killed_s2", 0))`; `rate`:

```python
    @property
    def rate(self) -> float | None:
        killed = self.killed_s1 + self.killed_s2
        d = killed + self.survived_s1
        return killed / d if d else None
```

`src/aramid/commands/mutation_score.py`: JSON gains `"killed_s2": s.killed_s2`; the text line reads `f"({s.killed_s1 + s.killed_s2}/{s.killed_s1 + s.killed_s2 + s.survived_s1}){fm}"`.

Run the analyzer tests plus `tests/unit/test_mutation_score_gate.py tests/unit/test_arm_mutation_score.py tests/integration/test_mutation_score_gate_e2e.py`: all pass.

- [ ] **Step 3: Failing consumer tests (scripted subprocesses)**

Append to `tests/integration/test_mutation_consumer.py` (the scripted pattern from `test_stage2_usage_error_never_reports_survivor`):

```python
# ------------------ a confirm-stage timeout is not a survivor (round 174 Q3) ---

def _scripted(monkeypatch, confirm_result):
    """Same shape as `test_stage2_usage_error_never_reports_survivor`: a
    targeted stage-1 run names test_calc.py and passes (putative survivor);
    the first full run is the baseline (green); every later full run is a
    confirm and returns `confirm_result`."""
    from aramid.runners.base import RunnerResult, ToolState
    fulls = {"n": 0}

    def scripted(argv, cwd, timeout, **kw):
        joined = " ".join(str(a) for a in argv)
        if "test_calc.py" in joined:
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        fulls["n"] += 1
        if fulls["n"] == 1:
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        return confirm_result
    monkeypatch.setattr(mut_consumer, "run_subprocess", scripted)


def test_confirm_timeout_moves_the_mutant_out_of_survived(tmp_path, monkeypatch):
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _scripted(monkeypatch, RunnerResult(tool="pytest", state=ToolState.TIMEOUT, duration_s=60.0))
    res = _consume(r, base, head, monkeypatch, tmp_path)
    t = res.extra["mutation_scores"]["targets"]["calc.py::is_adult"]
    assert t["survived_s1"] == 0 and t["timeouts"] >= 1 and t["fully_mutated"] is False
    assert res.extra["confirmed"] == 0 and res.findings == []


def test_confirm_kill_is_counted_as_killed_s2(tmp_path, monkeypatch):
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _scripted(monkeypatch, RunnerResult(tool="pytest", state=ToolState.OK, returncode=1))
    res = _consume(r, base, head, monkeypatch, tmp_path)
    t = res.extra["mutation_scores"]["targets"]["calc.py::is_adult"]
    assert t["killed_s2"] >= 1 and t["survived_s1"] == 0
```

If the `_scripted` discriminator between stage-1 and full argv proves brittle, use the simpler shape the existing tests use: count calls and treat every call whose argv equals `mut_consumer._full_argv(cfg)` as a full run -- read `test_stage2_usage_error_never_reports_survivor` and copy its exact discriminator.

Run: `python -m pytest tests/integration/test_mutation_consumer.py -q -p no:cacheprovider -k "confirm_timeout or confirm_kill"`
Expected: `KeyError: 'killed_s2'` / `survived_s1 == 1` failures.

- [ ] **Step 4: Consumer bookkeeping**

`_new_target` gains `"killed_s2": 0, "unconfirmed": 0`. In `_mutate`'s putative-survivor branch:

```python
                    stats["survived"] += 1
                    t = t_of(m.func)
                    t["survived_s1"] += 1
                    if confirms_used >= confirm_cap:
                        # Survived stage 1, never confirmed: not a survivor,
                        # not a kill -- and not a measurement either.
                        stats["truncated"] = True
                        t["survived_s1"] -= 1
                        t["unconfirmed"] += 1
                        continue
                    confirms_used += 1
                    s2 = run_subprocess(full_argv, wt, full_timeout,
                                        env=worktree_import_env(wt))
                    if s2.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                        t["survived_s1"] -= 1
                        t["timeouts"] += 1
                    elif s2.state is ToolState.OK and s2.returncode == 0:
                        stats["confirmed"] += 1
                        t["survivor_fps"].append(_mutant_fp(rel, m.op, m.line, lines))
                        findings.append(...unchanged...)
                    elif s2.state is ToolState.OK and s2.returncode in (1, 2):
                        stats["killed_s2"] += 1
                        t["survived_s1"] -= 1
                        t["killed_s2"] += 1
                        fp = _mutant_fp(rel, m.op, m.line, lines)
                        t["killed_fps"].append(fp)
                        repaired_ids.add(fp)
                    else:
                        stats["errors"] += 1
                        t["survived_s1"] -= 1
                        t["errors"] += 1
```

`_finalize_scores`: `t["fully_mutated"] = (t["killed_s1"] + t["killed_s2"] + t["survived_s1"] == t["generated"])`.

- [ ] **Step 5: Green across the mutation surface**

Run: `python -m pytest tests/integration/test_mutation_consumer.py tests/unit/test_mutation_score.py tests/unit/test_mutation_score_gate.py tests/unit/test_arm_mutation_score.py tests/integration/test_mutation_score_gate_e2e.py tests/unit/test_mutation_gate.py tests/integration/test_mutation_gate_e2e.py -q -p no:cacheprovider`
Expected: all pass. If a mutation-gate e2e test asserts an exact `extra` dict, add the two keys to its expectation.

- [ ] **Step 6: Gate and commit**

Commit: `fix(mutation): a mutant scores only on a verdict -- confirm-stage timeouts, errors and cap-skips leave survived_s1, full-suite kills count as killed_s2 (round 174 Q3)`.

---

### Task 4: Changelog, push, announce

- [ ] `CHANGELOG.md` under `## [Unreleased]` / `### Fixed`: three entries, one per task, each naming round 174.
- [ ] Gate, commit `docs: changelog for the three mutation-drain fixes`, push in the background with its own log, `gh run list --commit <full sha>`, want 7/7.
- [ ] Round to graphite-agent (and pawscout-agent, whose repo is also drained): what shipped, the `survived_s1` meaning change and its effect on old rows, and that a release carrying it is the operator's to cut. Append the resume point.
