# Doctor Rows for eslint, tsc and mypy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `aramid doctor` reports whether eslint, tsc and mypy are where the gate looks for them, in repos where the gate selects them.

**Architecture:** One new function in `runners/typecheck.py` owns "which typecheck tool runs here"; the runner's `run` and doctor both call it. A new doctor function builds the three rows from the runners' own predicates and paths and is printed beside the existing cargo-audit and clippy rows. Report only.

**Tech Stack:** Python 3.11+, pytest, the existing `ToolStatus` / `_report_line` in `src/aramid/commands/doctor.py`.

**Spec:** `docs/superpowers/specs/2026-11-26-doctor-stack-tool-rows-design.md`

## Global Constraints

- Doctor's exit code does not change for any new row. `--fix` never installs eslint, tsc or mypy.
- Doctor does not run the three tools. A found row shows the path and no version.
- No new row may call a missing tool "non-blocking". The gate consequence text is exactly: `At pre-push it shows as a degraded tool, and a --strict gate refuses the push`.
- No copy of the tsc/mypy precedence outside `typecheck.dispatched`.
- No change to how the gate selects or locates any tool.
- Test-first, one failing test seen before each implementation step. Tests assert whole rows (`_report_line` output), not substrings.
- New test files need basenames unique across `tests/` (`pytest --co tests` must collect).
- Run python as `python -P`. Commit with `git commit -F <file>`; never `--no-verify`; run `aramid check --staged` first.
- Before pushing: full unit suite (`python -P -m pytest -q -p no:cacheprovider -n 6 tests/unit`), `tests/integration/test_ci_parity.py`, and the WSL latent-mutant ratchet (0 total, baseline 0). Every new branch needs unit coverage for that ratchet.

## Review Focus

1. A repo with both `tsconfig.json` and a mypy config: mypy must read WARN "does NOT run", never OK. (Task 2, test 4)
2. A Python-only repo with no mypy config (this repo): no new row at all. (Task 2, test 5)
3. A workspace whose eslint lives in a package's own `node_modules`: the row must be MISSING and name the ROOT path the gate uses, not go looking elsewhere. (Task 2, test 2 asserts the exact root path)
4. Stack detection or config reading that raises (unreadable tree, malformed `pyproject.toml`): doctor must print its other rows and not crash. (Task 2, test 6)
5. A JS repo whose package manager is not npm (pnpm, yarn) or cannot be detected: the hint names the detected one, or says "your package manager", never a wrong command. (Task 2, test 3)

---

### Task 1: One owner for which typecheck tool runs

**Files:**
- Modify: `src/aramid/runners/typecheck.py` (`run`, near line 244)
- Test: `tests/unit/test_typecheck_dispatched.py` (create)

**Interfaces:**
- Produces: `typecheck.dispatched(root: Path) -> str | None`. Returns `typecheck.NAME_TSC` when `tsconfig.json` is at `root`, else `typecheck.NAME_MYPY` when a mypy config is present, else `None`.

- [ ] **Step 1: Write the failing tests**

```python
from aramid.runners import typecheck


def test_tsconfig_alone_dispatches_tsc(tmp_path):
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    assert typecheck.dispatched(tmp_path) == typecheck.NAME_TSC


def test_mypy_config_alone_dispatches_mypy(tmp_path):
    (tmp_path / "mypy.ini").write_text("[mypy]\n", encoding="utf-8")
    assert typecheck.dispatched(tmp_path) == typecheck.NAME_MYPY


def test_tsc_takes_the_slot_when_both_are_configured(tmp_path):
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    (tmp_path / "mypy.ini").write_text("[mypy]\n", encoding="utf-8")
    assert typecheck.dispatched(tmp_path) == typecheck.NAME_TSC


def test_neither_config_dispatches_nothing(tmp_path):
    assert typecheck.dispatched(tmp_path) is None


def test_run_goes_where_dispatched_says(tmp_path, monkeypatch):
    # The runner must not keep a second copy of the precedence.
    from types import SimpleNamespace
    monkeypatch.setattr(typecheck, "dispatched", lambda root: typecheck.NAME_MYPY)
    monkeypatch.setattr(typecheck, "run_mypy", lambda ctx: "mypy-ran")
    monkeypatch.setattr(typecheck, "run_tsc", lambda ctx: "tsc-ran")
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    assert typecheck.run(SimpleNamespace(root=tmp_path)) == "mypy-ran"
```

- [ ] **Step 2: Run them and see them fail**

Run: `python -P -m pytest -q -p no:cacheprovider tests/unit/test_typecheck_dispatched.py`
Expected: FAIL, `module 'aramid.runners.typecheck' has no attribute 'dispatched'`.

- [ ] **Step 3: Implement `dispatched(root: Path) -> str | None` and make `run` branch on it**

`run` keeps returning `RunnerResult("typecheck", ToolState.MISSING)` when it is `None`.

- [ ] **Step 4: Run the typecheck tests**

Run: `python -P -m pytest -q -p no:cacheprovider tests/unit/test_typecheck_dispatched.py tests/unit -k typecheck`
Expected: all pass.

- [ ] **Step 5: Commit**

`refactor(typecheck): one function says which tool the runner dispatches to`

---

### Task 2: The three doctor rows

**Files:**
- Modify: `src/aramid/commands/doctor.py` (new function beside `probe_deps`; one call where `cmd_doctor` prints `probe_deps`' rows; module docstring line 8, which says eslint/tsc/mypy are reported only at the runner layer)
- Test: `tests/unit/test_doctor_stack_tools.py` (create)
- Docs: `CHANGELOG.md` (`## [Unreleased]`), `docs/user-guide.md` (doctor section, near line 155), `docs/knowledge-base.md` (the `aramid doctor` entry of section 4)

**Interfaces:**
- Consumes: `typecheck.dispatched(root)`, `typecheck.has_mypy_config(root)`, `typecheck._tsc_bin(root)`, `eslint._eslint_bin(root)`, `toolpath.resolve("mypy")`, `detectors.detect_stacks(root, root)`, `detectors.detect_package_manager(root)`.
- Produces: `doctor.probe_stack_tools(root: Path) -> list[ToolStatus]`, in the order eslint, tsc, mypy. `cmd_doctor` prints each with `_report_line` directly after `probe_deps`' rows and does not fold them into any exit-code list.

Row contract (`PM` is the detected package manager when it is `npm`, `pnpm` or `yarn`, else the words `your package manager`; `TAIL` is the Global Constraints sentence):

| Case | ToolStatus | detail |
|---|---|---|
| eslint found | `("eslint", True, detail=str(path))` | the path |
| eslint not found | `("eslint", False, ...)` | `not found at {path} -- JS/TS lint is NOT being checked on this repo; the gate looks nowhere else, so install eslint in this repo with {PM}. {TAIL}` |
| tsc found | `("tsc", True, detail=str(path))` | the path |
| tsc not found | `("tsc", False, ...)` | `not found at {path} -- TypeScript is NOT being type-checked on this repo; the gate looks nowhere else, so install typescript in this repo with {PM}. {TAIL}` |
| mypy found | `("mypy", True, detail=str(resolved))` | the path |
| mypy not found | `("mypy", False, ...)` | `not found on PATH -- Python is NOT being type-checked on this repo although a mypy config is present; install mypy where aramid's hooks can find it. {TAIL}` |
| mypy configured, tsc dispatched | `("mypy", True, warn=True, ...)` | `configured, but it does NOT run in any gate: tsconfig.json is at the repo root, and the typecheck runner runs tsc alone` |

eslint's row appears when `"js" in detect_stacks(root, root)`. tsc's when `dispatched` is `NAME_TSC`. mypy's found/not-found rows when `dispatched` is `NAME_MYPY`; the WARN row when `dispatched` is `NAME_TSC` and `has_mypy_config(root)`.

- [ ] **Step 1: Write the failing tests**

Six tests in `tests/unit/test_doctor_stack_tools.py`, each asserting `[doctor._report_line(s) for s in doctor.probe_stack_tools(root)]` against whole lines:

1. `test_a_js_repo_with_its_tools_installed_reads_ok_with_their_paths`: `package.json`, `index.js`, `tsconfig.json`, and empty files at both `.bin` paths. Expect exactly an `OK` eslint row and an `OK` tsc row, each ending `({path})`.
2. `test_missing_js_tools_name_the_root_path_and_the_gate_consequence`: same repo without `node_modules` at the root, but with `packages/a/node_modules/.bin/eslint[.cmd]` present. Expect the two `MISSING` rows from the table, with the root paths, PM `npm` (add a `package-lock.json`).
3. `test_the_hint_names_the_detected_package_manager_or_none` (parametrized): `pnpm-lock.yaml` gives `pnpm`, `yarn.lock` gives `yarn`, no lockfile gives `your package manager` (check `detect_package_manager`'s own rule for a bare `package.json` first and assert what it returns).
4. `test_mypy_configured_beside_a_tsconfig_is_reported_as_not_running`: `tsconfig.json` plus `mypy.ini`, `toolpath.resolve` monkeypatched to find mypy. Expect the mypy row to be the `WARN` row from the table, never `OK`.
5. `test_a_python_repo_without_a_mypy_config_gets_no_row`: a `pyproject.toml` with only `[project]` and one `.py` file. Expect `[]`. Then add `mypy.ini` and expect one mypy row, `OK` with the resolved path when `toolpath.resolve` is monkeypatched to a path, the `MISSING` row when it returns `None`.
6. `test_a_probe_that_raises_yields_no_rows_and_no_crash`: monkeypatch `detect_stacks` to raise `OSError`, then separately write a `pyproject.toml` that is not valid TOML. `probe_stack_tools` must return a list both times (assert the exact list: no eslint row; mypy/tsc rows per what `dispatched` returns, or none if it raised).

Plus one in the same file for the wiring: `test_cmd_doctor_prints_the_stack_rows_and_keeps_its_exit_code`: monkeypatch `doctor.probe_stack_tools` to return one MISSING status, run `cmd_doctor` as the existing doctor unit tests do (see `tests/unit/test_doctor_probes.py` for the harness), and assert the row is in the output and the exit code equals the run without it.

- [ ] **Step 2: Run them and see them fail**

Run: `python -P -m pytest -q -p no:cacheprovider tests/unit/test_doctor_stack_tools.py`
Expected: FAIL, `module 'aramid.commands.doctor' has no attribute 'probe_stack_tools'`.

- [ ] **Step 3: Implement `probe_stack_tools(root: Path) -> list[ToolStatus]`**

Each of the two lookups (stack detection, typecheck dispatch) sits in its own `try`, so one failing leaves the other's rows. State the failure direction in a comment: a probe that cannot read the repo reports nothing, as `probe_deps` does.

- [ ] **Step 4: Wire it into `cmd_doctor` and correct the module docstring**

- [ ] **Step 5: Run the doctor tests**

Run: `python -P -m pytest -q -p no:cacheprovider -n 6 tests/unit/test_doctor_stack_tools.py tests/unit -k doctor` and `python -P -m pytest -q -p no:cacheprovider tests/integration/test_doctor.py`
Expected: all pass.

- [ ] **Step 6: Run the real command twice**

Run `aramid doctor` in this repo: expect no new row (Python, no mypy config) and exit 0. Then in a scratch repo made with `git init --template=<empty dir>` holding `package.json`, `index.js`, `tsconfig.json`: expect the two MISSING rows and the same exit code as before the change. Delete the scratch repo.

- [ ] **Step 7: Docs and changelog**

CHANGELOG entry under `## [Unreleased]`: doctor now lists eslint, tsc and mypy where the gate selects them; a missing one is refused by a `--strict` gate; nothing `aramid init` writes changed. User guide and knowledge base: the three rows, when each appears, that found means "the file is there" and not "it runs", and the both-configs WARN.

- [ ] **Step 8: Commit**

`feat(doctor): rows for eslint, tsc and mypy where the gate selects them`

---

### Task 3: The Rust rows' "non-blocking" wording

**Files:**
- Modify (only if the measurement says so): `src/aramid/commands/doctor.py` (`probe_deps`, the cargo-audit and clippy `detail` strings), their assertions in `tests/integration/test_doctor.py` and any unit twin, `docs/knowledge-base.md`

**Interfaces:**
- Consumes: the `TAIL` sentence from Global Constraints.

- [ ] **Step 1: Measure**

In a scratch repo (`git init --template=<empty dir>`) with a minimal `Cargo.toml`, `Cargo.lock` and `src/lib.rs`, run `aramid check --gate pre-push --all --strict --no-record --json` with cargo-audit and clippy not resolvable. If they are installed on this machine, hide them by running with a `PATH` that lacks `~/.cargo/bin`; confirm with `aramid doctor` in that repo that both rows read MISSING before trusting the result. Record the exit code and the `degraded` list. A run where either tool was found is not a measurement.

- [ ] **Step 2a: If the strict gate refuses (exit 1, the tool in `degraded`)**

Write the failing assertion first: the existing cargo-audit and clippy MISSING-row tests expect the row to end with `TAIL` in place of `(non-blocking: ... is not a BLOCK-tier gate)`. See them fail, change the two strings, see them pass.

- [ ] **Step 2b: If it does not refuse, or the tools cannot be hidden**

Change no wording. Add one sentence to the doctor entry of `docs/knowledge-base.md` saying what was measured (or that it could not be), with the date.

- [ ] **Step 3: Commit**

`fix(doctor): the Rust rows say what a missing tool costs at a strict gate` or `docs(kb): the Rust doctor rows' strict-gate behaviour, as measured`.

---

### After the tasks

- [ ] Full unit suite, `test_ci_parity`, WSL ratchet (0/0), then push with the push kit on a quiet machine, not within 35 minutes before a drain (03/07/11/15/19/23Z). Read CI after.
