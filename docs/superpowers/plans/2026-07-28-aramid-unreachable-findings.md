# Plan — Unreachable Findings (T-8)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A finding whose tool has left this repo's live selection (de-selected, disabled, or genuinely never runs again) can be retired as `unreachable` — auto-*detected* as a candidate, retired *manually* — instead of staying `open` forever with no run able to ever resolve it. Folded into the same branch: the `tsc` label mismatch (case 5), a same-shape defect discovered while writing the spec.

**Architecture:** One new module (`toolset.py`) answers "which tool names would this repo produce findings under, right now" by re-deriving `pipeline._is_applicable`'s own rules directly (no gate run, no RunnerResult). A new terminal ledger status (`unreachable`) is reachable only through that live predicate, never through run history — so a tool that merely crashed for a while can never be laundered into "unreachable" the way it could through a skip-streak. `RUN_STARTED` gains a diagnostic-only `selected` payload so the audit trail can later show *why* a finding was retireable.

**Tech Stack:** Python 3.14, existing aramid package (`src/aramid/`), pytest.

**Spec:** `docs/superpowers/specs/2026-07-28-aramid-unreachable-findings-design.md` (491 lines; read section 3, 4, 5, 7, 9 before starting — this plan does not repeat every rationale, only what each task needs). **This plan supersedes two things the spec got wrong or left open; both are recorded in Global Constraints 4 and 5, with the evidence.**

---

## Global Constraints

These bind every task. Read them before implementing any single task.

1. **Exact names, used verbatim everywhere:**
   - `EventType.FINDING_UNREACHABLE = "finding_unreachable"` (in `models.py`)
   - `Status.UNREACHABLE = "unreachable"` (materialized status string, also in `models.py` — note `Status` is dead code today, zero references repo-wide per T-9's own plan; add the member anyway, same reasoning T-9 used for `NOT_A_SECRET`)
   - CLI subcommand: `mark-unreachable`
   - status.py display label: `unreachable` (no hyphen needed — one word)
   - module: `src/aramid/toolset.py`, functions `selected_tool_names(root, cfg) -> set[str]` and `ghost_candidates(state, selected) -> dict[str, dict]`, constants `RUNNER_TOOL_NAMES: frozenset[str]` and `PRODUCER_TOOL_NAMES: frozenset[str]`

2. **The security property comes from the universe, not from a check** (spec section 3, 7). `PRODUCER_TOOL_NAMES` (tdd, red-proof, mutation, mutation-score, llm-review, js-mutation, fuzz, dast) are gate surface — `review.llm_gate_findings` and `mutation_gate.mutation_gate_findings` both materialize BLOCK-tier findings straight from `status == "open"` ledger state (`review.py:477-478`, `mutation_gate.py` mirror). Retiring one of those would silently drop a gate block. This is closed by never putting those names in `RUNNER_TOOL_NAMES` — `mark-unreachable`'s guard in Task 3 refuses on universe membership FIRST, before anything else, so a caller who never considers the question still can't retire a producer finding. Do not weaken this to a runtime check that could be bypassed by adding a new producer without updating `RUNNER_TOOL_NAMES`.

3. **Directional rule, inherited from T-9 (`docs/superpowers/plans/2026-07-27-aramid-not-a-secret.md`, its Global Constraint 5):** transitions move only toward more caution. There is no un-mark and no `unreachable` → anything-else command. The one reverse transition (resurrection, Task 2) is automatic, is a *re-opening*, and is therefore more cautious, not less — never add a manual "un-mark unreachable" command.

4. **CORRECTION — the `tsc` bug is a detection gap, not just a resolution gap (found while starting this plan, by execution, not reading).** The spec's section 11.1 (as committed, then corrected in commit `bab831e`) frames case 5 as "tsc findings never resolve." That undersells it. `typecheck.parse():116-121` dispatches `if result.tool == NAME_TSC: return parse_tsc(...)`. `parse_tsc`'s only non-test caller is `typecheck.parse` itself (`graphite query "callers parse_tsc"`, `decision_grade`). On Windows, a real `tsc` run's `RunnerResult.tool == "tsc.cmd"` (from `run_subprocess`'s `Path(argv[0]).name`, where `argv[0]` is `_tsc_bin`'s platform-suffixed path). So `result.tool == NAME_TSC` is **False**, and `parse_tsc` is **never called at all** — verified by executing `typecheck.parse()` directly against `RunnerResult(tool="tsc.cmd", state=OK, raw=<a real TS2322 line>)`: returns `[]`. The identical POSIX-shaped input (`tool="tsc"`) returns the expected `RawFinding`. **Real TypeScript errors are silently dropped on every Windows repo with a `tsconfig.json`, today — not stranded once detected, never detected.** Task 7's fix (relabel at `run_tsc`'s return) closes both consequences at once, because `parse()`'s dispatch and `pipeline.py:524`'s `scope_tools` both read the same `RunnerResult.tool`. This does not change Task 1's universe/selection logic: `selected_tool_names` derives "is tsc selected" structurally, from `typecheck.has_tsconfig(root)`, never from whether `parse()` actually produced a finding.

5. **CORRECTION — `tests` (the literal registry-key tool name) belongs in `RUNNER_TOOL_NAMES`, not in a relabeling fix set.** Spec section 3.1/10/11.2 poses this as an open measurement ("does `tests` reach `scope_tools`? if not, does it join section 11's fix set"). It was measured (execution, not reading — see Task 1): the literal `"tests"` **never** enters `scope_tools`, confirmed by constructing the exact dual-suite aggregate `runners/tests.py`'s own `parse()` produces for a missing-sub-tool case and running it through `pipeline._flatten` + the real `scope_tools` comprehension — the flattened sub-results are `("pytest", MISSING)` and `("npm", OK)`; `scope_tools == {"npm"}`; `"tests" in scope_tools` is `False`. **But the spec's own prescribed fix (relabel `tests-tool-missing`'s `tool="tests"` to the missing sub-tool's own name) is not safely implementable**: `pipeline.py:628`'s BLOCK-tier gating exclusion is `not (f.tool == "tests" and f.rule == tests.TOOL_MISSING_RULE)` — relabeling would make this conjunct always `False`, so the finding would always join `gating_block_findings` and hard-exit 1, **bypassing `--accept-degraded`** — reopening the exact hole the whole-branch review's "MUST FIX 2" closed. `policy.classify`'s `if rule == "tests-tool-missing": return BLOCK` (`policy.py:170`) is rule-keyed, not tool-keyed, so it is unaffected either way — the break is specific to `pipeline.py:628`. **Disposition: do not touch `tests.py` or `pipeline.py:628` for this.** Instead, Task 1's `selected_tool_names` adds the literal `"tests"` to its output whenever the `"tests"` runner key is applicable at all (`pipeline._is_applicable("tests", ctx)` is `True`) — a repo that still nominally runs a test suite, but whose binary is currently broken, is correctly **refused** by `mark-unreachable` (matches spec section 7: a broken toolchain is `aramid doctor`'s problem, not a ghost). It only becomes retireable once the `tests` key itself stops being applicable (suite genuinely removed, or `[tests].enabled = false`) — exactly when retirement should be allowed. This requires zero changes to `tests.py`/`pipeline.py`/`policy.py`; it is additive, inside `toolset.py` only. **Resurrection caveat, worked out so the implementer doesn't re-derive it:** resurrection (Task 2) depends on the SAME finding fingerprint being re-emitted by a later run (`record_run`'s `f.id not in state or state[f.id]["status"] in (...)` check on `present`/`findings`), not on the scope-based auto-resolve loop. A `tests-tool-missing` finding marked `unreachable` and later re-triggered (tests re-enabled, same binary still missing) re-fires the identical fingerprint and resurrects correctly — this path is independent of the `scope_tools`/`scope_files` gaps above.

6. **Found while planning, explicitly NOT in scope — do not chase these:**
   - `regression_pack` (a drain consumer, `consumers/regression_pack.py`) reuses the tool name `"semgrep"` for its findings (`json_or_crashed("semgrep", ...)` at `:41`, then `semgrep_runner.parse(checked, ...)` at `:46`) — it never stamps its own name `"regression_pack"` on a `Finding.tool`. Verified by reading, not re-executed (an unambiguous two-line read, not a live-detection-gap claim). Consequence: `"regression_pack"` needs **no entry** in `PRODUCER_TOOL_NAMES` — it would never match anything if added, and its actual findings are already correctly covered under `"semgrep"` in `RUNNER_TOOL_NAMES`.
   - `typecheck.run()` starves `mypy` whenever a repo has **both** `tsconfig.json` and a mypy config: `if has_tsconfig: return run_tsc(ctx)` runs unconditionally before the `has_mypy_config` check, so `run_mypy` is dead code in that scenario. `selected_tool_names` (Task 1) will therefore report `"mypy"` as selected whenever `has_mypy_config(root)` is true, even in a repo where it can never actually run because `tsc` shadows it — a stranded historical `mypy` finding in that exact scenario reads as "still selected" and `mark-unreachable` refuses it. Safe-direction inaccuracy (refuses to retire rather than over-retiring), same class as the pre-existing `npm` deps-vs-tests collision the spec already documents (section 3.1). Not fixed here.
   - The `<test-suite>` marker (`tests.py`'s `_SUITE_FILE_MARKER`) can never satisfy `rec.get("file") in scope_files` in `record_run`'s resolve loop, since it is never a real path in the discovered file set — this is the `scope_files` half of the resolution guard, explicitly out of scope per spec section 12 (ticket T-3 territory).

7. **Style:** match `mark-not-a-secret`'s existing shape exactly for the new command — same argument order `(root, finding_id, reason)`, same `--reason` required-and-non-empty check returning 3, same `Ledger(root / ".aramid" / "ledger.db")` + `try/finally: close()`, same `uuid.uuid4().hex`, same `_now()`. Read `src/aramid/commands/ledger_cmd.py:134-173` before writing Task 3.

8. **Never run the full pytest suite.** ~16 minutes; the controller runs it. Run only the files your task touches, e.g. `python -m pytest tests/unit/test_toolset.py -q`.

9. **Invocation:** `python -m aramid`, `python -m pytest`. Do not edit `graph-out/`. No backticks inside `git commit -m` strings — use `-F` with a file or a stdin heredoc. Query graphite (`python -m graphite query "callers X"` / `"calls X"`) before grepping across files for a symbol — this repo's `.claude/settings.json` pre-tool-use hook is in `strict` mode and will block a cross-file `Grep` tool call for a known symbol; literal-text searches scoped to specific named file paths are fine.

10. **Every new test must be proven able to fail** before being accepted (spec section 10's standing rule, restated). Before claiming a test passes, confirm it fails against the unmodified tree. A test that passes both before and after is not a regression guard. Two exceptions, both named explicitly in their tasks below: Task 2's compact test (template already exists — mirror `test_compact_preserves_not_a_secret_status`) and Task 6's coverage test (fails today for a *different* reason — see Task 6).

---

## Task 1 — `src/aramid/toolset.py`: the live predicate

**Files:**
- Create: `src/aramid/toolset.py`
- Test: `tests/unit/test_toolset.py`

**Interfaces:**
- Consumes: `aramid.pipeline.GATE_RUNNER_KEYS`, `aramid.pipeline._is_applicable` (a private cross-module import — precedent already exists in this codebase: `aramid.commands.status` imports `aramid.commands.schedule._query_argv`, `status.py:245`); `aramid.detectors.{detect_stacks,detect_package_manager,detect_tests}`; `aramid.runners.{typecheck,deps}`; `aramid.runners.tests._argv` (private, same precedent); `aramid.runners.base.RunContext`; `aramid.config.Config` (the `cfg` parameter's type, for reading `cfg.tests`/`cfg.test_command`).
- Produces: `RUNNER_TOOL_NAMES: frozenset[str]`, `PRODUCER_TOOL_NAMES: frozenset[str]`, `selected_tool_names(root: Path, cfg) -> set[str]`, `ghost_candidates(state: dict, selected: set[str]) -> dict[str, dict]` — consumed by Task 3 (`mark-unreachable`'s guard), Task 5 (`pipeline.run_gate`'s `RUN_STARTED.selected`), Task 6 (`status`'s candidate section).

### Step 1: Write the module

```python
"""toolset -- the live predicate: which tool names would THIS repo produce
findings under, right now (not which tools ran in some past gate run --
that's `scope_tools`, computed per-run in aramid.pipeline.run_gate from
actual RunnerResult.state). Spec: docs/superpowers/specs/2026-07-28-aramid-
unreachable-findings-design.md, section 3.

RUNNER_TOOL_NAMES is the retireable universe -- every tool name a real
runner (aramid.pipeline.RUNNERS) can stamp onto a Finding.tool.
PRODUCER_TOOL_NAMES is never retireable BY CONSTRUCTION: excluding those
families from the universe, rather than checking for them at the point of
use, is what makes them un-selectable even by a caller who never considers
the question (spec section 7).
"""
from pathlib import Path

from aramid.detectors import detect_package_manager, detect_stacks, detect_tests
from aramid.pipeline import GATE_RUNNER_KEYS, _is_applicable
from aramid.runners import deps, typecheck
from aramid.runners import tests as tests_runner
from aramid.runners.base import RunContext

# Every tool name a real runner (aramid.pipeline.RUNNERS) can stamp onto a
# Finding.tool. Measured by reading every RawFinding(...) construction site
# in src/aramid/runners/ (spec section 3) and pinned by
# test_toolset.py's membership/disjointness test.
#
# "tests" (the literal registry key, not a real binary) is included
# deliberately -- see this plan's Global Constraint 5. It is the ONE name
# in this set that selected_tool_names() below does not derive from a
# sub-tool's own applicability check alone; it tracks the "tests" runner
# key's OWN applicability instead.
RUNNER_TOOL_NAMES = frozenset({
    "gitleaks", "semgrep", "ruff", "eslint",
    typecheck.NAME_TSC, typecheck.NAME_MYPY,
    deps.NAME_PIP_AUDIT, "npm", "pnpm", "yarn",
    "pytest", "tests",
})

# The producer/consumer families from spec section 1.2/7: async consumers
# (llm-review, mutation, js-mutation, fuzz, dast) and synchronous producers
# appended outside the runner dict (tdd, red-proof, mutation-score). Each
# has its own resolution mechanism (an auto_resolve_* function, or -- for
# mutation-score -- no persistence to resolve at all, see
# mutation_score_gate.py's own docstring); none is ever retired by hand.
#
# "regression_pack" is deliberately NOT here: it reuses the tool name
# "semgrep" for its findings (consumers/regression_pack.py:41,46 --
# json_or_crashed("semgrep", ...) then semgrep_runner.parse(...)), never
# its own name, so it needs no entry in either set (verified by reading;
# see this plan's Global Constraint 6).
PRODUCER_TOOL_NAMES = frozenset({
    "tdd", "red-proof", "mutation", "mutation-score",
    "llm-review", "js-mutation", "fuzz", "dast",
})


def _build_ctx(root: Path, cfg) -> RunContext:
    """A RunContext built directly from config/filesystem state, with no
    gate run -- mirrors the subset of aramid.pipeline.run_gate's own
    RunContext construction (pipeline.py:465-474) that pipeline._is_applicable
    actually reads: stacks, pkg_manager, and the [tests] trio. Fields
    _is_applicable never reads (files, rng, gate_deadline, ...) are left at
    their RunContext defaults."""
    tests_cfg = cfg.tests if isinstance(cfg.tests, dict) else {}
    return RunContext(
        root=root,
        pkg_manager=detect_package_manager(root),
        stacks=detect_stacks(root, root),
        test_command=tests_cfg.get("command", cfg.test_command),
        tests_enabled=tests_cfg.get("enabled", True),
        detected_tests=detect_tests(root),
    )


def selected_tool_names(root: Path, cfg) -> set[str]:
    """Which tool names this repo would produce findings under, right now.
    Reuses pipeline._is_applicable's own rules, unioned across EVERY gate's
    key list -- Gate.PRE_COMMIT's ["gitleaks","ruff"] is not a subset of
    Gate.PRE_PUSH's list (ruff only ever runs at pre-commit; ruff findings
    must still count as "selected" when checking a pre-commit-produced
    finding). Then expands each applicable key to the tool name(s) a
    Finding.tool actually carries for it -- the expansion is NOT identity
    for three of the keys (spec section 3's table)."""
    ctx = _build_ctx(root, cfg)
    all_keys = {key for keys in GATE_RUNNER_KEYS.values() for key in keys}
    applicable = {key for key in all_keys if _is_applicable(key, ctx)}

    names: set[str] = set()
    for key in applicable:
        if key in ("gitleaks", "semgrep", "ruff", "eslint"):
            names.add(key)
        elif key == "typecheck":
            # Both can be added independently of each other -- see this
            # plan's Global Constraint 6 (mypy-starvation caveat) for the
            # one known conservative inaccuracy this causes.
            if typecheck.has_mypy_config(root):
                names.add(typecheck.NAME_MYPY)
            if typecheck.has_tsconfig(root):
                names.add(typecheck.NAME_TSC)
        elif key == "deps":
            if ctx.pkg_manager:
                names.add(ctx.pkg_manager)
            if any(root.glob("requirements*.txt")):
                names.add(deps.NAME_PIP_AUDIT)
        elif key == "tests":
            # See this plan's Global Constraint 5: "tests" (the literal
            # registry key) tracks its OWN applicability, not just its
            # sub-tools' -- this is what lets a broken-but-still-configured
            # test setup be correctly REFUSED by mark-unreachable rather
            # than silently retired.
            names.add("tests")
            if ctx.test_command:
                argv = tests_runner._argv(ctx.test_command)
                if argv:
                    names.add(Path(argv[0]).name)
            else:
                names.update(ctx.detected_tests)
    return names


def ghost_candidates(state: dict, selected: set[str]) -> dict[str, dict]:
    """Every OPEN finding whose tool is in the retireable universe but not
    currently selected -- the set `aramid status` lists as retirement
    candidates (Task 6) and the set `aramid ledger mark-unreachable`
    (Task 3) accepts. The predicate, spec section 3:
    candidate(finding) <=> finding.tool in RUNNER_TOOL_NAMES
                         and finding.tool not in selected
                         and finding.status == "open"
    """
    return {
        fid: rec for fid, rec in state.items()
        if rec.get("status") == "open"
        and rec.get("tool") in RUNNER_TOOL_NAMES
        and rec.get("tool") not in selected
    }
```

**Inherited, known conservative limitation (spec section 3.1, not fixed here or anywhere in this plan):** `npm` is emitted by two different runners — `deps.py` for the JS dependency audit and `tests.py` for the npm test suite. `selected_tool_names` adds `ctx.pkg_manager` (e.g. `"npm"`) under the `deps` branch AND can separately add `"npm"` again under the `tests` branch (via `ctx.detected_tests`) — same string, two producers, harmlessly redundant when both are true. A repo that loses its npm *test suite* while keeping its npm *deps audit* has a stranded finding whose tool still reads as selected, so `mark-unreachable` will refuse it. Fails toward refusing to retire, which is the safe direction — this is inherited automatically by the design above, not something to special-case.

- [ ] **Step 1: Write `src/aramid/toolset.py` exactly as above.**

### Step 2: Write the tests — prove each one fails first

Create `tests/unit/test_toolset.py`:

```python
"""RUNNER_TOOL_NAMES/PRODUCER_TOOL_NAMES membership, selected_tool_names'
per-key expansion, and ghost_candidates' predicate (T-8 section 3)."""
from pathlib import Path

from aramid import config as config_mod
from aramid import toolset
from aramid.runners import deps, typecheck


def _cfg(tmp_path, monkeypatch, root) -> config_mod.Config:
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    return config_mod.load_config(root)


# ------------------------------------------------------- universe/disjoint --

def test_runner_and_producer_tool_names_are_disjoint():
    assert toolset.RUNNER_TOOL_NAMES.isdisjoint(toolset.PRODUCER_TOOL_NAMES)


def test_universe_contains_every_real_runner_tool_constant():
    # Pins the frozensets against the REAL constants each module defines --
    # a rename in any runner module fails this, not a silently-drifted copy.
    from aramid.runners import eslint, gitleaks, ruff, semgrep
    for name in (gitleaks.NAME, ruff.NAME, semgrep.NAME, eslint.NAME,
                 typecheck.NAME_TSC, typecheck.NAME_MYPY, deps.NAME_PIP_AUDIT,
                 "npm", "pnpm", "yarn", "pytest", "tests"):
        assert name in toolset.RUNNER_TOOL_NAMES, name


def test_producer_tools_are_never_in_the_runner_universe():
    from aramid import mutation_gate, mutation_score_gate, red_proof, tdd
    for name in (tdd._TOOL, red_proof._TOOL, mutation_gate.TOOL,
                 mutation_score_gate.TOOL, "llm-review", "js-mutation",
                 "fuzz", "dast"):
        assert name in toolset.PRODUCER_TOOL_NAMES
        assert name not in toolset.RUNNER_TOOL_NAMES


def test_regression_pack_needs_no_entry_in_either_set():
    """T-8 Global Constraint 6: regression_pack reuses "semgrep", it never
    stamps its own name -- so its own module name has no place in either
    frozenset, and must not silently start matching one."""
    from aramid.consumers import regression_pack
    assert regression_pack.NAME not in toolset.RUNNER_TOOL_NAMES
    assert regression_pack.NAME not in toolset.PRODUCER_TOOL_NAMES


# ---------------------------------------------------- selected_tool_names ---

def test_gitleaks_always_selected_even_in_an_empty_repo(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    assert "gitleaks" in toolset.selected_tool_names(tmp_path, cfg)


def test_ruff_selected_only_for_python_stack(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    assert "ruff" not in toolset.selected_tool_names(tmp_path, cfg)
    (tmp_path / "pyproject.toml").write_text("[tool.x]\n", encoding="utf-8")
    assert "ruff" in toolset.selected_tool_names(tmp_path, cfg)


def test_tsc_selected_when_tsconfig_present(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    assert typecheck.NAME_TSC in toolset.selected_tool_names(tmp_path, cfg)


def test_pytest_selected_when_a_real_test_file_exists(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    (tmp_path / "test_x.py").write_text("def test_a(): pass\n", encoding="utf-8")
    selected = toolset.selected_tool_names(tmp_path, cfg)
    assert "pytest" in selected
    assert "tests" in selected  # the registry key itself, Global Constraint 5


def test_pytest_no_longer_selected_once_the_test_file_is_gone(tmp_path, monkeypatch):
    """Proves the ghost scenario end to end at the toolset layer: a repo
    that once had a pytest suite, and no longer does, drops BOTH "pytest"
    and the "tests" registry key from the selected set."""
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    selected = toolset.selected_tool_names(tmp_path, cfg)
    assert "pytest" not in selected
    assert "tests" not in selected


def test_tests_key_stays_selected_when_binary_missing_but_suite_still_detected(
        tmp_path, monkeypatch):
    """Global Constraint 5: a broken-but-still-configured test setup must
    stay "selected" -- mark-unreachable must refuse it (broken toolchain is
    `aramid doctor`'s problem), not silently retire it. selected_tool_names
    never inspects whether the pytest BINARY resolves -- only whether
    detect_tests() still finds a real suite -- so this holds regardless of
    whether pytest is actually installed on the machine running this test."""
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    (tmp_path / "test_x.py").write_text("def test_a(): pass\n", encoding="utf-8")
    assert "tests" in toolset.selected_tool_names(tmp_path, cfg)


def test_custom_test_command_basename_is_selected_not_pytest_or_npm(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    (tmp_path / "aramid.toml").write_text(
        'schema_version = 1\n[tests]\ncommand = "make test"\n', encoding="utf-8")
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    selected = toolset.selected_tool_names(tmp_path, cfg)
    assert "make" in selected
    assert "tests" in selected
    assert "pytest" not in selected


def test_tests_disabled_removes_the_tests_key_from_selection(tmp_path, monkeypatch):
    (tmp_path / "test_x.py").write_text("def test_a(): pass\n", encoding="utf-8")
    (tmp_path / "aramid.toml").write_text(
        'schema_version = 1\n[tests]\nenabled = false\n', encoding="utf-8")
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    selected = toolset.selected_tool_names(tmp_path, cfg)
    assert "tests" not in selected
    assert "pytest" not in selected


# ------------------------------------------------------- ghost_candidates ---

def test_ghost_candidates_excludes_producer_tools_even_if_never_selected():
    state = {"f1": {"status": "open", "tool": "mutation"}}
    assert toolset.ghost_candidates(state, selected=set()) == {}


def test_ghost_candidates_excludes_non_open_status():
    state = {"f1": {"status": "historical", "tool": "gitleaks"}}
    assert toolset.ghost_candidates(state, selected=set()) == {}


def test_ghost_candidates_includes_open_finding_whose_tool_left_selection():
    state = {"f1": {"status": "open", "tool": "ruff"}}
    assert "f1" in toolset.ghost_candidates(state, selected=set())


def test_ghost_candidates_excludes_a_still_selected_tool():
    state = {"f1": {"status": "open", "tool": "ruff"}}
    assert toolset.ghost_candidates(state, selected={"ruff"}) == {}
```

- [ ] **Step 2: Write the test file exactly as above.**
- [ ] **Step 3: Run the tests, confirm every one fails against a stub/empty `toolset.py`** (or, since you write the module first, confirm each assertion is meaningful by temporarily commenting out the relevant branch in `toolset.py` and watching its own test fail — this is the "prove it can fail" step for a brand-new module with no prior broken state to revert to).

  Run: `python -m pytest tests/unit/test_toolset.py -v`
  Expected after Steps 1-2: all pass, 15 tests.

- [ ] **Step 4: Commit.**

```bash
git add src/aramid/toolset.py tests/unit/test_toolset.py
git commit -F - <<'EOF'
feat(toolset): T-8 section 3 -- the live "which tools would this repo
produce findings under right now" predicate

New module, no other file touched. RUNNER_TOOL_NAMES/PRODUCER_TOOL_NAMES
close the gate-surface hole by construction (producer families are
excluded from the retireable universe, not guarded against at the point
of use). selected_tool_names reuses pipeline._is_applicable directly
rather than re-deriving its rules. Includes the "tests" literal per this
plan's Global Constraint 5 (measured: it never enters scope_tools, and
the spec's own prescribed relabel-fix breaks pipeline.py's accept-degraded
exclusion -- so it lives in the universe/selection layer instead).
EOF
```

---

## Task 2 — Ledger core: the event, the status, resurrection

**Files:**
- Modify: `src/aramid/models.py`
- Modify: `src/aramid/ledger.py`
- Test: `tests/unit/test_ledger_events.py`, `tests/unit/test_ledger_state.py`, `tests/unit/test_ledger_compact.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `EventType.FINDING_UNREACHABLE`, `Status.UNREACHABLE`, `_materialize`'s new branch, `compact()`'s widened `terminal_types`, `record_run`'s widened re-detect set — consumed by Task 3 (`mark-unreachable` appends this event), Task 4 (`override` reads the resulting status), Task 6 (`status` reads the resulting status).

### Step 1: `models.py` — two edits

a. Add to `EventType` (`:31-50`), beside `FINDING_NOT_A_SECRET`:

```python
    # S105 justification: same as Status.NOT_A_SECRET/FINDING_NOT_A_SECRET
    # above -- an EventType member name/value, not a credential.
    FINDING_UNREACHABLE = "finding_unreachable"  # noqa: S105
```

Wait — check whether ruff's S105 heuristic actually flags `"finding_unreachable"` before adding the `noqa`; it does NOT contain the substring "secret" or a credential-shaped word, so the `# noqa: S105` comment is very likely unnecessary here (unlike `NOT_A_SECRET`/`FINDING_NOT_A_SECRET`, which literally contain "SECRET"). Run `ruff check --select S105 src/aramid/models.py` after adding the plain line (no noqa) first; add the noqa only if ruff actually flags it. Do not copy the comment reflexively — this project's own ledger records exactly this mistake once already (`# noqa` comments added without verifying ruff actually needed them, T-10).

b. Add `UNREACHABLE = "unreachable"` to the `Status` StrEnum (`:14-23`), after `NOT_A_SECRET`.

### Step 2: `ledger.py` — three edits

a. In `_materialize` (`:22-44`), add a branch after the `finding_not_a_secret` branch, identical shape:

```python
        elif e.type.value == "finding_unreachable":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "unreachable"
                state[e.finding_id]["reason"] = e.payload.get("reason", "")
```

b. Widen the resurrection re-detect set in `record_run` (`:80`):

```python
            if f.id not in state or state[f.id]["status"] in ("fixed", "unreachable"):
```

(was `in ("fixed",)`). `overridden`/`rotated`/`not_a_secret` stay sticky — do not touch them.

c. In `compact()`, add `EventType.FINDING_UNREACHABLE.value` to `terminal_types` (`:136-139`):

```python
        terminal_types = {EventType.FINDING_RESOLVED.value,
                           EventType.FINDING_OVERRIDDEN.value,
                           EventType.FINDING_ROTATED.value,
                           EventType.FINDING_NOT_A_SECRET.value,
                           EventType.FINDING_UNREACHABLE.value}
```

Missing this silently reverts an `unreachable` finding to `open` on compaction — see the LANDMINE comment already at `:112-122`; `compact()` is dead code today (no `src/` call sites) but must still be kept correct.

### Step 3: Tests

**`tests/unit/test_ledger_events.py`** — materialization:

```python
def test_finding_unreachable_transitions_status(tmp_path):
    from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict
    led = Ledger(tmp_path / "l.db")
    f = Finding("id1", "ruff", "F401", "medium", Severity.MEDIUM, Verdict.WARN,
                "a.py", 1, "m", "e", Gate.PRE_PUSH)
    led.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [f])
    led.append(Event(EventType.FINDING_UNREACHABLE, "r2", "t2",
                     finding_id="id1", payload={"reason": "ruff no longer selected"}))
    rec = led.open_findings()["id1"]
    assert rec["status"] == "unreachable"
    assert rec["reason"] == "ruff no longer selected"
    led.close()


def test_finding_unreachable_for_unknown_id_is_ignored_no_phantom_entry(tmp_path):
    from aramid.models import Event, EventType
    led = Ledger(tmp_path / "l.db")
    led.append(Event(EventType.FINDING_UNREACHABLE, "r1", "t1",
                     finding_id="ghost-id", payload={"reason": "x"}))
    assert led.open_findings() == {}
    led.close()
```

**`tests/unit/test_ledger_state.py`** — resurrection, and its mirror (spec section 10 item 2+3 — both must exist, not just the positive case):

```python
def test_unreachable_finding_reopens_when_re_detected(tmp_path):
    from aramid.models import Event, EventType
    led = Ledger(tmp_path / "l.db")
    f = _f("id1", tool="ruff")
    led.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [f])
    led.append(Event(EventType.FINDING_UNREACHABLE, "r2", "t2",
                     finding_id="id1", payload={"reason": "ruff not selected"}))
    assert led.open_findings()["id1"]["status"] == "unreachable"

    led.record_run("r3", "t3", "pre-push", {"ruff"}, {"a.py"}, [f])  # tool returns
    assert led.open_findings()["id1"]["status"] == "open"
    led.close()


def test_overridden_rotated_not_a_secret_do_not_reopen_on_redetect(tmp_path):
    """Mirror of the resurrection test above -- spec section 10 item 3.
    Only "fixed"/"unreachable" re-detect; the three human-assertion
    statuses must stay sticky."""
    from aramid.models import Event, EventType
    for status_event, extra_events in (
        (EventType.FINDING_OVERRIDDEN, []),
        (EventType.FINDING_ROTATED, []),
        (EventType.FINDING_NOT_A_SECRET, []),
    ):
        led = Ledger(tmp_path / f"l-{status_event.value}.db")
        f = _f("id1", tool="gitleaks", historical=(status_event != EventType.FINDING_OVERRIDDEN))
        led.record_run("r1", "t1", "historical-scan" if f.historical else "pre-push",
                       {"gitleaks"}, set() if f.historical else {"a.py"}, [f])
        led.append(Event(status_event, "r2", "t2", finding_id="id1", payload={"reason": "x"}))
        before = led.open_findings()["id1"]["status"]

        led.record_run("r3", "t3", "pre-push", {"gitleaks"}, {"a.py"}, [f])

        assert led.open_findings()["id1"]["status"] == before, status_event
        led.close()
```

(Adjust `_f`'s signature to whatever helper already exists at the top of `test_ledger_state.py` — it currently takes `fid, tool="ruff", file="a.py", historical=False`; reuse it, do not redefine it.)

**`tests/unit/test_ledger_compact.py`** — mirror `test_compact_preserves_not_a_secret_status` (`:52-66`) exactly, substituting the new event:

```python
def test_compact_preserves_unreachable_status(tmp_path):
    # T-8: FINDING_UNREACHABLE must be in compact()'s terminal_types set. If
    # missing, compact() drops it from `keep` and deletes it, silently
    # reverting the status from "unreachable" back to "open".
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t", "pre-push", {"ruff"}, {"a.py"}, [_f("id1")])
    led.append(Event(EventType.FINDING_UNREACHABLE, uuid.uuid4().hex, "t2",
                     finding_id="id1", payload={"reason": "keep me"}))
    led.compact()
    rec = led.open_findings()["id1"]
    assert rec["status"] == "unreachable"
    assert rec["reason"] == "keep me"
    led.close()
```

- [ ] **Step 4: Run `python -m pytest tests/unit/test_ledger_events.py tests/unit/test_ledger_state.py tests/unit/test_ledger_compact.py tests/unit/test_models.py -q`. Confirm each new test fails first** by temporarily reverting one edit at a time (comment out the `_materialize` branch → the materialization tests fail; comment out the resurrection widening → the resurrection test fails, its mirror still passes; comment out the `compact()` addition → the compact test fails), then restore and confirm green.

- [ ] **Step 5: Commit.**

```bash
git add src/aramid/models.py src/aramid/ledger.py tests/unit/test_ledger_events.py tests/unit/test_ledger_state.py tests/unit/test_ledger_compact.py
git commit -F - <<'EOF'
feat(ledger): T-8 section 4/5/6 -- FINDING_UNREACHABLE event, Status.UNREACHABLE,
resurrection, compact() terminal_types

_materialize gains the new status transition, mirroring finding_not_a_secret's
shape. record_run's re-detect set widens to (fixed, unreachable) -- a tool
that returns and re-finds the problem re-opens it automatically, proven with
its mirror (overridden/rotated/not_a_secret stay sticky). compact()'s
terminal_types set gains the new event type -- otherwise compaction silently
reverts an unreachable finding to open with no error.
EOF
```

---

## Task 3 — `aramid ledger mark-unreachable`

**Files:**
- Modify: `src/aramid/commands/ledger_cmd.py`
- Modify: `src/aramid/cli.py`
- Test: `tests/integration/test_ledger_cmd.py`

**Interfaces:**
- Consumes: `aramid.toolset.{RUNNER_TOOL_NAMES, selected_tool_names}` (Task 1), `EventType.FINDING_UNREACHABLE`/`Status.UNREACHABLE` (Task 2).
- Produces: `cmd_ledger_mark_unreachable(root, finding_id, reason) -> int`, wired into `cli.py`'s `ledger` subcommand dispatch.

### Step 1: `ledger_cmd.py`

Add near the top (alongside the existing imports):

```python
from aramid import config as config_mod
from aramid import toolset
```

Add the new command at the end of the file, mirroring `cmd_ledger_mark_not_a_secret`'s shape (`:134-173`) but with the four distinct refusal conditions from spec section 4.2. Order: cheapest/most-fundamental check first (unknown id, then producer-tool — a NEVER-possible refusal regardless of status — then status, then the one check requiring a filesystem walk, `selected_tool_names`):

```python
# ------------------------------------------------------- mark-unreachable ---

def cmd_ledger_mark_unreachable(root, finding_id: str, reason: str) -> int:
    root = Path(root)
    reason = (reason or "").strip()
    if not reason:
        print("aramid: ledger mark-unreachable: --reason is required", file=sys.stderr)
        return 3

    try:
        cfg = config_mod.load_config(root)
    except Exception as exc:
        print(f"aramid: ledger mark-unreachable: engine error: {exc}", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: ledger mark-unreachable: unknown finding id {finding_id}",
                  file=sys.stderr)
            return 3

        tool = rec.get("tool")
        if tool not in toolset.RUNNER_TOOL_NAMES:
            print(f"aramid: ledger mark-unreachable: {finding_id} is a {tool!r} finding "
                  f"-- producer/consumer findings (tdd, red-proof, mutation, "
                  f"mutation-score, llm-review, js-mutation, fuzz, dast) resolve "
                  f"through their own producer's mechanism, never by hand",
                  file=sys.stderr)
            return 3

        status = rec.get("status")
        if status != "open":
            tails = {
                "unreachable": "already marked unreachable.",
                "fixed": "already fixed -- nothing to retire.",
                "historical": "a historical secret -- use `aramid ledger mark-rotated` "
                              "or `mark-not-a-secret` instead.",
                "overridden": "already overridden.",
                "rotated": "already retired by rotation.",
                "not_a_secret": "already marked not-a-secret.",
            }
            tail = tails.get(status, "mark-unreachable only applies to an open finding.")
            print(f"aramid: ledger mark-unreachable: {finding_id} is not open "
                  f"(status={status}) -- {tail}", file=sys.stderr)
            return 3

        selected = toolset.selected_tool_names(root, cfg)
        if tool in selected:
            print(f"aramid: ledger mark-unreachable: {finding_id}'s tool ({tool}) still "
                  f"runs in this repo -- not a ghost. If it fails every run, that is "
                  f"`aramid doctor`'s problem, not mark-unreachable's", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_UNREACHABLE, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: ledger: {finding_id} marked unreachable ({reason})")
        return 0
    finally:
        ledger.close()
```

Also add `"reason"` handling is already covered generically (`cmd_ledger_show`'s hardcoded key tuple at `:61-63` already includes `"reason"` since T-9 — confirm this by reading, do not re-add it).

### Step 2: `cli.py` — three edits, mirroring `mark-not-a-secret`

- Add `cmd_ledger_mark_unreachable` to the import block (`:25-31`; sorts after `cmd_ledger_mark_rotated`, before `cmd_ledger_show` — alphabetical).
- Add the subparser beside `:99-101`:
  ```python
  p_unreachable = ledger_sub.add_parser("mark-unreachable")
  p_unreachable.add_argument("id")
  p_unreachable.add_argument("--reason", required=True)
  ```
- Add the dispatch branch beside `:211-212`, and update the "a subcommand is required" message (`:213-215`) to `(list|show|filter|mark-rotated|mark-not-a-secret|mark-unreachable)`:
  ```python
          if args.ledger_command == "mark-unreachable":
              return cmd_ledger_mark_unreachable(root, args.id, args.reason)
  ```

### Step 3: Tests (`tests/integration/test_ledger_cmd.py`)

Add near the bottom, mirroring the `mark-not-a-secret` section's exact shape (`:173-380`):

```python
# ----------------------------------------------------- mark-unreachable ---

def test_mark_unreachable_transitions_open_finding_whose_tool_left_selection(
        tmp_path, capsys, monkeypatch):
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.close()

    rc = cmd_ledger_mark_unreachable(root, "f1", "ruff no longer selected for this repo")

    assert rc == 0
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["f1"]["status"] == "unreachable"
        events = [e for e in ledger.events() if e.type.value == "finding_unreachable"]
        assert len(events) == 1
        assert events[0].payload["reason"] == "ruff no longer selected for this repo"
    finally:
        ledger.close()


def test_mark_unreachable_refuses_when_tool_still_selected(tmp_path, capsys, monkeypatch):
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    (root / "pyproject.toml").write_text("[tool.x]\n", encoding="utf-8")  # keeps ruff selected
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.close()

    rc = cmd_ledger_mark_unreachable(root, "f1", "trying anyway")
    err = capsys.readouterr().err

    assert rc == 3
    assert "still runs in this repo" in err
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["f1"]["status"] == "open"
    finally:
        ledger.close()


def test_mark_unreachable_refuses_producer_tool_finding(tmp_path, capsys, monkeypatch):
    """Spec section 10 item 6 requires BOTH an llm-review finding AND a
    mutation finding to be attempted and refused -- these are the two
    named gate-surface producers (review.llm_gate_findings,
    mutation_gate.mutation_gate_findings) that materialize BLOCK-tier
    findings straight from status=="open"; a silent retire on either would
    drop a gate block."""
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "drain", set(), set(), [
        _f("f1", tool="mutation"),
        _f("f2", tool="llm-review"),
    ])
    ledger.close()

    rc1 = cmd_ledger_mark_unreachable(root, "f1", "trying anyway")
    err1 = capsys.readouterr().err
    rc2 = cmd_ledger_mark_unreachable(root, "f2", "trying anyway")
    err2 = capsys.readouterr().err

    assert rc1 == 3
    assert "never by hand" in err1
    assert rc2 == 3
    assert "never by hand" in err2
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["f1"]["status"] == "open"
        assert ledger.open_findings()["f2"]["status"] == "open"
    finally:
        ledger.close()


def test_mark_unreachable_refuses_historical_finding_redirects_to_gitleaks_commands(
        tmp_path, capsys, monkeypatch):
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                       [_f("hist1", tool="gitleaks", verdict=Verdict.BLOCK, historical=True)])
    ledger.close()

    rc = cmd_ledger_mark_unreachable(root, "hist1", "trying anyway")
    err = capsys.readouterr().err

    assert rc == 3
    assert "mark-rotated" in err
    assert "mark-not-a-secret" in err


def test_mark_unreachable_unknown_id_errors(tmp_path, capsys, monkeypatch):
    from aramid import config as config_mod
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    rc = cmd_ledger_mark_unreachable(tmp_path, "nope", "some reason")
    err = capsys.readouterr().err
    assert rc == 3
    assert "nope" in err


def test_mark_unreachable_requires_reason(tmp_path, capsys):
    rc = cmd_ledger_mark_unreachable(tmp_path, "hist1", "")
    err = capsys.readouterr().err
    assert rc == 3
    assert "reason" in err.lower()


def test_mark_unreachable_missing_reason_flag_exits_3_via_argparse(capsys):
    # Mirrors test_mark_not_a_secret_missing_reason_flag_exits_3_via_argparse
    # (:283-297) -- must go through cli.main, not a direct function call.
    rc = cli.main(["ledger", "mark-unreachable", "hist1"])
    err = capsys.readouterr().err
    assert rc == 3
    assert "the following arguments are required" in err


def test_mark_unreachable_twice_refuses_second_time(tmp_path, capsys, monkeypatch):
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.close()

    rc1 = cmd_ledger_mark_unreachable(root, "f1", "first reason")
    capsys.readouterr()
    rc2 = cmd_ledger_mark_unreachable(root, "f1", "second reason")
    err2 = capsys.readouterr().err

    assert rc1 == 0
    assert rc2 == 3
    assert "already marked unreachable" in err2


def test_unreachable_finding_reopens_when_tool_returns_via_real_dispatch(
        tmp_path, capsys, monkeypatch):
    """End-to-end through cli.main + record_run, not just the ledger unit
    test in Task 2 -- proves the whole command chain, not just _materialize."""
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.close()

    rc = cli.main(["ledger", "mark-unreachable", "f1", "--reason", "ruff not selected"])
    assert rc == 0
    capsys.readouterr()

    ledger = _ledger(root)
    ledger.record_run("r2", "t2", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    try:
        assert ledger.open_findings()["f1"]["status"] == "open"
    finally:
        ledger.close()
```

- [ ] **Step 4: Run `python -m pytest tests/integration/test_ledger_cmd.py -q`. Prove each new test fails first** — comment out the whole command body's guard chain one guard at a time and confirm the matching test (and only that one) goes red.

- [ ] **Step 5: Commit.**

```bash
git add src/aramid/commands/ledger_cmd.py src/aramid/cli.py tests/integration/test_ledger_cmd.py
git commit -F - <<'EOF'
feat(cli): T-8 section 4.2/9 -- aramid ledger mark-unreachable

Four refusals, each its own message: unknown id, a producer-tool finding
(never retired by hand), a non-open status (per-status redirect, mirroring
mark-not-a-secret's own table), and a still-selected tool ("not a ghost --
that's aramid doctor's problem"). Wired into cli.py identically to
mark-rotated/mark-not-a-secret.
EOF
```

---

## Task 4 — `override.py`: refuse an unreachable finding

**Files:**
- Modify: `src/aramid/commands/override.py`
- Test: `tests/integration/test_override.py`

**Interfaces:**
- Consumes: `Status.UNREACHABLE`/materialized `"unreachable"` string (Task 2).
- Produces: one new refusal branch in `cmd_override`.

### Step 1: Edit `override.py`

Spec section 7.1: `override`'s guard is orthogonal to status (it gates on `verdict == "block"` and the LLM confirmed-critical test only), so `open -> unreachable -> override -> overridden` was reachable. It grants no new capability (anything reachable that way was already overridable directly while `open`), but it costs the resurrection property — `overridden` is not in the re-detect set, so chaining would make the finding permanently sticky, immune to the tool-returns re-open Task 2 guarantees.

Add, right after the `rec is None` check (before the existing BLOCK-tier check), in `cmd_override` (`:44-71`):

```python
        # T-8 section 7.1: override gates on verdict/LLM-confirmed-critical
        # only, never on status -- so open -> unreachable -> override was
        # reachable, granting no NEW capability (anything reachable this
        # way was already overridable directly while open) but costing the
        # resurrection guarantee (overridden findings never re-detect).
        if rec.get("status") == "unreachable":
            print(f"aramid: override: {finding_id} is unreachable -- its tool does not "
                  f"run in this repo, so there is nothing to override", file=sys.stderr)
            return 3

```

### Step 2: Tests (`tests/integration/test_override.py`)

```python
def test_unreachable_finding_is_refused(tmp_path, capsys, monkeypatch):
    from aramid.models import Event, EventType
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.append(Event(EventType.FINDING_UNREACHABLE, "r2", "t2",
                        finding_id="f1", payload={"reason": "ruff not selected"}))
    ledger.close()

    rc = cmd_override(root, "f1", "let me override it anyway")
    err = capsys.readouterr().err

    assert rc == 3
    assert "unreachable" in err
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["f1"]["status"] == "unreachable"
        events = [e for e in ledger.events() if e.type.value == "finding_overridden"]
        assert events == []
    finally:
        ledger.close()
```

- [ ] **Step 3: Write the test, confirm it fails first** (comment out the new guard, watch the assertion on `rc == 3` fail with `rc == 0` and the status flip to `"overridden"`), then restore and confirm green.

  Run: `python -m pytest tests/integration/test_override.py -q`

- [ ] **Step 4: Commit.**

```bash
git add src/aramid/commands/override.py tests/integration/test_override.py
git commit -F - <<'EOF'
fix(override): T-8 section 7.1 -- refuse an unreachable finding

Closes the open -> unreachable -> override -> overridden chain. Grants no
new capability (override's guard was already orthogonal to status), but
without this an unreachable finding could become permanently sticky --
"overridden" is not in the resurrection re-detect set (T-8 section 5), so
chaining through override would defeat the tool-returns re-open guarantee.
EOF
```

---

## Task 5 — `RUN_STARTED.selected` (diagnostic only)

**Files:**
- Modify: `src/aramid/ledger.py`
- Modify: `src/aramid/pipeline.py`
- Test: `tests/unit/test_ledger_events.py`, `tests/unit/test_pipeline.py`

**Interfaces:**
- Consumes: `aramid.toolset.selected_tool_names` (Task 1).
- Produces: `Ledger.record_run(..., *, selected_tools: set[str] | None = None)`; `pipeline.run_gate` passes it, `commands/drain.py` and `commands/init.py` do not (verified: exactly three `record_run` call sites in `src/`, confirmed via `grep -rln "record_run" src/` restricted to already-known files — `pipeline.py:526`, `commands/drain.py:131`, `commands/init.py:178`).

### Step 1: `ledger.py` — widen `record_run`'s signature

```python
    def record_run(self, run_id, at, gate, scope_tools, scope_files, findings, *,
                   selected_tools: set[str] | None = None):
        state, seen = _materialize(self.events())
        present = {f.id for f in findings}
        payload = {"gate": gate, "tools": sorted(scope_tools)}
        if selected_tools is not None:
            payload["selected"] = sorted(selected_tools)
        self.append(Event(EventType.RUN_STARTED, run_id, at, payload=payload))
```

(Replace the existing two-line `RUN_STARTED` append at `:76-77` with the above — build `payload` as a local dict first, conditionally add `"selected"`, then append once.) Leave the rest of `record_run` (`:78-91`) unchanged.

**Do not** default `selected_tools` to `set()` and always add the key — spec section 8 is explicit that "key absent = no information" must stay distinguishable from "nothing was selected" for `drain`/`init`'s calls, which select no runners at all and must not read as "this repo has zero selectable tools."

### Step 2: `pipeline.py` — pass it from `run_gate`

At the `record_run` call site (`:526`), add a lazy import (avoids a circular import: `toolset.py` imports `pipeline.GATE_RUNNER_KEYS`/`pipeline._is_applicable` at module scope, so importing `toolset` at `pipeline.py`'s own module scope would cycle — same problem class `ledger.compact()` already solves with a local import of `aramid.queue`, `ledger.py:155`, for the identical reason):

```python
    # Local import: toolset.py imports pipeline.GATE_RUNNER_KEYS/_is_applicable
    # at module scope, so importing it here at module scope would be
    # circular (mirrors ledger.compact()'s identical fix for the
    # queue.py/ledger.py cycle, ledger.py:155).
    from aramid import toolset
    selected_tools = toolset.selected_tool_names(root, cfg)
    new_ids = ledger.record_run(run_id, at, str(gate), scope_tools, scope_files, findings,
                                selected_tools=selected_tools)
```

(Replaces the existing single-line call at `:526`.)

### Step 3: Tests

**`tests/unit/test_ledger_events.py`:**

```python
def test_record_run_selected_tools_recorded_when_passed(tmp_path):
    from aramid.models import EventType
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [],
                   selected_tools={"ruff", "gitleaks"})
    run_started = [e for e in led.events() if e.type is EventType.RUN_STARTED][0]
    assert run_started.payload["selected"] == ["gitleaks", "ruff"]
    led.close()


def test_record_run_selected_key_absent_when_not_passed(tmp_path):
    """T-8 section 8: 'key absent = no information' is a live state -- drain
    and init never pass selected_tools. payload.get("selected", []) would
    collapse "unknown" into "nothing selected"; assert the KEY is missing,
    not merely empty."""
    from aramid.models import EventType
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t1", "drain", set(), set(), [])
    run_started = [e for e in led.events() if e.type is EventType.RUN_STARTED][0]
    assert "selected" not in run_started.payload
    led.close()
```

**`tests/unit/test_pipeline.py`** — add near the other `run_gate`-level tests (after the fixtures at the top, `:1-70`):

```python
def test_run_gate_records_selected_tools_on_run_started(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                        _fake(RunnerResult(tool="gitleaks", state=ToolState.OK, raw="[]")))

    pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-sel")

    run_started = [e for e in ledger.events() if e.type is EventType.RUN_STARTED][0]
    assert "selected" in run_started.payload
    # gitleaks has no stack condition (pipeline._is_applicable's catch-all
    # True) -- always selected, in any repo, any gate.
    assert "gitleaks" in run_started.payload["selected"]
```

- [ ] **Step 4: Run `python -m pytest tests/unit/test_ledger_events.py tests/unit/test_pipeline.py -q`. Prove each fails first** — revert the `payload["selected"] = ...` line and confirm the two new `test_ledger_events.py` tests fail (one on a missing key, one on a KeyError); revert the `pipeline.py` call-site edit and confirm the `test_pipeline.py` test fails on the missing key.

- [ ] **Step 5: Commit.**

```bash
git add src/aramid/ledger.py src/aramid/pipeline.py tests/unit/test_ledger_events.py tests/unit/test_pipeline.py
git commit -F - <<'EOF'
feat(ledger): T-8 section 8 -- RUN_STARTED.selected, diagnostic only

record_run gains a keyword-only selected_tools, stamped from
toolset.selected_tool_names by its one caller that actually selects
runners (pipeline.run_gate). drain and init deliberately do not pass it --
"key absent" is a live, intentional state (no information), never
collapsed into "nothing selected". Not consulted by any gate/guard --
purely so a human reading the audit trail later can see why a finding was
retireable.
EOF
```

---

## Task 6 — `aramid status` surfaces

**Files:**
- Modify: `src/aramid/commands/status.py`
- Test: `tests/integration/test_status.py`

**Interfaces:**
- Consumes: `aramid.toolset.{selected_tool_names, ghost_candidates}` (Task 1), `Status.UNREACHABLE` (Task 2).
- Produces: `unreachable`/`fixed`/`rotated` buckets in `_open_counts_line`; a new `_unreachable_candidate_lines` section; a `Status`-coverage test.

**Two other ledger-state readers were checked (spec section 9) and need no change — recorded here so this task doesn't re-derive it or accidentally touch them:**
- `reporter._open_count_line:26-37` prints one unbucketed number (`sum(1 for rec in ... if status == "open")`). An `unreachable` finding correctly leaves that count; there is no second bucket to fall out of sync. No change.
- `pack_cmd.cmd_pack_compile:58-76` iterates every materialized finding and never filters on status at all (confirmed by reading: no `status` check anywhere in the function body) — it already compiles `fixed`/`overridden`/`rotated`/`not_a_secret` rows alike, so `unreachable` behaves exactly as `open` did there. Pre-existing, not this task's to change.

### Step 1: Widen `_open_counts_line` to cover every `Status` member

Spec section 6: "a test asserts the printed buckets cover every member of `Status`." `Status` today (after Task 2) has seven members: `OPEN`, `FIXED`, `OVERRIDDEN`, `HISTORICAL`, `ROTATED`, `NOT_A_SECRET`, `UNREACHABLE`. The CURRENT line (`status.py:38-43`) only names four (`open` as the bare count, `historical`, `not_a_secret`, `overridden`) — `fixed` and `rotated` are silently absent TODAY, not just after this task's addition. Making the coverage genuinely complete means adding both, not only `unreachable`:

```python
def _open_counts_line(state: dict) -> str:
    counts = Counter(rec.get("status") for rec in state.values())
    return (f"open findings: {counts.get('open', 0)} "
            f"(historical: {counts.get('historical', 0)}, "
            f"not-a-secret: {counts.get('not_a_secret', 0)}, "
            f"overridden: {counts.get('overridden', 0)}, "
            f"unreachable: {counts.get('unreachable', 0)}, "
            f"fixed: {counts.get('fixed', 0)}, "
            f"rotated: {counts.get('rotated', 0)})")
```

Blast radius: `tests/integration/test_status.py:131` asserts `"open findings: 2" in out` — a prefix match, survives the addition (T-9 already grew this line twice the same way without breaking it). Grep the test file for any OTHER assertion on this line's exact full text before assuming nothing else needs updating.

### Step 2: The `unreachable candidates` section

Add near the top of the file (`from aramid import toolset` alongside the existing `from aramid import config as config_mod` / `from aramid import review` imports), and a new function beside `_unrotated_historical_lines` (`:104-113`):

```python
def _unreachable_candidate_lines(root: Path, cfg, state: dict) -> list[str]:
    """Auto-DETECTED ghost candidates (T-8 section 9 item 2 -- the user's
    chosen auto-detect + manual-retire design): an open finding whose tool
    is in the retireable universe but not currently selected. Mirrors
    _unrotated_historical_lines's shape: one line per candidate, naming the
    exact command. Without this the operator must already suspect a finding
    is a ghost, reproducing the exact discoverability defect T-9 fixed."""
    selected = toolset.selected_tool_names(root, cfg)
    candidates = toolset.ghost_candidates(state, selected)
    return [
        f"  {fid} {rec.get('tool')}:{rec.get('rule')} {rec.get('file')} -- "
        f"tool no longer runs in this repo? "
        f"`aramid ledger mark-unreachable {fid} --reason ...`"
        for fid, rec in candidates.items()
    ]
```

Wire it into `cmd_status` (`:254-301`), after the `historical` block and before `_bake_lines`:

```python
        unreachable_candidates = _unreachable_candidate_lines(root, cfg, state)
        if unreachable_candidates:
            lines.append("  unreachable candidates:")
            lines.extend(unreachable_candidates)
```

### Step 3: Tests (`tests/integration/test_status.py`)

```python
def test_open_counts_line_names_every_status_member(monkeypatch):
    """T-8 section 6: the printed buckets must enumerate every Status
    member -- not just the ones known when this line was last touched --
    so the NEXT status added fails this test instead of silently dropping
    out of the printed total (the T-11 move: make the failure mode
    mechanical, not dependent on someone noticing).

    This test is proven to fail against the PRE-T-8 tree for a DIFFERENT
    reason than the one this task fixes: "fixed" and "rotated" are ALSO
    absent from the current line, independent of "unreachable" -- run it
    against main@bab831e first and confirm it fails on those two labels,
    not only the new one, before trusting this test guards what it claims to."""
    from aramid.commands import status as status_mod
    from aramid.models import Status
    line = status_mod._open_counts_line({})
    for member in Status:
        if member is Status.OPEN:
            continue  # the leading bare count IS Status.OPEN; not a named bucket
        label = member.value.replace("_", "-")
        assert label in line, (
            f"Status.{member.name} ({member.value!r}) has no bucket in "
            f"_open_counts_line -- it would silently vanish from the printed total")


def test_status_lists_unreachable_candidate_and_the_exact_retire_command(
        tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "pre-push", {"ruff"},
                       {"a.py"}, [_f("f1", tool="ruff", rule="F401")])
    # re-run with ruff de-selected (no python stack detected -- root has no
    # pyproject.toml/py files beyond what _repo's fixture writes)
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "unreachable candidates:" in out
    assert "f1" in out
    assert "aramid ledger mark-unreachable f1 --reason ..." in out


def test_status_omits_unreachable_section_when_no_candidates(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    Ledger(root / ".aramid" / "ledger.db").close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "unreachable candidates" not in out


def test_status_reports_unreachable_count_in_open_counts_line(tmp_path, monkeypatch, capsys):
    from aramid.models import Event, EventType
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "pre-push", {"ruff"},
                       {"a.py"}, [_f("f1", tool="ruff")])
    ledger.append(Event(EventType.FINDING_UNREACHABLE, "run2", "2026-01-02T00:00:00+00:00",
                        finding_id="f1", payload={"reason": "ruff not selected"}))
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "unreachable: 1" in out
    assert "unreachable candidates" not in out  # already retired, no longer a candidate
```

`_repo`'s existing fixture (`test_status.py:44-53`) writes a single `a.py` with `x = 1` and no `pyproject.toml` — check whether `detect_stacks` reports `"python"` for it anyway (it walks for any `.py` file, `detectors.py:87`) before asserting `"ruff"` is unselected in the candidate test; if ruff IS still detected for that fixture (likely — `a.py` is a `.py` file), adjust the second test to run `cmd_status` in a repo/`aramid.toml` that changes stack detection instead (e.g. a `tmp_path` with only a `.js`-suffixed tracked file, or a JS-only fixture), or delete `a.py` from a fresh, non-Python fixture directory before calling `cmd_status`. Verify the actual selection behavior with a quick throwaway `python -c` check before writing the assertion, rather than assuming.

- [ ] **Step 4: Run `python -m pytest tests/integration/test_status.py -q`. Prove each new test fails first.**

- [ ] **Step 5: Commit.**

```bash
git add src/aramid/commands/status.py tests/integration/test_status.py
git commit -F - <<'EOF'
feat(status): T-8 section 6/9 -- unreachable bucket + candidate section

_open_counts_line now names every Status member (fixed/rotated were
silently absent before this too -- made genuinely complete, pinned by a
coverage test). New "unreachable candidates" section mirrors
_unrotated_historical_lines: one line per open finding whose tool has left
selection, naming the exact mark-unreachable command.
EOF
```

---

## Task 7 — The `tsc` label fix (case 5, folded in)

**Files:**
- Modify: `src/aramid/runners/typecheck.py`
- Test: `tests/unit/test_runner_typecheck.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `run_tsc`'s return value always carries `NAME_TSC`, regardless of platform or state.

### Step 1: Fix `run_tsc`

```python
import dataclasses
```

at the top, alongside the existing imports. Then (`:64-68`):

```python
def run_tsc(ctx) -> RunnerResult:
    binp = _tsc_bin(ctx.root)
    if not binp.exists():
        return RunnerResult(NAME_TSC, ToolState.MISSING)
    result = run_subprocess([str(binp), "--noEmit"], ctx.root, TIMEOUT_S)
    # This plan's Global Constraint 4 (T-8 section 11): run_subprocess
    # labels RunnerResult.tool from argv[0]'s basename ("tsc.cmd" on
    # win32), which both mismatches parse_tsc's stamped tool AND makes
    # typecheck.parse()'s own dispatch (`if result.tool == NAME_TSC`) miss
    # entirely -- not just a ledger-resolution gap, a total detection gap.
    # Relabel unconditionally (not just the OK branch): run_subprocess's
    # own TIMEOUT path also carries the wrong name. Mirrors eslint.py's
    # json_or_crashed relabel.
    return dataclasses.replace(result, tool=NAME_TSC)
```

### Step 2: The proof — round-trip through the REAL `run_subprocess` seam, not a hand-built `RunnerResult`

Add to `tests/unit/test_runner_typecheck.py`, near the existing `test_run_dispatches_to_tsc_when_tsconfig_present` (`:90-103`) — **do not modify that existing test**, it tests a different concern (dispatch to `run_tsc` vs `run_mypy`) and its own fake already hardcodes the correct label, which is fine for what IT tests:

```python
def test_run_tsc_relabels_windows_cmd_suffix_so_parse_still_finds_the_error(
        tmp_path, monkeypatch):
    """T-8 section 11 (corrects the spec's own section 11.1, which framed
    this as resolve-only). run_subprocess derives RunnerResult.tool from
    argv[0]'s basename ("tsc.cmd" on win32, via _tsc_bin). typecheck.parse()
    dispatches on `result.tool == NAME_TSC` ("tsc") -- so an UNRELABELED
    Windows-shaped result makes parse_tsc unreachable and a real TS error is
    silently dropped, not merely stranded in the ledger.

    Proven by mocking run_subprocess to return EXACTLY the shape it produces
    on win32 (tool="tsc.cmd") regardless of the host platform actually
    running this test -- so it fails on every CI leg pre-fix, not only a
    Windows one, and it exercises run_tsc's REAL relabeling logic rather
    than a hand-built RunnerResult that would trivially agree either way."""
    _repo(tmp_path, tsconfig=True)
    real_ts_error = ("src/app.ts(10,5): error TS2322: Type 'string' is not "
                      "assignable to type 'number'.\n")
    monkeypatch.setattr(
        typecheck, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="tsc.cmd", state=ToolState.OK, raw=real_ts_error, returncode=2),
    )

    result = typecheck.run_tsc(RunContext(root=tmp_path))
    findings = typecheck.parse(result, RunContext(root=tmp_path))

    assert result.tool == typecheck.NAME_TSC, (
        "run_tsc must relabel to NAME_TSC regardless of argv[0]'s basename")
    assert len(findings) == 1
    assert findings[0].rule == "TS2322"
    assert findings[0].file == "src/app.ts"


def test_run_tsc_relabels_even_on_timeout(tmp_path, monkeypatch):
    """The relabel must be unconditional -- run_subprocess's TIMEOUT path
    ALSO carries argv[0]'s basename, not just the OK path."""
    _repo(tmp_path, tsconfig=True)
    monkeypatch.setattr(
        typecheck, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="tsc.cmd", state=ToolState.TIMEOUT),
    )
    result = typecheck.run_tsc(RunContext(root=tmp_path))
    assert result.tool == typecheck.NAME_TSC
    assert result.state is ToolState.TIMEOUT
```

**Generalization note, deliberately scoped down:** the spec (section 10 item 9) and this project's own advisor discussion both want this pattern generalized to every runner ("catches the next instance of this defect class"). During this planning session every OTHER runner (`gitleaks`, `ruff`, `semgrep`, `eslint`, `mypy`, `deps`'s four sub-tools, `tests`'s `pytest`/`npm` paths) was read and confirmed self-consistent: each either passes its own canonical name as `argv[0]` (so `run_subprocess`'s basename derivation already matches) or explicitly relabels via `json_or_crashed` (`eslint.py:49`, `deps.py` throughout). Writing the identical round-trip test for all of them would currently prove a negative (no bug found) rather than fix one, and this task is already large. **Not done here, deliberately** — if a future runner is added that launches a repo-local `.bin` binary the way `tsc` does (a platform-suffixed basename different from its parser's stamped name), the same round-trip pattern above is the template to reach for.

- [ ] **Step 3: Run `python -m pytest tests/unit/test_runner_typecheck.py -q`. Prove both new tests fail first** by reverting the `dataclasses.replace` line back to `return result` and confirming `test_run_tsc_relabels_windows_cmd_suffix_so_parse_still_finds_the_error` fails with `findings == []` and `result.tool == "tsc.cmd"`.

- [ ] **Step 4: Commit.**

```bash
git add src/aramid/runners/typecheck.py tests/unit/test_runner_typecheck.py
git commit -F - <<'EOF'
fix(typecheck): T-8 section 11 -- relabel run_tsc's RunnerResult.tool

run_subprocess derives .tool from argv[0]'s basename, which is "tsc.cmd"
on Windows (repo-local node_modules/.bin path). typecheck.parse()
dispatches on `result.tool == NAME_TSC` ("tsc"), so an unrelabeled Windows
result makes parse_tsc unreachable -- a real TS error is silently dropped
from every Windows gate run today, not merely stranded once detected (this
plan's Global Constraint 4 corrects the spec's own weaker framing).
Relabel unconditionally, mirroring eslint.py's json_or_crashed. Proven via
a mocked run_subprocess returning the exact Windows shape, so the test
fails on every CI leg pre-fix rather than requiring a live Windows tsc.cmd.
EOF
```

---

## Task 8 — End-to-end integration test

**Files:**
- Test: new file `tests/integration/test_unreachable_findings_e2e.py`

**Interfaces:**
- Consumes: everything from Tasks 1-6 (not Task 7 — the tsc fix is independent and already proven in Task 7).

Spec section 10 item 8: "build a repo whose detection strands a real finding, prove `status` names it as a candidate, retire it, prove it leaves the open count and the nag, then restore detection and prove it comes back open." Drive this through `run_gate` (not hand-appended ledger events), so it proves the whole chain including `toolset.selected_tool_names` agreeing with what `pipeline.run_gate` actually selected.

```python
"""T-8 end-to-end: a repo whose stack detection strands a ruff finding,
proven through the real pipeline -- not hand-appended ledger events."""
import subprocess
from pathlib import Path

from aramid import cli, config as config_mod, pipeline
from aramid.commands.status import cmd_status
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "app.py").write_text("import os\n", encoding="utf-8")  # F401-shaped
    _git(r, "add", "app.py")
    _git(r, "commit", "-q", "-m", "initial")
    return r


def test_ghost_ruff_finding_surfaces_retires_and_resurrects(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")

    # 1. Seed the ghost: a real ruff finding, run while python IS the stack.
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                        pipeline.RUNNERS["gitleaks"])  # keep gitleaks real (no-op, cheap)
    from aramid.normalizer import RawFinding
    fake_ruff_raw = [RawFinding(tool="ruff", rule="F401", severity_raw="low",
                                file="app.py", line=1, message="unused import")]
    monkeypatch.setitem(
        pipeline.RUNNERS, "ruff",
        type("F", (), {"run": staticmethod(lambda ctx: RunnerResult("ruff", ToolState.OK, raw="")),
                       "parse": staticmethod(lambda result, ctx: fake_ruff_raw)})())
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["gitleaks", "ruff"])

    result1 = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-seed")
    fid = next(f.id for f in result1.findings if f.tool == "ruff")

    # 2. Detection strands it: remove app.py so python is no longer detected
    #    (a real repo would lose it via a detector-fix branch, per spec's
    #    motivating pawscout case -- this fixture forces the same end state
    #    directly rather than re-deriving a detector regression).
    (root / "app.py").unlink()
    _git(root, "rm", "--cached", "-q", "app.py")
    _git(root, "commit", "-q", "-m", "remove python file")

    # 3. status names it as a candidate.
    rc = cmd_status(root)
    out = capsys.readouterr().out
    assert rc == 0
    assert "unreachable candidates:" in out
    assert fid in out
    assert f"aramid ledger mark-unreachable {fid} --reason ..." in out

    # 4. Retire it.
    rc = cli.main(["ledger", "mark-unreachable", fid, "--reason", "no python stack anymore"])
    assert rc == 0
    capsys.readouterr()

    # 5. It leaves the open count and the candidate nag.
    rc = cmd_status(root)
    out = capsys.readouterr().out
    assert "unreachable: 1" in out
    assert "unreachable candidates" not in out
    assert ledger.open_findings()[fid]["status"] == "unreachable"

    # 6. Restore detection, re-run the gate, prove it comes back open.
    (root / "app.py").write_text("import os\n", encoding="utf-8")
    _git(root, "add", "app.py")
    _git(root, "commit", "-q", "-m", "restore python file")
    cfg2 = config_mod.load_config(root)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["gitleaks", "ruff"])
    pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg2, ledger, run_id="run-restore")

    assert ledger.open_findings()[fid]["status"] == "open"
    ledger.close()
```

Verify this fixture actually strands/restores `"ruff"` from `selected_tool_names` as expected (`detect_stacks` reads `.py` files under `root`, `detectors.py:87`) with a quick throwaway check before trusting the assertions — do not assume the file-removal alone flips detection without confirming it live in this exact test's tmp_path shape (git's index/working-tree state after `rm --cached` vs the walk `detect_stacks`/`_iter_files` performs over the filesystem, not git state, matters here).

- [ ] **Step 1: Write the test file above.**
- [ ] **Step 2: Run it standalone, iterate on the fixture until steps 3-6 pass** — this test's main risk is the detection fixture (step 2) not actually flipping `selected_tool_names`'s output the way the test assumes; debug that with a `print(toolset.selected_tool_names(root, cfg))` before/after if it doesn't behave as expected, rather than adjusting assertions to match wrong behavior.

  Run: `python -m pytest tests/integration/test_unreachable_findings_e2e.py -v`

- [ ] **Step 3: Commit.**

```bash
git add tests/integration/test_unreachable_findings_e2e.py
git commit -F - <<'EOF'
test(e2e): T-8 section 10 item 8 -- ghost finding full lifecycle

Drives the whole chain through the real pipeline (not hand-appended ledger
events): a ruff finding stranded by detection change, surfaced as a status
candidate, retired via mark-unreachable, leaves the open count and the
nag, then resurrects when detection returns -- through a real run_gate
call, not just ledger._materialize.
EOF
```

---

## Task 9 — Documentation

**Files:**
- Modify: `src/aramid/data/ARAMID.md.tmpl`
- Modify: `ARAMID.md` (repo root, tracked, rendered)
- Modify: other doc sites (enumerate per the method below)
- Test: none new (existing `tests/unit/test_aramid_md_template_sync.py` re-verifies the sync)

**Method:** T-9's own Task 4 (`docs/superpowers/plans/2026-07-27-aramid-not-a-secret.md:281-322`) is the template — it names every doc file `mark-not-a-secret` touched, by having actually grepped for `mark-rotated` across the doc tree before writing. Do the same for `mark-unreachable`/`unreachable`: grep `docs/user-guide.md`, `docs/knowledge-base.md`, and `docs/superpowers/specs/2026-07-12-aramid-phase1-design.md` for wherever `mark-rotated`/`mark-not-a-secret`/the ledger status list/the `Status` enum is enumerated, and add the parallel entry. This plan does not re-enumerate those line numbers — they were not re-read during this planning session (T-9's own doc task already took the same measured, grep-first approach; repeat it rather than trusting a stale count here).

**Known, concrete (re-read this session):**

1. `src/aramid/data/ARAMID.md.tmpl` — two edits:
   - Line 95's `## Commands` list already reads: `` `aramid status` -- open findings, new-since-baseline, unrotated historical secrets (see `ledger mark-rotated` / `mark-not-a-secret` below). `` — extend to mention unreachable candidates:
     ```
     - `aramid status` -- open findings, new-since-baseline, unrotated historical secrets, unreachable candidates (see `ledger mark-rotated` / `mark-not-a-secret` / `mark-unreachable` below).
     ```
   - Add one new bullet to `## Commands` (after the `override` line, `:97`):
     ```
     - `aramid ledger mark-unreachable <id> --reason "..."` -- retire a finding whose tool no longer runs in this repo (de-selected, disabled, or removed) -- see `aramid status`'s "unreachable candidates" section for which ids qualify.
     ```

2. Regenerate `ARAMID.md` (repo root) through the real renderer, preserving the historical Onboarded date — **do not hand-edit it**, per `test_aramid_md_template_sync.py`'s own warning and T-11's precedent:
   ```python
   python -c "
   from pathlib import Path
   from aramid.commands.init import _render_aramid_md
   text = _render_aramid_md({'python'}, None)  # match this repo's OWN current Detected-stack/Package-manager header values -- read them from the CURRENT ARAMID.md before regenerating, do not guess
   text = text.replace('**Onboarded:** ' + __import__('datetime').date.today().isoformat(),
                       '**Onboarded:** 2026-07-25')
   Path('ARAMID.md').write_text(text, encoding='utf-8')
   "
   ```
   Read the current `ARAMID.md`'s `Detected stack:`/`Package manager:` header values FIRST and pass the matching set/string to `_render_aramid_md` — do not assume `{"python"}`/`None`; confirm from the file itself, mirroring `test_aramid_md_is_in_sync_with_its_template`'s own approach of deriving inputs from the current file rather than re-detecting.

- [ ] **Step 1: Update `ARAMID.md.tmpl` with the two edits above.**
- [ ] **Step 2: Regenerate `ARAMID.md`, preserving the 2026-07-25 Onboarded date.**
- [ ] **Step 3: Run `python -m pytest tests/unit/test_aramid_md_template_sync.py -v` — must pass (proves the regeneration is byte-for-byte what the updated template produces).**
- [ ] **Step 4: Grep `docs/user-guide.md`, `docs/knowledge-base.md`, `docs/superpowers/specs/2026-07-12-aramid-phase1-design.md` for `mark-rotated`/`mark-not-a-secret`/ledger status enumerations (following T-9's Task 4 method) and add the parallel `mark-unreachable`/`unreachable` entries at each site found.**
- [ ] **Step 5: Commit.**

```bash
git add src/aramid/data/ARAMID.md.tmpl ARAMID.md docs/user-guide.md docs/knowledge-base.md docs/superpowers/specs/2026-07-12-aramid-phase1-design.md
git commit -F - <<'EOF'
docs: T-8 -- document mark-unreachable and the unreachable status

ARAMID.md.tmpl + regenerated ARAMID.md (Onboarded date preserved), plus
user-guide.md/knowledge-base.md/the phase1 spec's ledger status
enumeration -- same doc sites T-9's mark-not-a-secret task touched,
extended the same way for the new status/command.
EOF
```

---

## Final check before declaring the branch done

- [ ] Full suite (controller runs it, not a subagent — ~16 min): `python -m pytest -q`, confirm no regressions beyond the new tests.
- [ ] `python -m aramid check --gate pre-push --all --accept-degraded --reason "T-8 self-check"` (or whatever this repo's own dogfood invocation is — check `.git/hooks/pre-push` or CI config for the exact form) against this repo itself, confirming aramid's own gate still passes with the new module/command wired in.
- [ ] Confirm all 9 tasks' commits exist, in order, on the current branch.
- [ ] Ask the user before pushing (per this repo's standing rule — every prior ticket in this ledger asked first) and before merging.
