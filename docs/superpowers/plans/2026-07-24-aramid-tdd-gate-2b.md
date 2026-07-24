# Aramid TDD Gate 2b — Mutation-Score Regression Teeth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the 2a analyzer's mutation-score regressions at the pre-push gate, with transition regressions BLOCK-armable via a new `[mutation].score_block_armed` bake and rate-delta regressions as permanent WARN.

**Architecture:** A new zero-persistence gate seam (`src/aramid/mutation_score_gate.py`, twin of `mutation_gate.py`) recomputes `mutation_score.latest_regressions(ledger.events())` fresh at every PRE_PUSH and materializes results as findings under the distinct tool `"mutation-score"`. Nothing is ever written to the ledger — no new EventType, no stored findings, no resolver — so 1b's `auto_resolve_mutation` can never wrongly resolve a regression (2a spec §12, resolved by construction). The only escape valve is ephemeral, test-mapped suppression per gate run.

**Tech Stack:** Python 3.11+ stdlib only (dataclasses, argparse, re, pathlib), pytest, ruff. Windows-first: every tool invoked as `python -m <tool>`.

**Spec:** `docs/superpowers/specs/2026-07-24-aramid-tdd-gate-2b-mutation-score-teeth-design.md` (approved 2026-07-24).

## Global Constraints

Every task's requirements implicitly include ALL of these:

- **Branch:** all work happens on `feat/tdd-gate-2b` (branched off `main` by the controller before Task 1). NEVER commit to `main`.
- **Do NOT modify:** `src/aramid/mutation_score.py` (the 2a analyzer is reused verbatim), `src/aramid/consumers/mutation.py`, `src/aramid/mutation_gate.py` (import from it only), `src/aramid/check.py`, `src/aramid/models.py`, the ledger schema. No new `EventType`. No ledger writes anywhere in new code. No stored findings, no resolver.
- **Distinct tool string:** the seam's findings use `tool="mutation-score"` and `rule` = `"transition"` | `"rate"`. Never `"mutation"` — `auto_resolve_mutation` and `mutation_gate_findings` both filter `tool == "mutation"` and must never see these findings.
- **Twin-rule discipline (spec §7):** the seam's inline verdict and `policy.classify`'s `tool == "mutation-score"` branch encode the SAME one-line rule: `BLOCK iff armed and rule == "transition"`, else `WARN`, where `armed = cfg.mutation.get("score_block_armed", False)`. The two must agree (pinned by the Task 2 twin-rule test).
- **Fail-open (spec §9):** `mutation_score_gate_findings` NEVER raises into `run_gate`. Any exception → skip the item or return `[]`. `[mutation].enabled = false` → `[]` (engine off = no re-drain backstop = an armed stale regression could never clear).
- **Severity mapping:** transition → `severity_raw="high"` / `Severity.HIGH`; rate → `severity_raw="low"` / `Severity.LOW`. Line is always `0` (fingerprints are opaque; the message names the function).
- **Exit-code contract:** a BLOCK finding drives `cmd_check` exit 1 (`pipeline.py` step 8) — the e2e tests assert `rc == 1` for block, `rc != 1` for not-blocked, exactly like `tests/integration/test_mutation_gate_e2e.py`.
- **Tests:** run ONLY the focused test files named in your task, always as `python -m pytest <files> -q`. NEVER run the bare full suite — it takes ~10–13 minutes and will look like a hang; the controller runs it in the background at Task 6.
- **Graphite:** the code graph is daemon-fresh. Before editing the shared files `pipeline.py` or `policy.py`, run `python -m graphite context src/aramid/pipeline.py` (resp. `policy.py`) and skim the output. Never edit `graph-out/`.
- **Commits:** commit after each green test cycle with the message given in the task's commit step. Backticks in `-m` strings are shell-expanded on this machine — commit messages below contain none; keep it that way.

---

### Task 1: The gate seam — `mutation_score_gate.py`

**Files:**
- Create: `src/aramid/mutation_score_gate.py`
- Create: `tests/unit/test_mutation_score_gate.py`

**Interfaces:**
- Consumes: `mutation_score.latest_regressions(events) -> list[Regression]` where `Regression` has `.target` (`"<rel>::<func>"`), `.kind` (`"transition"`|`"rate"`), `.baseline_index`, `.current_index`, `.detail` (rate: `"1.00 -> 0.33"`), `.transition_fps` (frozenset). Also `mutation_gate._module_tests(module: str) -> set[str]`, `gitutil.is_test_file(path) -> bool`, `compute_fingerprint(tool, rule, path, line_content, occurrence_index) -> str`.
- Produces: `mutation_score_gate.TOOL == "mutation-score"` and `mutation_score_gate_findings(cfg, ledger, gate: Gate, changed_files=None) -> list[Finding]` — Task 2's twin test and Task 3's pipeline wiring call exactly this.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_mutation_score_gate.py`:

```python
"""mutation_score_gate (2b): zero-persistence PRE_PUSH seam over the 2a
analyzer. Seeded-ledger tests mirror test_mutation_score.py's _crf pattern;
cfg fakes mirror test_mutation_gate.py's SimpleNamespace pattern."""
from types import SimpleNamespace

from aramid import mutation_score_gate
from aramid.fingerprint import compute_fingerprint
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Gate, Severity, Source, Verdict

FP = "deadbeef"


def _crf(idx, target, killed_s1, survived_s1, fully,
         killed_fps=(), survivor_fps=()):
    return Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", "t", payload={
        "consumer": "mutation", "item_id": "q",
        "mutation_scores": {"schema": 1, "targets": {target: {
            "generated": killed_s1 + survived_s1, "killed_s1": killed_s1,
            "survived_s1": survived_s1, "timeouts": 0, "errors": 0,
            "fully_mutated": fully, "killed_fps": list(killed_fps),
            "survivor_fps": list(survivor_fps)}}}})


def _transition_ledger(base, target="src/calc.py::is_adult"):
    """Baseline kills FP; current run has FP as a confirmed survivor.
    NOTE: the current run's rate (0.33) is also below baseline (1.00), so
    this history yields BOTH a transition and a rate regression -- tests
    filter by rule."""
    led = Ledger(base / "l.db")
    led.append(_crf(0, target, 2, 0, True, killed_fps=[FP, "other"]))
    led.append(_crf(1, target, 1, 2, True, killed_fps=["other"],
                    survivor_fps=[FP]))
    return led


def _rate_ledger(base, target="src/calc.py::is_adult"):
    """Rate drop 1.00 -> 0.33 with NO fps seeded: rate-only regression."""
    led = Ledger(base / "l.db")
    led.append(_crf(0, target, 3, 0, True))
    led.append(_crf(1, target, 1, 2, True))
    return led


def _cfg(armed, enabled=True):
    return SimpleNamespace(mutation={"enabled": enabled,
                                     "score_block_armed": armed})


def _findings(led, cfg, gate=Gate.PRE_PUSH, changed_files=None):
    try:
        return mutation_score_gate.mutation_score_gate_findings(
            cfg, led, gate, changed_files)
    finally:
        led.close()


def test_armed_transition_blocks(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True))
    trans = [f for f in got if f.rule == "transition"]
    assert len(trans) == 1
    f = trans[0]
    assert f.tool == "mutation-score"
    assert f.verdict is Verdict.BLOCK
    assert f.severity is Severity.HIGH and f.severity_raw == "high"
    assert f.file == "src/calc.py" and f.line == 0
    assert "is_adult" in f.message
    assert "1 previously-killed mutant(s) now survive" in f.message
    assert FP in f.evidence
    assert f.gate is Gate.PRE_PUSH and f.source is Source.DETERMINISTIC


def test_baking_transition_warns(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=False))
    trans = [f for f in got if f.rule == "transition"]
    assert [f.verdict for f in trans] == [Verdict.WARN]


def test_rate_warns_even_when_armed(tmp_path):
    got = _findings(_rate_ledger(tmp_path), _cfg(armed=True))
    assert [f.rule for f in got] == ["rate"]
    f = got[0]
    assert f.verdict is Verdict.WARN
    assert f.severity is Severity.LOW and f.severity_raw == "low"
    assert "1.00 -> 0.33" in f.message
    assert f.evidence == ""


def test_mapped_test_suppresses_transition_not_rate(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True),
                    changed_files={"tests/test_calc.py"})
    assert [f.rule for f in got] == ["rate"]   # transition ephemeral-suppressed


def test_module_test_suffix_variant_suppresses(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True),
                    changed_files={"src/calc_test.py"})
    assert "transition" not in [f.rule for f in got]


def test_source_touch_does_not_suppress(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True),
                    changed_files={"src/calc.py"})
    trans = [f for f in got if f.rule == "transition"]
    assert [f.verdict for f in trans] == [Verdict.BLOCK]


def test_unrelated_test_does_not_suppress(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True),
                    changed_files={"tests/test_other.py"})
    assert "transition" in [f.rule for f in got]


def test_none_changed_files_never_suppresses(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True),
                    changed_files=None)
    assert "transition" in [f.rule for f in got]


def test_empty_outside_pre_push(tmp_path):
    assert _findings(_transition_ledger(tmp_path / "a"), _cfg(True),
                     gate=Gate.PRE_COMMIT) == []
    assert _findings(_transition_ledger(tmp_path / "b"), _cfg(True),
                     gate=Gate.ALL) == []


def test_disabled_engine_returns_empty(tmp_path):
    """[mutation].enabled=false disables the seam entirely: the drain stops
    measuring, so no re-drain could ever clear a stale regression -- teeth
    without the measuring engine would be an inescapable block (spec s9)."""
    got = _findings(_transition_ledger(tmp_path),
                    _cfg(armed=True, enabled=False))
    assert got == []


def test_missing_mutation_config_defaults_to_baking(tmp_path):
    got = _findings(_transition_ledger(tmp_path), SimpleNamespace())
    trans = [f for f in got if f.rule == "transition"]
    assert [f.verdict for f in trans] == [Verdict.WARN]


def test_malformed_target_key_skipped_wellformed_surfaces(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.append(_crf(0, "nosep", 2, 0, True, killed_fps=[FP]))
    led.append(_crf(1, "nosep", 0, 1, True, survivor_fps=[FP]))
    led.append(_crf(2, "src/ok.py::f", 2, 0, True, killed_fps=[FP]))
    led.append(_crf(3, "src/ok.py::f", 0, 1, True, survivor_fps=[FP]))
    got = _findings(led, _cfg(armed=True))
    assert {f.file for f in got} == {"src/ok.py"}


def test_fail_open_broken_ledger():
    class Boom:
        def events(self):
            raise RuntimeError("boom")
    got = mutation_score_gate.mutation_score_gate_findings(
        _cfg(armed=True), Boom(), Gate.PRE_PUSH)
    assert got == []


def test_id_deterministic_and_never_finding_id_shaped(tmp_path):
    got1 = _findings(_transition_ledger(tmp_path / "a"), _cfg(True))
    got2 = _findings(_transition_ledger(tmp_path / "b"), _cfg(True))
    t1 = [f for f in got1 if f.rule == "transition"][0]
    t2 = [f for f in got2 if f.rule == "transition"][0]
    assert t1.id == t2.id
    assert t1.id == compute_fingerprint("mutation-score", "transition",
                                        "src/calc.py", "is_adult", 0)
```

- [ ] **Step 2: Run to verify the tests fail**

Run: `python -m pytest tests/unit/test_mutation_score_gate.py -q`
Expected: collection error — `ModuleNotFoundError: No module named 'aramid.mutation_score_gate'` (red confirmed).

- [ ] **Step 3: Write the seam**

Create `src/aramid/mutation_score_gate.py`:

```python
"""mutation_score_gate -- the zero-persistence pre-push seam for 2a's
mutation-score regressions (sub-project 2b). mutation_score.py detects two
advisory signals over CONSUMER_RUN_FINISHED history (per-mutant transition;
per-function stage-1 rate-delta); nothing surfaces them at the gate. This
module is mutation_gate.py's twin for DERIVED state: recompute
latest_regressions fresh each PRE_PUSH and materialize the results as
findings under the distinct tool "mutation-score" -- auto_resolve_mutation
and mutation_gate_findings both filter tool == "mutation", so neither ever
touches these; nothing is written to the ledger, so there is no stored
record to wrongly resolve ("only a re-drain truly clears it" holds by
construction -- the 2a spec s12 caveat, closed).

The verdict is computed HERE from [mutation].score_block_armed -- the SAME
rule policy.classify's tool == "mutation-score" branch encodes (BLOCK iff
armed AND rule == "transition"); the two one-line rules must agree.

Ephemeral test-mapped suppression (transitions only -- WARNs need no escape
valve): a push whose changed_files touch the module-mapped test
(test_<module>/<module>_test, per mutation_gate._module_tests) drops the
transition for THIS gate run only. No ledger write; a bare source-touch
never suppresses -- that is exactly the 1b auto-resolve hole 2b closes.
changed_files is the push's scope ONLY under mode "range"; pipeline passes
None otherwise (under "all"/"staged" the scope is the whole tree/staged set
and suppressing against it would suppress everything).

Fail-open contract identical to mutation_gate: NEVER raises into run_gate.
Documented limitations (spec s10): the fingerprint pins occurrence to 0, so
two same-op mutants on one identical line share an fp and a transition may
conflate them; findings are ephemeral (invisible to aramid status and to
apply_overrides -- escape = mapped test or disarm); a function rewritten
without its mapped test blocks until a re-drain re-measures, which is why
[mutation].enabled = false disables the seam entirely (engine off = no
re-drain backstop = an armed stale regression could never clear).
"""
from pathlib import Path

from aramid import gitutil, mutation_score
from aramid.fingerprint import compute_fingerprint
from aramid.models import Finding, Gate, Severity, Source, Verdict
from aramid.mutation_gate import _module_tests

TOOL = "mutation-score"


def mutation_score_gate_findings(cfg, ledger, gate: Gate,
                                 changed_files=None) -> list[Finding]:
    """Materialize current mutation-score regressions as gate findings.
    PRE_PUSH only; [] when [mutation].enabled is false. Never raises."""
    if gate is not Gate.PRE_PUSH:
        return []
    try:
        mcfg = getattr(cfg, "mutation", None) or {}
        if not mcfg.get("enabled", True):
            return []
        armed = bool(mcfg.get("score_block_armed", False))
        regressions = mutation_score.latest_regressions(ledger.events())
    except Exception:
        return []
    changed_test_stems = set()
    if changed_files:
        try:
            changed_test_stems = {Path(c).stem for c in changed_files
                                  if gitutil.is_test_file(c)}
        except Exception:
            changed_test_stems = set()
    out = []
    for r in regressions:
        try:
            rel, sep, func = r.target.partition("::")
            if not sep or not func:
                continue                    # malformed target key: skip
            if r.kind == "transition":
                if _module_tests(Path(rel).stem) & changed_test_stems:
                    continue    # ephemeral suppression, this gate run only
                verdict = Verdict.BLOCK if armed else Verdict.WARN
                severity_raw, severity = "high", Severity.HIGH
                message = (f"mutation-score regression in {func}: "
                           f"{len(r.transition_fps)} previously-killed "
                           f"mutant(s) now survive")
                evidence = ", ".join(sorted(r.transition_fps))
            elif r.kind == "rate":
                verdict = Verdict.WARN
                severity_raw, severity = "low", Severity.LOW
                message = (f"mutation-score rate regression in {func}: "
                           f"{r.detail}")
                evidence = ""
            else:
                continue
            out.append(Finding(
                id=compute_fingerprint(TOOL, r.kind, rel, func, 0),
                tool=TOOL, rule=r.kind, severity_raw=severity_raw,
                severity=severity, verdict=verdict, file=rel, line=0,
                message=message, evidence=evidence, gate=gate,
                source=Source.DETERMINISTIC))
        except Exception:
            continue
    return out
```

- [ ] **Step 4: Run to verify all tests pass**

Run: `python -m pytest tests/unit/test_mutation_score_gate.py -q`
Expected: 14 passed.

- [ ] **Step 5: Regression-guard the untouched neighbors**

Run: `python -m pytest tests/unit/test_mutation_score.py tests/unit/test_mutation_gate.py -q`
Expected: all pass (2a analyzer and 1b seam byte-untouched).

- [ ] **Step 6: Commit**

```bash
git add src/aramid/mutation_score_gate.py tests/unit/test_mutation_score_gate.py
git commit -m "feat(mutation-score-gate): zero-persistence pre-push seam for score regressions (2b Task 1)"
```

---

### Task 2: The classify twin — `policy.py` branch + twin-rule test

**Files:**
- Modify: `src/aramid/policy.py` (insert after the `tool == "mutation"` branch, currently lines 107–116)
- Modify: `tests/unit/test_policy.py` (append at end)
- Modify: `tests/unit/test_mutation_score_gate.py` (append twin-rule test + one import)

**Interfaces:**
- Consumes: Task 1's `mutation_score_gate_findings` and its test helpers `_transition_ledger`/`_cfg`; `policy.classify(tool, rule, severity_raw, gate, cfg) -> tuple[Severity, Verdict]`.
- Produces: the `tool == "mutation-score"` classify branch that Task 3's pipeline flow and `_has_genuine_block` rely on.

- [ ] **Step 1: Write the failing tests (red-first twin)**

Append to `tests/unit/test_policy.py` (it already imports `policy`, `Gate`, `Severity`, `Verdict`, `SimpleNamespace`):

```python
# --- classify: mutation-score (sub-project 2b) -------------------------------

def _msc_cfg(armed: bool):
    # classify reads cfg.block_rules early, then the tool branch; a minimal
    # namespace with the attributes classify touches is enough.
    return SimpleNamespace(block_rules={},
                           mutation={"score_block_armed": armed})


def test_mutation_score_transition_armed_is_block():
    sev, verdict = policy.classify("mutation-score", "transition", "high",
                                   Gate.PRE_PUSH, _msc_cfg(armed=True))
    assert sev is Severity.HIGH         # assert severity in BOTH (1a T2a lesson)
    assert verdict is Verdict.BLOCK


def test_mutation_score_transition_disarmed_is_warn():
    sev, verdict = policy.classify("mutation-score", "transition", "high",
                                   Gate.PRE_PUSH, _msc_cfg(armed=False))
    assert sev is Severity.HIGH
    assert verdict is Verdict.WARN


def test_mutation_score_rate_is_warn_even_armed():
    sev, verdict = policy.classify("mutation-score", "rate", "low",
                                   Gate.PRE_PUSH, _msc_cfg(armed=True))
    assert sev is Severity.LOW
    assert verdict is Verdict.WARN
```

Append to `tests/unit/test_mutation_score_gate.py`, and add `from aramid import policy` to that file's imports:

```python
def test_twin_rule_seam_and_classify_agree(tmp_path):
    """The seam's inline verdict and policy.classify's tool=="mutation-score"
    branch encode the SAME rule (the 1b dual-rule discipline). Red-first:
    fails while classify lacks the branch (it falls through to the default
    WARN while the armed seam says BLOCK)."""
    for armed in (True, False):
        cfg = SimpleNamespace(
            block_rules={},
            mutation={"enabled": True, "score_block_armed": armed})
        led = _transition_ledger(tmp_path / ("armed" if armed else "baking"))
        try:
            got = mutation_score_gate.mutation_score_gate_findings(
                cfg, led, Gate.PRE_PUSH)
        finally:
            led.close()
        assert got, "fixture must yield findings for the twin comparison"
        for f in got:
            _sev, verdict = policy.classify(f.tool, f.rule, f.severity_raw,
                                            Gate.PRE_PUSH, cfg)
            assert f.verdict is verdict, (f.rule, armed)
```

- [ ] **Step 2: Run to verify the new tests fail**

Run: `python -m pytest tests/unit/test_policy.py tests/unit/test_mutation_score_gate.py -q`
Expected: `test_mutation_score_transition_armed_is_block` FAILS (classify falls through to default WARN) and `test_twin_rule_seam_and_classify_agree` FAILS on the armed transition (seam BLOCK vs classify WARN). The disarmed/rate tests pass (default WARN is coincidentally right — the armed cases are the red teeth).

- [ ] **Step 3: Add the classify branch**

In `src/aramid/policy.py`, insert directly AFTER the `tool == "mutation"` branch (after the line `return severity, Verdict.BLOCK if armed else Verdict.WARN` of that branch, before the `ruff_block = ...` line):

```python
    # Mutation-score gate (2b): DERIVED regression findings materialized at
    # PRE_PUSH by mutation_score_gate -- zero persistence, never stored, so
    # never subject to auto_resolve_mutation. Transitions BLOCK once the repo
    # opts in via [mutation].score_block_armed; rate-deltas are permanent
    # WARN. Same routing rationale as the tdd/mutation branches: through
    # classify so _has_genuine_block treats an armed transition BLOCK as
    # genuine and it survives the fresh-clone downgrade.
    # mutation_score_gate.mutation_score_gate_findings computes this SAME
    # rule inline; the two must agree (pinned by the twin-rule test).
    if tool == "mutation-score":
        armed = cfg.mutation.get("score_block_armed", False)
        if armed and rule == "transition":
            return severity, Verdict.BLOCK
        return severity, Verdict.WARN
```

- [ ] **Step 4: Run to verify all tests pass**

Run: `python -m pytest tests/unit/test_policy.py tests/unit/test_mutation_score_gate.py -q`
Expected: all pass (15 in the gate file, all policy tests green).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/policy.py tests/unit/test_policy.py tests/unit/test_mutation_score_gate.py
git commit -m "feat(policy): mutation-score classify branch + twin-rule test (2b Task 2)"
```

---

### Task 3: Pipeline wiring + end-to-end integration

**Files:**
- Modify: `src/aramid/pipeline.py` (import line 29; PRE_PUSH producer block, currently lines 330–332)
- Create: `tests/integration/test_mutation_score_gate_e2e.py`

**Interfaces:**
- Consumes: `mutation_score_gate.mutation_score_gate_findings(cfg, ledger, gate, changed_files)` (Task 1); the classify branch (Task 2); `cmd_check(root, gate, mode) -> int`.
- Produces: the wired gate — later tasks only add config/CLI surface.

- [ ] **Step 1: Write the failing e2e test**

Create `tests/integration/test_mutation_score_gate_e2e.py`:

```python
"""End-to-end (real git, real @{u}..HEAD range, real cmd_check): a seeded
transition regression in CONSUMER_RUN_FINISHED history warns while baking,
blocks when [mutation].score_block_armed, is EPHEMERALLY suppressed when the
pushed range adds the mapped test, is NOT suppressed under mode "all", and
survives a fresh-ledger baseline (the classify branch makes
_has_genuine_block see the armed BLOCK as genuine). Mirrors
test_mutation_gate_e2e.py: GATE_RUNNER_KEYS emptied so the exit code
reflects only the gate producers, never a stray lint/tests-failed BLOCK."""
import subprocess

from aramid import pipeline
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Gate

NOW = "2026-07-24T12:00:00+00:00"
FP = "deadbeef"


def _no_runners(monkeypatch):
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})


def _run(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


def _repo_with_upstream(tmp_path):
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    r = tmp_path / "repo"
    r.mkdir()
    _run(r, "init", "-q", "-b", "main")
    _run(r, "config", "user.email", "t@t")
    _run(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "src" / "widget.py").write_text("def add(a, b):\n    return a + b\n",
                                         encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "c1")
    _run(r, "remote", "add", "origin", str(remote))
    _run(r, "push", "-q", "-u", "origin", "main")
    return r


def _crf(idx, killed_s1, survived_s1, killed_fps, survivor_fps):
    return Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", NOW, payload={
        "consumer": "mutation", "item_id": "q",
        "mutation_scores": {"schema": 1, "targets": {"src/widget.py::add": {
            "generated": killed_s1 + survived_s1, "killed_s1": killed_s1,
            "survived_s1": survived_s1, "timeouts": 0, "errors": 0,
            "fully_mutated": True, "killed_fps": list(killed_fps),
            "survivor_fps": list(survivor_fps)}}}})


def _seed_transition(r):
    """Baseline kills FP; current run confirms FP as a survivor."""
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.append(_crf(0, 2, 0, [FP, "other"], []))
        led.append(_crf(1, 1, 1, ["other"], [FP]))
    finally:
        led.close()


def _arm_score(r):
    (r / "aramid.toml").write_text(
        "schema_version = 1\n\n[mutation]\nscore_block_armed = true\n",
        encoding="utf-8")


def _commit_unrelated(r):
    (r / "src" / "other.py").write_text("y = 2\n", encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "unrelated change")


def _commit_mapped_test(r):
    (r / "tests").mkdir(exist_ok=True)
    (r / "tests" / "test_widget.py").write_text(
        "from src.widget import add\n\n\ndef test_add():\n"
        "    assert add(1, 2) == 3\n",
        encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "add widget test")


def test_e2e_baking_warns_armed_blocks_mapped_test_suppresses(tmp_path,
                                                              monkeypatch):
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _seed_transition(r)
    _commit_unrelated(r)          # something in @{u}..HEAD, no mapped test

    # Baking: the transition WARNs, never blocks.
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1

    # Armed: the transition blocks.
    _arm_score(r)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1

    # Mapped test in the pushed range -> ephemeral suppression, no block.
    _commit_mapped_test(r)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1


def test_e2e_mode_all_never_suppresses(tmp_path, monkeypatch):
    """Under mode "all" the pipeline passes changed_files=None -- the mapped
    test sitting in the tree must NOT suppress (only a range push does)."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _seed_transition(r)
    _arm_score(r)
    _commit_mapped_test(r)        # mapped test exists and is in the range

    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1                # range mode: suppressed

    rc = cmd_check(r, Gate.PRE_PUSH, "all")
    assert rc == 1                # all mode: no suppression -> blocks


def test_e2e_armed_block_survives_fresh_baseline(tmp_path, monkeypatch):
    """A fresh ledger (no baseline snapshot) with an armed transition still
    blocks -- the fresh-clone downgrade does NOT fire because
    _has_genuine_block sees the armed mutation-score BLOCK as genuine via
    the classify branch."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm_score(r)
    _seed_transition(r)
    _commit_unrelated(r)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1
```

- [ ] **Step 2: Run to verify the e2e tests fail**

Run: `python -m pytest tests/integration/test_mutation_score_gate_e2e.py -q`
Expected: FAIL — the armed assertions get `rc != 1` because nothing wires the seam into `run_gate` yet (the baking assertions pass vacuously; the armed `rc == 1` asserts are the red teeth).

- [ ] **Step 3: Wire the producer into the pipeline**

In `src/aramid/pipeline.py`:

(a) extend the import on line 29:

```python
from aramid import gitutil, mutation_gate, mutation_score_gate, policy, redact, tdd
```

(b) replace the PRE_PUSH producer append (currently):

```python
        findings = [*findings,
                    *review_mod.llm_gate_findings(cfg, ledger, gate),
                    *mutation_gate.mutation_gate_findings(cfg, ledger, gate)]
```

with:

```python
        findings = [*findings,
                    *review_mod.llm_gate_findings(cfg, ledger, gate),
                    *mutation_gate.mutation_gate_findings(cfg, ledger, gate),
                    # 2b: derived mutation-score regressions. changed_files
                    # only under mode "range" (same rationale as the
                    # auto_resolve guard above): under "all"/"staged",
                    # scope_files is the whole tree / staged set, and
                    # test-mapped suppression against that would suppress
                    # everything. Ephemeral only -- no ledger write.
                    *mutation_score_gate.mutation_score_gate_findings(
                        cfg, ledger, gate,
                        scope_files if mode == "range" else None)]
```

- [ ] **Step 4: Run to verify e2e + neighbors pass**

Run: `python -m pytest tests/integration/test_mutation_score_gate_e2e.py tests/integration/test_mutation_gate_e2e.py tests/unit/test_pipeline.py -q`
Expected: all pass (new e2e green; 1b e2e and pipeline unit tests unchanged-green).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/pipeline.py tests/integration/test_mutation_score_gate_e2e.py
git commit -m "feat(pipeline): wire mutation-score gate producer at pre-push (2b Task 3)"
```

---

### Task 4: `aramid arm --mutation-score` + CLI wiring

**Files:**
- Modify: `src/aramid/commands/arm.py`
- Modify: `src/aramid/cli.py` (arm subparser, currently lines 114–119; dispatch, currently lines 221–223)
- Create: `tests/unit/test_arm_mutation_score.py`
- Modify: `tests/integration/test_cli_dispatch.py` (append)

**Interfaces:**
- Consumes: `_armed_sub(key_re, new_line, text, count=0)`, `_MUT_SECTION_RE`, and the existing `cmd_arm` structure in `arm.py`.
- Produces: `cmd_arm(root, llm=False, autolearn=False, tdd=False, mutation=False, mutation_score=False) -> int` and the `aramid arm --mutation-score` flag — Task 5's defaults/README reference them.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_arm_mutation_score.py`:

```python
"""arm --mutation-score (2b): ends the mutation-score bake by setting
score_block_armed = true INSIDE the [mutation] table -- mirrors the
section-scoped arm --mutation path and must never touch [js_mutation] or
the sibling mutation_block_armed key."""
import tomllib

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def test_arm_mutation_score_writes_into_mutation_section(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n\n[mutation]\nenabled = true\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, mutation_score=True) == 0

    text = toml.read_text(encoding="utf-8")
    assert "score_block_armed = true" in text
    assert text.index("[mutation]") < text.index("score_block_armed = true")
    cfg = config_mod.load_config(tmp_path)
    assert cfg.mutation["score_block_armed"] is True


def test_arm_mutation_score_appends_fresh_section_when_absent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, mutation_score=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["score_block_armed"] is True


def test_arm_mutation_score_idempotent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[mutation]\nscore_block_armed = false\n",
                    encoding="utf-8")

    cmd_arm(tmp_path, mutation_score=True)
    cmd_arm(tmp_path, mutation_score=True)

    text = toml.read_text(encoding="utf-8")
    assert text.count("score_block_armed") == 1
    assert "score_block_armed = true" in text
    tomllib.loads(text)                  # no duplicate-key corruption


def test_arm_mutation_score_preserves_inline_comment(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[mutation]\nscore_block_armed = false  # bake note\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, mutation_score=True) == 0

    got = toml.read_text(encoding="utf-8")
    assert "score_block_armed = true  # bake note" in got
    assert tomllib.loads(got)["mutation"]["score_block_armed"] is True


def test_arm_mutation_score_does_not_touch_js_mutation(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text(
        "[js_mutation]\nenabled = true\n\n[mutation]\nenabled = true\n",
        encoding="utf-8")

    assert cmd_arm(tmp_path, mutation_score=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["score_block_armed"] is True
    assert "score_block_armed" not in parsed["js_mutation"]


def test_arm_mutation_score_missing_toml_errors(tmp_path):
    assert cmd_arm(tmp_path, mutation_score=True) == 3


def test_cmd_arm_mutation_score_reports(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n",
                                          encoding="utf-8")

    assert cmd_arm(tmp_path, mutation_score=True) == 0

    out = capsys.readouterr().out
    assert "score_block_armed=true" in out
    assert "mutation-score bake ended" in out


def test_arm_mutation_and_score_keys_do_not_interfere(tmp_path):
    """The two [mutation] arming keys are independent: arming one never
    rewrites the other (the _MUT_KEY_RE / _SCORE_KEY_RE literals cannot
    cross-match)."""
    toml = tmp_path / "aramid.toml"
    toml.write_text("[mutation]\nmutation_block_armed = false\n"
                    "score_block_armed = false\n", encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["mutation_block_armed"] is True
    assert parsed["mutation"]["score_block_armed"] is False

    assert cmd_arm(tmp_path, mutation_score=True) == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["mutation_block_armed"] is True
    assert parsed["mutation"]["score_block_armed"] is True
```

Append to `tests/integration/test_cli_dispatch.py` (after the existing `test_arm_dispatch_mutation_and_llm_mutually_exclusive`, following that file's exact monkeypatch pattern):

```python
def test_arm_dispatch_with_mutation_score_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False,
                        mutation=False, mutation_score=False:
                        captured.update(llm=llm, autolearn=autolearn,
                                        tdd=tdd, mutation=mutation,
                                        mutation_score=mutation_score) or 0)

    assert cli.main(["arm", "--mutation-score"]) == 0
    assert captured["mutation_score"] is True
    assert captured["mutation"] is False
    assert captured["llm"] is False
    assert captured["autolearn"] is False
    assert captured["tdd"] is False


def test_arm_dispatch_mutation_score_and_mutation_mutually_exclusive():
    rc = subprocess.run([sys.executable, "-m", "aramid", "arm",
                         "--mutation-score", "--mutation"],
                        capture_output=True, text=True)
    assert rc.returncode == 3
```

- [ ] **Step 2: Run to verify the new tests fail**

Run: `python -m pytest tests/unit/test_arm_mutation_score.py "tests/integration/test_cli_dispatch.py::test_arm_dispatch_with_mutation_score_flag" "tests/integration/test_cli_dispatch.py::test_arm_dispatch_mutation_score_and_mutation_mutually_exclusive" -q`
Expected: FAIL — `cmd_arm() got an unexpected keyword argument 'mutation_score'` and the CLI rejects the unknown `--mutation-score` flag.

- [ ] **Step 3: Implement arm + CLI**

In `src/aramid/commands/arm.py`:

(a) after the `_MUT_SECTION_RE` definition, add:

```python
_SCORE_KEY_RE = re.compile(
    r"(?m)^score_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
```

(b) after `_arm_mutation_text`, add:

```python
def _arm_mutation_score_text(text: str) -> str:
    """Comment-preserving single-key rewrite into the [mutation] table
    (mirrors _arm_mutation_text): key exists -> substitute; [mutation]
    section exists -> insert the key under the header; neither -> append a
    fresh [mutation] section. score_block_armed is a globally unique key
    name, so no section scoping is needed; _MUT_KEY_RE (literal
    mutation_block_armed) can never match it and vice versa."""
    if _SCORE_KEY_RE.search(text):
        return _armed_sub(_SCORE_KEY_RE, "score_block_armed = true", text)
    m = _MUT_SECTION_RE.search(text)
    if m:
        insert_at = m.end()
        return text[:insert_at] + "\nscore_block_armed = true" + text[insert_at:]
    prefix = "" if not text or text.endswith("\n") else "\n"
    return text + prefix + "[mutation]\nscore_block_armed = true\n"
```

(c) change the `cmd_arm` signature to:

```python
def cmd_arm(root, llm: bool = False, autolearn: bool = False, tdd: bool = False,
            mutation: bool = False, mutation_score: bool = False) -> int:
```

(d) after the `if mutation:` block (after its `return 0`), add:

```python
    if mutation_score:
        toml_path.write_text(_arm_mutation_score_text(text), encoding="utf-8")
        print(f"aramid: arm: score_block_armed=true written to {toml_path}")
        print("aramid: arm: mutation-score bake ended -- transition "
              "regressions now BLOCK at pre-push.")
        return 0
```

In `src/aramid/cli.py`:

(e) replace the arm subparser help string and flag group (currently lines 114–119) with:

```python
    p_arm = sub.add_parser("arm", help="end a WARN-only bake (semgrep default, --llm for the LLM reviewer, --autolearn for learned uplift, --tdd for code-without-test findings, --mutation for surviving-mutant findings, --mutation-score for score-regression transitions)")
    arm_which = p_arm.add_mutually_exclusive_group()
    arm_which.add_argument("--llm", action="store_true")
    arm_which.add_argument("--autolearn", action="store_true")
    arm_which.add_argument("--tdd", action="store_true")
    arm_which.add_argument("--mutation", action="store_true")
    arm_which.add_argument("--mutation-score", action="store_true")
```

(f) replace the arm dispatch (currently lines 221–223) with:

```python
    if args.command == "arm":
        return cmd_arm(root, llm=args.llm, autolearn=args.autolearn,
                       tdd=args.tdd, mutation=args.mutation,
                       mutation_score=args.mutation_score)
```

- [ ] **Step 4: Run to verify all pass, including neighbors**

Run: `python -m pytest tests/unit/test_arm_mutation_score.py tests/unit/test_arm_mutation.py tests/unit/test_arm_llm.py tests/integration/test_cli_dispatch.py -q`
Expected: all pass (new 8 + 2 dispatch; every pre-existing arm/dispatch test untouched-green).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/arm.py src/aramid/cli.py tests/unit/test_arm_mutation_score.py tests/integration/test_cli_dispatch.py
git commit -m "feat(cli): aramid arm --mutation-score ends the score bake (2b Task 4)"
```

---

### Task 5: Config default + armed-state line in the advisory command

**Files:**
- Modify: `src/aramid/data/defaults.toml` (the `[mutation]` table, currently lines 123–129)
- Modify: `src/aramid/commands/mutation_score.py`
- Modify: `tests/integration/test_mutation_score_cmd.py` (append)

**Interfaces:**
- Consumes: `config_mod.load_config(root)` (returns a Config whose `.mutation` is a dict); the existing `cmd_mutation_score(root, *, as_json=False) -> int`.
- Produces: `[mutation].score_block_armed = false` shipped default; the text report's armed-state line. JSON output is deliberately unchanged (spec §6: one added header line, text only).

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_mutation_score_cmd.py`, and add this import at the top of the file:

```python
from aramid import config as config_mod
```

```python
def test_cmd_text_shows_baking_state(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 3, 0, True)
    led.close()
    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "transition regressions: WARN (baking)" in out


def test_cmd_text_shows_armed_state(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    (tmp_path / "aramid.toml").write_text(
        "schema_version = 1\n\n[mutation]\nscore_block_armed = true\n",
        encoding="utf-8")
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 3, 0, True)
    led.close()
    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "transition regressions: BLOCK (armed)" in out


def test_cmd_empty_history_still_shows_arm_state(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "no mutation scores recorded" in out
    assert "transition regressions: WARN (baking)" in out


def test_cmd_json_output_shape_unchanged(tmp_path, capsys):
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 3, 0, True)
    led.close()
    rc = cmd_mutation_score(tmp_path, as_json=True)
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert set(doc) == {"targets", "regressions"}   # no armed key added
```

- [ ] **Step 2: Run to verify the new tests fail**

Run: `python -m pytest tests/integration/test_mutation_score_cmd.py -q`
Expected: the three new text tests FAIL (no armed-state line printed yet); `test_cmd_json_output_shape_unchanged` and all pre-existing tests pass.

- [ ] **Step 3: Implement config default + command line**

(a) In `src/aramid/data/defaults.toml`, in the `[mutation]` table directly under the `mutation_block_armed = false` line, add:

```toml
score_block_armed = false      # NEW (2b) -- arms mutation-score transition regressions; see policy.classify
```

(b) In `src/aramid/commands/mutation_score.py`, add the import:

```python
from aramid import config as config_mod
```

and inside `cmd_mutation_score`'s main `try:` block, replace the section from `if not latest:` through `lines = ["aramid mutation-score:"]` so the text paths both carry the armed-state line (JSON branch stays byte-identical above this):

```python
        armed = bool(config_mod.load_config(root)
                     .mutation.get("score_block_armed", False))
        arm_line = ("  transition regressions: BLOCK (armed)" if armed
                    else "  transition regressions: WARN (baking)")
        if not latest:
            print("aramid mutation-score: no mutation scores recorded")
            print(arm_line)
            return 0
        lines = ["aramid mutation-score:", arm_line]
```

(The `load_config` call sits inside the existing `try`, so a corrupt `aramid.toml` lands in the engine-error tier — exit 3 — consistent with the command's contract. Note the JSON branch `return 0` happens before this code, so `--json` never pays the config read.)

- [ ] **Step 4: Run to verify all pass**

Run: `python -m pytest tests/integration/test_mutation_score_cmd.py tests/unit/test_config.py -q`
Expected: all pass (the config tests guard that the defaults.toml addition parses and merges cleanly).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/data/defaults.toml src/aramid/commands/mutation_score.py tests/integration/test_mutation_score_cmd.py
git commit -m "feat(mutation-score): score_block_armed default + armed-state report line (2b Task 5)"
```

---

### Task 6: README limitations + ruff + full-suite handoff

**Files:**
- Modify: `README.md` (the mutation-score advisory subsection added in 2a Task 6)

**Interfaces:**
- Consumes: everything shipped in Tasks 1–5.
- Produces: user-facing docs; the controller's full-suite verdict gates the branch.

- [ ] **Step 1: Extend the README**

Locate the `aramid mutation-score` advisory subsection in `README.md` (added by 2a Task 6 — search for "mutation-score"). Append this content at the end of that subsection (adjust the heading level to match the section it sits in — one level deeper than the subsection heading):

```markdown
#### 2b: regression teeth at pre-push

Every `pre-push` gate recomputes the regressions above straight from drain
history — nothing is stored, so no stale record can be wrongly resolved and
only a re-drain that re-measures the function truly clears a regression.

- **Transition regressions** (a previously-killed mutant now survives) are
  findings under tool `mutation-score`, rule `transition`, severity high.
  They WARN during the bake and BLOCK once the repo opts in with
  `aramid arm --mutation-score` (sets `[mutation].score_block_armed = true`).
- **Rate regressions** (stage-1 kill-rate dropped between fully-measured
  runs) are permanent WARN, rule `rate`, severity low. They never block.
- **The only escape valve is ephemeral:** a push whose range adds or
  modifies the module-mapped test (`test_<module>.py` / `<module>_test.py`)
  suppresses the transition for that gate run only. Touching the source
  file does not suppress — that is exactly the optimistic-resolution hole
  the surviving-mutant gate has and this gate closes.

Additional limitations beyond the advisory ones above:

1. Two same-operator mutants on one identical line share a fingerprint, so
   an armed transition may conflate them (the killing test for one kills
   the class).
2. Regression findings are derived per-gate and never persisted: they do
   not appear in `aramid status` and cannot be overridden via
   `aramid override` — the escape hatches are the mapped test or disarming.
3. A function rewritten without its mapped test keeps blocking on the old
   measurement until a re-drain re-measures it. Because a disabled engine
   could then never clear it, `[mutation].enabled = false` disables this
   gate entirely; use `score_block_armed = false` to drop only the teeth.
```

- [ ] **Step 2: Ruff over every file the branch touched**

Run: `python -m ruff check src/aramid/mutation_score_gate.py src/aramid/policy.py src/aramid/pipeline.py src/aramid/commands/arm.py src/aramid/cli.py src/aramid/commands/mutation_score.py tests/unit/test_mutation_score_gate.py tests/unit/test_arm_mutation_score.py tests/integration/test_mutation_score_gate_e2e.py`
Expected: clean (pre-existing violations in files you did not create may be left, but note them).

- [ ] **Step 3: Commit the docs**

```bash
git add README.md
git commit -m "docs: mutation-score regression teeth + 2b limitations (2b Task 6)"
```

- [ ] **Step 4: Full suite — CONTROLLER ONLY**

The task subagent STOPS here and reports back. The controller runs the full suite in the background (`python -m pytest -q`, ~10–13 min, 962+ tests expected) and verifies 0 failures before the whole-branch review. A subagent must never run this — it exceeds the foreground tool timeout and reads as a hang.

---

## Self-Review (performed at authoring, 2026-07-24)

- **Spec coverage:** §3 seam → T1; §4 suppression → T1 (unit) + T3 (mode guard e2e); §5 finding shape → T1; §6 file list → T1–T5 exactly, no extra files; §7 classify twin → T2; §8 flow → T3; §9 fail-open (incl. enabled=false) → T1; §10 limitations → module docstring (T1) + README (T6); §11 tests → T1–T5 map 1:1, full suite → T6/controller; §12 → architecture (no task needed); §13 non-goals — no task violates them.
- **Type consistency:** `mutation_score_gate_findings(cfg, ledger, gate, changed_files=None)` identical in T1 (def), T2 (twin test), T3 (pipeline call). `cmd_arm(..., mutation_score=False)` identical in T4 impl, T4 dispatch lambda. Severity/raw pairs consistent T1↔T2 tests.
- **Known intentional deviations:** none. `Regression.baseline_index`/`current_index` are unused by the seam (display uses message text only) — deliberate, matches spec §5 finding shape.
