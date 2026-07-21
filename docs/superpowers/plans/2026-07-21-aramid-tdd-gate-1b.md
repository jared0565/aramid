# Aramid TDD-Enforcement Gate — Sub-project 1b (Mutation Gate Teeth + Resolution) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the drain's existing surviving-mutant findings *teeth* at the pre-push gate — an arm-able BLOCK plus the gate-side resolution that makes armed teeth safe — mirroring the LLM reviewer gate.

**Architecture:** A new `src/aramid/mutation_gate.py` holds two pure, never-raises pre-push functions: `mutation_gate_findings` (materialize still-open `tool=="mutation"` ledger findings into the gate; verdict computed inline from `[mutation].mutation_block_armed`) and `auto_resolve_mutation` (module-mapped optimistic resolution, run before the block check). A `policy.classify` `tool=="mutation"` branch encodes the identical armed→BLOCK rule so `_has_genuine_block` treats an armed BLOCK as genuine on a fresh clone with no `check.py` change. Wired into `run_gate` beside the LLM twins, after the ratchet.

**Tech Stack:** Python 3.12+, stdlib `re`/`pathlib`, pytest, ruff. Reuses `aramid.ledger`, `aramid.models`, `aramid.gitutil.is_test_file`, `aramid.fingerprint.normalize_path`.

## Global Constraints

Copied verbatim from the spec (`docs/superpowers/specs/2026-07-21-aramid-tdd-gate-1b-mutation-teeth-design.md`). Every task's requirements implicitly include these:

- **Pre-push only.** Both new gate functions return `[]` / do nothing for any gate other than `Gate.PRE_PUSH`. Never runs at pre-commit or `--all`-gate-`pre-commit`.
- **Fail-open, never raises.** `mutation_gate_findings` and `auto_resolve_mutation` must never raise into `run_gate`; an outer per-record `try/except` skips a malformed rec (leaving it `open` for manual triage) and any unexpected error contributes nothing. A broken seam must never block a push or crash the gate.
- **Verdict rule (one line, stated twice, must agree):** armed (`cfg.mutation.get("mutation_block_armed", False)` is `True`) → `Verdict.BLOCK`; else `Verdict.WARN`. Encoded in **both** `mutation_gate_findings` (inline) and `policy.classify`'s `tool=="mutation"` branch. The seam computes it inline (mirroring `review.llm_gate_findings`), NOT by calling `classify`.
- **Disarmed never blocks.** A disarmed mutation finding is WARN, surfaced at pre-push, and ratchet-exempt — achieved structurally by appending the surfaced findings **after** the pre-push ratchet in `run_gate` (exactly like the LLM gate). No explicit ratchet-exemption list entry.
- **Survives fresh-clone by construction.** An armed mutation BLOCK returns BLOCK from `classify`, so `check._has_genuine_block` sees it as genuine — **no `check.py` change, no new `Source` enum member.** The materialized finding keeps `Source.DETERMINISTIC`.
- **Only surface `tool=="mutation"`, `status=="open"` records.** Ignore every other tool/status (resolved, overridden, historical, rotated).
- **Module-mapped resolution predicate:** resolve an open mutation finding on source path `p` (module stem `m = Path(p).stem`) iff, over the push's changed files `C` (compared with `fingerprint.normalize_path`): `normalize_path(p) ∈ C`, **or** some `c ∈ C` is a test file (`gitutil.is_test_file(c)`) whose basename stem is `test_<m>` or `<m>_test`. Resolution runs **before** the block check.
- **No `config.py` change.** `mutation_block_armed` lives inside the `[mutation]` table already surfaced as `cfg.mutation` (config.py:44,111); `cfg.mutation.get("mutation_block_armed", False)` reads it and defaults `False` when absent.
- **No change to** `check.py`, ledger schema, the `Source` enum, or `consumers/mutation.py`.
- **`arm --mutation` is section-scoped** into `[mutation]` (mirrors `_arm_llm_text`), NOT root-scoped like `_arm_tdd`. Must never touch the `[js_mutation]` table.
- **Green bar:** `python -m pytest` passes; `python -m ruff check` stays at or below the baseline (**43**).

---

## File Structure

- **Create** `src/aramid/mutation_gate.py` — the two pre-push functions (`mutation_gate_findings`, `auto_resolve_mutation`) + the `_module_tests` helper. One clear responsibility: the mutation twin of `review.py`'s zero-token pre-push helpers.
- **Modify** `src/aramid/policy.py` — one additive `tool=="mutation"` branch in `classify`.
- **Modify** `src/aramid/pipeline.py` — import `mutation_gate`; call `auto_resolve_mutation` + append `mutation_gate_findings` in the existing PRE_PUSH block.
- **Modify** `src/aramid/data/defaults.toml` — add `mutation_block_armed = false` to `[mutation]`.
- **Modify** `src/aramid/commands/arm.py` + `src/aramid/cli.py` — add `--mutation`.
- **Create** `tests/unit/test_mutation_gate.py` — seam + resolution unit tests (Tasks 2, 3).
- **Create** `tests/unit/test_mutation_genuine.py` — `_has_genuine_block` fresh-clone unit tests (Task 1).
- **Create** `tests/unit/test_arm_mutation.py` — `arm --mutation` unit tests (Task 5).
- **Create** `tests/integration/test_mutation_gate_e2e.py` — real-git end-to-end (Task 6).
- **Modify** `tests/unit/test_policy.py`, `tests/unit/test_pipeline.py`, `tests/integration/test_cli_dispatch.py` — additive tests (Tasks 1, 4, 5).

---

### Task 1: Config default + `classify` mutation branch + fresh-clone genuineness

**Files:**
- Modify: `src/aramid/data/defaults.toml` (add key to `[mutation]`)
- Modify: `src/aramid/policy.py` (add branch after the `tdd` branch, ~policy.py:104)
- Test: `tests/unit/test_policy.py` (append), `tests/unit/test_mutation_genuine.py` (create)

**Interfaces:**
- Consumes: `policy.classify(tool, rule, severity_raw, gate, cfg) -> tuple[Severity, Verdict]`; `cfg.mutation` (a dict); `check._has_genuine_block(result, cfg) -> bool`.
- Produces: an armed `tool=="mutation"` finding classifies to `Verdict.BLOCK`; disarmed to `Verdict.WARN`. This is the verdict authority `_has_genuine_block` reads.

- [ ] **Step 1: Write the failing classify tests**

Append to `tests/unit/test_policy.py` (the file already imports `policy`, `SimpleNamespace`, `Gate`, `Severity`, `Verdict`):

```python
# --- classify: mutation (sub-project 1b) ------------------------------------

def _mut_cfg(armed: bool):
    # classify reads cfg.block_rules early, then the tool branch; a minimal
    # namespace with the attributes classify touches is enough.
    return SimpleNamespace(block_rules={}, mutation={"mutation_block_armed": armed})


def test_mutation_disarmed_is_warn():
    sev, verdict = policy.classify("mutation", "flip_comparison", "medium",
                                   Gate.PRE_PUSH, _mut_cfg(armed=False))
    assert sev is Severity.MEDIUM
    assert verdict is Verdict.WARN


def test_mutation_armed_is_block():
    sev, verdict = policy.classify("mutation", "flip_comparison", "medium",
                                   Gate.PRE_PUSH, _mut_cfg(armed=True))
    assert sev is Severity.MEDIUM       # assert severity in BOTH (1a T2a lesson)
    assert verdict is Verdict.BLOCK
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_policy.py -k mutation -v`
Expected: FAIL — `test_mutation_armed_is_block` gets `Verdict.WARN` (no mutation branch yet, falls through to the default WARN).

- [ ] **Step 3: Add the classify branch**

In `src/aramid/policy.py`, immediately after the `tdd` branch (the block ending `return severity, Verdict.BLOCK if armed else Verdict.WARN` at ~policy.py:103), insert:

```python
    # Mutation gate (1b): the drain's surviving-mutant findings. WARN during
    # the bake; BLOCK once the repo opts in via [mutation].mutation_block_armed.
    # Same shape as the tdd branch -- routing the verdict through classify (not
    # only the gate seam) makes _has_genuine_block treat an armed mutation BLOCK
    # as genuine with no check.py change, so it survives the fresh-clone
    # downgrade. mutation_gate.mutation_gate_findings computes this SAME rule
    # inline (mirroring llm_gate_findings); the two must agree.
    if tool == "mutation":
        armed = cfg.mutation.get("mutation_block_armed", False)
        return severity, Verdict.BLOCK if armed else Verdict.WARN
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_policy.py -k mutation -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Add the default config key**

In `src/aramid/data/defaults.toml`, in the `[mutation]` table (after `confirm_cap = 3`), add:

```toml
mutation_block_armed = false   # NEW (1b) -- arms surviving-mutant findings; see policy.classify
```

- [ ] **Step 6: Write the failing fresh-clone genuineness tests**

Create `tests/unit/test_mutation_genuine.py`:

```python
"""_has_genuine_block must treat an armed mutation BLOCK as genuine (so it
survives check.py's fresh-clone downgrade) and must NOT treat it as genuine
when the repo is disarmed -- genuineness is re-derived from cfg via
policy.classify, never from the stored verdict alone (the fresh-clone safety).
"""
from dataclasses import replace
from types import SimpleNamespace

from aramid.commands import check
from aramid.models import Finding, Gate, Severity, Source, Verdict


def _mut_block():
    return Finding(id="m" * 64, tool="mutation", rule="flip_comparison",
                   severity_raw="medium", severity=Severity.MEDIUM,
                   verdict=Verdict.BLOCK, file="src/pkg/x.py", line=42,
                   message="mutant survived: flip_comparison", evidence="",
                   gate=Gate.PRE_PUSH, source=Source.DETERMINISTIC)


def test_armed_mutation_block_is_genuine():
    cfg = SimpleNamespace(block_rules={}, mutation={"mutation_block_armed": True})
    result = SimpleNamespace(findings=[_mut_block()], degraded_block_tier=False)
    assert check._has_genuine_block(result, cfg) is True


def test_mutation_block_not_genuine_when_disarmed():
    # A stored BLOCK verdict is re-derived from cfg: not armed -> classify WARN
    # -> not genuine -> would be downgraded on a fresh clone. This is what
    # prevents a stale/forged BLOCK from surviving when the repo is not armed.
    cfg = SimpleNamespace(block_rules={}, mutation={"mutation_block_armed": False})
    result = SimpleNamespace(findings=[_mut_block()], degraded_block_tier=False)
    assert check._has_genuine_block(result, cfg) is False
```

- [ ] **Step 7: Run the genuineness tests to verify they pass**

Run: `python -m pytest tests/unit/test_mutation_genuine.py -v`
Expected: PASS (2 passed). (These pass because Step 3's classify branch is what `_has_genuine_block` calls. If you revert Step 3, `test_armed_mutation_block_is_genuine` fails — confirming the branch is load-bearing.)

- [ ] **Step 8: Commit**

```bash
git add src/aramid/policy.py src/aramid/data/defaults.toml tests/unit/test_policy.py tests/unit/test_mutation_genuine.py
git commit -m "feat(mutation-gate): classify tool==mutation via [mutation].mutation_block_armed"
```

---

### Task 2: `mutation_gate_findings` — surface open mutation findings at pre-push

**Files:**
- Create: `src/aramid/mutation_gate.py`
- Test: `tests/unit/test_mutation_gate.py` (create)

**Interfaces:**
- Consumes: `ledger.open_findings() -> dict[str, dict]` (each rec has `tool`, `status`, `severity`, `rule`, `file`, `line`, `message`, `evidence`); `cfg.mutation` (dict); `Gate`, `Finding`, `Severity`, `Source`, `Verdict`.
- Produces: `mutation_gate.mutation_gate_findings(cfg, ledger, gate: Gate) -> list[Finding]` — the seam `run_gate` appends at pre-push (Task 4). Module constant `TOOL = "mutation"`.

- [ ] **Step 1: Write the failing seam tests**

Create `tests/unit/test_mutation_gate.py`:

```python
from types import SimpleNamespace

from aramid import mutation_gate
from aramid.ledger import Ledger
from aramid.models import (Event, EventType, Finding, Gate, Severity, Source,
                           Verdict)

NOW = "2026-07-21T12:00:00+00:00"


def _mut_finding(fid="m" * 64, file="src/pkg/x.py", line=42, op="flip_comparison"):
    return Finding(id=fid, tool="mutation", rule=op, severity_raw="medium",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file,
                   line=line, message=f"mutant survived: {op}", evidence="",
                   gate=Gate.ALL, source=Source.DETERMINISTIC)


def _seed(led, finding):
    led.record_run("r0", NOW, "drain", set(), set(), [finding])


def _seed_raw(led, fid, payload):
    led.append(Event(EventType.FINDING_DETECTED, "r0", NOW,
                     finding_id=fid, payload=payload))


def _cfg(armed):
    return SimpleNamespace(mutation={"mutation_block_armed": armed})


def test_gate_blocks_open_mutation_when_armed(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        got = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert len(got) == 1
    assert got[0].verdict is Verdict.BLOCK
    assert got[0].tool == "mutation"
    assert got[0].source is Source.DETERMINISTIC
    assert got[0].file == "src/pkg/x.py"
    assert got[0].line == 42


def test_gate_warns_while_baking(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        got = mutation_gate.mutation_gate_findings(_cfg(False), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert [f.verdict for f in got] == [Verdict.WARN]


def test_gate_empty_outside_pre_push(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        assert mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_COMMIT) == []
        assert mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.ALL) == []
    finally:
        led.close()


def test_gate_ignores_non_mutation(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        other = Finding(id="s" * 64, tool="semgrep", rule="x", severity_raw="ERROR",
                        severity=Severity.HIGH, verdict=Verdict.WARN, file="a.py",
                        line=1, message="m", evidence="e", gate=Gate.ALL)
        _seed(led, other)
        got = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert [f.tool for f in got] == ["mutation"]


def test_gate_skips_resolved_and_overridden(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding(fid="a" * 64))
        led.append(Event(EventType.FINDING_RESOLVED, "r1", NOW, finding_id="a" * 64))
        _seed(led, _mut_finding(fid="b" * 64))
        led.append(Event(EventType.FINDING_OVERRIDDEN, "r1", NOW,
                         finding_id="b" * 64, payload={"reason": "accepted"}))
        got = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert got == []


def test_gate_skips_malformed_rec_but_surfaces_wellformed(tmp_path):
    """A rec with line stored as null (int(None) -> TypeError) is SKIPPED, not
    crashed; a well-formed rec alongside it still surfaces."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed_raw(led, "d" * 64, {"tool": "mutation", "file": "src/pkg/y.py",
                                  "line": None, "severity": "medium",
                                  "rule": "flip", "message": "m"})
        _seed(led, _mut_finding())
        got = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert [f.id for f in got] == ["m" * 64]
    assert got[0].verdict is Verdict.BLOCK
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_mutation_gate.py -v`
Expected: FAIL at import — `ModuleNotFoundError: No module named 'aramid.mutation_gate'`.

- [ ] **Step 3: Create the module with `mutation_gate_findings`**

Create `src/aramid/mutation_gate.py`:

```python
"""mutation_gate -- the zero-token pre-push seam for the drain's surviving-
mutant findings (sub-project 1b). consumers/mutation.py writes stage-2
full-suite-CONFIRMED survivors to the ledger, but nothing surfaces them at the
gate (only LLM findings are, via review.llm_gate_findings). This module is
their twin: materialize still-open mutation findings at pre-push
(mutation_gate_findings) and optimistically resolve them when the push
addresses the gap (auto_resolve_mutation), mirroring review's llm helpers.

Both functions are pure ledger/git-fact computation and NEVER raise into
run_gate (fail-open: a broken seam must never block a push or crash the gate).
The verdict is computed inline from [mutation].mutation_block_armed -- the SAME
rule policy.classify's tool=="mutation" branch encodes (which is what makes
_has_genuine_block treat an armed mutation BLOCK as genuine on a fresh clone);
the two one-line rules must agree.
"""
from aramid.models import Finding, Gate, Severity, Source, Verdict

TOOL = "mutation"


def mutation_gate_findings(cfg, ledger, gate: Gate) -> list[Finding]:
    """Materialize still-open mutation findings as gate findings (spec 1b).
    PRE_PUSH only. Verdict computed HERE from [mutation].mutation_block_armed
    -- never read from the stored record -- so arming applies retroactively:
    BLOCK when armed, WARN while baking."""
    if gate is not Gate.PRE_PUSH:
        return []
    armed = bool(cfg.mutation.get("mutation_block_armed", False))
    verdict = Verdict.BLOCK if armed else Verdict.WARN
    out = []
    for fid, rec in sorted(ledger.open_findings().items()):
        if rec.get("tool") != TOOL or rec.get("status") != "open":
            continue
        # Per-record guard (fail-safe): a MALFORMED rec (e.g. line stored as
        # null so int(rec.get("line", 0)) raises TypeError) is SKIPPED -- never
        # crash the gate. A skipped rec stays open, forcing manual triage, the
        # safe outcome for a block gate. Mirrors review.llm_gate_findings.
        try:
            try:
                severity = Severity(rec.get("severity", "medium"))
            except ValueError:
                severity = Severity.MEDIUM
            out.append(Finding(
                id=fid, tool=TOOL, rule=rec.get("rule", ""),
                severity_raw=rec.get("severity", ""), severity=severity,
                verdict=verdict, file=rec.get("file", ""),
                line=int(rec.get("line", 0)), message=rec.get("message", ""),
                evidence=rec.get("evidence", ""), gate=gate,
                source=Source.DETERMINISTIC))
        except Exception:
            continue
    return out
```

The import line is intentionally **only** what `mutation_gate_findings` uses, so Task 2 is independently ruff-clean (no unused-import F401). Task 3 extends the imports (adds `from pathlib import Path`, `from aramid import gitutil`, `from aramid.fingerprint import normalize_path`, and `Event, EventType` to the models import) when `auto_resolve_mutation` lands in the same file.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_mutation_gate.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Ruff check the new module**

Run: `python -m ruff check src/aramid/mutation_gate.py`
Expected: no new findings (no unused imports — Step 3 note).

- [ ] **Step 6: Commit**

```bash
git add src/aramid/mutation_gate.py tests/unit/test_mutation_gate.py
git commit -m "feat(mutation-gate): mutation_gate_findings surfaces open mutants at pre-push"
```

---

### Task 3: `auto_resolve_mutation` — module-mapped gate-side resolution

**Files:**
- Modify: `src/aramid/mutation_gate.py` (add `_module_tests` + `auto_resolve_mutation`; extend imports)
- Test: `tests/unit/test_mutation_gate.py` (append)

**Interfaces:**
- Consumes: `ledger.open_findings()`, `ledger.append(Event(...))`, `gitutil.is_test_file(rel) -> bool`, `normalize_path(path) -> str`, `Path(...).stem`.
- Produces: `mutation_gate.auto_resolve_mutation(ledger, run_id: str, at: str, changed_files) -> list[str]` — returns resolved finding ids; appends `FINDING_RESOLVED` events. Called by `run_gate` **before** the block check (Task 4).

- [ ] **Step 1: Write the failing resolution tests**

Append to `tests/unit/test_mutation_gate.py`:

```python
def test_resolve_when_source_touched(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())                      # on src/pkg/x.py
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"src/pkg/x.py"})
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == ["m" * 64]
    assert state["m" * 64]["status"] == "fixed"


def test_resolve_when_mapped_test_added(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())                      # module stem "x"
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"tests/test_x.py"})        # test_<module>.py
    finally:
        led.close()
    assert resolved == ["m" * 64]


def test_resolve_when_underscore_test_added(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"src/pkg/x_test.py"})      # <module>_test.py
    finally:
        led.close()
    assert resolved == ["m" * 64]


def test_no_resolve_for_unrelated_test(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())                      # module "x"
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"tests/test_y.py"})        # different module
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["m" * 64]["status"] == "open"


def test_no_resolve_for_unrelated_nontest(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"README.md", "src/pkg/other.py"})
    finally:
        led.close()
    assert resolved == []


def test_resolve_skips_malformed_rec_without_raising(tmp_path):
    """A rec with file stored as null must be SKIPPED -- stays open, never
    crashes."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed_raw(led, "d" * 64, {"tool": "mutation", "file": None,
                                  "line": 1, "severity": "medium"})
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"src/pkg/x.py"})
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["d" * 64]["status"] == "open"


def test_resolution_before_materialize_no_double_surface(tmp_path):
    """After auto_resolve_mutation fires, mutation_gate_findings must not
    re-surface the resolved finding (the run_gate ordering: resolve, then
    materialize)."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        mutation_gate.auto_resolve_mutation(led, "r1", NOW, {"tests/test_x.py"})
        got = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert got == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_mutation_gate.py -k resolve -v`
Expected: FAIL — `AttributeError: module 'aramid.mutation_gate' has no attribute 'auto_resolve_mutation'`.

- [ ] **Step 3: Extend the module imports and add the resolver**

In `src/aramid/mutation_gate.py`, change the import block at the top to:

```python
from pathlib import Path

from aramid import gitutil
from aramid.fingerprint import normalize_path
from aramid.models import Event, EventType, Finding, Gate, Severity, Source, Verdict
```

Then append below `mutation_gate_findings`:

```python
def _module_tests(module: str) -> set[str]:
    """Mapped-test basenames for a source module stem, per the
    consumers/mutation.py::_stage1_argv convention (test_<module>.py)."""
    return {f"test_{module}", f"{module}_test"}


def auto_resolve_mutation(ledger, run_id: str, at: str, changed_files) -> list[str]:
    """Optimistically resolve open mutation findings the push addresses, BEFORE
    the block check (mirrors review.auto_resolve_llm's call site), so a dev who
    added a test is not blocked by a stale finding. Module-mapped (spec 1b §4):
    resolve a finding on x.py iff the push changed x.py OR added/modified a test
    whose basename stem is test_<x>/<x>_test. Liberal by design -- a wrong
    resolve only lets a test-gap slip until the re-drain re-reports it (never a
    security hole); the async re-drain is the authoritative backstop. Two source
    files sharing a module stem are resolved together by one mapped test -- an
    accepted, low-stakes consequence of module-mapping."""
    changed_norm = {normalize_path(c) for c in changed_files}
    changed_test_stems = {Path(c).stem for c in changed_files
                          if gitutil.is_test_file(c)}
    resolved = []
    for fid, rec in ledger.open_findings().items():
        if rec.get("tool") != TOOL or rec.get("status") != "open":
            continue
        try:
            path = rec.get("file", "")
            if not path:
                continue                            # malformed: no file -> skip
            module = Path(path).stem
            source_touched = normalize_path(path) in changed_norm
            test_added = bool(_module_tests(module) & changed_test_stems)
            if source_touched or test_added:
                ledger.append(Event(EventType.FINDING_RESOLVED, run_id, at,
                                    finding_id=fid,
                                    payload={"auto_resolved": "gap_addressed"}))
                resolved.append(fid)
        except Exception:
            continue
    return resolved
```

- [ ] **Step 4: Run the resolution tests to verify they pass**

Run: `python -m pytest tests/unit/test_mutation_gate.py -v`
Expected: PASS (all — 6 seam + 7 resolution).

- [ ] **Step 5: Ruff check**

Run: `python -m ruff check src/aramid/mutation_gate.py`
Expected: no new findings (all imports now used).

- [ ] **Step 6: Commit**

```bash
git add src/aramid/mutation_gate.py tests/unit/test_mutation_gate.py
git commit -m "feat(mutation-gate): auto_resolve_mutation (module-mapped, gate-side)"
```

---

### Task 4: Wire both functions into `run_gate`

**Files:**
- Modify: `src/aramid/pipeline.py` (import + the PRE_PUSH block at pipeline.py:316-320)
- Test: `tests/unit/test_pipeline.py` (append)

**Interfaces:**
- Consumes: `mutation_gate.auto_resolve_mutation(ledger, run_id, at, scope_files)`, `mutation_gate.mutation_gate_findings(cfg, ledger, gate)`; the existing `scope_files = set(files)` (pipeline.py:303), `run_id`, `at`.
- Produces: at pre-push, `GateResult.findings` includes surfaced mutation findings (appended after the ratchet, so disarmed WARNs never escalate); open mutation findings whose gap the push addressed are resolved before the exit-code decision.

- [ ] **Step 1: Write the failing wiring tests**

Append to `tests/unit/test_pipeline.py`. (Mirror the no-runner harness `test_llm_gate.py::test_pipeline_pre_push_integration` uses: monkeypatch `pipeline.GATE_RUNNER_KEYS` so no subprocess runners select, seed a mutation finding via `record_run`, run `run_gate`. The seeded finding is on a path **not present** in the repo, so `auto_resolve_mutation` never resolves it — isolating the surfacing/verdict behavior from resolution.)

```python
import subprocess

from aramid import config as config_mod
from aramid.ledger import Ledger
from aramid.models import (Finding, Gate, Severity, Source, Verdict)

_MUT_NOW = "2026-07-21T12:00:00+00:00"


def _mut_repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=r, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=r, check=True)
    (r / "src").mkdir()
    (r / "src" / "real.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=r, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "c1"], cwd=r, check=True)
    return r


def _seed_mut(led, fid="g" * 64, file="src/pkg/ghost.py"):
    # ghost.py is NOT in the repo -> auto_resolve_mutation never resolves it.
    f = Finding(id=fid, tool="mutation", rule="flip_comparison",
                severity_raw="medium", severity=Severity.MEDIUM,
                verdict=Verdict.WARN, file=file, line=7,
                message="mutant survived: flip_comparison", evidence="",
                gate=Gate.ALL, source=Source.DETERMINISTIC)
    led.record_run("r0", _MUT_NOW, "drain", set(), set(), [f])


def test_pre_push_surfaces_mutation_finding(tmp_path, monkeypatch):
    from aramid import pipeline
    r = _mut_repo(tmp_path)
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        _seed_mut(led)
        got = pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led)
        assert got.exit_code == 0                       # disarmed WARN, ratchet-exempt
        assert any(f.tool == "mutation" and f.verdict is Verdict.WARN
                   for f in got.findings)

        cfg.mutation["mutation_block_armed"] = True
        got = pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led)
        assert got.exit_code == 1                       # armed -> BLOCK
        assert any(f.tool == "mutation" and f.verdict is Verdict.BLOCK
                   for f in got.findings)
    finally:
        led.close()


def test_mutation_findings_absent_at_pre_commit(tmp_path, monkeypatch):
    from aramid import pipeline
    r = _mut_repo(tmp_path)
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT: []})
    cfg = config_mod.load_config(r)
    cfg.mutation["mutation_block_armed"] = True
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        _seed_mut(led)
        got = pipeline.run_gate(r, Gate.PRE_COMMIT, "staged", cfg, led)
        assert not any(f.tool == "mutation" for f in got.findings)
    finally:
        led.close()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_pipeline.py -k "pre_push_surfaces_mutation or absent_at_pre_commit" -v`
Expected: FAIL — `test_pre_push_surfaces_mutation_finding` finds no `tool=="mutation"` finding (not wired yet).

- [ ] **Step 3: Add the import**

In `src/aramid/pipeline.py`, change line 29 from:

```python
from aramid import gitutil, policy, redact, tdd
```
to:
```python
from aramid import gitutil, mutation_gate, policy, redact, tdd
```

- [ ] **Step 4: Wire the calls into the PRE_PUSH block**

In `src/aramid/pipeline.py`, replace the existing block (pipeline.py:316-320):

```python
    # Phase 2b (spec section 5): the pre-push LLM ledger gate -- zero tokens,
    # a DB read. Auto-resolve runs FIRST so fixed findings never block.
    if gate is Gate.PRE_PUSH:
        review_mod.auto_resolve_llm(root, ledger, run_id, at)
        findings = [*findings, *review_mod.llm_gate_findings(cfg, ledger, gate)]
```

with:

```python
    # Phase 2b (spec section 5) + 1b: the pre-push LLM and mutation ledger
    # gates -- zero tokens, DB reads. Auto-resolve runs FIRST so fixed findings
    # never block. Both gate producers are appended AFTER the ratchet above, so
    # a disarmed (WARN) finding is ratchet-exempt and never auto-escalates.
    if gate is Gate.PRE_PUSH:
        review_mod.auto_resolve_llm(root, ledger, run_id, at)
        mutation_gate.auto_resolve_mutation(ledger, run_id, at, scope_files)
        findings = [*findings,
                    *review_mod.llm_gate_findings(cfg, ledger, gate),
                    *mutation_gate.mutation_gate_findings(cfg, ledger, gate)]
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_pipeline.py -k "pre_push_surfaces_mutation or absent_at_pre_commit" -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Run the full pipeline + gate suites (guard against regressions)**

Run: `python -m pytest tests/unit/test_pipeline.py tests/unit/test_mutation_gate.py tests/unit/test_llm_gate.py -q`
Expected: all pass. (Confirms the new append didn't disturb the existing LLM-gate ordering.)

- [ ] **Step 7: Commit**

```bash
git add src/aramid/pipeline.py tests/unit/test_pipeline.py
git commit -m "feat(mutation-gate): wire auto_resolve + gate findings into run_gate pre-push"
```

---

### Task 5: `aramid arm --mutation`

**Files:**
- Modify: `src/aramid/commands/arm.py` (regexes, `_arm_mutation_text`, `cmd_arm` signature + branch)
- Modify: `src/aramid/cli.py` (flag + dispatch + help)
- Test: `tests/unit/test_arm_mutation.py` (create), `tests/integration/test_cli_dispatch.py` (append)

**Interfaces:**
- Consumes: `cmd_arm(root, llm=False, autolearn=False, tdd=False, mutation=False) -> int`; the repo's `aramid.toml`.
- Produces: `arm --mutation` sets `[mutation].mutation_block_armed = true` (section-scoped); `cfg.mutation["mutation_block_armed"] is True` after `load_config`.

- [ ] **Step 1: Write the failing arm tests**

Create `tests/unit/test_arm_mutation.py`:

```python
"""arm --mutation: ends the mutation bake by setting mutation_block_armed =
true INSIDE the [mutation] table in aramid.toml -- mirrors the SECTION-scoped
_arm_llm_text path (NOT the root-scoped _arm_tdd path), and must never touch
the sibling [js_mutation] table."""
import tomllib

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def test_arm_mutation_writes_into_mutation_section(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n\n[mutation]\nenabled = true\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0

    text = toml.read_text(encoding="utf-8")
    assert "mutation_block_armed = true" in text
    # key lands INSIDE [mutation], after the header
    assert text.index("[mutation]") < text.index("mutation_block_armed = true")
    cfg = config_mod.load_config(tmp_path)
    assert cfg.mutation["mutation_block_armed"] is True


def test_arm_mutation_appends_fresh_section_when_absent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["mutation_block_armed"] is True


def test_arm_mutation_idempotent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[mutation]\nmutation_block_armed = false\n", encoding="utf-8")

    cmd_arm(tmp_path, mutation=True)
    cmd_arm(tmp_path, mutation=True)

    text = toml.read_text(encoding="utf-8")
    assert text.count("mutation_block_armed") == 1
    assert "mutation_block_armed = true" in text
    tomllib.loads(text)                      # no duplicate-key corruption


def test_arm_mutation_preserves_inline_comment(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[mutation]\nmutation_block_armed = false  # bake note\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0

    got = toml.read_text(encoding="utf-8")
    assert "mutation_block_armed = true  # bake note" in got
    assert tomllib.loads(got)["mutation"]["mutation_block_armed"] is True


def test_arm_mutation_does_not_touch_js_mutation(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[js_mutation]\nenabled = true\n\n[mutation]\nenabled = true\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["mutation_block_armed"] is True
    assert "mutation_block_armed" not in parsed["js_mutation"]


def test_cmd_arm_missing_toml_errors_for_mutation(tmp_path):
    assert cmd_arm(tmp_path, mutation=True) == 3


def test_cmd_arm_mutation_reports(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0

    out = capsys.readouterr().out
    assert "mutation_block_armed=true" in out
    assert "mutation bake ended" in out


def test_cmd_arm_plain_does_not_touch_mutation(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    (tmp_path / "aramid.toml").write_text(
        "semgrep_block_armed = false\n\n[mutation]\nmutation_block_armed = false\n",
        encoding="utf-8")

    assert cmd_arm(tmp_path) == 0

    cfg = config_mod.load_config(tmp_path)
    assert cfg.semgrep_block_armed is True
    assert cfg.mutation["mutation_block_armed"] is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_arm_mutation.py -v`
Expected: FAIL — `cmd_arm() got an unexpected keyword argument 'mutation'`.

- [ ] **Step 3: Add the regexes and `_arm_mutation_text` in `arm.py`**

In `src/aramid/commands/arm.py`, after the `_LLM_SECTION_RE` definition (arm.py:32), add:

```python
_MUT_KEY_RE = re.compile(
    r"(?m)^mutation_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_MUT_SECTION_RE = re.compile(r"(?m)^\[mutation\]\s*$")
```

(`^\[mutation\]` cannot match `[js_mutation]` — the char after `[` must be `m`.)

After `_arm_llm_text` (arm.py:57), add the section-scoped writer:

```python
def _arm_mutation_text(text: str) -> str:
    """Comment-preserving single-key rewrite into the [mutation] table (mirrors
    _arm_llm_text): key exists -> substitute; [mutation] section exists ->
    insert the key under the header; neither -> append a fresh [mutation]
    section. Never matches [js_mutation] (section regex anchors on [mutation])."""
    if _MUT_KEY_RE.search(text):
        return _armed_sub(_MUT_KEY_RE, "mutation_block_armed = true", text)
    m = _MUT_SECTION_RE.search(text)
    if m:
        insert_at = m.end()
        return text[:insert_at] + "\nmutation_block_armed = true" + text[insert_at:]
    prefix = "" if not text or text.endswith("\n") else "\n"
    return text + prefix + "[mutation]\nmutation_block_armed = true\n"
```

- [ ] **Step 4: Add the `mutation` branch to `cmd_arm`**

In `src/aramid/commands/arm.py`, change the signature (arm.py:78):

```python
def cmd_arm(root, llm: bool = False, autolearn: bool = False, tdd: bool = False,
            mutation: bool = False) -> int:
```

Then, immediately after the `if llm:` block returns (after arm.py:109), insert:

```python
    if mutation:
        toml_path.write_text(_arm_mutation_text(text), encoding="utf-8")
        print(f"aramid: arm: mutation_block_armed=true written to {toml_path}")
        print("aramid: arm: mutation bake ended -- surviving-mutant findings "
              "now BLOCK at pre-push.")
        return 0
```

- [ ] **Step 5: Run the arm tests to verify they pass**

Run: `python -m pytest tests/unit/test_arm_mutation.py -v`
Expected: PASS (9 passed).

- [ ] **Step 6: Write the failing cli dispatch/mutual-exclusion tests**

Append to `tests/integration/test_cli_dispatch.py` (mirror the existing `arm --tdd` dispatch tests; the file already imports `cli`/`main` and monkeypatches `cmd_arm`). Add:

```python
def test_arm_mutation_dispatches(monkeypatch):
    seen = {}
    monkeypatch.setattr("aramid.cli.cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False,
                        mutation=False: seen.update(
                            llm=llm, autolearn=autolearn, tdd=tdd, mutation=mutation) or 0)
    assert cli.main(["arm", "--mutation"]) == 0
    assert seen == {"llm": False, "autolearn": False, "tdd": False, "mutation": True}


def test_arm_mutation_and_llm_mutually_exclusive():
    # argparse mutually-exclusive group -> SystemExit(2) -> cli remaps to 3.
    assert cli.main(["arm", "--mutation", "--llm"]) == 3
```

> **Implementer note:** match the existing dispatch tests in this file for the exact monkeypatch target and lambda shape — if the existing `arm --tdd` dispatch test patches `cmd_arm` with a different signature, widen it to accept `mutation=False` too (a strengthening, not a rewrite), the same way Task 5 of 1a widened the tdd dispatch lambdas.

- [ ] **Step 7: Run to verify failure, then wire the cli flag**

Run: `python -m pytest tests/integration/test_cli_dispatch.py -k mutation -v`
Expected: FAIL (`--mutation` is not a recognized arm flag → exit 3 for the dispatch test).

In `src/aramid/cli.py`, add `--mutation` to the mutually-exclusive arm group (after cli.py:113):

```python
    arm_which.add_argument("--mutation", action="store_true")
```

Update the arm help text (cli.py:109) to mention it, e.g. append `, --mutation for surviving-mutant findings` to the `help=` string.

Change the dispatch (cli.py:213) to:

```python
    if args.command == "arm":
        return cmd_arm(root, llm=args.llm, autolearn=args.autolearn,
                       tdd=args.tdd, mutation=args.mutation)
```

- [ ] **Step 8: Run the cli tests to verify they pass**

Run: `python -m pytest tests/integration/test_cli_dispatch.py -k mutation -v`
Expected: PASS (2 passed).

- [ ] **Step 9: Commit**

```bash
git add src/aramid/commands/arm.py src/aramid/cli.py tests/unit/test_arm_mutation.py tests/integration/test_cli_dispatch.py
git commit -m "feat(mutation-gate): aramid arm --mutation (section-scoped [mutation] toggle)"
```

---

### Task 6: Real-git end-to-end + full suite + ruff

**Files:**
- Test: `tests/integration/test_mutation_gate_e2e.py` (create)

**Interfaces:**
- Consumes: `check.cmd_check(root, gate, mode, ...) -> int`, a real git repo with an upstream so `mode="range"` resolves `@{u}..HEAD`, a seeded `.aramid/ledger.db` mutation finding.
- Produces: end-to-end proof that a seeded surviving-mutant finding warns (disarmed) / blocks (armed) / resolves when a mapped test enters the pushed range, and that an armed BLOCK survives the fresh-ledger downgrade.

- [ ] **Step 1: Write the failing end-to-end test**

Create `tests/integration/test_mutation_gate_e2e.py`:

```python
"""End-to-end (real git, real @{u}..HEAD range, real cmd_check): a seeded
surviving-mutant ledger finding warns while baking, blocks when armed, and
resolves when the pushed range adds the mapped test -- the whole 1b chain
through the exit code. Real subprocess RUNNERS are isolated out
(GATE_RUNNER_KEYS -> []) so the exit code reflects ONLY the mutation ledger
gate, never a stray lint/tests-failed BLOCK from the fixture repo -- exactly as
tests/unit/test_llm_gate.py::test_pipeline_pre_push_integration does. The git
range that drives auto_resolve_mutation stays fully real.
"""
import subprocess

from aramid import pipeline
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Source, Verdict

NOW = "2026-07-21T12:00:00+00:00"


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


def _seed_survivor(r):
    """Seed an OPEN mutation finding on src/widget.py (module stem 'widget')."""
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        f = Finding(id="w" * 64, tool="mutation", rule="flip_arith",
                    severity_raw="medium", severity=Severity.MEDIUM,
                    verdict=Verdict.WARN, file="src/widget.py", line=2,
                    message="mutant survived: a - b", evidence="",
                    gate=Gate.ALL, source=Source.DETERMINISTIC)
        led.record_run("r0", NOW, "drain", set(), set(), [f])
    finally:
        led.close()


def _commit_unrelated(r):
    (r / "src" / "other.py").write_text("y = 2\n", encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "unrelated change")


def _arm_mutation(r):
    (r / "aramid.toml").write_text(
        "schema_version = 1\n\n[mutation]\nmutation_block_armed = true\n",
        encoding="utf-8")


def test_e2e_baking_warns_armed_blocks_then_resolves(tmp_path, monkeypatch):
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _seed_survivor(r)

    # An unrelated commit puts something in the @{u}..HEAD range WITHOUT
    # touching widget.py or a mapped test -> the survivor is not resolved.
    _commit_unrelated(r)

    # Baking (no arm config): warns, does not block.
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1

    # Armed: the survivor blocks.
    _arm_mutation(r)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1

    # Add the mapped test in the pushed range -> resolves before the block
    # check -> no longer blocks.
    (r / "tests").mkdir()
    (r / "tests" / "test_widget.py").write_text(
        "from src.widget import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n",
        encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "add widget test")
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1


def test_e2e_armed_block_survives_fresh_ledger(tmp_path, monkeypatch):
    """A fresh ledger (no baseline) with an armed survivor still blocks -- the
    fresh-clone downgrade does NOT fire because _has_genuine_block sees the
    armed mutation BLOCK as genuine (via the classify branch)."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm_mutation(r)
    _seed_survivor(r)
    _commit_unrelated(r)
    # has_baseline() is False here -> cmd_check takes the fresh path, writes a
    # baseline, and must NOT downgrade the armed BLOCK.
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1
```

- [ ] **Step 2: Run the end-to-end test to verify it passes**

Run: `python -m pytest tests/integration/test_mutation_gate_e2e.py -v`
Expected: PASS (2 passed). If `test_e2e_..._then_resolves` fails at the "armed blocks" step because the unrelated commit's range is empty, verify `_commit_unrelated` actually advanced HEAD past `@{u}` (the push set the upstream to the first commit; the unrelated commit is the pushable range).

> **Implementer note (do not silently weaken):** if `cmd_check` returns `2`/`3` at the "baking warns" or "resolves" step because a real runner degraded in the sandbox, do NOT change the assertion to accept `1`. `assert rc != 1` already tolerates degraded (2) and engine (3) codes while still proving "does not BLOCK". Only `== 1` is the block signal under test. If the *armed* step returns something other than 1, investigate the range/seed, not the assertion.

- [ ] **Step 3: Run the entire test suite**

Run: `python -m pytest -q`
Expected: all pass (previous baseline was 904 passed / 3 skipped; this adds ~30 tests — expect ~934 passed / 3 skipped, 0 failed).

- [ ] **Step 4: Run ruff over the whole tree**

Run: `python -m ruff check .`
Expected: finding count at or below the baseline of **43**. If any new finding is attributable to this branch's code, fix it; do not raise the baseline.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_mutation_gate_e2e.py
git commit -m "test(mutation-gate): real-git e2e -- warn/block/resolve + fresh-clone survival"
```

---

## Self-Review

**1. Spec coverage.** Every spec section maps to a task:
- §1/§2 (seam mirrors llm, materialize from ledger) → Task 2. §2.3 (classify branch, fresh-clone) → Task 1. §3 (open mutation records) → Task 2. §4 (module-mapped resolution) → Task 3. §5 (components) → Tasks 1-5. §6 (arming/ratchet-exempt) → Tasks 1, 4. §7 (config) → Task 1. §8 (CLI) → Task 5. §9 (data flow / wiring) → Task 4. §10 (fail-open + accepted limitation) → Tasks 2, 3 (fail-safe guards); the accepted limitation is documented behavior, not code. §11 (testing) → Tasks 1-6. §12 (invariants) → Global Constraints + Task 6.

**2. Placeholder scan.** No TBD/TODO; every code step carries complete code; every command has an expected result. The one prose "reserved" note is in the spec, not the plan.

**3. Type consistency.** `mutation_gate_findings(cfg, ledger, gate)` and `auto_resolve_mutation(ledger, run_id, at, changed_files)` signatures are identical in Tasks 2/3 (definition), Task 4 (call site), and all tests. `cmd_arm(root, llm, autolearn, tdd, mutation)` matches across arm.py, cli.py, and both test files. `TOOL = "mutation"` is the single tool-name constant. The verdict rule (`armed → BLOCK else WARN`) is written identically in `policy.classify` (Task 1) and `mutation_gate_findings` (Task 2), per the Global Constraint.

**Known deliberate structural mirror (not a DRY defect):** `mutation_gate_findings`/`auto_resolve_mutation` parallel `review.llm_gate_findings`/`review.auto_resolve_llm` in shape but differ in filter (`tool=="mutation"` vs `source=="llm"`), verdict rule (plain armed toggle vs confirmed+critical), and resolution predicate (module-mapped changed-files vs evidence-gone-from-HEAD). They are genuinely separate seams with different rules, following the codebase's existing per-surface-gate pattern — not a shared block to factor.
