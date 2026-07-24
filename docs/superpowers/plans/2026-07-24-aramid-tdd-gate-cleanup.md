# Aramid TDD Gate — Deferred-Minors Cleanup Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clear the TDD-enforcement-gate epic's deferred-minor backlog — 11 FIX items, 13 WONTFIX — the substantive one being that `tdd` and `red-proof` ledger findings can never auto-resolve.

**Architecture:** Two new dedicated resolution mirrors — `tdd.auto_resolve_tdd` (module-mapped, pure function of the range's changed files) and `red_proof.auto_resolve_red_proof` (resolves only files the base run proved definitively red) — called from `run_gate`'s existing PRE_PUSH block under its existing `mode == "range"` guard, alongside `review.auto_resolve_llm` and `mutation_gate.auto_resolve_mutation`. Everything else in the bundle is additive test, annotation, and documentation hygiene.

**Tech Stack:** Python 3.11+ stdlib, pytest, ruff. Windows-first: every tool as `python -m <tool>`.

**Spec:** `docs/superpowers/specs/2026-07-24-aramid-tdd-gate-cleanup-design.md` (approved 2026-07-24).
**Inventory of record:** `.superpowers/sdd/deferred-inventory.md` — per-item evidence for all 26 items.

## Global Constraints

Every task's requirements implicitly include ALL of these:

- **Branch:** all work on `feat/tdd-gate-cleanup` (branched off `main` @ `2349fd2` by the controller before Task 1). NEVER commit to `main`. NEVER push.
- **This is a CLEANUP, not a redesign.** Nothing may change a verdict, arm anything, alter classification, or change gate behavior on any path other than the single `1a-F2` resolution fix. Suite baseline is **1035 passed / 3 skipped / 0 failed** — any change to an existing test's outcome that is not a deliberate, named part of your task is a defect in this bundle, not an acceptable side effect.
- **Do NOT modify:** `src/aramid/policy.py`, `src/aramid/check.py`, `src/aramid/models.py`, `src/aramid/ledger.py` (no schema change, no `record_run` signature change, no new `EventType`), `src/aramid/config.py`, `src/aramid/data/defaults.toml`, `src/aramid/cli.py`, `src/aramid/mutation_gate.py`, `src/aramid/review.py`, all runners, all consumers, `.github/workflows/`. Read them freely; the two precedents are your templates.
- **No shared helper, no abstraction.** `auto_resolve_tdd` and `auto_resolve_red_proof` are deliberate MIRRORS of `mutation_gate.auto_resolve_mutation` / `review.auto_resolve_llm`, each owning its own semantics in its own producer module. Do NOT refactor the four into a common helper, and do NOT "improve" the two existing ones. (`1b-M2`/`1b-M3` were WONTFIX'd in this very inventory precisely because deliberate mirrors beat abstraction here.)
- **Resolution writes are DURABLE.** A wrong `FINDING_RESOLVED` event cannot be un-appended. The three guards below are load-bearing; none is optional:
  1. **`mode == "range"` only** — never resolve under `all`/`staged` (their `scope_files` is the whole tracked tree / staged set).
  2. **`present_ids` skip** — never resolve a finding the producer re-fired in THIS run (`auto_resolve` runs AFTER `record_run`, pipeline.py:325 vs :309; `record_run` applies the same guard to itself at ledger.py:82).
  3. **`red-proof` resolves only definitively-proven-red files** — `res.state is ToolState.OK and res.returncode in (1, 2)`. Budget-break, unreadable blob, rc 5, and timeout prove NOTHING and must never resolve.
- **Fail-open discipline preserved:** neither new function may raise into `run_gate`. Per-record `try/except Exception: continue` inside the loop, exactly as `auto_resolve_mutation` does (mutation_gate.py:83-96). `red_proof.scan_scoped`'s outer fail-open returns `[], set()`.
- **WONTFIX items are OUT OF SCOPE — do not "helpfully" fix them:** `1a-F6` (getattr style — reviewer said KEEP), `1a-F7`, `1a-F8`, `1b-M2`/`M3`/`M4`/`M5`/`M7`, `2a-d`, `2a-f`, `2b-M2` (unlogged fail-open excepts — user explicitly declined upgrading this), `SP3-M2`, `SP3-M3`.
- **Tests:** run ONLY the focused test files named in your task, as `python -m pytest <files> -q`. NEVER run the bare full suite (~17 min — it looks like a hang; the controller runs it at the end).
- **TDD:** write the failing test first, watch it fail for the RIGHT reason, then implement. Report the observed RED output shape in your task report.
- **Graphite:** before editing `pipeline.py`, run `python -m graphite context src/aramid/pipeline.py` and skim it. Never edit `graph-out/`. (Note: the graph's cross-module call edges are known-unreliable — advisory only, never decision-grade.)
- **Commits:** commit after each green cycle with the task's exact message. No backticks in commit messages (shell expansion on this machine).

---

### Task 1: `1a-F2` — producer findings auto-resolve

**Files:**
- Modify: `src/aramid/tdd.py` (add imports + `auto_resolve_tdd`)
- Modify: `src/aramid/red_proof.py` (`scan` → thin wrapper over new `scan_scoped`; add `auto_resolve_red_proof`)
- Modify: `src/aramid/pipeline.py` (call `scan_scoped`; add the two resolution calls)
- Modify: `tests/unit/test_tdd.py` (append unit tests)
- Modify: `tests/unit/test_red_proof.py` (append unit tests)
- Modify: `tests/integration/test_red_proof_gate.py` (**re-point the inert monkeypatch**, line ~169; add fire-then-resolve e2e)
- Modify: `tests/integration/test_tdd_gate.py` (add fire-then-resolve e2e)

**Interfaces:**
- Consumes: `ledger.open_findings() -> dict[str, dict]` (records carry `tool`, `file`, `status` — verified at `ledger.py:14-19`); `ledger.append(Event(...))`; `Event`, `EventType` from `aramid.models`; `normalize_path` from `aramid.fingerprint`; `gitutil.is_test_file(rel) -> bool`.
- Produces:
  - `tdd.auto_resolve_tdd(ledger, run_id: str, at: str, changed_files, present_ids) -> list[str]`
  - `red_proof.scan_scoped(ctx, cfg) -> tuple[list[RawFinding], set[str]]`
  - `red_proof.scan(ctx, cfg) -> list[RawFinding]` (unchanged signature/semantics — thin wrapper)
  - `red_proof.auto_resolve_red_proof(ledger, run_id: str, at: str, proven_red, present_ids) -> list[str]`

- [ ] **Step 1: Write the failing tests**

Unit tests appended to `tests/unit/test_tdd.py` (build a real `Ledger` on `tmp_path` the way `tests/unit/test_mutation_gate.py:19` does, seed via `record_run`, then assert `open_findings()` membership):

1. `test_auto_resolve_tdd_resolves_when_mapped_test_added` — open `tdd` finding on `a.py`; `changed_files={"tests/test_a.py"}` (**`a.py` NOT touched** — this is the canonical case the rejected `scope_tools` mechanism provably cannot resolve, spec §2.2(1); it is the discriminating test of the whole task); assert the id leaves `open_findings()`.
2. `test_auto_resolve_tdd_resolves_when_source_touched_and_gap_addressed` — `changed_files={"a.py"}`, finding not in `present_ids` → resolved.
3. `test_auto_resolve_tdd_skips_refired_finding` — the §2.4 invariant. Same as (2) but the id IS in `present_ids` → stays open. **This test must fail if the `present_ids` guard is dropped.**
4. `test_auto_resolve_tdd_ignores_unrelated_files` — `changed_files={"b.py"}`, unmapped → stays open.
5. `test_auto_resolve_tdd_ignores_other_tools` — a `ruff` finding on `a.py` is never touched.
6. `test_auto_resolve_tdd_skips_malformed_record` — record with no `file` → skipped, no crash.

Unit tests appended to `tests/unit/test_red_proof.py`:

7. `test_auto_resolve_red_proof_resolves_proven_red` — open `red-proof` finding on `tests/test_foo.py`; `proven_red={"tests/test_foo.py"}` → resolved.
8. `test_auto_resolve_red_proof_ignores_unproven` — `proven_red=set()` (the budget-break / rc-5 / timeout case) → stays open. **Must fail if the definitive-verdict rule is loosened to "changed but no finding emitted".**
9. `test_auto_resolve_red_proof_skips_refired_finding` — id in `present_ids` → stays open.
10. `test_scan_scoped_collects_proven_red` — drive the existing `_plumb` fake with rc 1 for one subject and rc 0 for another; assert `scan_scoped` returns the rc-0 file as a finding and the rc-1 file in the proven-red set, and that rc 5 / `ToolState.TIMEOUT` appear in NEITHER.
11. `test_scan_is_thin_wrapper` — `scan(ctx, cfg) == scan_scoped(ctx, cfg)[0]` on the same fake, proving back-compat.

Integration (real git, mirroring the existing e2e patterns in these files):

12. `tests/integration/test_tdd_gate.py::test_fire_then_resolve_two_push` — push 1: commit `a.py` alone → `tdd` finding recorded open. Push 2: commit **only** `tests/test_a.py` → run `run_gate` at `PRE_PUSH`, `mode="range"` → assert the finding's ledger status is resolved.
13. `tests/integration/test_red_proof_gate.py::test_fire_then_resolve_two_push` — push 1 commits a test that passes on base → `red-proof` finding open. Push 2 changes that test so it is genuinely red on base → assert resolved.
14. `tests/integration/test_red_proof_gate.py::test_auto_resolve_skipped_outside_range_mode` — seed an open finding, run `mode="all"` → assert it stays open (the §2.2(2) guard).

- [ ] **Step 2: Re-point the inert monkeypatch (do this in Step 1's RED cycle, before implementing)**

`tests/integration/test_red_proof_gate.py:169` currently reads:

```python
    monkeypatch.setattr(red_proof, "scan", lambda ctx, cfg: [raw])
```

This is `test_run_gate_disarmed_red_proof_is_ratchet_exempt` — the test sub-project 3's plan review added specifically because it is the ONLY one that genuinely pins the ratchet exemption. The moment `pipeline` calls `scan_scoped`, this patch stops affecting the run and the test passes vacuously forever. Re-point it:

```python
    monkeypatch.setattr(red_proof, "scan_scoped", lambda ctx, cfg: ([raw], set()))
```

**Prove it is not inert:** in your task report, record the counterfactual — temporarily make `scan_scoped` return `([], set())` and confirm the exemption test's assertions FAIL. If they still pass, the test is vacuous and you must fix it before proceeding. This is a hard gate on the task.

- [ ] **Step 3: Implement `tdd.auto_resolve_tdd`**

Add to `src/aramid/tdd.py` (imports: `from aramid.fingerprint import normalize_path`, `from aramid.models import Event, EventType`). Structure it as a near-verbatim mirror of `mutation_gate.auto_resolve_mutation` (mutation_gate.py:66-97), differing only in the tool name, the `present_ids` guard, and the payload label:

```python
def auto_resolve_tdd(ledger, run_id: str, at: str, changed_files, present_ids) -> list[str]:
    """Resolve open code-without-test findings the push addresses (mirrors
    mutation_gate.auto_resolve_mutation, which mirrors review.auto_resolve_llm).
    Module-mapped: resolve a finding on x.py iff the range changed x.py OR
    added/modified a test whose basename stem is test_<x>/<x>_test -- the
    common fix is adding tests/test_x.py WITHOUT touching x.py, which is
    exactly what the ledger's own tool/file scope cannot express.

    present_ids (NOT needed by the two precedents, which resolve only
    drain-produced findings) skips anything this run's producer re-fired:
    auto_resolve runs AFTER record_run, so a still-broken file is already
    re-detected/open by now and must not be resolved out from under itself.

    Liberal by design and self-healing: the fingerprint is tool+rule+path
    (line=0), so a wrong resolve re-fires identically on the next push that
    touches the file without a test. Never raises into run_gate."""
```

Body: `changed_norm = {normalize_path(c) for c in changed_files}`; `changed_test_stems = {Path(c).stem for c in changed_files if gitutil.is_test_file(c)}`; loop `ledger.open_findings().items()`, `continue` unless `rec.get("tool") == _TOOL and rec.get("status") == "open" and fid not in present_ids`; per-record `try:` → `path = rec.get("file", "")`, skip if empty, `module = Path(path).stem`, resolve iff `normalize_path(path) in changed_norm or {f"test_{module}", f"{module}_test"} & changed_test_stems`; append `Event(EventType.FINDING_RESOLVED, run_id, at, finding_id=fid, payload={"auto_resolved": "test_added"})`; `except Exception: continue`.

- [ ] **Step 4: Implement `red_proof.scan_scoped` + `auto_resolve_red_proof`**

Rename the existing `scan` body to `scan_scoped(ctx, cfg) -> tuple[list[RawFinding], set[str]]`. Mechanical changes, no logic changes:
- Every early `return []` becomes `return [], set()` (lines ~57, 59, 64, 71, 80 and the outer `except Exception:` at ~108).
- Add `proven_red: set[str] = set()` next to `out`.
- In the verdict block (~line 93), the existing `if res.state is ToolState.OK and res.returncode == 0:` keeps emitting the finding; add the sibling branch `elif res.state is ToolState.OK and res.returncode in (1, 2): proven_red.add(rel)`. **Do not** add anything for rc 5, timeouts, or other rcs — the existing comment at :97-98 explains why, and Global Constraint 3 requires it.
- Final `return out, proven_red`.

Then the wrapper, preserving the public entry point exactly:

```python
def scan(ctx, cfg) -> list[RawFinding]:
    """Findings-only view of scan_scoped, preserving the original entry point
    (unit tests and any caller that does not need the resolution scope)."""
    return scan_scoped(ctx, cfg)[0]
```

Then `auto_resolve_red_proof(ledger, run_id, at, proven_red, present_ids) -> list[str]` — same mirror shape as Step 3, but the resolve condition is simply `normalize_path(rec.get("file", "")) in {normalize_path(p) for p in proven_red}`, with payload `{"auto_resolved": "red_proven"}`. Docstring must state that only definitively-red files appear in `proven_red`, and why budget-break/rc-5/timeout deliberately do not.

- [ ] **Step 5: Wire pipeline**

Two edits in `src/aramid/pipeline.py`, both inside existing `if gate is Gate.PRE_PUSH:` blocks.

Producer call (~line 277-283) — bind the scope, initializing before the block so it is defined on every path:

```python
    rp_proven_red: set[str] = set()
    if gate is Gate.PRE_PUSH:
        all_raws.extend(tdd.scan(ctx, cfg))
        # ... existing red_proof comment block, unchanged ...
        rp_raws, rp_proven_red = red_proof.scan_scoped(ctx, cfg)
        all_raws.extend(rp_raws)
```

Resolution call (~line 333, inside the existing `if mode == "range":`, immediately after `auto_resolve_mutation`):

```python
        if mode == "range":
            mutation_gate.auto_resolve_mutation(ledger, run_id, at, scope_files)
            # 1a-F2: the two synchronous producers resolve too. Same mode
            # guard and the same reason -- resolving on all/staged scope
            # would durably clear every open producer finding on tracked
            # source. present_ids skips anything re-fired THIS run (these
            # producers, unlike the drain's, fire in the run being resolved).
            present_ids = {f.id for f in findings}
            if getattr(cfg, "tdd", {}).get("enabled", True):
                tdd.auto_resolve_tdd(ledger, run_id, at, scope_files, present_ids)
            red_proof.auto_resolve_red_proof(ledger, run_id, at,
                                             rp_proven_red, present_ids)
```

`getattr(cfg, "tdd", {})` deliberately matches the producer's own fail-safe access style at `tdd.py:41` (`1a-F6`, WONTFIX'd as KEEP). `red_proof` needs no `enabled` guard — its `proven_red` is empty whenever it is disabled or skipped.

- [ ] **Step 6: Verify and commit**

`python -m pytest tests/unit/test_tdd.py tests/unit/test_red_proof.py tests/unit/test_pipeline.py tests/integration/test_tdd_gate.py tests/integration/test_red_proof_gate.py -q` — all green, including every pre-existing test in those files (`test_pipeline.py` is in the list because it exercises the producer call site).

Report in `task-1-report.md`: the RED output shape per new test; the Step-2 counterfactual result; and confirmation that no pre-existing test in those five files changed outcome.

Commit: `fix(ledger): tdd and red-proof findings auto-resolve when the push addresses them (1a-F2)`

---

### Task 2: Test-hardening batch (`1a-F3`, `1a-F4`, `1a-F5`, `2a-b`, `2a-c`, `SP3-M1`, `SP3-M4`)

Seven independent additive test items. **No `src/` file may be modified in this task** — if a test cannot be written without changing production code, stop and report rather than changing it.

**Files:** `tests/integration/test_tdd_gate.py`, `tests/unit/test_policy.py`, `tests/unit/test_pipeline.py`, `tests/unit/test_mutation_score.py`, `tests/unit/test_red_proof.py`, `tests/integration/test_red_proof_gate.py`.

- [ ] **Step 1: `1a-F3` — the composed real-`tdd.scan` e2e (the substantive one here)**

1a spec §11.9 asked for a test driving `tdd.scan → run_gate → exit code` with a **real, non-monkeypatched** scan; none exists (`test_pipeline.py:318,346,507,527` all monkeypatch it; `test_tdd_gate.py` calls `tdd.scan` directly via its `_scan` helper, never through the gate). Add one to `tests/integration/test_tdd_gate.py`, mirroring the real-git e2e pattern `tests/integration/test_red_proof_gate.py` already uses: a real repo, a real range where a production `.py` changed with no new test lines, run through `run_gate` (or `cmd_check`) at `PRE_PUSH`, assert the exit code and that a `tdd` finding is present. **The point is that nothing about `tdd.scan` is faked** — if your test monkeypatches the producer, it is not this item.

- [ ] **Step 2: the five trivial test items**

- `1a-F4` — `tests/unit/test_policy.py:253` `test_tdd_armed_is_block` discards `_sev`. Add `assert _sev is Severity.MEDIUM` (rename the binding from `_sev` since it is now used).
- `1a-F5` — negative test in `tests/unit/test_pipeline.py`: at `Gate.PRE_COMMIT` (and/or mode `"all"`) no `tdd` finding is produced. Code-guaranteed by `pipeline.py:277`, currently untested. Assert on absence of `tdd` findings in `result.findings` with the real producer reachable.
- `2a-b` — `tests/unit/test_mutation_score.py`: feed `iter_target_scores` a target dict **missing a required key** (`killed_s1`/`survived_s1`/`fully_mutated`/`fps`) so the real `except (KeyError, TypeError, ValueError): continue` at `mutation_score.py:47-56` fires. The existing `test_iter_skips_malformed_and_wrong_schema` covers wrong-schema / no-scores / non-dict-target but never missing-key.
- `2a-c` — `tests/unit/test_mutation_score.py:28` `test_run_index_is_event_stream_position` uses `_crf(1, ...)` at actual stream position 1, so index and position coincide and the test cannot distinguish `run_index = stream position` from `run_index = int(run_id label)`. Make them **differ** (e.g. a run labelled `"7"` sitting at stream position 0) and assert the position wins.
- `SP3-M4` — `tests/integration/test_red_proof_gate.py:210` `test_e2e_armed_genuinely_red_passes` has no docstring; its three sibling e2e tests all carry one explaining what makes the pass non-vacuous. Add the matching one-liner.

- [ ] **Step 3: `SP3-M1` — actually assert the captured pytest argv/cwd**

`tests/unit/test_red_proof.py:27-45`'s `_plumb` builds and returns `runs` "for assertions" per its own docstring, but every call site (`_plumb(monkeypatch, ...)` at lines 49, 60, 65, 70, 75, 80, 101, 106, 115, 121, 129, 136, 141, 154, …) discards it. Capture it in at least one test and assert the real contract: argv is `[sys.executable, "-m", "pytest", "-q", <rel>]` and cwd is the worktree path. Prefer the test that already exercises a normal subject run.

- [ ] **Step 4: Verify and commit**

`python -m pytest tests/integration/test_tdd_gate.py tests/unit/test_policy.py tests/unit/test_pipeline.py tests/unit/test_mutation_score.py tests/unit/test_red_proof.py tests/integration/test_red_proof_gate.py -q`

For each of the seven items, report the RED evidence — the assertion that fails when the item's target is broken (for `2a-b`/`2a-c`/`SP3-M1`, state explicitly what one-token change to `src/` makes the new test fail; do NOT commit that change). A test-hardening item that cannot be made to fail is not hardening.

Commit: `test: close seven deferred coverage gaps from the TDD-gate epic (1a-F3/F4/F5, 2a-b/c, SP3-M1/M4)`

---

### Task 3: Docs + annotations + lint (`2a-e`, `2b-M4`, `2b-M5`)

**Files:** `src/aramid/mutation_score.py` (annotations only), `README.md`.

- [ ] **Step 1: `2a-e` — return-type annotations**

Add `->` return annotations to `baseline_for` (line ~70), `latest_by_target` (~79), `detect` (~88), `latest_regressions` (~109) in `src/aramid/mutation_score.py`. Their siblings `iter_target_scores` and `TargetScore.rate` in the same file already have them. **Annotations only** — do not touch a single line of logic, and derive each type from what the function actually returns (read the body; do not guess).

- [ ] **Step 2: `2b-M4` / `2b-M5` — README clarity**

In `README.md`'s "2b: regression teeth at pre-push" section (~lines 182-200):
- `2b-M4`: rate regressions (~192-195) are described, and the very next bullet (~196-200) is titled "The only escape valve is ephemeral" but discusses **only** the transition case. State explicitly that **rate** regressions need no escape valve because they are permanent-WARN and never block. A reader today can reasonably conclude the section forgot them.
- `2b-M5`: replace the vague "arming rate is out of scope for 2b and gets revisited only with real-drain evidence" roadmap phrasing (~194-195) with something concrete about what evidence would justify revisiting.

Every factual claim you write must be verified against shipped code before you write it — this repo's review convention. Do not describe behavior you have not read.

- [ ] **Step 3: ruff + verify + commit**

`python -m ruff check` over every file touched by **all three tasks** of this bundle (list them explicitly in your report — the Task 1 and Task 2 files too, not just your own). Expect `All checks passed!`.

`python -m pytest tests/unit/test_mutation_score.py -q` — annotations must not disturb it.

Commit: `docs: clarify 2b rate-regression escape valve + annotate mutation_score returns (2a-e, 2b-M4/M5)`

---

## Self-Review Checklist (controller, before the whole-branch review)

- [ ] All 11 FIX items landed; all 13 WONTFIX items untouched.
- [ ] Step-2 counterfactual recorded: the re-pointed ratchet-exemption test provably fails when `scan_scoped` returns empty.
- [ ] The three durability guards (`mode == "range"`, `present_ids`, definitive-red-only) each have a test that fails when the guard is removed.
- [ ] Full suite run by the CONTROLLER in background: 1035 baseline + exactly the new tests, 0 failures, 0 new skips.
- [ ] Ledger appended at every milestone.
