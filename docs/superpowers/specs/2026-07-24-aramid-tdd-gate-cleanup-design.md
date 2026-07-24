# Aramid TDD Gate — Deferred-Minors Cleanup Bundle

**Date:** 2026-07-24
**Epic:** TDD-enforcement gate — ALL FOUR SIGNALS SHIPPED (1a code-without-test, 1b mutation teeth, 2a/2b mutation-score measurement+teeth, 3 red-first proof). Merged to main locally @ `2349fd2`; suite 1035 passed / 3 skipped / 0 failed.
**Status:** Scope approved by user (2026-07-24, option 1 of 4); ready for writing-plans.
**Scope:** the epic's deferred-minor backlog — **11 FIX, 13 WONTFIX** out of 26 code-verified inventoried items.
**Inventory of record:** `.superpowers/sdd/deferred-inventory.md` (per-item evidence, line numbers, verdicts). This spec does not restate it; it designs the one substantive item and enumerates the rest.

---

## 1. Context & Motivation

The epic is complete. What remains is the accrued minor debt its five whole-branch reviews deliberately deferred. A scoping pass re-read every deferred item **against current code** (not against the ledger's memory of it) and found 26 items: 24 still OPEN, 2 already STALE — `1a-F1` (hooks.py `git config` encoding) was fixed by a later unrelated sweep `7e61640`, and `2a-a` (under-counted `errors`/`timeouts` buckets) was fully honored by 2b's design and is documented at `mutation_score_gate.py:34-36`.

Of the 24 open items, exactly **one is a real defect** (`1a-F2`). The other ten FIX items are test-teeth, annotation, and documentation hygiene. Thirteen are WONTFIX — deliberate mirrors, provably-inert observations, or items the epic's own later triage de-prioritized.

**The bundle's governing principle:** this is a *cleanup*, not a redesign. Nothing here may change a verdict, arm anything, or alter gate behavior on any path other than the one defect being fixed. The suite baseline is 1035 passed / 3 skipped; the bundle is additive plus one behavioral fix.

## 2. The substantive item — 1a-F2: producer findings never auto-resolve

### 2.1 The defect

`pipeline.py:307` builds the ledger's resolution scope from the runner dictionary only:

```python
scope_tools = {r.tool for r in flat_results if r.state is ToolState.OK}
```

`tdd.scan()` (pipeline.py:278) and `red_proof.scan()` (pipeline.py:283) append to `all_raws` **outside** that dictionary — they are synchronous producers, not runners. So `"tdd"` and `"red-proof"` never enter `scope_tools`, and `ledger.py:83`'s resolution guard —

```python
if rec["status"] == "open" and fid not in present \
   and rec.get("tool") in scope_tools and rec.get("file") in scope_files:
```

— can never fire for either producer. **Consequence:** a developer who fixes the gap (adds the missing test; makes the test genuinely red-first) leaves the finding OPEN forever. It inflates `status`/reporter open counts, and — because an open finding is a real ledger row — it is a permanent wrong answer to "what is outstanding", on the two signals whose entire purpose is to be actioned and cleared. Sub-project 3 doubled the exposure by adding a second unresolvable producer.

### 2.2 Mechanism decision (deviation from the approved wording — stated, not re-asked)

The approved scope described the fix as *"add producer tool names to `scope_tools` when they ran."* Reading the code to write this spec produced primary-source evidence that **this mechanism does not work**, on two independent grounds. It is therefore rejected and replaced. The *item* being fixed is unchanged; only the mechanism is.

**(1) It under-resolves the canonical case — the one the item is about.**
`ledger.py:83` also requires `rec["file"] in scope_files`. The normal way a `tdd` finding on `a.py` gets fixed is *adding `tests/test_a.py`* — typically **without touching `a.py`**. On that push `ctx.files == {"tests/test_a.py"}`, so `tdd.py:43-46`'s `if not prod:` returns `[]`, *and* `a.py ∉ scope_files`. The finding still never resolves. Adding the tool name buys nothing in the majority case.

**(2) It over-resolves on `--all`.**
`record_run` (pipeline.py:307-309) is **not mode-guarded**, unlike `auto_resolve_mutation`, which pipeline.py:333 deliberately wraps in `if mode == "range":` with the comment that resolving on `"all"`/`"staged"` *"would durably clear every open … finding on tracked source."* `aramid check --all --gate pre-push` is a legal invocation (`cli.py:53`; `--gate` defaults to `pre-commit`, so **CI's `check --all --strict --json` is not affected** — but the combination is reachable). Under it, `ctx.rng` is falsy → `tdd.py:52` sets `has_new_test_lines = any(is_test_file(f) for f in ctx.files)` → true in any repo containing a test → `[]` returned, with `scope_files` = the entire tracked tree. Every open `tdd` finding in the repo would be **durably resolved**. That is precisely the bug pipeline.py:333's guard exists to prevent.

A third, weaker point reinforces both: both producers are fail-open (`except Exception: return []`), so "returned no findings" is indistinguishable from "crashed" — there is no honest `when they ran` signal to condition on at the `scope_tools` layer.

### 2.3 Design adopted — two dedicated mirrors

Mirror the precedent this codebase has already used **twice**: `review.auto_resolve_llm` and `mutation_gate.auto_resolve_mutation`, both called from the existing `if gate is Gate.PRE_PUSH:` block at pipeline.py:325-334, both writing `FINDING_RESOLVED` events with their own scope logic. Add two more: `tdd.auto_resolve_tdd` and `red_proof.auto_resolve_red_proof`.

**No shared helper, no abstraction over the four.** Two independent forces in this codebase cut against it: `1b-M2`/`1b-M3` were WONTFIX'd in this very inventory *because* deliberate mirrors of `review.*` were judged better than abstraction, and sub-project 3's whole-branch review made "single verdict authority, **no twin anywhere**" its first invariant. Three sibling mirrors, each owning its own semantics, is the house pattern. (This is also why the inventory's own speculative aside — *"likely a shared helper given it would now apply to three producers"* — is not adopted.)

**Call site** (inside the existing `if gate is Gate.PRE_PUSH:` block, under the existing `mode == "range"` guard, immediately after `auto_resolve_mutation`):

```python
if mode == "range":
    mutation_gate.auto_resolve_mutation(ledger, run_id, at, scope_files)
    present_ids = {f.id for f in findings}
    if getattr(cfg, "tdd", {}).get("enabled", True):
        tdd.auto_resolve_tdd(ledger, run_id, at, scope_files, present_ids)
    red_proof.auto_resolve_red_proof(ledger, run_id, at, rp_proven_red, present_ids)
```

`getattr(cfg, "tdd", {})` matches the producer's own fail-safe access style (`tdd.py:41`) — the style `1a-F6` was explicitly WONTFIX'd as *"reviewer says KEEP, fail-safe."* `red_proof` needs no `enabled` guard: its evaluated-set is empty whenever it is disabled or skipped.

### 2.4 The new invariant neither precedent needs

`auto_resolve_llm` and `auto_resolve_mutation` resolve findings produced **asynchronously by the drain** — never by the current run. `tdd` and `red-proof` fire **in the same run**, and `auto_resolve` runs *after* `record_run` (pipeline.py:325 vs :309). So a finding the producer legitimately **re-fired this run** is already re-`FINDING_DETECTED` (open) by the time resolution runs, and would be resolved out from under itself.

Both new functions therefore **must skip ids present in this run's findings** — mirroring the guard `record_run` already applies to itself (`fid not in present`, ledger.py:82). Hence the `present_ids` parameter. This invariant is load-bearing: without it, a still-broken `a.py` that re-fires every push would show as resolved in the ledger while still being reported at the gate.

### 2.5 Per-producer resolution semantics

The two differ — which is the third reason one coarse `scope_tools` entry cannot serve both: a single `(tools, files)` pair cannot express two different evaluated-sets.

**`tdd` — module-mapped; no producer plumbing at all.** A near-verbatim mirror of `auto_resolve_mutation` (mutation_gate.py:66-97): resolve an open `tdd` finding on `x.py` iff the range changed `x.py` **or** added/modified a test whose basename stem is `test_<x>` / `<x>_test`. This is a pure function of `changed_files` — it needs no signal from the producer, which is what makes it small. It resolves the §2.2(1) canonical case that `scope_tools` cannot.

Liberal by design, exactly as 1b's docstring argues: a wrong resolve is **self-healing**, because the fingerprint is `tool+rule+path` (line=0, the 1a stability trick) — the next push that touches `x.py` without a test re-fires the identical id. Two source files sharing a module stem resolve together on one mapped test; accepted, same as 1b.

**`red-proof` — precise evaluated-set; resolve only what was definitively proven.** Module-mapping does not apply (the finding *is* on the test file). Walking `red_proof.py:81-98`, three paths emit no finding while proving **nothing**: the `break` at :82 (wall budget exhausted), the `continue` at :86 (unreadable/empty head blob), and the fall-through at :97-98 (rc 5 nothing-collected, timeout, other rc). On a slow repo these are **routine control flow, not pathological failure** — so a naive "no finding emitted ⇒ resolved" rule would false-resolve in normal operation, on the one producer that has teeth when armed.

The resolvable set is therefore exactly the files that reached a **definitive red verdict**: `res.state is ToolState.OK and res.returncode in (1, 2)`. Those are cheap to accumulate inside the existing loop, alongside `out`.

| Base-run outcome for a subject | Emits finding? | Resolves an old finding? |
|---|---|---|
| rc 0 — never red | **yes** (the finding) | no |
| rc 1 / 2 — red proven | no | **yes** |
| rc 5 — nothing collected | no | no — proves nothing |
| timeout / other rc / unreadable blob | no | no — unattributable |
| budget exhausted before this subject | no | no — never evaluated |

### 2.6 Plumbing the evaluated-set, and the hazard it creates

`red_proof.scan()` returns a bare list today, and ~16 unit tests plus pipeline call it that way. Keep it working: move the body to `scan_scoped(ctx, cfg) -> tuple[list[RawFinding], set[str]]` and leave `scan()` as a thin wrapper returning `scan_scoped(...)[0]`. Every early return and the outer fail-open become `return [], set()`. Pipeline calls `scan_scoped`, binding `rp_proven_red` (initialized to `set()` before the PRE_PUSH block so it is defined on every path).

**HAZARD — the plan must own this.** Exactly one test monkeypatches the producer entry point: `tests/integration/test_red_proof_gate.py:169`, `monkeypatch.setattr(red_proof, "scan", lambda ctx, cfg: [raw])`. That is `test_run_gate_disarmed_red_proof_is_ratchet_exempt` — the test sub-project 3's *plan review* specifically added because it is the only one that genuinely pins the ratchet exemption. Once pipeline calls `scan_scoped`, that monkeypatch goes **silently inert**: the test keeps passing while no longer exercising the exemption at all, and a regression there re-escalates disarmed WARNs (spec §4 violation). It must be re-pointed at the new seam, and a test must fail if pipeline stops consuming it. Silent inertness is the failure mode to design against here.

(`tests/unit/test_red_proof.py` patches `run_subprocess`, not `scan`, and `tests/unit/test_pipeline.py` patches only `pipeline.tdd.scan` — both keep working through the thin wrapper. This is a one-site hazard, not a sweep.)

### 2.7 What this bundle defines that no spec did

The 1a design document is **silent** on producer resolution semantics — it specifies detection and arming only. `2b` never needed any (its findings are ephemeral, no ledger write). So §2.5 is not a restatement of existing intent; it **defines** the resolution contract for the two synchronous producers. It belongs in the record as a decision, not as a bug fix footnote.

## 3. The other ten FIX items

All are additive test/doc/annotation hygiene. None changes behavior.

| ID | Change | File |
|---|---|---|
| 1a-F3 | Composed e2e driving a **real** (non-monkeypatched) `tdd.scan` → `run_gate` → exit code; 1a spec §11.9 asked for it and no test does it. Mirror sub-project 3's `test_red_proof_gate.py` real-git e2e pattern. | `tests/integration/test_tdd_gate.py` |
| 1a-F4 | Assert `Severity.MEDIUM`, not just the verdict — `_sev` is currently discarded. | `tests/unit/test_policy.py:253` |
| 1a-F5 | Negative test: `tdd.scan` produces nothing at `PRE_COMMIT` / mode `all`. Code-guaranteed (`pipeline.py:277`), untested. | `tests/unit/test_pipeline.py` |
| 2a-b | Feed `iter_target_scores` a target dict missing a required key, exercising the real `except (KeyError, …): continue` at `mutation_score.py:47-56`. | `tests/unit/test_mutation_score.py` |
| 2a-c | Make `run_index` discriminate **stream position** from the `run_id` label — today `_crf(idx)` sets both to the same value, so the test cannot tell them apart. | `tests/unit/test_mutation_score.py:28` |
| 2a-e | Return-type annotations on `baseline_for`, `latest_by_target`, `detect`, `latest_regressions` (siblings in the same file already have them). | `src/aramid/mutation_score.py:70,79,88,109` |
| 2b-M4 | State explicitly that **rate** regressions need no escape valve (permanent-WARN, never blocks) — currently only the transition case's valve is spelled out. | `README.md:182-200` |
| 2b-M5 | Replace the vague "arming rate … revisited only with real-drain evidence" roadmap phrasing. | `README.md:194-195` |
| SP3-M1 | Actually assert the pytest argv/cwd that `_plumb` returns "for assertions" — no call site captures it today. | `tests/unit/test_red_proof.py:27` |
| SP3-M4 | Add the vacuous-pass docstring its three sibling e2e tests all carry. | `tests/integration/test_red_proof_gate.py:210` |

## 4. WONTFIX (13) — recorded, not silently dropped

`1a-F6` (getattr style — reviewer said KEEP, fail-safe), `1a-F7` (cosmetic help string, present as designed), `1a-F8` (mutual-exclusion gap that mirrors a pre-existing one; de-prioritized by the epic's own triage), `1b-M2`/`M3`/`M4`/`M5`/`M7` (deliberate mirrors of `review.*`, or provably inert given git's forward-slash paths), `2a-d` (O(targets × scores) rescan — advisory tool, small histories), `2a-f` (deliberate precedent mirror of `status.py`'s duplication), `2b-M2` (unlogged fail-open excepts — plan-prescribed style in **both** the 1b and 2b seams; the user considered and declined upgrading this), `SP3-M2` (path-separator assumption, confirmed inert, Windows-green empirically), `SP3-M3` (one worktree-add under a pathological budget — cosmetic, and reordering would change behavior).

Full per-item rationale: `.superpowers/sdd/deferred-inventory.md`.

## 5. Verification

- **Fire-then-resolve, two-push, for each producer** — the tests that would have caught 1a-F2. Push 1 fires the finding; push 2 addresses it; assert the ledger row is `resolved`. For `tdd`, push 2 **adds only the test file** (the §2.2(1) case `scope_tools` provably cannot resolve — this is the discriminating test). For `red-proof`, push 2 makes the test genuinely red on base.
- **Re-fire is not resolved** — the §2.4 invariant: a still-broken file that re-fires stays open. Must fail if `present_ids` is dropped.
- **Non-definitive verdicts do not resolve** — rc 5 / timeout / budget-exhausted leave an open `red-proof` finding open.
- **`mode != "range"` resolves nothing** — the §2.2(2) guard.
- **Monkeypatch inertness proof** (§2.6) — a test that fails if pipeline stops consuming the scoped seam.
- **Full suite by the controller** (~17 min): baseline 1035 passed / 3 skipped / 0 failed. Expected delta is the new tests plus zero regressions; any change to the 1035 that is not a new test is a defect in this bundle.
- **ruff clean** over every touched file.

## 6. Out of scope

Pushing the 9 unpushed commits to origin (separate, needs explicit authorization); the CI Node 20 runner bump; the parked Graphite decision-grade audit and the graph-promotion of 1a §9's advisory stub; the Phase-2c-1 ticket bucket (different, earlier epic — verified already fixed); and every WONTFIX item in §4.

## 7. Risks

1. **Resolution is a durable ledger write.** A wrong `FINDING_RESOLVED` cannot be un-appended. Mitigated by: the `mode == "range"` guard (§2.2(2)), the `present_ids` guard (§2.4), red-proof's definitive-verdict-only rule (§2.5), and self-healing fingerprints — but this is the one place in the bundle where a mistake is persistent, and it deserves the plan review's sharpest attention.
2. **Silent test inertness** (§2.6) — the failure mode that hides itself.
3. **Scope creep from item 1** eating the ten trivials. They stay in their own tasks; the bundle is not done if only 1a-F2 lands.
