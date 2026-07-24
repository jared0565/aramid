# Aramid TDD Gate — Sub-project 2b: Mutation-Score Regression Teeth

**Date:** 2026-07-24
**Epic:** TDD-enforcement gate (1a code-without-test SHIPPED; 1b mutation-gate teeth SHIPPED; 2a mutation-score measurement + advisory SHIPPED @ 26f99a3, CI green)
**Status:** Design approved; ready for writing-plans.
**Scope of this spec:** 2b only — give the 2a analyzer's regressions a pre-push gate presence and arming. Detection code is untouched; 2b consumes `mutation_score.latest_regressions()` as-is.

---

## 1. Context & Motivation

2a records a per-function mutation-outcome taxonomy each drain and detects two advisory regression signals in `src/aramid/mutation_score.py`: the **per-mutant transition** (a mutant killed in the target's most-recent-prior fully-mutated run that now survives confirmed, joined `extra × extra` by fingerprint) and the **per-function stage-1 rate-delta**. Both are currently visible only via `aramid mutation-score`.

2b is the teeth: surface both at the pre-push gate, and let the repo arm transitions to BLOCK after a bake. The 1b overlap is deliberate and is precisely the value: a transitioned mutant usually also has an open 1b `tool == "mutation"` survivor finding, but that finding is **durably** resolved by a bare source-touch (`auto_resolve_mutation` is liberal by design — the re-drain is its backstop). The 2b signal is the one that persists through that hole: it is re-derived from measurement history at every gate, and only a mapped-test push slips through, per-gate.

## 2. Decisions (brainstorm 2026-07-24)

1. **Teeth scope:** transition regressions BLOCK once armed; rate-delta regressions surface as **permanent WARN** (never block in 2b). Matches signal precision: NEW-2's fingerprint-collapse caveat is tolerable for transitions; rate is too noisy to arm.
2. **Arming:** new `[mutation].score_block_armed` (default `false`) + `aramid arm --mutation-score`. Own bake, independent of 1b's `mutation_block_armed`, per the per-signal bake precedent (semgrep/tdd/llm/mutation/pack).
3. **Escape valve:** **test-mapped ephemeral suppression** — a transition regression is dropped for *this gate run only* when the push touches the module-mapped test. No ledger write; a bare source-touch does NOT suppress.
4. **Architecture:** **gate-time derived findings, zero persistence** — no new EventType, no stored findings, no resolver. This resolves the 2a §12 caveat by construction (§12 below).

## 3. The gate seam

New `src/aramid/mutation_score_gate.py`, twin of `mutation_gate.py`:

```python
TOOL = "mutation-score"

def mutation_score_gate_findings(cfg, ledger, gate, changed_files) -> list[Finding]:
    """PRE_PUSH only. Recompute regressions from CONSUMER_RUN_FINISHED history
    via mutation_score.latest_regressions(ledger.events()); apply ephemeral
    test-mapped suppression against changed_files (None disables suppression);
    materialize the rest as findings. Verdict computed HERE from
    [mutation].score_block_armed -- the SAME rule policy.classify's
    tool=="mutation-score" branch encodes; the two must agree. NEVER raises
    into run_gate (fail-open)."""
```

- Returns `[]` at any gate other than PRE_PUSH, and — like the consumer itself — returns `[]` when `[mutation].enabled` is false: with the measuring engine off there is no re-drain backstop, so stale regressions would block inescapably (§9).
- Regressions are recomputed fresh every gate from the ledger's measurement history — each target's latest measurement vs its most-recent-prior `fully_mutated` baseline. **"Only a re-drain truly clears it" is automatic:** no durable per-finding state exists to wrongly resolve.
- Verdict inline: transition → `BLOCK` if `cfg.mutation.get("score_block_armed", False)` else `WARN`; rate → always `WARN`.
- Appended in `pipeline.py`'s PRE_PUSH block alongside the llm and mutation producers — after the ratchet, so a baking WARN is ratchet-exempt and never auto-escalates; before the exit-code computation, so an armed BLOCK drives the block exit code (exit 1 from `cmd_check`, per `pipeline.py`'s step-8 rule and the 1b e2e contract).

## 4. Ephemeral test-mapped suppression

Applies to **transition findings only** (WARNs need no escape valve; rate findings are never suppressed).

A transition regression on target `"<rel>::<func>"` is suppressed for this gate run iff `changed_files` contains a **test file** (per `gitutil.is_test_file`) whose basename stem is in `{f"test_{module}", f"{module}_test"}` for `module = Path(rel).stem` — the exact `mutation_gate._module_tests` convention (**reuse that helper by import** — one definition of the mapping convention).

- `changed_files` is the push's `scope_files` **only under mode `"range"`**; the pipeline passes `None` otherwise (mirrors the 1b guard at `pipeline.py:328`): under `"all"`/`"staged"` the scope is the whole tracked tree / staged set, and suppressing against it would suppress everything. Findings still surface in all modes.
- Suppression writes nothing. The next push re-evaluates from scratch; only a re-drain that re-measures the target clean removes the regression from history.

## 5. Finding shape

One `Finding` per surviving `Regression` (the analyzer emits at most one transition + one rate per target):

| Field | Value |
|---|---|
| `tool` | `"mutation-score"` — distinct tool: `auto_resolve_mutation` and `mutation_gate_findings` both filter `tool == "mutation"`, so neither ever touches these, by construction |
| `rule` | `Regression.kind`: `"transition"` \| `"rate"` |
| `file` | the `rel` half of the target key (split on `"::"`, first part) |
| `line` | `0` — fingerprints are opaque hashes; the message carries the function |
| `severity_raw` / `severity` | transition → `"high"` (sharper than 1b's medium survivors: was killed, now survives); rate → `"low"` |
| `message` | transition: `"mutation-score regression in <func>: N previously-killed mutant(s) now survive"`; rate: `"mutation-score rate regression in <func>: <Regression.detail>"` (e.g. `0.67 -> 0.33`) |
| `evidence` | transition: sorted `transition_fps` joined; rate: `""` |
| `id` | deterministic synthetic id: `compute_fingerprint("mutation-score", kind, rel, func, 0)` — stable across gates for display; never stored, so it cannot collide with anything in the ledger |
| `verdict` | per §3 |
| `gate` / `source` | `Gate.PRE_PUSH` / `Source.DETERMINISTIC` |

## 6. Components & file structure

| File | Change |
|---|---|
| `src/aramid/mutation_score_gate.py` | **NEW** — the seam (§3–§5). |
| `src/aramid/pipeline.py` | Append the producer in the PRE_PUSH block; pass `scope_files` when `mode == "range"` else `None`. |
| `src/aramid/policy.py` | New `classify` branch (§7). |
| `src/aramid/commands/arm.py` | `--mutation-score` → writes `score_block_armed = true` into `[mutation]` (new `_SCORE_KEY_RE` + writer mirroring `_arm_mutation_text`; the key name is globally unique so no section-scoping is needed, and `_MUT_KEY_RE` cannot match it — its literal is `mutation_block_armed`). |
| `src/aramid/cli.py` | Wire the arm flag (additive-only). |
| `src/aramid/data/defaults.toml` | `score_block_armed = false` under `[mutation]` with a pointer comment. |
| `src/aramid/commands/mutation_score.py` | One added header line showing arming state (`transition regressions: BLOCK (armed)` / `WARN (baking)`) so the advisory command and the gate visibly agree. |

**Not touched:** `mutation_score.py` (analyzer reused verbatim), `consumers/mutation.py`, `mutation_gate.py`, `check.py`, `models.py`, ledger schema. No new `EventType`, no new store.

## 7. Verdict rule (the classify twin)

```python
if tool == "mutation-score":
    armed = cfg.mutation.get("score_block_armed", False)
    return severity, Verdict.BLOCK if (armed and rule == "transition") else Verdict.WARN
```

Routing the verdict through `classify` (not only the seam) makes `_has_genuine_block` treat an armed transition BLOCK as genuine with no `check.py` change, so it survives the fresh-clone downgrade — the same shape as the tdd/mutation branches. The seam computes the same rule inline; **the two one-line rules must agree** (pinned by a red-first test, §11).

## 8. Data flow

```
drain history: CONSUMER_RUN_FINISHED.payload["mutation_scores"]  (2a, unchanged)
  └─ PRE_PUSH: mutation_score_gate_findings(cfg, ledger, gate, changed_files)
       └─ mutation_score.latest_regressions(ledger.events())     (2a analyzer, unchanged)
            └─ transition findings minus test-mapped ephemeral suppression (range mode only)
            └─ rate findings (always WARN, never suppressed)
                 └─ appended after ratchet → exit code   (BLOCK ⇢ 2 when armed)
aramid mutation-score: same analyzer + arming-state header line  (advisory, unchanged core)
```

## 9. Error handling & fail-open

- The seam never raises into `run_gate` (contract identical to `mutation_gate.py`): PRE_PUSH-gated at the top; the analyzer call and per-regression materialization wrapped; a malformed regression (e.g. a target key without `"::"`) is skipped, never crashes the gate.
- The analyzer underneath is already schema-gated fail-open (2a §9). Empty history, no baselines, wrong schema → `[]` silently.
- `changed_files=None` (non-range modes) disables suppression only; findings still surface.
- `[mutation].enabled = false` disables the seam entirely (`[]`): the drain stops measuring, so no re-drain could ever clear a stale regression — teeth without the measuring engine would be an inescapable block. Disarming (`score_block_armed = false`) drops only the BLOCK verdict while keeping the WARN surface.

## 10. Documented limitations (module docstring + README, 1b §10 style)

1. **NEW-2 armed:** `_mutant_fp` pins occurrence to 0, so two same-op mutants on one identical line share a fingerprint — a transition BLOCK may conflate them. Accepted: same operator on identical line content is semantically near-identical; the killing test for one kills the class.
2. **Ephemeral findings are invisible to `aramid status`:** nothing is persisted, so regressions appear only in gate output and `aramid mutation-score`. Deliberate trade for §12 correctness.
3. **Stale-block window:** a function rewritten *without* its mapped test still blocks on the old measurement until a re-drain re-measures it. Escape hatches: add the mapped test, or disarm. Gate-produced findings sit outside `apply_overrides` (pipeline step 6 runs before the producers append) — same posture as 1b's seam.
4. **Inherited 2a limits:** code-change-triggered only (silent on test-weakening against unchanged code); a rename re-keys `"<rel>::<func>"` and drops the baseline; transition recall bounded by `confirm_cap`.
5. **Rate WARN is permanent in 2b** — it never arms here; revisit only with real-drain evidence.
6. **NEW-1 honored by construction:** detection reads only `killed_s1`/`survived_s1`/`fully_mutated`/fps — never the under-counted, write-only `errors`/`timeouts` buckets.

## 11. Testing strategy (synthetic seeded ledgers, 2a pattern — no real drains)

**`mutation_score_gate.py`:**
- Armed → transition BLOCK, rate WARN; baking → both WARN.
- Suppression: transition dropped iff `changed_files` contains the mapped test (both `test_<module>` and `<module>_test` stems); NOT dropped on a bare source-touch; rate never dropped; inert when `changed_files=None`.
- Non-PRE_PUSH gate → `[]`; `[mutation].enabled = false` → `[]`. Malformed history / malformed target key → skipped, no raise.
- Finding shape: tool/rule/file/line/severity/message/evidence; id deterministic across two invocations.

**Red-first twin-rule test:** the seam's inline verdict equals `policy.classify`'s for `("mutation-score", "transition")` and `("mutation-score", "rate")`, armed and baking — written to fail before the classify branch exists (pins the 1b "two one-line rules must agree" discipline).

**`policy.py`:** armed transition → BLOCK; armed rate → WARN; disarmed both → WARN.

**`commands/arm.py`:** `--mutation-score` key-substitute / `[mutation]`-section-insert / fresh-section paths; comment preservation; `[js_mutation]` never matched; `_MUT_KEY_RE` and `_SCORE_KEY_RE` non-interference (arming one never rewrites the other).

**Pipeline integration:** seeded regression history at PRE_PUSH range mode yields the finding; armed → the gate blocks; with the mapped test in the push's scope the transition is suppressed and the gate does not block.

**CLI:** dispatch test for the new arm flag.

**Final task:** README limitations + full suite (CONTROLLER runs it in background, ~10–13 min; subagents run only focused files) + ruff.

## 12. Resolution of the 2a §12 reuse caveat

2a §12 asked 2b to choose between a distinct tool that bypasses `auto_resolve_mutation` + its own gate seam, vs a shared tool with an explicit resolution bypass. **Decision: distinct tool, and further — no persisted findings at all.** Regressions are pure derived state over measurement history the ledger already preserves; materializing them per-gate means there is no stored record for `auto_resolve_mutation` to wrongly resolve, no lifecycle to keep consistent with history, and the §12 principle ("only a re-drain truly clears it") holds by construction rather than by discipline.

## 13. Non-goals / YAGNI

- No arming of rate-delta; no severity/threshold tuning knobs for it.
- No persisted regression findings, no new `EventType`, no resolver, no `aramid status` integration.
- No suppression config surface (the mapped-test rule is fixed, mirroring 1b's module-mapping).
- No changes to the 2a analyzer, consumer taxonomy, or `[mutation]` measurement knobs.
- No historical backfill; teeth apply to whatever history has accrued since 2a shipped.
- No cross-repo aggregation, no trend analysis.
