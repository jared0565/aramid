# Aramid TDD Gate — Sub-project 2a: Mutation-Score Measurement + Persistence

**Date:** 2026-07-22
**Epic:** TDD-enforcement gate (1a code-without-test signal SHIPPED; 1b mutation-gate teeth SHIPPED @ e9aa5f5, CI green)
**Status:** Design approved; ready for writing-plans.
**Scope of this spec:** 2a only — *measurement + persistence, surfaced advisory (no teeth)*. 2b (regression detection + arming) is a separate spec.

---

## 1. Context & Motivation

The mutation consumer (`src/aramid/consumers/mutation.py`) is the epic's TDD test-quality oracle: a mutant the full suite cannot kill = tests too weak to catch a bug. 1b gave the drain's **surviving** mutants teeth at the pre-push gate.

Sub-project 2 asks a sharper, second-order question: **did a code change leave a function *less*-tested than its last measurement?** That is *mutation-score regression*. It is split:

- **2a (this spec):** record a per-function outcome taxonomy each drain, persist it, and surface it **advisory** through a read-only analyzer + query command. No gate, no verdict, no arming. Shippable on its own; it lets us *see* scores and *validate the metric on real code* before enforcing anything.
- **2b (future spec):** detection-with-teeth — arm regressions to BLOCK at the gate, reusing the `[mutation]` config + arming surface, and resolve the `auto_resolve` inheritance question (§12).

---

## 2. Fundamental constraint: the metric is code-change-triggered

`consume()` mutates **only the functions whose code changed in the queue item's range** (`consumers/mutation.py:76-83`):

```
changed = gitutil.diff_new_lines(ctx.root, item.base, item.head)
files   = sorted(f for f in changed if f.endswith(".py") and not _is_test_file(f))
...
muts    = mutation.generate_mutants(original, changed[rel])   # _eligible_spans ∩ changed lines
```

**Consequence (load-bearing, document like 1b spec §10):** mutation-score regression is observable **only when a target's code changes and it is re-mutated.** A function whose source is untouched is never re-mutated, so test-weakening against stable code is **invisible** to this metric. 2a measures: *"this code change left function F less-tested than F's last measurement."* Narrower than "continuously monitor every function's test quality," and deliberately so.

---

## 3. The two signals

### 3.1 Per-mutant transition (core — precise, truncation-proof)

A specific mutant (by fingerprint) that was **KILLED** in the target's most-recent-prior *fully-mutated* run and now **SURVIVES (confirmed)** on a line whose content did not itself change. Unambiguous regression, no denominator.

- **Join:** `baseline.killed_fps ∩ current.survivor_fps`.
- **Truncation-proof:** compares only mutants both runs actually reached a verdict on; a budget-dropped mutant is simply absent from a set.
- **"Line didn't change" is automatic:** the fingerprint hashes `line_content` (`fingerprint.py:12`), so a changed line yields a different fp and cannot match the baseline.
- **`confirm_cap` costs recall, never precision:** a stage-1 survivor that never got full-suite confirmation (cap hit) is *not* in `survivor_fps`, so it can't produce a false transition; it will simply fire on a later drain that confirms it.

### 3.2 Per-function rate-delta (richer, noisier)

The target's **stage-1 kill-rate** dropped below its baseline rate:

```
rate(F) = killed_s1(F) / (killed_s1(F) + survived_s1(F))          # timeouts & errors EXCLUDED
```

- **Why stage-1, not the confirmed level:** `stats["tested"]` is incremented *before* the try-block (`consumers/mutation.py:145`), so it includes timeouts and errors — both of which the consumer treats as unattributable and never reports. Using it as the denominator injects noise. More importantly, defining the rate at the *confirmed* level (`killed_s1+killed_s2` over `confirmed`) makes a function "fully measured" only when **all** its stage-1 survivors got confirmed — i.e. ≤ `confirm_cap` (default 3) survivors. That makes rate-delta **structurally blind to high-survivor functions**, which are exactly the badly-regressed ones the layer exists to catch. Every *tested* mutant has a stage-1 verdict, so stage-1 has no `confirm_cap` cliff.
- **Compared only between `fully_mutated` runs** (§5.3) — never against a truncated measurement.
- **Self-delta cancels the narrow-selection bias:** stage-1's targeted `-k`/`test_<module>.py` selection systematically over-reports survivors, but comparing a function against *its own* prior stage-1 rate cancels the systematic term; and when the delta moves because a `test_<module>.py` was added or removed, that shift is exactly the test-surface change we want to track.

---

## 4. Signal fidelity: the extra×extra join invariant

**The single most important correctness rule in 2a.** Both sides of every join — `killed_fps` and `survivor_fps` — are computed **inside the consumer via one shared helper** and ride in `extra`. The analyzer joins `extra × extra` and **must never touch `Finding.id`.**

Rationale: if the killed side were computed in the consumer while the survivor side came from the normalizer's `Finding.id`, any drift in the fingerprint recipe (`normalize_line`, `normalize_path` casefold, occurrence pinned to 0) would leave the two fingerprint spaces disjoint → **zero transitions forever**, and the feature would ship "green" while detecting nothing. Computing both sides through the same helper makes the two spaces identical by construction.

The helper deliberately mirrors the normalizer's recipe (`compute_fingerprint("mutation", op, rel, line_content, 0)`), so a confirmed survivor's `extra` fp *coincidentally* equals its `Finding.id` — which gives 2b optionality — **but 2a must not depend on that equality.**

---

## 5. Data model

### 5.1 `Mutant.func`

Add a structured field to `mutation.Mutant` (`mutation.py:19-26`):

```python
@dataclass
class Mutant:
    file: str
    line: int
    op: str
    description: str
    source: str
    func: str = ""      # NEW: enclosing eligible function name (enc[2])
```

Set it in `generate_mutants` from the `_enclosing` result already computed (`mutation.py:86`, `enc[2]`). Every generated mutant has an enclosing function (`generate_mutants` skips nodes where `enc is None`, lines 87-88), so attribution is total — no catch-all bucket. Default `""` keeps the dataclass backward-compatible for any positional construction in tests.

### 5.2 `extra["mutation_scores"]` schema

The consumer builds one block per drain and returns it in `ConsumerResult.extra` (merged into `CONSUMER_RUN_FINISHED` via `drain.py:138-139` `payload.setdefault`; the key `mutation_scores` does not collide with the reserved payload keys `consumer/item_id/state/duration_s/cost/finding_count/note`):

```
extra["mutation_scores"] = {
  "schema": 1,
  "targets": {
    "<rel>::<func>": {
      "generated":    int,      # mutants generated for this function (incl. budget-dropped)
      "killed_s1":    int,      # stage-1 kills
      "survived_s1":  int,      # putative stage-1 survivors: every mutant stage-1 did NOT kill,
                                #   whatever its later fate (confirmed survivor, killed by the full
                                #   suite = killed_s2, or confirm-capped). = the existing per-function
                                #   analog of stats["survived"]. Cap-independent.
      "timeouts":     int,      # stage-1 timeouts attributed to this function
      "errors":       int,      # unattributable/argv/restore errors for this function
      "fully_mutated": bool,    # see §5.3
      "killed_fps":   [str,..], # fps of killed_s1 ∪ killed_s2 mutants
      "survivor_fps": [str,..]  # fps of CONFIRMED survivors only
    }, ...
  }
}
```

The key is `"<rel>::<func>"` (posix `rel` as diffed, `::` separator). `rel` is the repo-relative source path the consumer already iterates (`consumers/mutation.py:126`). The per-function taxonomy replaces the current item-global `stats` **as the score source**; the existing `stats`/`note` behaviour and the survivor findings are unchanged (2a is additive — it does not alter what the consumer *reports*, only what it *records*).

### 5.3 `fully_mutated` semantics

`fully_mutated(F) = True` iff **every generated mutant of F reached a stage-1 verdict** — i.e. no budget-drop, no stage-1 timeout, no error touched F's mutant set. Implemented as the single condition:

```
fully_mutated(F) = (killed_s1(F) + survived_s1(F) == generated(F))
```

Any budget-dropped, timed-out, or errored mutant makes the sum `< generated`, so the flag is `False`. `confirm_cap` truncation does **not** break it (a confirm-capped mutant still got a stage-1 verdict and is counted in `survived_s1`) — this is precisely why the rate-delta uses the stage-1 denominator. Rate-delta compares only `fully_mutated` runs; the transition core does not require it (set-intersection is truncation-proof on its own).

### 5.4 The shared fingerprint helper

```python
def _mutant_fp(rel: str, op: str, line: int, original_lines: list[str]) -> str:
    lc = original_lines[line - 1] if 0 <= line - 1 < len(original_lines) else ""
    return compute_fingerprint("mutation", op, rel, lc, 0)
```

`original` is already read per file (`consumers/mutation.py:133`); split once to `original_lines`. Called for every killed and every confirmed-survivor mutant. Fail-safe: an out-of-range line yields `lc == ""` rather than raising. Occurrence is pinned to `0` to match `PIN_OCCURRENCE` semantics and to keep both join sides consistent.

---

## 6. Components & file structure

| File | Change |
|---|---|
| `src/aramid/mutation.py` | Add `Mutant.func`; set it in `generate_mutants`. |
| `src/aramid/consumers/mutation.py` | Build per-function taxonomy + fps; add `mutation_scores` to `extra`. Existing findings/`stats`/`note` unchanged. |
| `src/aramid/mutation_score.py` | **NEW** read-only analyzer: parse taxonomy from ledger, derive baselines by seq, compute transitions + rate-regressions. No `Verdict`, no gate, no ledger writes. |
| `src/aramid/commands/mutation_score.py` + `cli.py` | **NEW** advisory query command (`aramid mutation-score [--json]`) — plain dump of current per-target scores + detected regressions. |

No changes to `policy.py`, `check.py`, `pipeline.py`, `models.py`, the ledger schema, `[mutation]` config, or the arm surface. 2a introduces **no new `EventType` and no new store** — baselines are derived from the `CONSUMER_RUN_FINISHED` history that `ledger.compact()` already preserves per `(consumer, item_id)` (`ledger.py:167-176`).

---

## 7. Analyzer API (`mutation_score.py`)

```python
@dataclass(frozen=True)
class TargetScore:
    target: str            # "<rel>::<func>"
    run_seq: int           # ledger seq of the CONSUMER_RUN_FINISHED it came from
    killed_s1: int
    survived_s1: int
    fully_mutated: bool
    killed_fps: frozenset[str]
    survivor_fps: frozenset[str]

    @property
    def rate(self) -> float | None:      # None when denominator is 0
        d = self.killed_s1 + self.survived_s1
        return self.killed_s1 / d if d else None

@dataclass(frozen=True)
class Regression:
    target: str
    kind: str              # "transition" | "rate"
    baseline_seq: int
    current_seq: int
    detail: str            # transition: fp(s); rate: "0.67 -> 0.33"
    transition_fps: frozenset[str] = frozenset()

def iter_target_scores(events) -> list[TargetScore]:
    """Every (target, run) measurement in ledger order (schema-gated; malformed rows skipped)."""

def baseline_for(scores: list[TargetScore], target: str, before_seq: int) -> TargetScore | None:
    """Most-recent-prior FULLY_MUTATED score for target with run_seq < before_seq, or None."""

def detect(current: TargetScore, baseline: TargetScore) -> list[Regression]:
    """Transition: baseline.killed_fps & current.survivor_fps (non-empty -> Regression).
       Rate: both fully_mutated and current.rate < baseline.rate (both non-None) -> Regression.
       Returns [] when baseline is None or nothing regressed."""

def latest_regressions(events) -> list[Regression]:
    """For each target's latest measurement, detect() vs its baseline_for(). Advisory list."""
```

**Baseline rule:** the baseline for a target's measurement at seq *S* is that target's **most-recent-prior `fully_mutated` measurement** (max `run_seq < S`). A later *partial* run is never a baseline and never overwrites one. This is a pure fold over history — no cursor, no state file.

---

## 8. Data flow

```
drain: consume(item) --mutate changed funcs--> per-function taxonomy + fps
        └─ ConsumerResult.extra["mutation_scores"]
             └─ drain.py setdefault --> CONSUMER_RUN_FINISHED.payload  (compact() preserves per (consumer,item_id))
                  └─ mutation_score.iter_target_scores(ledger.events())
                       └─ baseline_for() [most-recent-prior fully_mutated by seq]
                            └─ detect() --> advisory Regression list
                                 └─ `aramid mutation-score` prints scores + regressions   (NO gate, NO teeth)
```

---

## 9. Error handling & fail-open

- **Consumer:** `_mutant_fp` never raises (out-of-range line → `""`). Taxonomy assembly is inside the existing per-mutant try/except discipline; a failure counts an `error` for that function and continues — it never crashes the drain and never marks the item degraded (parallels the existing consumer contract).
- **Analyzer:** `iter_target_scores` is schema-gated (`mutation_scores["schema"] == 1`); a payload that is absent, malformed, wrong-schema, or missing keys is **skipped** (fail-open — advisory stays silent, never raises). No baseline ⇒ no regression, silently.
- **Query command:** on an empty/absent history prints "no mutation scores recorded" and exits 0. It is strictly read-only — a reporting command with no side effects and no gate participation.

---

## 10. Documented limitations (1b §10 style — state them in code + README)

1. **Code-change-triggered (§2):** silent on test-weakening against unchanged code.
2. **Rate-delta is a narrow-oracle self-delta:** silent on any function whose mutants were budget-dropped, timed out, or errored (`fully_mutated == False`).
3. **Function-key loses baseline on rename:** a renamed function has no prior `"<rel>::<func>"` key, so its first post-rename measurement has no baseline (one missed signal at the rename boundary; normal thereafter). A file rename likewise re-keys.
4. **Timeouts/errors shrink `fully_mutated` coverage:** a slow or import-fragile target may rarely qualify for rate-delta; the transition core still works on whatever verdicts exist.
5. **Transition recall bounded by `confirm_cap`:** a regression that only produces an unconfirmed (cap-truncated) survivor fires on a later drain, not the first.

---

## 11. Testing strategy (synthetic seeded history — not real longitudinal drains)

**`mutation.py`:** `generate_mutants` populates `Mutant.func` = enclosing function name; nested/multiple functions attribute correctly.

**`consumers/mutation.py`** (seed a tiny repo + throwaway worktree as the existing consumer tests do, or unit-test the taxonomy assembly in isolation):
- per-function `killed_s1`/`survived_s1`/`generated` correct; two functions in one file kept separate.
- `fully_mutated` **True** when all of F's mutants reach a stage-1 verdict; **False** under budget truncation and under a stage-1 timeout on F.
- `timeouts`/`errors` excluded from the rate numerator/denominator.
- `killed_fps`/`survivor_fps` computed via the shared helper; a confirmed survivor's fp equals `compute_fingerprint("mutation", op, rel, line_content, 0)`.

**`mutation_score.py`** (seed `CONSUMER_RUN_FINISHED` events directly in a ledger):
- **Red-first transition test (pins the extra×extra join):** seed a prior `fully_mutated` run with `killed_fps={FP}` and a current run with `survivor_fps={FP}` sharing the same line-content → `detect()` yields one `transition` Regression. (Written to fail first against an empty `detect`.)
- Rate-delta: baseline `fully_mutated` 3/3, current `fully_mutated` 1/3 → one `rate` Regression `"1.00 -> 0.33"`; current **partial** (not `fully_mutated`) → **no** rate Regression.
- Baseline selection: chooses the most-recent-prior `fully_mutated` by seq; an intervening partial run is not chosen and does not shadow the older full one.
- No baseline (first-ever measurement, or all priors partial) → `[]`.
- Fail-open: malformed/absent/wrong-schema `mutation_scores` payloads are skipped, not raised.

**`commands/mutation_score.py`:** dump shape for scores + regressions; empty-history message; `--json` structure.

---

## 12. Reuse caveat carried forward to 2b (recorded here, decided there)

If 2b emits regressions as `tool == "mutation"` findings, they inherit 1b's `auto_resolve_mutation` — module-mapped, **range-gated optimistic** resolution (resolve F's finding if the push touched F's source or added `test_<module>`). That is correct for a *surviving mutant* (a test that now covers it) but **wrong for a regression**: only a re-drain that re-measures F can truly clear it; a mere source-touch would wrongly resolve it. 1b's `mutation_gate_findings` also filters `tool == "mutation"` + status open, so a regression finding under that tool would be swept into the same seam. **2b must decide:** a distinct tool/rule that bypasses `auto_resolve_mutation` and gets its own gate seam, or a shared tool with an explicit resolution-bypass. 2a records and analyzes only; it emits no verdict-bearing findings, so it is unaffected.

---

## 13. Non-goals / YAGNI

- No gate wiring, no `Verdict`, no arming, no `check.py`/`policy.py`/`pipeline.py` changes.
- No new `EventType`, no new state store, no machine-global rollup.
- No historical backfill or migration — scores accrue from the first drain after 2a ships.
- No cross-repo aggregation.
- No trend/graphing beyond the single-baseline delta.
