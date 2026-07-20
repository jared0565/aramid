# Aramid 2c Ticket Bundle — Design

Date: 2026-07-20
Status: approved (user), pre-plan
Base: main @ 3cb45cf (752 tests green, ruff baseline 43)

## 1. Purpose

Close every deferred residual from the Phase 2c-1 (mutation) and 2c-2 (fuzz)
whole-branch reviews in one branch: four mutation tickets (I2, M1, M2, M5),
the fuzz M4 truncation-flag Minor, and the fuzz side-effect README caveat.
All six were re-verified OPEN against main @ 3cb45cf before scoping (standing
practice: tickets are re-checked against code, not trusted from the ledger).

Non-goals: 2c-1b (Stryker/JS adapter), 2c-3 (DAST), any gate-path change, any
fingerprint-scheme change beyond the scoped pin in section 5.

## 2. I2 — baseline-failing give-up counter (mutation)

Problem: `consumers/mutation.py` returns DEGRADED `"baseline failing"`
unconditionally when the item-head worktree's full suite is red
(mutation.py:92-95). The drain refuses to mark an item drained while any
consumer is degraded, so a permanently-red suite pins the item for
`item_expiry_days` and re-runs every consumer each drain.

Fix: mirror llm_review's malformed give-up, DRY'd into a shared helper.

- `consumers/base.py` gains
  `prior_note_count(ledger, consumer: str, item_id: str, prefix: str) -> int`
  — llm_review's `_malformed_attempts` logic verbatim: count
  `CONSUMER_RUN_FINISHED` events whose payload matches consumer + item_id and
  whose note starts with `prefix`.
- `consumers/llm_review.py:_malformed_attempts` becomes a thin call through
  the helper. Its existing tests must pass UNCHANGED — that is the refactor's
  teeth.
- `consumers/mutation.py` adds `_BASELINE_GIVE_UP = 3` (mirrors
  `_MALFORMED_GIVE_UP`). Placement: after the no-pytest structural skip,
  BEFORE the worktree add (cheap; no wasted worktree + baseline run). If
  `prior_note_count(ctx.ledger, NAME, item.id, "baseline failing") >= 3`,
  return OK with note `"mutation giving up: baseline persistently failing"`.
- The DEGRADED `"baseline failing"` return itself stays: drains 1–3 still
  retry, so a transiently-red suite recovers; only the 4th attempt stops
  pinning the item.

Note-prefix coupling: the give-up counter keys on the literal note string
`"baseline failing"`. The note text is therefore load-bearing; a comment at
both sites (the DEGRADED return and the counter call) records this.

## 3. M1 — killed-counter stage split (mutation)

Problem: one `stats["killed"]` is incremented at stage-1 kill
(mutation.py:126) and stage-2 confirm-run kill (mutation.py:144); the split is
invisible, and no test pins that stage-1 narrowing actually ran (a regression
to full-suite-always would be silent, just slow).

Fix:
- Replace `"killed"` with two keys: `killed_s1` (stage-1) and `killed_s2`
  (stage-2 kill of a putative survivor). No combined key — `extra` is the
  only consumer of these stats and honest per-stage counts are the point.
- New teeth test: monkeypatch `run_subprocess` to capture argvs; with a
  fixture repo that has `tests/test_<module>.py`, assert the first mutant's
  stage-1 argv references that targeted test file (not the bare full-suite
  argv) — pinning that narrowing ran.

## 4. M2 — stage-1 `-k` safety + exit-code classification (mutation)

Problem (sharper than ticketed): `_stage1_argv` falls back to
`-k <module-stem>` with the raw stem (mutation.py:46). A stem that is a
pytest keyword (`not`, `and`, `or`) or contains expression-breaking
characters (hyphen etc.) makes pytest exit 4 (usage error) — and
`returncode not in (0, 5)` counts that as a KILL. The suite never ran, but
the mutant is scored killed: a false kill, systematically, for every mutant
in that file.

Fix, two parts:
- (a) Safe fallback: the `-k` form is used only when the stem matches
  `^[A-Za-z0-9_]+$` AND is not one of `not`/`and`/`or`. Otherwise stage 1
  uses the full-suite argv — always correct, just slower (and a stage-1
  full-suite failure is a genuine kill, so no correctness interaction with
  stage 2).
- (b) Kill classification: stage-1 and stage-2 "killed" verdicts change from
  `returncode not in (0, 5)` to `returncode in (1, 2)` — 1 = test failures,
  2 = interrupted/collection error, which a mutant that breaks imports
  genuinely causes. The survivor sets are UNCHANGED: stage-1 putative
  survivor on `returncode in (0, 5)` (pass, or nothing selected), stage-2
  confirmed survivor on `returncode == 0` only. Any other nonzero (3
  internal error, 4 usage error) is `stats["errors"] += 1` and continue:
  neither killed nor survivor, unattributable — the same discipline as
  timeouts. (For stage 2 the error path means the putative survivor is NOT
  reported: consistent with "a survivor is only reported if the full suite
  passes on it".)

## 5. M5 — occurrence_index pin for variable-set consumers (normalizer/drain)

Problem: `normalize()` assigns `occurrence_index` by counting duplicates of
(tool, rule, file, normalized-line-content) within one batch
(normalizer.py:52-54). Mutation/fuzz batches are budget-truncated, so the
batch membership varies across drains; the nth duplicate's index shifts and
its fingerprint drifts → ghost open findings in the ledger that never
resolve. llm-review already solved this for itself by pinning
occurrence_index=0 (review.py:351-354).

Fix (consumer-owned pin flag; user-selected):
- `consumers/mutation.py` and `consumers/fuzz.py` each declare a module attr
  `PIN_OCCURRENCE = True`.
- `commands/drain.py:_consume_item` reads
  `getattr(CONSUMERS[name], "PIN_OCCURRENCE", False)` and passes it to
  `normalize(..., pin_occurrence=pin)`.
- `normalizer.py:normalize` gains keyword-only `pin_occurrence: bool = False`;
  when True, `occurrence_index = 0` for every finding in the batch (the
  counter is not consulted). Gate-path callers are untouched (default False).

Semantics: one finding per (tool, rule, file, line-content) — the llm-review
precedent. Duplicate survivors/crashes on identical content collapse to one
fingerprint; truncation can never drift ids. Regression-pack does NOT set the
flag: its tool is "semgrep" and its fingerprints must stay byte-identical to
the gate's for the same finding.

Migration: mutation/fuzz fingerprints shipped yesterday and the project is
pre-release — re-fingerprinting them is free (per the standing
RELEASE-MIGRATION note, this MUST be re-examined if ever done post-release).

## 6. Fuzz M4 — honest truncation flag

Problem: `consumers/fuzz.py:98-99` sets `truncated = True` at the top of the
next loop iteration once the function budget hits 0 — even when the budget
exactly fit and no candidate anywhere was dropped (exact-fit over-report).

Fix: `truncated` is set only when candidates were ACTUALLY dropped:
- the in-file slice case (`len(cands) > budget`) — unchanged; or
- on budget exhaustion, a candidacy-only sweep of the REMAINING changed
  files (the existing `_candidate_functions` AST pass; no fuzzing, no
  driver) finds >= 1 candidate.

Exact fit with an empty remainder → not truncated. Cost is bounded: AST
parse of files already in the changed set. Unreadable/missing remaining
files count as not-candidates (consistent with the main loop's skip).

## 7. Docs — fuzz side-effect caveat

One sentence in README's fuzz section: crash repro seeds assume the target is
deterministic given its arguments; functions that depend on external state
(files, network, globals, time) may not reproduce from the recorded seed.

## 8. Testing

Every code ticket lands with discriminating tests (weak-vs-strong checked):

- I2: fixture ledger with 3 prior `"baseline failing"` runs for the item →
  OK + give-up note, and NO worktree add attempted; with 2 prior → still
  DEGRADED. Helper refactor: llm_review's existing malformed-give-up tests
  pass unchanged.
- M1: stats carry `killed_s1`/`killed_s2` (asserted separately via
  monkeypatched `run_subprocess` verdict scripting); narrowing-argv pin test
  per section 3.
- M2: `not.py` (or hyphenated) module fixture → stage-1 argv is the
  full-suite form, no `-k`; monkeypatched exit-4 stage-1 → counted in
  `errors`, not `killed_s1`, mutant not scored; monkeypatched exit-4
  stage-2 → survivor NOT reported.
- M5: same finding set normalized as two different truncated subsets →
  identical fingerprints for the shared members (pin on); parity test: an
  unpinned batch still counts occurrences (regression-pack path unchanged);
  drain e2e asserts the pin flag actually flows (a duplicate-line fixture
  yields one finding id).
- M4: exact-fit budget with empty remainder → no truncated flag; one dropped
  candidate (in-file and next-file variants) → flag set.

Gates: full suite green (752 base + new), ruff parity with the 43 baseline on
branch base, whole-branch sonnet review, CI green post-merge.

## 9. Invariants (unchanged, review-checked)

- Gate path untouched: no behavior change in `pipeline.py`, `policy.py`,
  runners, or hooks. `normalize()` changes are additive-default
  (pin_occurrence=False) — gate callers byte-identical behavior.
- Drain findings remain WARN-only/detect-only; no resolve, no BLOCK path.
- Ledger event shapes untouched (I2 only READS events).
- Live tree untouchable: all mutation/fuzz execution stays inside the
  throwaway worktree.
- Consumer state discipline: OK = done/permanent-skip, DEGRADED =
  transient/retry, ERROR = failed — I2 converts a permanent condition from
  the wrong bucket (retry-forever) to the right one after 3 honest retries.
