# Aramid LLM-subsystem hardening bundle — design

Date: 2026-07-19
Scope decision (user, on record): bundle = autolearn merge tickets (A) + Phase 2b
LLM-subsystem deferrals (B). Phase 1/2a residuals (hooks.py encoding, override-reason
gap, shim self-timeout) stay on the shelf.
Branch: `feat/llm-hardening` off `main @ 75b46c9`.

## 0. Scope corrections found during design (code-verified)

**Refute-budget cap: ALREADY SHIPPED — no work.** The Phase 2b deferred ticket
"per-drain refute cap + dedupe" was implemented in commit `1786328` during the
reviewer-model-selection feature and survives in current `consumers/llm_review.py`:
`max_refutes_per_drain` (default 6), `_refutes_used` per-drain counter reset by
`begin_drain()`, fresh-vs-ledger AND fresh-vs-itself dedupe (`seen_fids`), fail-safe
clipping (capped-out critical → `apply_refute(cand, True, "refute unavailable
(drain refute budget exhausted)")` → demoted, `confirmed=False`, never blocks),
`refute_clipped=N` in the run note, and `outcome:"unavailable"` telemetry entries.
Tested in `tests/unit/test_llm_consumer.py` and `tests/unit/test_config.py`.
The user's decision (per-drain cap + dedupe, DEGRADED-visible, fail-safe) matches
the shipped behavior; the progress-ledger deferral entry was stale.

All other tickets below were re-verified OPEN against current code.

## 1. Items

### Item 1 (behavior): arm.py key-regex family — inline comments + root-key placement

Current: `_KEY_RE` / `_LLM_KEY_RE` (`arm.py:18-19`) end in `\s*$`; `_AL_KEY_RE`
(`arm.py:22`) ends in `[^\S\n]*$`. A trailing inline comment
(`semgrep_block_armed = false  # note`) defeats all three → the "key exists"
branch misses → a duplicate key is inserted → `tomllib` raises "Cannot overwrite
a value" on next load (fails closed = exit 3 blocks, but the user's config file
is corrupted and must be hand-repaired).

Fix:
- Extend all three regexes to match an optional trailing comment and **preserve
  it** on rewrite: capture `(?P<comment>[^\S\n]*#[^\n]*)?` before `$` and re-emit
  it after the new value via a substitution function (not a fixed string).
- Root-key placement (same function, composing hazard): the no-key semgrep path
  (`arm.py:94-96`) appends `semgrep_block_armed = true` at EOF; if the file ends
  inside a `[section]` (e.g. `[llm]`, which `arm --llm` itself creates), the key
  lands in that table → root lookup misses → arm prints success but is
  ineffective. Fix: when the key is absent, insert it before the FIRST section
  header (`_NEXT_SECTION_RE`) if one exists, else append at EOF. Reachable only
  on hand-edited configs (init stub always writes the root key), but the
  inline-comment bug is exactly the hand-edit path that falls through to it.

Tests: per-family rewrite tests with inline comments (comment preserved verbatim,
exactly one key after rewrite, `tomllib.loads` round-trips), the
`[llm.autolearn]` scoped variant with a commented `armed` line, and a
root-key-insertion test with a file ending in a `[llm]` section (key must land
at root; `load_config` sees `semgrep_block_armed=True`).

### Item 2 (behavior): self-refute audit flag + README correction

Current: `review.select_refuter` (`review.py:85-93`) falls back to the
reviewer's own arm when no other provider is available. Telemetry
(`refute_infos`) records `refuter_provider`, so self-refute is inferable by
joining against the served provider, but nothing marks it explicitly and the
persisted finding carries no trace. README (lines ~60, ~104) says
"cross-provider refute" without qualification.

Fix (user decision: audit flag + README fix; keep single-provider confirmation
working):
- Each `refute_infos` entry gains `"self_refute": bool` (refuter provider ==
  reviewer provider).
- When a refute VERDICT comes from a self-refute, tag the reason passed to
  `apply_refute` so the persisted explanation reads
  `[refute survived (self-refute): …]` / `[refuted (self-refute): …]` — the
  marker rides the existing reason-text channel; `apply_refute` itself is
  UNCHANGED. Budget-clipped entries keep `self_refute: false` (no call made).
- README: qualify the cross-provider claim — falls back to self-refute when only
  one provider is installed, flagged in telemetry and the finding record.

Invariant: telemetry/reason-text only; no `confirmed`/`refuted` value can change.

### Item 3 (behavior): openrouter spend visibility on timeout / write-fail

Current (`providers/openrouter.py`): a `TimeoutError` (line 60) returns with no
spend record even though the call may have been billed server-side; a spend-log
write failure (lines 94-95) is a silent `except OSError: pass` — both under-count
month spend, eroding the cap.

Fix (visibility only; cap math untouched):
- On timeout: best-effort append a spend record
  `{"at": …, "provider": NAME, "model": model, "tokens_in": 0, "tokens_out": 0,
  "cost_usd": 0.0, "note": "timeout — cost unknown"}` so audits see the call
  happened. Verified against `spend.py`: `append_spend` JSON-dumps any dict (the
  extra `note` key is harmless) and `month_spend_usd` reads only
  `provider`/`at`/`cost_usd`, so a 0.0 record cannot loosen the cap and the
  marker's valid `at` cannot trip the fail-closed malformed-line path.
- On ANY spend-append `OSError` (success path and timeout path): print a
  one-line warning to stderr (`aramid: openrouter: spend log write failed — month
  spend is now under-counted`) instead of silence.

Tests: timeout path appends the marker record; append-OSError prints the stderr
warning and still returns the response; cap behavior unchanged (existing tests).

### Item 4 (behavior): consumer telemetry — cost/tokens on unparseable cascade/audit responses

Current (`consumers/llm_review.py`): the cascade path adds `r2.cost_usd` /
tokens only when `parse_review_response` succeeds (lines 241-246); the audit
path likewise only inside `if ca is not None` (lines 274-278). An unparseable
response from a real call drops its cost/tokens from telemetry and the
`ConsumerResult.cost` sum — money spent, books wrong.

Fix: move cost/token accumulation to "call returned without transport error"
(i.e. right after each `_call` when `r.error` is empty or ERR_MALFORMED —
matching how the primary review call at lines 200-202 accounts before parsing).
`_reviews_used` increment stays parse-gated for cascade (an unparseable cascade
should not consume a review slot — current semantics kept).

Tests: cascade unparseable → cost/tokens present in note/selection; audit
unparseable (`performed: False`) → cost/tokens still accumulated.

### Item 5 (behavior): T6 — fail-open wrap for `target_arm` / `bucket_for`

Current: `tgt = review.target_arm(...)` and `bucket = autolearn.bucket_for(...)`
(`llm_review.py:134-135`) sit OUTSIDE the fail-open try (which starts at 140).
Verified non-raising today; this is structural hardening so a future change
can't crash the item (drain's per-repo isolation would catch it, but the item
would record as consumer error instead of degrading to ladder behavior).

Fix: wrap both in their own try/except → on exception `tgt = None`,
`bucket = "plain"` (verified: `bucket_for`'s default for unmatched reasons,
`autolearn.py:82-89`).
Downstream already guards on `tgt is not None`; `eff_score = item.score` path
unchanged. A successful computation's result must be bit-identical to today.

Test: monkeypatch `bucket_for` to raise → consume completes, review still
served, selection records the fallback bucket; same for `target_arm`.

### Item 6 (tests-only): T8b — cascade guard paths + budget call count

- Cascade triggered but `next_arm_above` returns None (already at frontier) →
  no extra call (`attempts` length pinned).
- Cascade triggered but next arm's provider not in `avail` → no extra call.
- Cascade triggered with review budget exhausted (`_reviews_used >= max_items`)
  → no extra call.
- Existing budget test additionally asserts total provider CALL COUNT (not just
  outcome) so a budget leak is caught even if state stays right.

### Item 7 (tests-only): T13 — doctor foreign-state-version DEGRADED branch

Write a state file with `{"version": "<not STATE_VERSION>"}` → doctor's
autolearn probe line reports `DEGRADED autolearn    foreign state version` with
the `--rebuild` hint (`doctor.py:306-308`). Companion: unreadable-state branch
if not already covered.

### Item 8 (tests-only): T3 — `refuted` materialization assertion

Append a FINDING_DETECTED event whose payload has `refuted: True` through the
real Ledger → `open_findings()` record carries `refuted == True` (and False
default when absent). Locks the snapshot key (`ledger.py:19`) end-to-end.

### Item 9 (comments/fixture): compact() landmines + `_cfg` pin composition

- `Ledger.compact()` (`ledger.py:106`) gains a landmine comment: compact is
  currently DEAD CODE; wiring it in will (a) shrink the event list below
  autolearn rollup cursors → `rollup` resets cursor to 0 and RE-FOLDS the
  surviving events → posterior double-count (`autolearn.py:234-236` documents
  the reset, not the double-fold), and (b) destroy `_malformed_attempts`
  per-item history (compact keeps one global latest CONSUMER_RUN_FINISHED,
  `ledger.py:152`) → the malformed-give-up counter resets. Any wiring must
  version/rebuild autolearn state and accept the give-up reset.
- `tests/unit/test_llm_consumer.py::_cfg` (line 63-64): a test passing its own
  `autolearn={...}` REPLACES the hermetic dict — `audit_every` silently reverts
  to the code default 8 → hash-sampled audits desync scripted providers. Fix:
  merge the override over the hermetic base
  (`{"enabled": True, "armed": False, "audit_every": 0, **over.pop("autolearn", {})}`)
  so `audit_every=0` persists unless a test sets it explicitly. Verify no
  existing test relied on replacement semantics (grep `autolearn=` call sites).

## 2. Invariants (whole-branch review checks all four)

1. **Block path**: the only source of `confirmed=True` remains `apply_refute` on
   a survived critical; new markers are telemetry/reason-text only; the gate
   reads `confirmed`, never `self_refute`/`refuted`.
2. **Fail-open direction**: Item 5 can only turn a crash into ladder-default
   behavior, never change a successful computation. Item 4 only ADDS
   already-spent cost/tokens.
3. **Money fail-closed**: cap enforcement (`_under_cap`, `month_spend_usd`)
   untouched; the 0.0 timeout marker cannot loosen the cap; write-fail becomes
   LOUD, never permissive.
4. **Arm rewrite safety**: every rewrite output must `tomllib.loads` cleanly
   with exactly one target key, comments preserved byte-for-byte.

## 3. Testing strategy

Every behavior change lands with tests that FAIL on the old code (reviewer
reverts the fix to confirm red — the repo's teeth-proof convention). Test-only
items are pure additions. Full suite (665 at branch base) stays green; ruff
clean on new/changed code; CI green before merge.

## 4. Task grouping (approach A — user-approved)

| Task | Content | Kind |
|------|---------|------|
| 1 | Item 1: regex family + root-key placement + tests | behavior |
| 2 | Item 2: self-refute flag + README | behavior |
| 3 | Item 3: openrouter spend visibility | behavior |
| 4 | Items 4+5: consumer cost accounting + fail-open wrap | behavior |
| 5 | Items 6+7+8: test batch (cascade guards, doctor branch, refuted materialization) | tests-only |
| 6 | Item 9: compact() landmines + `_cfg` pin composition | comments/fixture |

Tasks 1-3 are independent; Task 4 touches `llm_review.py` alone; Task 5 adds
tests over Task 4's final code (ordered after it); Task 6 independent.
Whole-branch review at the end (sonnet reviewers by default; opus dispatches
glitched 3× last feature — resume via SendMessage if attempted), then
finishing-a-development-branch with the user's merge choice.

## 5. Out of scope (explicitly)

Phase 1/2a residuals: `hooks.py:65` git-config encoding, override-reason
propagation gap, Phase 2a shim 2s self-timeout. Refute cap (shipped, section 0).
No changes to policy.py, check.py, pipeline.py, or any gate/verdict logic.
