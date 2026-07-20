# Aramid Cleanup Bundle — Design

Date: 2026-07-20
Status: approved (user), pre-plan
Base: main @ 8390ce9 (772 tests green, ruff baseline 43)
Branch: feat/cleanup-bundle

## 1. Purpose

Seven verified-backlog cleanup items (from the 2026-07-20 18-agent survey,
each re-checked against current code), closed in one branch. Mix of latent-bug
de-risking, a security-gate drift guard, a correctness fix, a test-coverage
gap, and two documentation/disposition items. None overlap the release-hardening
merge.

Non-goals: roadmap features 2c-1b (JS mutation) and 2c-3 (DAST), each a separate
spec. No gate-path behavior change except where a fix's effect IS the intended
change (items 3 and 7).

## 2. Item 1 — compact() landmine (preventative)

Both bugs are dead-code-gated: `Ledger.compact()` (`ledger.py:107`) has no `src/`
call sites, and the only way ledger events shrink is via compact(), so neither
bug is reachable today. This item de-risks them for whenever a compaction command
is wired.

**Bug (2) — give-up history loss.** `compact()` keeps only the latest
`CONSUMER_RUN_FINISHED` row per type (`ledger.py:158-166`, `latest_singleton`),
but `consumers/base.py:prior_note_count` counts per-(consumer, item_id) rows with
load-bearing note prefixes (llm_review malformed give-up, mutation baseline
give-up). Collapsing to one row silently resets those counters.
Fix: `compact()`'s keep-set additionally preserves every `CONSUMER_RUN_FINISHED`
row that carries a `consumer` + `item_id` payload (the give-up-relevant rows),
not just the newest one. The RUN_FINISHED / TRIAGE_RECORDED singletons are
unaffected.

**Bug (1) — autolearn posterior double-count.** `autolearn.rollup`
(`autolearn.py:234-236`) resets `cursor` to 0 when `cursor > len(events)` (a
shrunk/compacted ledger) but then folds the surviving events onto the
*already-populated* posteriors it deep-copied from `state` → double-count. A
correct rebuild is cross-repo (posteriors aggregate across every registered repo,
keyed by arm-cell, not by repo), so a single per-repo rollup call cannot rebuild
correctly.
Fix: when `cursor > len(events)`, `rollup` returns the state with the fold
**skipped** (no double-count, no corruption) — correct counts after a compaction
require a global `aramid autolearn --rebuild`, which replays all registry ledgers
into fresh posteriors. Document that contract in both `compact()`'s LANDMINE
comment and `rollup`'s docstring (the current "restarts from 0" wording is
misleading — it implies a safe rebuild that doesn't happen).

**Tests:** (a) a ledger with three `"baseline failing @ <head>"`
`CONSUMER_RUN_FINISHED` rows for one item survives `compact()` with all three
give-up rows intact (pre-fix: 1 survives). (b) a `rollup` call with
`cursor > len(events)` does NOT increase posteriors beyond a single fold
(pre-fix: doubles).

## 3. Item 2 — shared confirmed-critical-LLM BLOCK predicate

The predicate `source==llm & confirmed & severity==critical` is hand-mirrored at
three sites: the gate (`review.py:479-481`, enum-based + `armed`), the override
refusal (`override.py:58-62`, raw-rec string compares, deliberately *without*
`armed`), and a status count (`status.py:160-161`). Future drift between the gate
and the override refusal is a silent-suppression risk on a BLOCK gate.

Fix: add `review.is_confirmed_critical_llm(rec: dict) -> bool` returning
`rec.get("source")=="llm" and bool(rec.get("confirmed")) and
rec.get("severity")=="critical"` — the raw-rec subset only, **never** `armed`.
- `review.py` gate verdict becomes `Verdict.BLOCK if armed and
  is_confirmed_critical_llm(rec) else Verdict.WARN` (equivalent: `rec["severity"]
  =="critical"` iff the parsed enum is `CRITICAL`; a malformed severity is
  non-critical either way → WARN). The Finding is still built with the parsed
  enum severity; the per-rec malformed try/except fail-safe stays.
- `override.py:58-62` calls the helper directly (armed-independent — the
  retroactive-arming defense, `override.py` docstring — must NOT gain `armed`).
- `status.py:161` reuses the helper.

Test: an override attempt on a `source==llm, confirmed=True, severity==critical`
rec is refused (exit 3) regardless of arming; the gate yields WARN when
`armed=False` and BLOCK when `armed=True` for the same rec.

## 4. Item 3 — deps force_refresh wiring

`runners/deps.py` reads `getattr(ctx, "force_refresh", False)` to bypass the
≤24h audit cache, but `RunContext` (`runners/base.py:26`) never declares the
field and no production caller sets it, so `check --all` serves a stale cache
instead of re-auditing — contradicting the deps docstring.

Fix: add `force_refresh: bool = False` to `RunContext` (additive, like
`extra_semgrep_configs`; keeps every construction site valid). `pipeline.run_gate`
sets `force_refresh=True` when `mode=="all"` so a full audit re-runs pip-audit /
npm/pnpm/yarn audit fresh. Update the deps docstring (`deps.py:31-33`) — the
"pipeline isn't implemented yet" note is stale.

Behavior change (intended): `check --all` (and CI's `check --all --strict`) now
re-audits deps instead of reusing a cache; a new CVE that appeared within the 24h
window is no longer masked. `getattr` fallback stays for pre-commit/pre-push
contexts (cache still used there).

Test: `RunContext().force_refresh is False`; a `mode="all"` run bypasses a
pre-seeded cache (deps re-invokes the audit), a non-"all" mode reuses it.

## 5. Item 4 — triage content_signal scoped diff

`triage.py:151` fetches `gitutil.diff_text(root, base, head)` with no `paths=`,
so `content_signal` scans the full unfiltered diff body — a tracked graphite
artifact's churn can nudge the advisory triage score, even though `paths` was
filtered through `config.filter_paths` (`triage.py:150`).

Fix: scope the diff to the filtered paths WITH the empty-set guard —
`diff = gitutil.diff_text(root, base, head, paths=paths) if paths else ""`.
The guard is essential: `diff_text`'s pathspec is `["--", *paths] if paths else
[]`, so passing an empty `paths` would fall back to the FULL diff — reintroducing
the bug at its worst on an all-graphite changeset (exactly the target case). When
every changed file is filtered out, `content_signal` sees an empty body and
contributes nothing.

Test: a non-empty risky diff body (`+ exec(payload)`) attributed to a tracked
graphite path (`graph-out/graph.json`, filtered out of `paths`) yields no
`risky-content` reason (existing graphite triage tests pass `""` diffs and so do
not exercise this — the new test feeds a real body).

## 6. Item 5 — bounded post-kill drain test

`runners/base.py:99-105`: on `TimeoutExpired`, `run_subprocess` calls
`_kill_tree(proc)` then a BOUNDED `proc.communicate(timeout=5)` then `proc.kill()`.
The only timeout test (`test_runner_base.py:42-55`) is self-declared happy-path:
`_kill_tree` succeeds, so the post-kill drain returns immediately and the 5s cap
is never exercised. The failed-kill safety branch (the fix's whole motivation)
has no reproduction.

Fix: refactor the hardcoded `5` into a module constant `_POST_KILL_DRAIN_S = 5.0`
so a test can shrink it. Add a test that monkeypatches `_kill_tree` to a no-op
(child survives the kill attempt), runs `run_subprocess` with a short outer
timeout against a long-sleeping child, and asserts state is TIMEOUT and wall time
is bounded near the (shrunk) cap and far below the child's sleep — proving the
`communicate(timeout=...)` cap is what bounds the wait and `proc.kill()` reaps the
survivor. No production behavior change (constant == current literal).

## 7. Item 6 — update-rules formal close

`commands/update_rules.py:41` prints a "STUB -- no network fetch performed"
message and only reports the pinned source + vendored path. The vendored
`owasp.yml` already works (scans pass today), and a real pinned fetch has an
unresolved design (semgrep's `p/owasp-top-ten` is a live registry pack, not
tag-addressable) and can't be end-to-end tested offline.

Fix (user disposition: formally close): downgrade the message from "STUB" to a
documented "offline by design — the OWASP ruleset is vendored at build time; to
refresh, re-vendor from a pinned semgrep-rules ref and rebuild the package."
Update the module docstring accordingly. A one-line README note under the gate
description. The command stays informational and exits 0.

Test: `cmd_update_rules` output contains the "vendored at build time" wording and
NOT "STUB"; exit code 0.

## 8. Item 7 — pnpm/yarn drift guard + provenance

`parse_pnpm` (`deps.py:263`) does `data.get("report",{}).get("advisories") or
data.get("advisories", {})` → any unrecognized shape yields `{}` → 0 findings
silently (missed CVEs). `parse_yarn` (`deps.py:271-290`) `continue`s past any
line lacking a `children` dict → a format shift yields 0 silently. Both parsers'
JS shapes are reconstructed, not live-captured (`deps.py:19-26`).

Fix (user disposition: add a drift guard) — a **shape-shift** detector that does
NOT depend on unverified exit-code semantics:
- pnpm: after an OK result whose payload is a non-empty dict, if NEITHER
  `report.advisories` NOR a top-level `advisories` key is PRESENT (key existence,
  not truthiness) → return CRASHED (unrecognized shape; a genuinely clean pnpm
  audit still carries an empty-but-present advisories container). CRASHED →
  degraded → surfaces for manual check (fail toward visibility, the
  security-gate-safe direction).
- yarn: after an OK result, if there is ≥1 non-empty JSON-parseable line but NONE
  produced a finding (all lacked a `children` dict) → CRASHED. Empty/whitespace
  output (a clean audit) is untouched.
- Provenance: pin the fixtures' documented tool version in a header comment on
  `tests/fixtures/pnpm-audit.json` / `yarn-audit.json`.

Placement: in `parse_pnpm`/`parse_yarn` the parser can only return findings, so
the guard raises a sentinel the runner path converts to CRASHED — OR the guard
lives in `run_js`/the `_or_crashed` helpers where the state is set. The plan will
pick the seam that keeps `parse_*` pure and the state on `RunnerResult`; the
observable contract is "unrecognized-but-present shape → CRASHED, not silent [].".

Tests: the known-good pnpm/yarn fixtures still parse to their expected findings
(regression-lock, proving no false-positive); a crafted pnpm payload with a
drifted container and a crafted yarn payload with unrecognized-shape lines each
yield CRASHED (the new teeth).

**Post-review mitigation (whole-branch review, user disposition "add a
mitigation first").** The initial CRASHED disposition above has a blast-radius
problem the review surfaced: item 3 makes CI's `check --all --strict` always
live-audit, so a CRASHED deps runner → `degraded_tools` → exit 2 → `--strict`
→ exit 1. If the hand-authored (unverified) pnpm/yarn shape ever differs from a
real clean-audit shape, EVERY clean pnpm/yarn CI run would hard-fail
permanently. Superseding disposition: an unrecognized-but-present shape now
surfaces as a **non-blocking advisory WARN finding** (`deps-audit-shape-
unrecognized`, medium severity — below the deps `critical` block threshold),
emitted by `parse_pnpm`/`parse_yarn` (which keeps `run_js` shape-agnostic and
the state OK, so deps is never degraded by drift alone). The finding is exempt
from the pre-push new-warning→BLOCK ratchet (`pipeline.py`, keyed on the rule
name) so it never hard-blocks a push either. It is still visible in every
findings report — never a silent `[]` — but a possible false-positive can no
longer break CI. The non-dict-`advisories` crash the review found (a present
but non-dict container reaching `_parse_advisories_dict`) is also closed:
`_pnpm_shape_recognized` requires a dict container, so that shape routes to the
advisory WARN instead of an uncaught `.items()` crash.

## 9. Testing & gates

- TDD per item: failing test → red → minimal impl → green → commit. One commit
  per item (item 1 and item 7 may be two commits each given two sub-fixes).
- Full suite green (772 base + new). Ruff parity with the baseline measured at
  branch creation.
- Whole-branch adversarial review (sonnet subagent).
- CI green on the merge commit.

## 10. Invariants (review-checked)

1. **Gate path** changes only via item 2 (behavior-equivalent predicate
   refactor), item 3 (`--all` re-audit — the intended fix, cache still used at
   pre-commit/pre-push), and item 7 (drift → non-blocking advisory WARN, see
   the post-review mitigation in §8 — fail toward visibility WITHOUT a hard CI
   failure on a possible false positive). No other gate behavior moves.
2. **No BLOCK downgrade**: item 2 keeps the gate's `armed & confirmed & critical`
   BLOCK and the override's armed-independent refusal; the helper is the shared
   subset, never widened with `armed`.
3. **Dead-code de-risking**: item 1 changes only paths reachable after a
   (non-existent) compaction; no live behavior moves.
4. **Additive RunContext**: item 3's `force_refresh` default `False` keeps every
   existing construction site and adapter valid.
5. **Fail toward visibility**: item 7 surfaces unrecognized dep-audit shapes as
   a visible non-blocking advisory WARN finding rather than silently clean —
   never the reverse, and never a hard CI failure on a possible false positive
   (post-review mitigation, §8).
