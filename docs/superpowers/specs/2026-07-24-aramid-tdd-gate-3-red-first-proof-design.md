# Aramid TDD Gate — Sub-project 3: Red-First Proof

**Date:** 2026-07-24
**Epic:** TDD-enforcement gate (1a code-without-test, 1b mutation teeth, 2a mutation-score measurement, 2b mutation-score teeth — ALL SHIPPED, CI green @ 9a78eae)
**Status:** Design approved; ready for writing-plans.
**Scope:** the epic's final signal — verify that the range's new tests were actually *red* against the pre-change tree, with 1a-style bake-then-arm teeth in this one sub-project.

---

## 1. Context & Motivation

The epic's other signals police the *presence* and *strength* of tests: 1a fires when changed production code comes with no new test lines; 2a/2b fire when a change leaves a function less-tested than its last measurement. None of them ask whether the new tests **prove the change**. A test that already passes on the pre-change tree was never red — it demonstrates nothing about the new behavior (it may assert tautologies, test old behavior, or have been reverse-engineered from the implementation).

Sub-project 3 closes that gap with the TDD definition itself: run the range's new tests against the range's **base** tree. If they pass there, they were never red.

Complementarity (independent flags, independent bakes):
- **1a:** you added no tests → `tdd` finding.
- **3 (this spec):** you added tests that prove nothing → `red-proof` finding.
- **2b:** your change weakened existing kills → `mutation-score` finding.

## 2. Decisions (brainstorm 2026-07-24)

1. **Execution: synchronous at PRE_PUSH**, inside `run_gate`. The gate already runs the full suite synchronously (the `tests` runner is BLOCK-tier), so a focused base-tree run of just the changed test files adds seconds, not minutes — and avoids the drain-consumer tax (consumer + gate seam + resolution semantics) entirely.
2. **Granularity: changed test files, head version.** Pure git facts, mirroring 1a's "new test lines" notion. Per-test AST attribution is deferred (§10.1).
3. **Teeth in this sub-project:** 1a's shape — WARN by default, dedicated default-off `red_proof_block_armed` + `aramid arm --red-proof`. Diff-scoping + default-off + bake make one-sub-project teeth safe.
4. **Architecture: distinct tool `"red-proof"`**, own producer module, own `[red_proof]` table. Findings join the raw stream **before** `normalize()` (the 1a path) — classify is the single verdict authority (no twin-rule to keep in agreement), and overrides/suppressions apply as the standard escape hatch (which 2b's post-ratchet seam findings do not get).

## 3. The detection rule

Evaluated at **PRE_PUSH** only, honoring `cfg.red_proof["enabled"]` (default true):

1. **Base resolution:** the range's base commit, parsed from the resolved range. No meaningful base — the first-push `FULL_HISTORY` case, or modes `"all"`/`"staged"` — → skip silently, zero findings.
2. **Subjects** = files in the range that are test files (`gitutil.is_test_file`) **and** have ≥1 added line (`gitutil.diff_new_lines(root, base, head)`), after the existing ignore-path filtering. No subjects → return `[]` before any worktree work (zero cost on the common no-new-tests push — that case is 1a's business).
3. **Base worktree:** `git worktree add --detach <tmp>/wt <base>` (the `consumers/mutation.py` pattern; removal + prune + `rmtree` in `finally`, stderr leak-warning fallback).
4. **Materialize head content:** for each subject, write the **head** version of the file (via `git show <head>:<rel>` — exact even under a dirty working tree) into the base worktree at its own path, creating parent directories (a brand-new test file in a brand-new directory works). Only subject files are materialized — the rest of the tree stays at base (§10.3).
5. **Run each subject separately:** `[sys.executable, "-m", "pytest", "-q", <rel>]`, cwd = worktree, per-file timeout `test_timeout_s`. The whole scan is bounded by `wall_budget_s`; when the budget is exhausted, remaining subjects are skipped silently.
6. **Per-file verdicts:**

| pytest rc on base | Meaning | Result |
|---|---|---|
| `0` | every test in the file passes on the pre-change tree | **finding** (never red) |
| `1`, `2` | test failures / collection error — the file is red on base (a test importing a brand-new module *is* red) | red proven; nothing |
| `5` | nothing collected (helper-only file) | nothing to prove; nothing |
| timeout / other rc / any exception | unattributable | fail-open; nothing |

7. **Finding shape:** `RawFinding(tool="red-proof", rule="test-not-red", file=<test file rel>, line=0, severity_raw="medium", message="new test lines pass against the pre-change tree (never red)")`. `line=0` makes the fingerprint a function of tool+rule+path only (the 1a stability trick): the same never-red file across pushes is one finding, not churn.

## 4. Arming & verdict semantics (the 1a shape — no seam)

- Producer output joins `all_raws` **before** the second filter and `normalize()`, exactly where `tdd.scan` sits — so classify, fingerprinting, the ledger, the ratchet, and overrides/suppressions all apply unchanged.
- **`policy.classify` branch (single verdict authority — no inline twin anywhere):**

```python
    if tool == "red-proof":
        armed = cfg.red_proof.get("red_proof_block_armed", False)
        return severity, Verdict.BLOCK if armed else Verdict.WARN
```

- **Ratchet exemption:** the pre-push ratchet's exclusion set gains `"red-proof"` alongside `tdd` — a disarmed WARN must stay advisory and never auto-escalate. (Armed findings are already BLOCK from classify; the exemption only affects the disarmed case.)
- **Fresh clone:** an armed BLOCK is genuine via `_has_genuine_block` → survives the downgrade, with no `check.py` change (1a §2.2 consequence).
- **Escape hatches:** `aramid override` works (findings are in the normal pre-normalize stream); disarm; or make the test genuinely red.
- **Diff-scoped safety:** only test files changed in the push are ever run — arming can never wall-block pre-existing repo state.

| State | Verdict | Blocks a push? |
|---|---|---|
| Disarmed (default) | WARN, ratchet-exempt | Never — advisory |
| Armed | BLOCK via classify | Yes, per never-red changed test file |

## 5. Components & file structure

| File | Change |
|---|---|
| `src/aramid/red_proof.py` | **NEW** — the producer (§3): base resolution, subject selection, worktree lifecycle, per-file runs, verdict mapping. Never raises into `run_gate`. |
| `src/aramid/pipeline.py` | Call the producer in the PRE_PUSH block next to `tdd.scan` (pre-normalize); add `"red-proof"` to the ratchet exemption. |
| `src/aramid/policy.py` | The §4 classify branch. |
| `src/aramid/config.py` | `red_proof: dict` field on `Config` + loader line (mirrors `tdd`/`mutation`). |
| `src/aramid/data/defaults.toml` | The §6 `[red_proof]` table. |
| `src/aramid/commands/arm.py` | `--red-proof` → writes `red_proof_block_armed = true` into `[red_proof]` (section-scoped writer + globally-unique key regex — the `_arm_mutation_score_text` pattern). |
| `src/aramid/cli.py` | Flag joins the mutually-exclusive arm group; dispatch passes it through. The 2b lesson applies: the five existing `cmd_arm` dispatch-test lambdas must be widened with the new kwarg. |
| `README.md` | Red-first-proof subsection + §10 limitations. |

**Not touched:** `check.py`, `models.py`, ledger schema, all consumers, `mutation_gate.py`, `mutation_score_gate.py`, `tdd.py`. No new EventType, no new store.

## 6. Config schema (defaults.toml)

```toml
[red_proof]                      # NEW (sub-project 3)
enabled = true
red_proof_block_armed = false    # bake-then-arm; `aramid arm --red-proof` flips it
wall_budget_s = 120              # whole-scan wall clock (all subject files)
test_timeout_s = 60              # per pytest invocation against the base tree
```

Additive; absent keys default as above, so existing repos are unaffected until they opt in.

## 7. Data flow

```
git push → check.cmd_check(PRE_PUSH) → pipeline.run_gate
  ├─ runners (incl. full test suite) → all_raws
  ├─ tdd.scan(ctx)            ────────────→ all_raws     (1a)
  ├─ red_proof.scan(...)  [NEW] ──────────→ all_raws     (base worktree + focused pytest per subject)
  ├─ normalize(…, classify)   tool=="red-proof": armed ? BLOCK : WARN   [NEW branch]
  ├─ ledger.record_run → ratchet (red-proof WARN exempt) → overrides/suppressions
  └─ exit code → fresh-clone downgrade unless _has_genuine_block (armed ⇒ genuine)
```

## 8. Error handling & fail-open

- The producer never raises into `run_gate`: any git failure, worktree-add failure, decode error, or unexpected exception yields zero findings (a broken producer must never block a push or crash the gate — the whole-file fail-open discipline).
- Worktree cleanup in `finally`: `worktree remove --force`, `worktree prune`, `rmtree(ignore_errors=True)`, stderr leak warning on failure (verbatim `consumers/mutation.py` pattern).
- Budget/timeout exhaustion skips silently — never a finding, never an error.
- No secrets are produced (no `RawFinding.secret`); nothing joins the redaction path.

## 9. CLI

`aramid arm --red-proof` flips `red_proof_block_armed` in the repo's `aramid.toml` (comment-preserving single-key rewrite into `[red_proof]`; prints before/after state, mirroring the other arm flags). Joins the existing mutually-exclusive group, so `arm --red-proof --tdd` exits 3.

## 10. Documented limitations (module docstring + README)

1. **Whole-file verdict:** the per-file run is red iff *any* test in the file fails on base — an old test in a changed file failing on base masks a never-red new test. Recall loss only, never a false positive. Per-test AST attribution deferred.
2. **Collection-error leniency:** any import failure on base counts as red — including a file that is trivially broken on base for reasons unrelated to the new behavior.
3. **Only subject files are materialized at head:** a new test that depends on head changes to non-test files it imports (e.g. a root-level `conftest.py`, a new fixture module) sees the base versions and usually collection-errors → counts as red (folds into #2).
4. **Range-mode only:** first-push `FULL_HISTORY` and modes `all`/`staged` skip silently — no base, no proof.
5. **Single run, no flake retries:** an order-dependent or flaky test may pass or fail on base spuriously; bake-then-arm absorbs this before teeth.
6. **Push-time cost:** seconds per changed test file (worktree add + focused pytest), bounded by `wall_budget_s`; over budget the remainder is skipped silently, so a huge test-file push degrades to partial coverage, never to a block or a hang.

## 11. Testing strategy (git fixtures, 1a style — real repos, no mocks)

**Producer (`red_proof.py`), on seeded fixture repos:**
- Genuinely red-first push (new test fails on base, passes on head) → no finding.
- Never-red push (new test passes on base — e.g. `assert True` or asserting pre-existing behavior) → one finding for that file; verify tool/rule/file/line=0 and message.
- No added test lines in range → producer returns `[]` **before** any worktree is created (assert zero subprocess cost path).
- New test file importing a module that only exists at head → collection error on base → red → no finding.
- Changed helper-only test file (no collectable tests) → rc 5 → no finding.
- Budget exhaustion: `wall_budget_s=0` → all subjects skipped, `[]`, no raise.
- Fail-open: unresolvable base / broken git → `[]`, no raise. Worktree is cleaned up (no leaked `aramid-*` temp dirs / registered worktrees).
- Fingerprint stability: same never-red file across two pushes → same finding id.

**classify:** armed → BLOCK, disarmed → WARN (severity MEDIUM asserted in both — the 1a T2a lesson).

**Ratchet exemption (red-proof):** a new disarmed `red-proof` WARN does not escalate at pre-push (red-proof: without the exemption it would — mirrors 1a's tdd exemption test).

**arm/CLI:** `--red-proof` round-trip (substitute / section-insert / fresh-section / comment-preserving / idempotent); key-regex non-interference with the other arm keys; dispatch test + mutual-exclusion test; the five existing dispatch lambdas widened (2b lesson).

**config:** defaults parse; `[red_proof]` table surfaces on `Config`.

**End-to-end (real git + `cmd_check`, mirrors the 1b/2b e2e pattern):** disarmed never-red push → warns, doesn't block; armed never-red push → blocks (exit 1); armed genuinely-red push → passes; armed BLOCK survives a fresh ledger (`_has_genuine_block`).

**Final task:** README + ruff + full suite (CONTROLLER runs it in background, ~14 min; subagents run only focused files).

## 12. Non-goals / YAGNI

- No per-test AST attribution (whole-file verdicts only).
- No drain consumer, no gate seam, no ledger persistence beyond the normal finding stream, no new EventType.
- No flake-retry machinery.
- No materialization of non-subject files at head; no dependency analysis.
- No pre-commit enforcement; no non-Python stacks (keys on the existing Python test-file convention; stack-awareness is the same extension point as 1a).
- No graph involvement of any kind.
