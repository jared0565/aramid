# Aramid Stack/Test Detector Fix — Implementation Plan

**Date:** 2026-07-26
**Branch:** `feat/detector-stack-fix` (base `f462d27`)

## Context

Onboarding aramid to its first non-self repo (`pawscout-worker`, a Cloudflare
Worker / TypeScript project) surfaced a product bug that blocks **every** push
on **most** JS/TS repos. All three defects below were measured live on
2026-07-25/26, not inferred:

| # | Defect | Evidence |
|---|---|---|
| 1 | `detect_tests` calls a repo "pytest" because a `tests/` dir merely **exists** | pawscout's `tests/` is all `.test.ts`, **zero** `test_*.py`; `detect_tests` returned `{'npm','pytest'}` |
| 2 | `detect_stacks` calls a repo "python" on **one** stray file | the only `.py` outside `node_modules` is `.claude/graph-reminder.py`; returned `{'js','python'}` |
| 3 | `runners/tests.py: run()` checks `"pytest" in kinds` **before** npm, with no tiebreak | ran `pytest -q` on a TS repo → **rc 5, "no tests ran"** → blocking `tests-failed` → `tests` is BLOCK-tier → exit 1 at pre-push |

Measured end-to-end on pawscout: gate exit 1 in 20s with
`pytest:tests-failed "pytest exited 5: no tests were collected"`. The
workaround (`[tests].command = ["npm","test"]`) works — verified, exit 1 in
128s with `npm:tests-failed`, i.e. the *right* suite finally running — but it
requires every JS/TS repo to hand-write config before aramid is usable.

Also in scope: both detectors `rglob` through `node_modules`. `ignore_paths`
(which already contains `node_modules/`) is applied later in
`config.filter_paths`, never in the detectors.

## Global Constraints

1. **Do not regress aramid's own gate.** aramid has **no** `package.json`;
   `detect_stacks(root, root)` → `{'python'}` and `detect_tests(root)` →
   `{'pytest'}` today. Both must still hold after this change. Verify by
   running the detectors against the repo root, not by reasoning.
2. **Dogfooding will NOT exercise the new code path.** aramid's own
   `aramid.toml` sets `[tests].command`, which short-circuits detection
   entirely in `runners/tests.py: run()`. A green aramid pre-push proves
   nothing about this change. Fixture repos are the only real proof.
3. **Mirror `runners/deps.py`, do not invent a new aggregation.** That module
   already solves "one registry key, two underlying tools":
   `_run_mixed(ctx)` returns a `RunnerResult` carrying a `.sub_results` list,
   and `parse()` recurses via `getattr(result, "sub_results", None)`.
4. **INVERT deps' combined-state rule.** `deps._run_mixed` uses OR
   (`ok = py.state is OK or js.state is OK`) — lenient, correct for audits.
   `tests` requires the opposite: **worst-state-wins**, both suites must be OK
   for the combined result to be OK. Copying deps verbatim silently inverts
   the requirement this task exists to satisfy.
5. **`.tool` on the combined result is the registry key `"tests"`**, matching
   `deps` (`RunnerResult("deps", ...)`). Per-suite `.tool` values
   (`"pytest"`, `"npm"`) live on the sub-results. This is load-bearing:
   `runners/tests.py: parse()` branches on `result.tool == "pytest"` for the
   rc-5 message, and `commands/check.py:34-47` documents that
   `degraded_block_tier` is read off `GateResult` **precisely because**
   `RunnerResult.tool` can diverge from the registry key. Do not "fix" that
   divergence here.
6. **No behaviour change when only one suite is detected.** Single-suite
   repos must take the existing single-result path, not a one-element
   aggregate.
7. Preserve the rc-5 wording shipped in the `[tests]` work — it names
   `[tests].command` and is doing its job in the field.
8. `python -m` invocation convention. Never edit `graph-out/`. No backticks
   inside `git commit -m` strings (use `-F` with a file or a stdin heredoc).
9. Red-first proof required per task: show the new tests failing before the
   source change, passing after.

## Design decisions (settled — do not re-litigate)

- **Dual-stack policy: run BOTH suites and aggregate.** Chosen by the user
  over "pick one, warn loudly" and "refuse to guess". Rationale: aramid's own
  `_tests_config_notices` docstring states that a check reporting nothing for
  a reason indistinguishable from "clean" is the failure class this engine
  exists to prevent. Silently skipping a whole suite is exactly that.
- **Timeout is per-suite**, matching today's single-suite semantics.
  `_timeout(ctx)` is unchanged and applies to each subprocess. The gate's
  wall-clock budget still caps the whole slot — so two sequential suites can
  exceed it. Task 3 adds a notice for that case rather than silently halving.
- **`detect_stacks` dot-directory exclusion.** `.claude/graph-reminder.py` is
  tooling, not project source. Exclude dot-directories **and** `node_modules`
  from the `.py` walk. Match the existing in-file idiom from
  `nested_git_dirs`: `"node_modules" not in p.parts`. The exclusion must
  compose with the `scope` parameter (`scope_subpath`), which is a distinct
  argument from `root` — `init.py:252` passes `(root, scope_root)` while
  `pipeline.py:297` passes `(root, root)`.
- **`detect_tests` must accept all three pytest conventions**, not just
  `test_*.py`: pytest's default `python_files` is `test_*.py *_test.py`, and
  a `conftest.py` also denotes a pytest suite. Requiring only `test_*.py`
  would newly break real Python repos — a regression in the opposite
  direction.

---

### Task 1: `detectors.py` — stop the false positives

Fix `detect_stacks` and `detect_tests`. Both currently walk `node_modules`.

**`detect_tests(root)`** — drop the bare `(root / "tests").exists()` clause.
A repo is "pytest" iff it has an actual Python test file: any of
`test_*.py`, `*_test.py`, or `conftest.py`, excluding `node_modules` and
dot-directories. The `npm` branch (a `test` script in `package.json`) is
unchanged.

**`detect_stacks(root, scope)`** — keep `(root / "pyproject.toml").exists()`.
Replace `any(scope.rglob("*.py"))` with a walk that ignores `node_modules`
and dot-directories. The `package.json` → `js` branch is unchanged.

**Tests** (`tests/unit/test_detectors.py`), each a fixture repo on tmp_path:

| fixture | `detect_stacks` | `detect_tests` |
|---|---|---|
| TS-only + `tests/` dir of `.test.ts` + `package.json` test script | `{'js'}` | `{'npm'}` |
| TS repo whose only `.py` is `.claude/graph-reminder.py` | `{'js'}` | `{'npm'}` |
| Python repo, `tests/test_foo.py` | `{'python'}` | `{'pytest'}` |
| Python repo, `tests/foo_test.py` only | `{'python'}` | `{'pytest'}` |
| Python repo, `conftest.py` only | `{'python'}` | `{'pytest'}` |
| Python repo, `pyproject.toml`, no `.py` at all | `{'python'}` | `set()` |
| genuine dual-stack (`pyproject.toml` + `test_*.py` + `package.json` script) | `{'js','python'}` | `{'npm','pytest'}` |
| `.py` present **only** under `node_modules/` | `{'js'}` | `{'npm'}` |
| aramid's own repo root | contains `python` | contains `pytest` |

The last row is Global Constraint 1 as an executable assertion.

---

### Task 2: `runners/tests.py` — run both suites, aggregate worst-state-wins

Rework `run(ctx)`. Current precedence (`test_command` → pytest → npm →
MISSING) becomes: an explicit `test_command` still wins outright and
short-circuits everything (unchanged). Otherwise, on `detect_tests(ctx.root)`:

- both `pytest` and `npm` → run both, return the aggregate described below
- exactly one → today's single-result path, unchanged (Global Constraint 6)
- neither → `RunnerResult("tests", ToolState.MISSING)`, unchanged

**Aggregate** — mirror `deps._run_mixed`, with the state rule INVERTED per
Global Constraint 4:

- `.tool` = `"tests"`; `.sub_results` = `[pytest_result, npm_result]`
- state is `OK` **only if both** sub-results are `OK`; otherwise the worst
  sub-state. One suite OK + one MISSING is **not** OK — `tests` is in
  `BLOCK_TIER_KEYS`, so this degrades and blocks at pre-push. That is the
  deliberate consequence of "neither suite can hide"; state it in the
  docstring so it is not later mistaken for a bug.
- `.returncode` on the aggregate is not meaningful; per-suite return codes
  live on the sub-results, which is what `parse` reads.

**`parse(result, ctx)`** — add the `sub_results` recursion exactly as
`deps.parse` does it, as the first branch. Each sub-result then flows through
the existing per-tool logic untouched, so the rc-5 `result.tool == "pytest"`
message keeps working with no edit to that branch.

**Tests** (`tests/unit/test_runner_tests.py`), with fake sub-runners — do not
shell out to real pytest/npm:

- both OK → aggregate OK, `.tool == "tests"`, two sub-results
- pytest OK + npm failing → aggregate NOT OK (the inverted-rule regression
  test; name it so its purpose survives)
- pytest OK + npm MISSING → aggregate degraded, not OK
- both fail → findings from **both** suites appear (neither hidden)
- single-suite repo → single result, **no** `sub_results` attribute
- explicit `[tests].command` set on a dual-stack repo → command wins, neither
  suite auto-runs
- rc 5 from the pytest sub-result still produces the `[tests].command`
  wording

---

### Task 3: budget notice + docs

**Notice.** Extend `pipeline._tests_config_notices` for the dual-suite case:
when both suites will run and `2 × [tests].timeout_s` exceeds the gate's
wall-clock budget, warn that the slot can be abandoned mid-run. Same rationale
as the existing over-budget notice — it is the identical failure class
(a check that reports nothing for a reason indistinguishable from clean).
Test it alongside the existing notice tests in `tests/unit/test_pipeline.py`.

**Docs.**
- `docs/knowledge-base.md` — document the corrected detector rules and the
  dual-stack run-both behaviour, including the block-on-degrade consequence.
- `docs/user-guide.md` — note that `[tests].command` remains the escape hatch
  and still overrides detection entirely.
- `src/aramid/data/ARAMID.md.tmpl` — the onboarding template should say what
  a dual-stack repo does, since that is now a real behaviour a new user meets.
- `README.md` — only if a documented limitation actually changes.

---

## Self-Review Checklist (controller, before the whole-branch review)

- [ ] `detect_stacks(Path('.'), Path('.'))` on aramid still contains `python`;
      `detect_tests(Path('.'))` still contains `pytest` (Constraint 1, run it)
- [ ] Full suite green; count == baseline 1108 + exactly the new tests
- [ ] Red-first proof shown per task (tests fail before, pass after)
- [ ] `deps.py` untouched — the precedent was copied, not refactored
- [ ] Combined-state rule is worst-wins, and a test would fail if flipped to
      deps' OR
- [ ] Single-suite repos produce no `sub_results` attribute
- [ ] rc-5 `[tests].command` wording preserved verbatim
- [ ] `ruff` clean over every touched file
- [ ] `python -m aramid check --gate pre-push` rc 0 before any push
- [ ] End-to-end: on pawscout with its `aramid.toml` **removed**, the gate
      selects `npm test` rather than pytest (the original bug, gone). Restore
      the file afterwards — that repo's config is not this branch's business.

## Out of scope

pawscout's broken vitest install, its 2 critical CVEs, and the untracked
`.aramid/` directory in that repo are all the user's calls and unrelated to
this diff. Do not fold them in.
