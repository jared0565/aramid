# Aramid 2c-1b — JS/TS Mutation Adapter — Design

Date: 2026-07-20
Status: approved (user), pre-plan
Base: main @ dd30898 (791 tests green, ruff baseline 43, CI green)
Branch: feat/2c1b-js-mutation (created at plan time)

## 1. Purpose

The mutation consumer (`consumers/mutation.py` + owned `ast` mutator `mutation.py`)
catches weak tests by mutating an item's changed lines and checking whether the
suite still passes; survivors are WARN-tier findings. It is Python-only today —
`consume` early-returns OK-skip on a repo with no `pytest` stack, a seam the
Phase-2c1 design explicitly left for "2c-1b (Stryker adapter)".

This feature fills that seam for JavaScript/TypeScript, mirroring the Python
consumer's architecture and value prop: an **owned, self-contained mutator** that
works on **any** JS/TS repo with an `npm test` script, needing **no** external
mutation tool installed (not Stryker). It runs alongside the Python consumer;
each is stack-gated, so a Python repo fires only Python, a JS repo only JS, and a
mixed repo both.

Two foundational decisions (user-approved):
- **Owned mutator, not a StrykerJS adapter.** Stryker requires per-repo setup
  (a `stryker.conf`, a runner plugin), so a Stryker adapter would MISSING-skip on
  the large majority of repos — contradicting the "works on any repo with a test
  command" value the Python consumer delivers.
- **Pure-Python token-level mutant generation.** Python has no stdlib JS parser
  (the Python mutator's fidelity came from stdlib `ast`). A pure-Python JS/TS
  lexer + token mutation keeps aramid Python-only, self-contained (no Node
  artifact in the wheel, no vendored parser), and Windows-first, at the cost of
  token-level (not full-AST) fidelity.

## 2. Modules

Mirror the Python split:
- `src/aramid/jsmutate.py` — the owned token mutator. Pure, no subprocess, no I/O.
  Public surface: `generate_mutants(source: str, target_lines: set[int]) ->
  list[Mutant]` (identical signature to `mutation.generate_mutants`), and a
  `Mutant` dataclass `{file, line, op, description, source}` (same shape as
  `mutation.Mutant`; `file` stamped by the consumer, `source` is the full mutated
  module text).
- `src/aramid/consumers/js_mutation.py` — the drain-time orchestrator.
  `NAME = "js_mutation"`, `consume(item, ctx) -> ConsumerResult`, `PIN_OCCURRENCE
  = True`, registered `base.CONSUMERS[NAME] = sys.modules[__name__]`. Added to the
  import block in `commands/drain.py` (the registration side-effect site).

## 3. Stack gate (the 2c-1b seam)

`consume` early-returns **OK** (state="ok", note `"no js test stack (mutation
skipped)"`, no findings) when `"npm" not in detectors.detect_tests(ctx.root)`.
`detect_tests` returns `{"npm"}` iff `package.json` has a `scripts.test` entry, so
this gate means "the repo has a runnable JS test command". OK-not-DEGRADED is
load-bearing: the drain refuses to `mark_drained` an item while any consumer is
degraded (`drain.py`), so a permanent structural absence (no JS stack) must be OK,
never degraded — exactly the discipline the Python consumer adopted for its
pytest gate.

## 4. Mutant generation — pure-Python token mutator (`jsmutate.py`)

A minimal JS/TS lexer scans `source` character-by-character, tracking which
**region** each position is in:
- code
- line comment (`// … EOL`)
- block comment (`/* … */`)
- single-quoted string (`'…'`, with `\` escapes)
- double-quoted string (`"…"`, with `\` escapes)
- template literal (`` `…` ``, with `\` escapes; nested `${…}` interpolations are
  treated conservatively as string for MVP — expressions inside `${}` are NOT
  mutated, avoiding brace-tracking complexity)
- regex literal (`/…/flags`) — a `/` **opens a regex region** (interior never
  mutated) when it appears where a regex is grammatically possible: after
  `(`,`,`,`=`,`:`,`[`,`!`,`&`,`|`,`?`,`{`,`;`, `return`, or start-of-input,
  skipping whitespace. A `/` in any other position is **division** (an operator
  aramid never mutates anyway). This rule is deterministic and errs toward
  treating a doubtful `/` as a regex — the failure mode is a *missed* mutation,
  never a mutation inside a regex. (The `/` character itself is never a mutation
  target in either case, so misclassifying a division as a regex only costs the
  mutations on that one line.)

Only within **code** regions, and only on lines in `target_lines`, four operator
families apply (mirroring `mutation._mutations_at`). Tokenizing uses maximal
munch so multi-char operators are matched whole (e.g. `===` is one token, not
`==` + `=`; `<=`/`>=`/`=>`/`<<`/`>>`/`&&`/`||` are whole tokens):
- **cmp-flip**: `===`↔`!==`, `==`↔`!=`, `<`↔`<=`, `>`↔`>=`. (Never touch `=>`,
  `<<`, `>>`, `<=`/`>=` are themselves the flipped forms — each maps to exactly
  one counterpart.)
- **logical-swap**: `&&`↔`||`.
- **int-bound**: an integer numeric literal → value+1. Decimal integer literals
  only for MVP (`/\b\d+\b/` in code region, not immediately preceded/followed by
  `.`, `x`/`X`, `e`/`E`, or an identifier char — excludes floats, hex, bigint,
  and identifier fragments). Rendered as `str(value+1)`.
- **not-drop**: a unary prefix `!` (not part of `!=`/`!==`) dropped, so `!x` → `x`.
  Recognized when `!` is in prefix position (start of an operand: preceded by
  `(`,`,`,`=`,`:`,`[`,`{`,`;`,`&`,`|`,`?`,`return`, or an operator/whitespace),
  and NOT followed by `=` (which would be `!=`/`!==`, handled by cmp-flip).

Each mutation site produces one `Mutant` whose `source` is the full module text
with exactly that one token replaced (single-mutation-per-mutant, like Python).
`description` is human-readable (e.g. `"=== -> !=="`, `"drop ! at col N"`).
Deterministic sort by `(line, op, description)` (mirrors `mutation.py:98`).
Invalid input never raises: the lexer is total over any string; an empty
`target_lines` or a file with no eligible sites yields `[]`.

Operator swaps preserve syntactic validity (they are like-for-like token
replacements), so mutants compile/parse under the repo's own build — broken-syntax
mutants are not expected. A mutant that nonetheless fails to compile (e.g. a TS
type error introduced by `not-drop`) is simply killed by the test command.

## 5. Test execution — single-stage full `<pm> test`

**DEVIATION from the Python two-stage (user-approved judgment call 1).** JS test
runners (jest/mocha/vitest/node:test) have no portable "run only tests for this
module" flag, so aramid runs the repo's own full test command once per mutant:
`<pm> test`, where `pm = detectors.detect_package_manager(root)` (npm/pnpm/yarn),
defaulting to `npm` when no lockfile pins one. Invocation is
`run_subprocess([pm(.cmd on Windows), "test"], wt, mutant_timeout_s, env=…)`.

Interpretation of the mutant test run (returncode):
- **0** → the suite PASSED with the mutant applied → **survivor** (confirmed —
  the single stage IS the full suite, so no separate stage-2 is needed and there
  are no false survivors from partial-suite isolation). Append a WARN finding.
- **non-zero** (any) → the suite failed the mutant → **killed**. (JS runners exit
  non-zero on test failure and on compile/parse errors alike; both mean the mutant
  did not survive.)
- **TIMEOUT** (state) → count `timeouts++`, skip (unattributable), do not report.
- **MISSING** (state — pm binary absent) → environment-missing, OK-skip (see §11).

There is no `confirm_cap` (that was a stage-2 concept). `max_mutants` and
`wall_budget_s` bound the loop; hitting either sets `truncated=True`, surfaced in
the note and (with `PIN_OCCURRENCE`) keeping fingerprints stable across truncated
runs.

## 6. Worktree + node_modules (judgment call 2)

Mirror the Python throwaway worktree: `gitutil._run(root, "worktree", "add",
"--detach", <wt>, item.head)`. Because a fresh worktree does not contain
`node_modules` (gitignored, per-directory), `<pm> test` there would fail to
resolve dependencies. Before any test run, **link** the main repo's
`node_modules` into the worktree:
- Windows: a directory **junction** via `mklink /J <wt>/node_modules
  <root>/node_modules` (junctions need no admin privilege, unlike symlinks).
- Unix: `os.symlink(<root>/node_modules, <wt>/node_modules)`.

Preconditions and failure handling:
- If `<root>/node_modules` does not exist (deps never installed) → **OK-skip**,
  note `"node_modules not installed (js mutation skipped)"`. Structural absence,
  not a failure.
- If the junction/symlink creation itself fails → **DEGRADED** (transient env
  issue), note `"could not link node_modules"`; the item is retried next drain.
- **Teardown order is safety-critical.** In `finally`, FIRST unlink the
  junction/symlink (`os.unlink` on Unix; on Windows a junction is removed with
  `os.rmdir`/`Path.unlink` on the link itself — removing the LINK only, never its
  target), THEN remove the worktree. Removing the worktree directory while the
  junction is still live risks a recursive delete following the junction into the
  **real** `<root>/node_modules` (`shutil.rmtree` follows Windows junctions). So:
  unlink-junction → `git worktree remove --force` → `prune` → guarded
  `shutil.rmtree` of any residual worktree dir (which is now junction-free). Every
  step is exception-guarded.

Documented caveat: the linked `node_modules` reflects the **working checkout's**
installed deps, not necessarily `item.head`'s. If the lockfile changed between
them, the modules can be slightly stale. This is acceptable for a WARN-tier
advisory signal; the baseline run (§7) catches gross incompatibility (missing
module → baseline red → degraded/give-up), and no per-mutant reinstall is done
(explicit non-goal — it would blow the wall budget).

## 7. Baseline + give-up

Mirror the Python consumer:
- Run `<pm> test` once in the worktree at `item.head` before mutating. Non-OK
  state or non-zero returncode → **DEGRADED**, note `f"baseline failing @
  {item.head[:12]}"` (the string prefix is load-bearing — the give-up counter
  matches it). A red baseline means mutation results would be meaningless.
- **Give-up**: `base.prior_note_count(ledger, NAME, item.id, f"baseline failing @
  {item.head[:12]}") >= _BASELINE_GIVE_UP` (=3) → **OK-skip**, note `"js mutation
  giving up: baseline persistently failing"`. Head-scoped, mirroring the Python
  fix so a coalesced queue item advancing its head resets the counter.

## 8. Config

New `[js_mutation]` block in config, mirroring `[mutation]`, all overridable via
`aramid.toml`, with defaults sourced from `defaults.toml`:
- `enabled` (default True; False → OK note `"disabled"`)
- `max_mutants` (default 20)
- `wall_budget_s` (default 600)
- `mutant_timeout_s` (default 120)

(No `confirm_cap` — single-stage.) `ctx.cfg.js_mutation` is read the same way
`mutation.py` reads `ctx.cfg.mutation`.

## 9. Findings & result

- Survivor → `RawFinding(tool="js-mutation", rule=<mutant.op>,
  severity_raw="medium", file=<rel>, line=<mutant.line>, message=f"mutant
  survived: {mutant.description}")`. WARN-tier: `medium` is below any deps/gate
  block threshold and mutation findings classify to WARN (never BLOCK), exactly
  like the Python consumer's survivors (verified there by a WARN-never-BLOCK
  test).
- `ConsumerResult(consumer="js_mutation", state="ok", findings=…, duration_s=…,
  cost=0.0, note=…, extra=stats)` where `stats` = `{generated, tested, killed,
  survived, timeouts, errors, truncated}`.
- `PIN_OCCURRENCE = True` so the drain pins `occurrence_index=0` for
  truncation-stable fingerprints.

## 10. File selection

Mirror Python: `changed = gitutil.diff_new_lines(root, item.base, item.head)`
(→ `dict[str, set[int]]`). Keep files whose suffix is in the JS/TS set
(`.js .jsx .mjs .cjs .ts .tsx .mts .cts`, matching `eslint._JS_SUFFIXES`) and
which are NOT test files, then apply `config_mod.filter_paths(files, ctx.cfg)`.
Empty → OK note `"no js files in range"`.

Test-file exclusion (`_is_test_file` for JS): a path is a test file if any path
segment is `__tests__`, or the basename matches `*.test.*` or `*.spec.*` (the
dominant JS/TS test-file conventions). Mutating test files is pointless (they
aren't the code under test).

## 11. Error handling (never crash the drain)

- `run_subprocess` MISSING (no `npm`/`pnpm`/`yarn` on PATH) → OK-skip, note
  `"js package manager not found (mutation skipped)"`.
- Per-mutant TIMEOUT → `timeouts++`, skip (unattributable to kill or survive).
- Worktree add failure → DEGRADED (transient), note `"worktree add failed"`.
- node_modules link failure → DEGRADED (see §6).
- `generate_mutants` is pure and total; a defensive `try/except` around the
  per-file generate call counts `errors++` and continues (mirrors the Python
  consumer's generator-crash guard test).
- `finally`: restore the original file text, remove the worktree (`--force` +
  `prune`), tear down the junction/symlink; every teardown is exception-guarded
  so a leak degrades to a stderr note, never a crash.

## 12. Testing & CI

CI is Python-only (no Node); the design keeps CI green:
- **`jsmutate.py` unit tests** (`tests/unit/test_jsmutate.py`) — pure, no
  subprocess: one test per operator family (cmp-flip, logical-swap, int-bound,
  not-drop); lexer region tests proving NO mutation inside strings ('…', "…",
  `` `…` ``), line/block comments, or regex literals; the regex-vs-divide
  disambiguation (`a / b` divides and IS eligible for nothing; `/ab+/.test(x)` is
  a regex and its interior is untouched); maximal-munch (`===` not split; `=>`
  arrow untouched; `<=` treated as one token); determinism of ordering;
  `target_lines` scoping; invalid/empty source → `[]`.
- **Consumer flow tests** (`tests/integration/test_js_mutation_consumer.py`) via
  the **scripted-`run_subprocess` monkeypatch** pattern (no real Node): baseline
  green→mutant loop; survivor reported (mutant test returns 0); killed
  (non-zero); TIMEOUT counted not killed; baseline red → DEGRADED; give-up after
  3 (head-scoped); no-js-stack → OK-skip; node_modules-absent → OK-skip;
  disabled → OK note; WARN-never-BLOCK classification; worktree torn down.
- **Real-`npm test` integration** (optional, one happy-path test) gated behind a
  Node-availability skip (mirror how eslint/typecheck real-tool tests are gated),
  so it runs locally where Node exists and is skipped in the Python-only CI.
- Full suite green (791 base + new). Ruff parity with the branch-creation baseline
  (expected 43).
- Whole-branch adversarial review (sonnet). CI green on the merge commit.

## 13. Decisions (review-checked)

| Decision | Choice | Why |
|---|---|---|
| Engine | Owned mutator, not Stryker | Works on any JS repo with `npm test`; Stryker needs per-repo setup (rarely present) |
| Mutant generation | Pure-Python token lexer + swaps | Keeps aramid Python-only/self-contained/Windows-first; no vendored parser or Node artifact |
| Stages | Single full `<pm> test` per mutant | JS runners lack a portable narrow flag; full-suite pass = confirmed survivor |
| node_modules | Junction/symlink from main repo | A fresh worktree has none; reinstalling per drain blows the budget |
| TS | Handled by the repo's own build | Mutate source, let `npm test` compile; type-error mutant → killed |
| Findings | WARN-tier, cost 0.0, PIN_OCCURRENCE | Mirrors the Python consumer exactly |

## 14. Non-goals

- No StrykerJS integration (any tier).
- No two-stage narrowing / per-runner test selection.
- No per-mutant dependency (re)install.
- No mutation operators beyond the four Python families.
- No mutation of expressions inside template-literal `${…}` interpolations (MVP
  treats template contents as string).
- No coverage-guided mutant selection.

## 15. Invariants

1. **Never pins the queue forever**: structural absence (no JS stack, no
   node_modules, no pm) → OK-skip; DEGRADED reserved for transient states
   (baseline red, worktree/link failure) with a bounded give-up.
2. **No false survivors**: a survivor requires a full-suite PASS with the mutant
   applied; the single stage is the full suite.
3. **No mis-mutation**: the lexer only mutates code regions; ambiguous `/` sites
   are never mutated; operator swaps are like-for-like and syntactically valid.
4. **Never crashes the drain**: every subprocess/worktree/link failure maps to a
   ConsumerResult state; `finally` restores + tears down, exception-guarded.
5. **Zero tokens**: `cost=0.0`, no network, no LLM.
6. **CI stays green without Node**: all mutator + consumer-flow tests are pure
   Python (scripted subprocess); real-Node tests are skip-gated.
7. **Never deletes the real `node_modules`**: the junction/symlink is unlinked
   (link-only) BEFORE the worktree directory is removed, so no teardown path
   recurses through it into `<root>/node_modules` (§6).
