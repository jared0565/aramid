# Aramid Phase 2c-1 — Mutation Consumer

**Status:** approved 2026-07-20
**Depends on:** Phase 2a chassis (queue/drain/consumer protocol), merged; Phase 1 gate engine.
**Staging decision (user, on record):** Phase 2c decomposed — 2c-1 = mutation only.
Fuzz/property harness is 2c-2, DAST baseline is 2c-3, each with its own spec later
(same pattern as Phase 2 splitting into 2a/2b/2c).

## 1. Overview

The first heavy-deterministic consumer: for each drained queue item, mutate the
functions the item's commits touched and ask whether the repo's own test suite
notices. A mutant the full suite cannot kill is a **test-coverage gap on
recently-changed, risk-scored code** — exactly the slice worth hardening first.
Zero tokens; the spend is CPU, bounded per item.

### Decisions fixed during brainstorming

| Decision | Choice |
|---|---|
| Staging | 2c-1 = mutation only; fuzz = 2c-2; DAST = 2c-3 (own specs) |
| Mutator | Internal stdlib-`ast` mutator, owned by aramid — NOT an external tool. mutmut 3.x is fork-based (no Windows); Cosmic Ray is heavy machinery; Windows-first is a hard requirement. Python-first; JS repos get an explicit DEGRADED note until a Stryker adapter (2c-1b, not this spec) |
| Test execution | Two-stage: targeted pytest kill-run per mutant, then full-suite CONFIRMATION for putative survivors (capped). A survivor is only reported if the FULL suite fails to kill it — narrow selection can never manufacture false test-gap findings |
| Blocking posture | WARN-tier always. No `block_rules` entry, no arming path in this phase (future arming would mirror the semgrep/LLM bake-then-arm pattern) |
| Isolation | All mutation happens in a throwaway `git worktree` at the item's head sha — the live working tree is NEVER touched |

### Non-goals

- No JS/TS mutation (2c-1b: Stryker adapter — the consumer's stack detection
  leaves the seam).
- No fuzz/property harness (2c-2), no DAST (2c-3).
- No arming/blocking, no ratchet participation beyond normal WARN recording.
- No mutation of test files themselves; no mutation outside diff-touched functions.
- No coverage-based or import-graph test selection — the naming heuristic plus
  full-suite confirmation is the deliberate simplicity floor.

## 2. Mutator core — `src/aramid/mutation.py`

Stdlib `ast` only. Public surface:

```python
@dataclass
class Mutant:
    file: str          # repo-relative, forward slashes; generate_mutants sees
                       # only source, so it emits file="" and the CONSUMER
                       # stamps the real path on each returned Mutant
    line: int          # 1-based line of the mutated node (original source)
    op: str            # operator id, e.g. "cmp-flip", "bool-swap", "int-bound", "not-drop"
    description: str   # human line, e.g. "== -> != in check_token"
    source: str        # full mutated module source (ast.unparse)

def generate_mutants(source: str, target_lines: set[int]) -> list[Mutant]
```

- Walks module functions (sync+async, methods included); a function is eligible
  when its `lineno..end_lineno` span intersects `target_lines` (the diff's
  changed lines for that file). Everything else is untouched.
- Operator families (exactly four, applied one node at a time — one mutant per
  application site):
  1. `cmp-flip`: `==`↔`!=`, `<`↔`<=`, `>`↔`>=` (single-comparator `Compare` nodes only).
  2. `bool-swap`: `and`↔`or` (`BoolOp`).
  3. `int-bound`: integer `Constant` → value+1 (skip `True`/`False` — they are
     `bool` constants and must be excluded by exact-type check).
  4. `not-drop`: `if not X:` → `if X:` (`UnaryOp Not` as the direct `If.test`).
- Rendered via `ast.unparse` on a deep-copied tree: mutated files lose comments
  and formatting. Acceptable by design — mutants exist only inside the
  throwaway worktree.
- Deterministic order (file walk order, then line, then op) so budget truncation
  is reproducible and fingerprints stable across re-drains.
- Test files are never mutated: any file whose repo-relative path matches
  `tests/` prefix or `test_*.py` / `*_test.py` basename is skipped at the
  consumer layer before `generate_mutants` is called.

## 3. Consumer — `src/aramid/consumers/mutation.py`

`NAME = "mutation"`, registered in `CONSUMERS` alongside `regression-pack` and
`llm-review`. `consume(item, ctx) -> ConsumerResult`:

1. **Scope**: resolve the item's commit range to changed `.py` files + changed
   line sets (existing `gitutil` diff helpers). Apply the §8b ignore filter and
   graphite-artifact exclusion (`config.filter_paths`) — hard requirement.
   Drop test files (rule above). No eligible files → `OK`, note
   `"no python files in range"`, zero findings.
2. **Stack check**: no Python stack or no pytest detected (existing `detectors`)
   → `DEGRADED`, note `"no python test stack"` (JS-only repos land here — the
   2c-1b seam).
3. **Worktree**: `git worktree add <tmp> <item.head>` under the scratch temp
   dir; ALL subsequent steps run inside it; `git worktree remove --force` +
   `prune` in a `finally`. The user's working tree is never written. A worktree
   whose creation fails → `ERROR` with the git stderr in the note.
4. **Baseline**: run the full suite once, un-mutated (`python -m pytest -q`,
   `runners/tests.py`-style invocation, `[mutation].mutant_timeout_s` × 4 as
   its timeout). Red or timed-out baseline → `DEGRADED "baseline failing"`,
   no findings — survival is unattributable on a broken base.
5. **Mutant loop** (until `max_mutants` generated-and-tested or
   `wall_budget_s` exhausted):
   - write `mutant.source` over the file in the worktree;
   - **stage 1 (kill run)**: targeted pytest — `tests/**/test_<module>.py` when
     it exists, else `-k <module>` — with `mutant_timeout_s`;
   - failed (non-zero) → killed; move on;
   - passed → putative survivor → **stage 2 (confirmation)**: full suite, up to
     `confirm_cap` per item; full-suite failure → killed (stage-1 selection was
     just narrow); full-suite pass → **confirmed survivor** → finding;
   - either stage TIMES OUT → the mutant is **unattributable**: excluded from
     findings, counted in `extra["timeouts"]` (a hung mutant is not evidence of
     a test gap);
   - restore the original file from git (`git checkout -- <file>` in the
     worktree) after every mutant.
6. **Findings**: confirmed survivor →
   `RawFinding(tool="mutation", rule=<op>, file, line, message="mutant survived: <description>")`
   → the drain's existing normalize/classify partial wiring (same path as
   regression-pack findings). `ref_for` = item head sha, so fingerprints are
   stable across re-drains. `policy.classify` has no mutation rule anywhere in
   `block_rules.toml` → WARN by construction; that absence is itself asserted
   by a test.
7. **Result**: `ConsumerResult(consumer="mutation", state=OK, findings=...,
   cost=0.0, note=<one-line summary>, extra={"generated": n, "tested": n,
   "killed": n, "survived": n, "confirmed": n, "timeouts": n,
   "truncated": bool})`. Truncation (budget or cap hit) is never silent: the
   note names what was dropped.

## 4. Config — `[mutation]`

```toml
[mutation]
enabled = true
max_mutants = 20        # generated-and-tested per item
wall_budget_s = 600     # whole-item wall clock for the mutant loop
mutant_timeout_s = 120  # per pytest invocation (stage 1 and stage 2 alike)
confirm_cap = 3         # full-suite confirmation runs per item
```

Defaults live in `defaults.toml`; layered config merge as everywhere else.
`enabled = false` → consumer returns `OK` with note `"disabled"` and no
worktree is ever created.

## 5. Invariants

1. **Live tree untouchable**: no code path writes to `ctx.root`'s working tree;
   every mutation write targets the throwaway worktree. Worktree removal runs
   in a `finally` and is itself exception-guarded (leak = loud note, never a
   crash).
2. **Gate untouched**: no changes to pipeline/policy/hooks/check. Mutation
   findings enter solely via the drain's existing consumer path.
3. **WARN-only**: no mutation rule in `block_rules.toml`; `verdict=="block"`
   unreachable for `tool=="mutation"` (test-asserted).
4. **No false survivors**: a finding requires a full-suite pass on the mutant
   (stage 2). Narrow stage-1 selection can only cause extra confirmation work
   or (at cap) an *unreported* survivor — never a false report. Cap/budget
   drops are visible in `extra`.
5. **Fail-open drain**: any unexpected exception inside `consume` is contained
   by the drain's existing per-repo isolation; the consumer additionally
   catches per-mutant errors (a single unparseable/unwritable mutant skips,
   counted, never aborts the item).
6. **Zero tokens, zero deps**: stdlib only; `cost=0.0`.

## 6. Testing

- Mutator unit tests per operator family, incl.: function outside
  `target_lines` produces zero mutants; `True` constant NOT int-bound-mutated;
  deterministic ordering; `ast.unparse` round-trip is syntactically valid
  (compile() smoke).
- Consumer integration (fixture repo, real git + real pytest):
  - weak test → survivor confirmed at stage 2 → reported (the payoff test);
  - strong test → killed at stage 1 → no finding;
  - **stage-2 rescue**: mutant killed ONLY by a cross-module test that stage-1
    selection misses → proves confirmation prevents the false survivor;
  - baseline-red → DEGRADED, no findings;
  - budget truncation → `truncated` true, note says so;
  - worktree cleaned up on success AND on an injected mid-loop exception;
  - block-unreachable: classify a mutation finding through real policy + block
    rules → WARN.
- e2e: real `aramid drain` on a registered fixture repo with a queued item →
  CONSUMER_RUN_FINISHED event carries the mutation extra payload; ledger holds
  the WARN finding.

## 7. Execution shape

Branch `feat/phase2c1-mutation` off current `main`. Plan via
superpowers:writing-plans; execution mode chosen by the user at plan handoff.
Same finishing gates as prior features: ruff parity, full suite, whole-branch
review, CI, finishing skill.
