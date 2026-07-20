# Aramid Phase 2c-2 — Fuzz Consumer

**Status:** approved 2026-07-20
**Depends on:** Phase 2a chassis; Phase 2c-1 (worktree pattern, consumer-state
semantics: OK = done/permanent-skip, DEGRADED = transient/retry-next-drain,
ERROR = failed/retry — the 2c-1 execution amendment is binding here too).
**Staging:** 2c-2 = the owned fuzz harness. Hypothesis-profile rerun is 2c-2b
(not this spec); DAST is 2c-3.

## 1. Overview

Second heavy-deterministic consumer: for each drained queue item, call the
top-level functions the item's commits touched with deterministic, seeded,
type-hint-derived inputs, and report **deep crashes** — builtin
almost-always-a-bug exceptions — as WARN-tier findings. Zero tokens, CPU
bounded per item, reproducible by construction (the seed is the repro).
Unlike mutation, fuzzing needs no test suite — it applies to any repo with
type-hinted Python, a strictly larger population.

### Decisions fixed during brainstorming

| Decision | Choice |
|---|---|
| Engine | Owned stdlib seeded generator driven by type hints — NOT atheris (libFuzzer: no Windows), NOT Hypothesis (target-env dependency). Mirrors 2c-1's owned-mutator precedent |
| Crash oracle | Deep-crash allowlist ONLY: `IndexError, KeyError, ZeroDivisionError, AttributeError, UnboundLocalError, RecursionError, UnicodeError, OverflowError`. `TypeError`/`ValueError`/`NotImplementedError`/all repo-defined exceptions = contract, never reported |
| Side effects | Accepted at the same trust class as running the repo's test suite: subprocess with `cwd=worktree` (relative writes land in the throwaway) + a default-on scary-name skip-list (`[fuzz].skip_name_patterns`). Residual absolute-path/network effects accepted, on record |
| Noise cap | At most ONE finding per (function, exception type) per item |
| Blocking | WARN-only; no `block_rules` entry; no arming path |

### Non-goals

- No methods, classmethods, or async functions (skipped + counted).
- No coverage guidance, corpus persistence, or input shrinking — the
  deterministic seed IS the repro.
- No Hypothesis integration (2c-2b), no JS (needs its own engine), no DAST (2c-3).

## 2. Generator — `src/aramid/fuzzgen.py`

Stdlib only (`random.Random(seed)`, `typing` introspection via
`typing.get_type_hints`/`get_origin`/`get_args`).

```python
SUPPORTED: int, float, str, bytes, bool, NoneType,
           list[T], dict[K, V], tuple[T, ...] / tuple[A, B],
           Optional[T] and unions whose every member is supported

def supported_params(fn) -> list[str] | None
    # param names when EVERY parameter (no *args/**kwargs) has a supported
    # hint; None when the function is not fuzzable (unhinted, unsupported
    # hint, or introspection raises)

def gen_value(hint, rng: random.Random, depth: int = 0)
    # one value for a hint; containers recurse with depth cap 3, len 0..5;
    # ints from {0, ±1, ±2, bignum, rng}; strs/bytes mix ascii, unicode
    # (é, emoji, NUL), empty; floats include 0.0, -0.0, inf, -inf, nan

def case_seed(file: str, func: str, index: int) -> int
    # deterministic: int.from_bytes(sha256(f"{file}:{func}:{index}").digest()[:8])
```

Determinism is a hard requirement: same repo state → same inputs → same
crashes → same fingerprints across drains.

## 3. Driver — `src/aramid/fuzzdriver.py`

Runs INSIDE the worktree as `[sys.executable, "-m", "aramid.fuzzdriver",
<spec.json path>]` with `cwd=worktree`. The spec file lists targets:
`{"targets": [{"file": rel, "module": dotted-or-path, "functions": [names],
"cases": N}]}`. For each target module:

1. Import from the worktree (worktree root prepended to `sys.path`,
   `importlib.import_module` on the dotted path derived from the rel path;
   packages resolved by presence of `__init__.py`, else top-level module).
   Import failure → `{"import_failure": rel}` record, module skipped.
2. For each function, for `case_index` in `range(cases)`: build kwargs via
   `gen_value` per param with `random.Random(case_seed(...))`, call, catch
   `BaseException`:
   - allowlisted exception → crash record `{"func", "file", "case", "exc",
     "msg" (truncated 200), "args_repr" (truncated 100), "line"}` where
     `line` = deepest traceback frame lineno whose frame file is the target
     file (fallback: the function's `__code__.co_firstlineno`);
   - anything else → counted as contract, not recorded. `KeyboardInterrupt`
     is re-raised (never swallowed); `SystemExit` is caught and counted as
     contract — a fuzzed CLI-style function calling `sys.exit()` must not
     kill the batch;
   - after the FIRST allowlisted crash per (function, exc type), further
     identical crashes are counted, not re-recorded.
3. Emit one JSON object to stdout: `{"records": [...], "cases_run": n,
   "crashes": n, "contract_exceptions": n, "import_failures": [...]}` and
   exit 0. Any driver-internal error → exit nonzero (consumer counts the
   batch as errored, never crashes the drain).

A hung target function hangs the whole batch — killed by the consumer's
`run_subprocess` timeout, counted as `timeouts`, unattributable, no finding.

## 4. Consumer — `src/aramid/consumers/fuzz.py`

`NAME = "fuzz"`, registered in `CONSUMERS` + drain.py import, like 2c-1.
`consume(item, ctx)`:

1. `[fuzz].enabled` false → OK `"disabled"` (no worktree).
2. Scope: `gitutil.diff_new_lines` → non-test `.py` files (2c-1's
   `_is_test_file` rule) → §8b/graphite `filter_paths`. Empty → OK
   `"no python files in range"`.
3. Worktree at `item.head` (identical mkdtemp + `worktree add --detach` +
   guarded `finally` removal as 2c-1).
4. Parse each file's HEAD source (`ast`) for top-level `def`s overlapping the
   file's changed lines. Dropped: async defs and name-skip-list matches
   (each counted). Kept deliberately: underscore-private functions (internal
   code crashes matter) and decorated functions (the driver calls whatever
   the name resolves to at import time). Per function, `fuzzgen.supported_params`
   decides fuzzability (import happens in the driver, not the consumer — the
   consumer decides candidacy from the AST + the driver re-checks hints at
   import time; a function the driver finds unfuzzable is counted, skipped).
5. Cap functions at `[fuzz].max_functions` (deterministic order: file, then
   def line) — beyond-cap → `truncated`. Write the spec JSON into the
   scratch temp dir, run the driver once per item (single batch) with
   `batch_timeout_s`; wall-clock `wall_budget_s` guards the whole step.
6. Findings from crash records:
   `RawFinding(tool="fuzz", rule=f"crash-{exc.lower()}", severity_raw="medium",
   file=rel, line=record line, message="fuzz crash: {func}({args_repr}) raised
   {exc}: {msg}")`. WARN by construction (no block_rules entry — test-asserted).
7. `ConsumerResult(state=OK, findings, cost=0.0, note=summary,
   extra={"functions_seen", "functions_fuzzed", "skipped_unhinted",
   "skipped_name", "skipped_async", "cases_run", "crashes",
   "contract_exceptions", "findings", "timeouts", "import_failures",
   "truncated"})`. Truncation and skips are never silent.

State mapping (2c-1 amendment applied from day one): permanent absences
(no python files, no fuzzable functions) → OK + loud note; transient
(worktree add failure) → ERROR; batch timeout → OK with `timeouts` counted
(the batch ran; the budget did its job — NOT degraded, an item must not pin
on a slow function).

## 5. Config — `[fuzz]`

```toml
[fuzz]
enabled = true
max_functions = 10        # fuzzed per queue item
cases_per_function = 50
wall_budget_s = 300       # whole-item wall clock
batch_timeout_s = 120     # the single driver subprocess
skip_name_patterns = [
  "*deploy*", "*delete*", "*remove*", "*drop*", "*push*", "*send*",
  "*upload*", "*kill*", "*wipe*", "*publish*", "*destroy*", "*truncate*",
]
```

fnmatch against the bare function name, case-insensitive. Defaults in
`defaults.toml`; layered merge as everywhere.

## 6. Invariants

1. **Live tree untouchable** — identical to 2c-1: all execution in the
   throwaway worktree, removal in a guarded `finally`.
2. **Gate untouched** — no pipeline/policy/hooks/check changes.
3. **WARN-only** — no fuzz entry in `block_rules.toml`; BLOCK unreachable for
   `tool="fuzz"` (test-asserted through real classify).
4. **Determinism** — same head sha + config → same cases → same findings;
   `case_seed` is content-independent of wall clock and host.
5. **Noise floor** — contract exceptions and repo-defined exceptions can
   never become findings; one finding per (function, exc type).
6. **Fail-open drain** — driver exit-nonzero / malformed JSON → consumer
   returns OK with `errors` noted, never raises into the drain; per-record
   parse guards.
7. **Zero tokens, zero deps** — stdlib only; `cost=0.0`.

## 7. Testing

- fuzzgen unit: every supported hint produces a value of the right type;
  seed determinism (two runs identical); unsupported hint → None from
  `supported_params`; container depth cap; special floats present across a
  seed sweep.
- fuzzdriver unit (subprocess, real): seeded `IndexError` bug → crash record
  with correct file/line/exc; contract `ValueError` raiser → zero records,
  `contract_exceptions` counted; dedupe (many crashing cases → one record per
  (func, exc)); import-failure module → counted, others still fuzzed.
- Consumer integration (real git + worktree): payoff (diff-touched hinted
  function with a seeded off-by-one `IndexError` → finding, correct
  file/line, note says so); contract-only function → zero findings; no
  fuzzable functions → OK + loud note; skip-list honored (scary name not
  fuzzed, counted); worktree cleanup on success AND injected crash;
  WARN-classify assertion; truncation visible (`max_functions=1` with 2
  candidates); drain e2e: CONSUMER_RUN_FINISHED carries fuzz extra payload,
  ledger holds the WARN finding, item drains.

## 8. Execution shape

Branch `feat/phase2c2-fuzz` off current `main`. Plan via writing-plans;
execution mode chosen at handoff. Gates: ruff parity, full suite,
whole-branch review, CI, finishing skill.
