# Aramid 2c Ticket Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all six 2c-1/2c-2 review residuals: mutation I2 (baseline give-up), M1 (killed split), M2 (`-k` safety + exit-code classification), M5 (occurrence pin), fuzz M4 (honest truncation flag), and the fuzz side-effect README caveat.

**Architecture:** Five small code changes confined to the drain subsystem (`consumers/base.py`, `consumers/mutation.py`, `consumers/fuzz.py`, `normalizer.py` additive-default kwarg, `commands/drain.py` one line) plus one README sentence. Gate path untouched.

**Tech Stack:** Python stdlib only. Tests via `python -m pytest` (Windows: tools live in `%APPDATA%\Python\Python314\Scripts`, not on PATH — never bare `pytest`).

**Spec:** `docs/superpowers/specs/2026-07-20-aramid-2c-ticket-bundle-design.md`

## Global Constraints

- Branch: `feat/2c-ticket-bundle` off main @ 42a5d51. Never implement on main.
- Gate path untouched: no behavior change for `pipeline.py`, `policy.py`, runners, hooks. `normalize()` change is keyword-only with default `False`.
- Drain findings stay WARN-only/detect-only. Ledger event shapes untouched (I2 only READS events).
- Ruff parity: `python -m ruff check .` must report exactly the baseline count measured on the branch base (expected 43). No new violations.
- Full suite green before merge: `python -m pytest -q` (752 base + new).
- Commit trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` (all commits; omitted from the inline commands below for brevity — always add it).
- The literal note string `"baseline failing"` is load-bearing (give-up counter keys on it); comments at both sites.

---

### Task 1: Shared `prior_note_count` helper + I2 baseline-failing give-up

**Files:**
- Modify: `src/aramid/consumers/base.py` (add helper at end, after `CONSUMERS`)
- Modify: `src/aramid/consumers/llm_review.py:62-70` (`_malformed_attempts` → thin wrapper)
- Modify: `src/aramid/consumers/mutation.py` (give-up check before worktree add)
- Test: `tests/integration/test_mutation_consumer.py` (2 new tests)

**Interfaces:**
- Produces: `base.prior_note_count(ledger, consumer: str, item_id: str, prefix: str) -> int` — counts `CONSUMER_RUN_FINISHED` events for (consumer, item_id) whose note starts with `prefix`. Used by llm_review and mutation; later consumers may adopt it.
- Produces: `mutation._BASELINE_GIVE_UP = 3` (module const, mirrors `llm_review._MALFORMED_GIVE_UP`).

- [ ] **Step 0: Create the branch**

```bash
git checkout -b feat/2c-ticket-bundle
```

Record the ruff baseline: `python -m ruff check . 2>&1 | tail -1` — expect `Found 43 errors` (or the actual count; note it, every later task must match it).

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_mutation_consumer.py`:

```python
def _seed_baseline_failures(r, n):
    from aramid.models import Event, EventType
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for i in range(n):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"seed{i}", "t",
                             payload={"consumer": "mutation", "item_id": "q1",
                                      "state": "degraded",
                                      "note": "baseline failing"}))
    finally:
        led.close()


def test_baseline_giveup_after_three_failures(tmp_path, monkeypatch):
    # 3 prior "baseline failing" runs for this item -> OK give-up, and NO
    # pytest invocation at all (run_subprocess poisoned to prove it): the
    # give-up check must fire BEFORE the worktree/baseline work.
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _seed_baseline_failures(r, 3)
    monkeypatch.setattr(mut_consumer, "run_subprocess",
                         lambda *a, **kw: (_ for _ in ()).throw(
                             AssertionError("give-up path must not run pytest")))
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "giving up" in res.note
    assert res.findings == []
    assert _no_worktrees(r)


def test_baseline_two_failures_still_degrades(tmp_path, monkeypatch):
    # Below the give-up threshold the transient-retry contract stands.
    r, base, head = _repo(tmp_path,
                          "def test_always_fails():\n    assert False\n")
    _seed_baseline_failures(r, 2)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    assert "baseline failing" in res.note
```

Note: `_repo`, `_consume`, `_no_worktrees`, `WEAK_TEST`, `Ledger`, `mut_consumer` already exist in this file. The QueueItem id in `_consume` is `"q1"` — the seeded payloads match it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration/test_mutation_consumer.py::test_baseline_giveup_after_three_failures tests/integration/test_mutation_consumer.py::test_baseline_two_failures_still_degrades -v`
Expected: FAIL — first test hits the poisoned `run_subprocess` (AssertionError "give-up path must not run pytest"); second PASSES already (degraded is current behavior — it is the pin that the threshold is 3, not 2).

- [ ] **Step 3: Implement the helper + wrapper + give-up**

`src/aramid/consumers/base.py` — add import at top and helper at end:

```python
from aramid.models import EventType
```

```python
def prior_note_count(ledger, consumer: str, item_id: str, prefix: str) -> int:
    """How many CONSUMER_RUN_FINISHED events this consumer has already
    recorded for this queue item with a note starting with `prefix`.
    Give-up counters (llm_review malformed, mutation baseline-failing) key
    on this -- the note strings involved are load-bearing."""
    n = 0
    for e in ledger.events():
        if (e.type is EventType.CONSUMER_RUN_FINISHED
                and e.payload.get("consumer") == consumer
                and e.payload.get("item_id") == item_id
                and str(e.payload.get("note", "")).startswith(prefix)):
            n += 1
    return n
```

`src/aramid/consumers/llm_review.py` — replace the body of `_malformed_attempts` (lines 62-70):

```python
def _malformed_attempts(ledger, item_id: str) -> int:
    return base.prior_note_count(ledger, NAME, item_id, "malformed response")
```

Then check whether `EventType` is still referenced anywhere else in llm_review.py: `python -m ruff check src/aramid/consumers/llm_review.py`. If ruff flags the import unused, change line 21 to `from aramid.models import Source`. If other uses remain, leave the import.

`src/aramid/consumers/mutation.py` — add const after `NAME = "mutation"`:

```python
_BASELINE_GIVE_UP = 3   # mirrors llm_review._MALFORMED_GIVE_UP
```

and insert AFTER the no-pytest structural skip (the `return ... "no python test stack"` block) and BEFORE `started = time.monotonic()`:

```python
    if base.prior_note_count(ctx.ledger, NAME, item.id,
                             "baseline failing") >= _BASELINE_GIVE_UP:
        # A permanently-red suite must stop pinning the queue item: after 3
        # honest DEGRADED retries this becomes a permanent-skip. Keys on the
        # literal "baseline failing" note below -- both strings load-bearing.
        return ConsumerResult(consumer=NAME, state="ok",
                              note="mutation giving up: baseline persistently failing")
```

(`from aramid.consumers import base` is already imported in mutation.py.) Add the matching comment on the DEGRADED return:

```python
        if base_res.state is not ToolState.OK or base_res.returncode != 0:
            # Note text is load-bearing: the give-up counter above matches
            # notes starting with "baseline failing".
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note="baseline failing",
                                  duration_s=time.monotonic() - started)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_mutation_consumer.py tests/unit/test_llm_review.py tests/integration/test_llm_review.py -v` (adjust llm-review test paths to whichever exist — `python -m pytest tests -k llm -q` finds them). The llm-review malformed-give-up tests must pass UNCHANGED — that is the refactor's teeth.
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .   # must equal the recorded baseline
git add src/aramid/consumers/base.py src/aramid/consumers/llm_review.py src/aramid/consumers/mutation.py tests/integration/test_mutation_consumer.py
git commit -m "fix(mutation): baseline-failing give-up after 3 retries; shared prior_note_count helper (I2)"
```

---

### Task 2: M1 — killed-counter stage split + narrowing teeth

**Files:**
- Modify: `src/aramid/consumers/mutation.py` (stats keys)
- Test: `tests/integration/test_mutation_consumer.py` (1 new test, 2 assertions updated)

**Interfaces:**
- Produces: `stats`/`extra` keys `killed_s1` (stage-1 kill) and `killed_s2` (stage-2 kill). The combined `killed` key is REMOVED — `extra` is its only consumer. Task 3's code shows the post-split keys.

- [ ] **Step 1: Update existing assertions + write the failing test**

In `tests/integration/test_mutation_consumer.py`:
- `test_strong_suite_kills_no_findings`: change `assert res.extra["killed"] >= 1` → `assert res.extra["killed_s1"] >= 1` (a strong targeted suite kills at stage 1).
- `test_stage2_rescue_prevents_false_survivor`: change `assert res.extra["killed"] >= 1` → `assert res.extra["killed_s2"] >= 1` (the cross-file test only runs at the full-suite confirmation).

Append:

```python
def test_stage1_narrowing_actually_ran(tmp_path, monkeypatch):
    # Pin that stage 1 uses the targeted tests/test_<module>.py argv, not the
    # full suite -- a silent regression to full-suite-always would only show
    # as slowness. Spy wraps the REAL run_subprocess.
    r, base, head = _repo(tmp_path, WEAK_TEST)
    calls = []
    real = mut_consumer.run_subprocess

    def spy(argv, cwd, timeout, **kw):
        calls.append([str(a) for a in argv])
        return real(argv, cwd, timeout, **kw)

    monkeypatch.setattr(mut_consumer, "run_subprocess", spy)
    _consume(r, base, head, monkeypatch, tmp_path)
    targeted = [c for c in calls if any(a.endswith("test_calc.py") for a in c)]
    assert targeted, "stage 1 must have invoked the targeted test file"
    assert not any("-k" in c for c in calls), \
        "with tests/test_calc.py present the -k fallback must not fire"
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/integration/test_mutation_consumer.py -v`
Expected: the two updated assertions FAIL with KeyError `'killed_s1'`/`'killed_s2'`; the narrowing test PASSES already (it pins current behavior against future regression — verify it by temporarily breaking `_stage1_argv` to return `_full_argv()` unconditionally, seeing it fail, then reverting).

- [ ] **Step 3: Implement the split**

`src/aramid/consumers/mutation.py`:
- stats init: replace `"killed": 0` with `"killed_s1": 0, "killed_s2": 0`.
- stage-1 kill (`stats["killed"] += 1` inside the `s1.returncode not in (0, 5)` branch): → `stats["killed_s1"] += 1`.
- stage-2 kill (the `else: stats["killed"] += 1` after the confirmed branch): → `stats["killed_s2"] += 1`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_mutation_consumer.py tests/integration/test_drain* -q`
Expected: all PASS (drain e2e asserts `"confirmed"` in payload, unaffected).

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/consumers/mutation.py tests/integration/test_mutation_consumer.py
git commit -m "feat(mutation): split killed counter by stage + pin stage-1 narrowing (M1)"
```

---

### Task 3: M2 — `-k` safety + exit-code classification

**Files:**
- Modify: `src/aramid/consumers/mutation.py` (`_stage1_argv`, both verdict sites)
- Test: `tests/integration/test_mutation_consumer.py` (3 new tests)

**Interfaces:**
- Consumes: `killed_s1`/`killed_s2` keys from Task 2.
- Produces: `_SAFE_STEM` regex + `_K_KEYWORDS` set (module consts). Kill = pytest returncode in (1, 2); returncodes 3/4 → `stats["errors"]`, mutant unscored; survivor sets unchanged (stage-1: 0/5, stage-2: 0 only).

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_mutation_consumer.py`:

```python
def test_stage1_argv_unsafe_stem_falls_back_to_full_suite(tmp_path):
    # pytest -k chokes on expression keywords and non-word chars (exit 4 =
    # usage error, which previously scored as a KILL). Unsafe stems must use
    # the always-correct full-suite argv instead.
    for fname in ("not.py", "and.py", "or.py", "my-mod.py", "weird mod.py"):
        argv = mut_consumer._stage1_argv(tmp_path, fname)
        assert "-k" not in argv, fname
    safe = mut_consumer._stage1_argv(tmp_path, "calc.py")
    assert safe[-2:] == ["-k", "calc"]


def test_stage1_usage_error_counts_error_not_kill(tmp_path, monkeypatch):
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    seq = {"n": 0}

    def scripted(argv, cwd, timeout, **kw):
        seq["n"] += 1
        if seq["n"] == 1:      # baseline full suite: green
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        return RunnerResult(tool="pytest", state=ToolState.OK, returncode=4)

    monkeypatch.setattr(mut_consumer, "run_subprocess", scripted)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.extra["errors"] >= 1
    assert res.extra["killed_s1"] == 0, "usage error is not a kill"
    assert res.findings == []


def test_stage2_usage_error_never_reports_survivor(tmp_path, monkeypatch):
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    fulls = {"n": 0}

    def scripted(argv, cwd, timeout, **kw):
        joined = " ".join(str(a) for a in argv)
        if "test_calc.py" in joined:   # stage-1 targeted: mutant survives
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        fulls["n"] += 1
        if fulls["n"] == 1:            # baseline: green
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        return RunnerResult(tool="pytest", state=ToolState.OK, returncode=4)

    monkeypatch.setattr(mut_consumer, "run_subprocess", scripted)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.findings == [], "survivor is only reported when the full suite PASSES"
    assert res.extra["confirmed"] == 0
    assert res.extra["errors"] >= 1
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/integration/test_mutation_consumer.py -v -k "usage_error or unsafe_stem"`
Expected: FAIL — unsafe stems currently produce `-k not` etc.; exit-4 currently lands in `killed_s1` (first behavioral test) and `killed_s2` (second).

- [ ] **Step 3: Implement**

`src/aramid/consumers/mutation.py` — add near the top (with `import re` added to imports):

```python
_SAFE_STEM = re.compile(r"^[A-Za-z0-9_]+$")
_K_KEYWORDS = {"not", "and", "or"}   # pytest -k expression keywords
```

Replace `_stage1_argv`'s final line:

```python
def _stage1_argv(wt: Path, rel: str) -> list[str]:
    module = Path(rel).stem
    tests_dir = wt / "tests"
    if tests_dir.exists():
        hits = sorted(tests_dir.rglob(f"test_{module}.py"))
        if hits:
            return [sys.executable, "-m", "pytest", "-q",
                    *(str(p.relative_to(wt)) for p in hits)]
    if _SAFE_STEM.match(module) and module.lower() not in _K_KEYWORDS:
        return [sys.executable, "-m", "pytest", "-q", "-k", module]
    # Unsafe -k token (pytest keyword / expression-breaking chars): pytest
    # would exit 4 (usage error) and the suite would never run. Full suite
    # is always correct, just slower.
    return _full_argv()
```

Replace the stage-1 verdict block (currently `if s1.state is ToolState.OK and s1.returncode not in (0, 5): killed`):

```python
                    if s1.state is ToolState.OK and s1.returncode in (1, 2):
                        # 1 = test failures; 2 = interrupted/collection error
                        # (an import-breaking mutant genuinely causes 2).
                        stats["killed_s1"] += 1
                        continue
                    if s1.state is ToolState.OK and s1.returncode not in (0, 5):
                        # 3 = internal error, 4 = usage error: argv's fault,
                        # never the mutant's -- unattributable, like timeouts.
                        stats["errors"] += 1
                        continue
```

Replace the stage-2 verdict tail (after the `confirmed` branch, currently `else: stats["killed_s2"] += 1`):

```python
                    elif s2.state is ToolState.OK and s2.returncode in (1, 2):
                        stats["killed_s2"] += 1
                    else:
                        # Non-verdict full-suite outcome (internal/usage error,
                        # crash): the putative survivor is NOT reported -- a
                        # survivor requires the full suite to PASS on it.
                        stats["errors"] += 1
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_mutation_consumer.py -q`
Expected: all PASS (including the Task 1/2 tests — real pytest exits 1 on kill, still classified killed).

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/consumers/mutation.py tests/integration/test_mutation_consumer.py
git commit -m "fix(mutation): safe -k fallback + exit-code verdicts (usage error is not a kill) (M2)"
```

---

### Task 4: M5 — occurrence_index pin for variable-set consumers

**Files:**
- Modify: `src/aramid/normalizer.py:41-57` (keyword-only `pin_occurrence`)
- Modify: `src/aramid/commands/drain.py:114-117` (read flag, pass through)
- Modify: `src/aramid/consumers/mutation.py`, `src/aramid/consumers/fuzz.py` (module attr)
- Test: `tests/unit/test_normalizer.py` (2 new), `tests/integration/test_mutation_consumer.py` (2 new)

**Interfaces:**
- Produces: `normalize(..., *, pin_occurrence: bool = False)`; module attr `PIN_OCCURRENCE = True` on mutation and fuzz (absent elsewhere — drain reads it with `getattr(module, "PIN_OCCURRENCE", False)`).

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_normalizer.py` (uses the file's existing `_classify` helper and import style):

```python
def test_pin_occurrence_collapses_duplicates(tmp_path, monkeypatch):
    from aramid import gitutil
    monkeypatch.setattr(gitutil, "read_for_fingerprint", lambda root, ref, f: "x = y[0]\n")
    raws = [RawFinding("mutation", "cmp-flip", "medium", "a.py", 1, "m1"),
            RawFinding("mutation", "cmp-flip", "medium", "a.py", 1, "m2")]
    out = normalize(raws, tmp_path, lambda f: "HEAD", b"salt", Gate.ALL,
                    _classify, pin_occurrence=True)
    assert len({f.id for f in out}) == 1   # one finding per (tool,rule,file,line-content)


def test_pin_occurrence_makes_ids_subset_stable(tmp_path, monkeypatch):
    # THE M5 drift scenario: budget truncation changes batch membership; the
    # nth duplicate's id must not depend on who else is in the batch.
    from aramid import gitutil
    monkeypatch.setattr(gitutil, "read_for_fingerprint", lambda root, ref, f: "x = y[0]\n")
    ra = RawFinding("fuzz", "crash-indexerror", "medium", "a.py", 1, "c1")
    rb = RawFinding("fuzz", "crash-indexerror", "medium", "a.py", 1, "c2")
    full = normalize([ra, rb], tmp_path, lambda f: "HEAD", b"salt", Gate.ALL,
                     _classify, pin_occurrence=True)
    alone = normalize([rb], tmp_path, lambda f: "HEAD", b"salt", Gate.ALL,
                      _classify, pin_occurrence=True)
    assert full[1].id == alone[0].id
```

(The existing `test_two_identical_lines_get_distinct_ids` pins the default unpinned path — gate parity — and must stay green.)

Append to `tests/integration/test_mutation_consumer.py`:

```python
def test_pin_occurrence_declared_only_on_variable_set_consumers():
    from aramid.consumers import fuzz as fz
    import aramid.consumers.regression_pack as rp
    assert mut_consumer.PIN_OCCURRENCE is True
    assert fz.PIN_OCCURRENCE is True
    assert getattr(rp, "PIN_OCCURRENCE", False) is False, \
        "regression-pack fingerprints must keep exact gate parity"


def test_drain_passes_pin_flag_per_consumer(tmp_path, monkeypatch):
    # Flag-flow teeth: spy on drain's normalize and record the kwarg each
    # consumer's batch was normalized with.
    from aramid import registry
    from aramid.commands import drain as drain_mod
    from aramid.commands.drain import cmd_drain
    from aramid import queue as queue_mod

    r, base, head = _repo(tmp_path, WEAK_TEST)
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "drain.lock")
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    registry.register(r, "2026-07-20T10:00:00+00:00")
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        queue_mod.enqueue(led, "2026-07-20T10:00:00+00:00", base, head, 55, ["seed"])
    finally:
        led.close()

    seen = {}
    real_norm = drain_mod.normalize

    def spy(raws, root, ref_for, salt, gate, classify, *, pin_occurrence=False):
        seen[raws[0].tool] = pin_occurrence
        return real_norm(raws, root, ref_for, salt, gate, classify,
                         pin_occurrence=pin_occurrence)

    monkeypatch.setattr(drain_mod, "normalize", spy)
    cmd_drain([str(r)])
    assert seen.get("mutation") is True, \
        "mutation batch must normalize with pin_occurrence=True"
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_normalizer.py tests/integration/test_mutation_consumer.py -v -k "pin"`
Expected: FAIL — `normalize() got an unexpected keyword argument 'pin_occurrence'`; `AttributeError: ... has no attribute 'PIN_OCCURRENCE'`.

- [ ] **Step 3: Implement**

`src/aramid/normalizer.py` — signature and index line:

```python
def normalize(raws: list[RawFinding], root: Path, ref_for: Callable[[str], str],
              salt: bytes, gate: Gate, classify, *,
              pin_occurrence: bool = False) -> list[Finding]:
```

```python
        # pin_occurrence (M5): variable-set drain consumers (mutation, fuzz)
        # have budget-truncated batches, so positional occurrence indices
        # drift across drains -> ghost never-resolving findings. Pinning to 0
        # gives one finding per (tool, rule, file, line-content) -- the
        # llm_fingerprint precedent (review.py). Gate callers keep the
        # counter (default False): their batches are complete scans.
        occurrence_index = 0 if pin_occurrence else occurrence_counts[occ_key]
        occurrence_counts[occ_key] += 1
```

`src/aramid/commands/drain.py` — in `_consume_item`, replace the `normalize(...)` call:

```python
        if result.findings:
            pin = getattr(module, "PIN_OCCURRENCE", False)
            findings = normalize(result.findings, root, lambda f: item.head, salt,
                                 Gate.ALL, functools.partial(policy.classify, cfg=cfg),
                                 pin_occurrence=pin)
```

`src/aramid/consumers/mutation.py` and `src/aramid/consumers/fuzz.py` — after `NAME = ...`:

```python
# M5: batches are budget-truncated (variable membership across drains), so
# the drain normalizes them with occurrence_index pinned to 0 -- one finding
# per (tool, rule, file, line-content), truncation-stable fingerprints.
PIN_OCCURRENCE = True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_normalizer.py tests/integration/test_mutation_consumer.py tests/integration/test_fuzz_consumer.py -q`
Expected: all PASS (pre-release: no stored mutation/fuzz fingerprints to migrate).

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/normalizer.py src/aramid/commands/drain.py src/aramid/consumers/mutation.py src/aramid/consumers/fuzz.py tests/unit/test_normalizer.py tests/integration/test_mutation_consumer.py
git commit -m "fix(drain): pin occurrence_index for budget-truncated consumers (M5)"
```

---

### Task 5: Fuzz M4 — honest truncation flag

**Files:**
- Modify: `src/aramid/consumers/fuzz.py:96-119` (target-collection loop + helper)
- Test: `tests/integration/test_fuzz_consumer.py` (2 new tests + fixture)

**Interfaces:**
- Produces: `fuzz._any_candidates_remain(wt: Path, rels, changed: dict, skip_patterns) -> bool` (candidacy-only sweep, no fuzzing).

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_fuzz_consumer.py`:

```python
OK_FN = ("def ok(a: int) -> int:\n"
         "    return a\n")


def _two_file_repo(tmp_path, second_feature_body):
    # Two changed .py files; [fuzz] budget of exactly ONE function so the
    # second file is reached with budget 0. cases kept tiny for speed.
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 1\ncases_per_function = 5\n"
        "wall_budget_s = 200\nbatch_timeout_s = 90\n", encoding="utf-8")
    (r / "lib.py").write_text("def placeholder() -> None:\n    return None\n",
                              encoding="utf-8")
    (r / "other.py").write_text("Y = 0\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "lib.py").write_text(OK_FN, encoding="utf-8")          # 1 candidate
    (r / "other.py").write_text(second_feature_body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)


def test_exact_fit_budget_not_flagged_truncated(tmp_path, monkeypatch):
    # Budget exactly consumed and the remaining changed file has NO
    # candidates: claiming truncation is an over-report (fuzz M4).
    r, base, head = _two_file_repo(tmp_path, "X = 1\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.extra["truncated"] is False
    assert "truncated" not in res.note


def test_dropped_candidate_flagged_truncated(tmp_path, monkeypatch):
    # The remaining changed file DOES have a candidate that the budget
    # dropped: the flag must be set.
    r, base, head = _two_file_repo(
        tmp_path, "def also(b: int) -> int:\n    return b\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.extra["truncated"] is True
    assert "truncated" in res.note
```

(`sorted(files)` visits `lib.py` before `other.py`, so the budget of 1 is spent on `lib.py`'s candidate first. The in-file slice case — one file, two candidates, budget 1 — is already covered by the existing 2c-2 suite.)

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/integration/test_fuzz_consumer.py -v -k "truncated"`
Expected: `test_exact_fit_budget_not_flagged_truncated` FAILS (current code flags on next loop entry); `test_dropped_candidate_flagged_truncated` PASSES (pins existing correct behavior).

- [ ] **Step 3: Implement**

`src/aramid/consumers/fuzz.py` — add helper after `_candidate_functions`:

```python
def _any_candidates_remain(wt: Path, rels, changed: dict, skip_patterns) -> bool:
    """Candidacy-only sweep (AST parse, no fuzzing) over not-yet-visited
    changed files: keeps the truncated flag honest on exact-fit budget
    exhaustion. Unreadable/missing files count as no-candidates, matching
    the main loop's skip."""
    for rel in rels:
        src_path = wt / rel
        if not src_path.exists():
            continue
        try:
            source = src_path.read_text(encoding="utf-8")
        except OSError:
            continue
        cands, _, _ = _candidate_functions(source, changed[rel], skip_patterns)
        if cands:
            return True
    return False
```

Replace the loop head (lines 96-100):

```python
        targets, budget = [], max_functions
        for i, rel in enumerate(files):
            if budget <= 0:
                # Exact fit must not over-report (fuzz M4): only claim
                # truncation if a remaining file actually has candidates.
                if _any_candidates_remain(wt, files[i:], changed, skip_patterns):
                    stats["truncated"] = True
                break
```

(The in-file slice branch `len(cands) > budget` keeps setting `truncated` — that is an actual drop.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_fuzz_consumer.py -q`
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/consumers/fuzz.py tests/integration/test_fuzz_consumer.py
git commit -m "fix(fuzz): truncated flag only on actual candidate drop (M4)"
```

---

### Task 6: README side-effect caveat + full-suite gate

**Files:**
- Modify: `README.md:98-102` (the 2c-2 fuzz paragraph)

- [ ] **Step 1: Add the caveat sentence**

Extend the fuzz paragraph (currently ending "…Python repos with type hints, no test suite required)."):

```markdown
2c-2 (shipped) adds the fuzz consumer: diff-touched type-hinted functions are
called with deterministic seeded inputs in a throwaway worktree, and deep-crash
exceptions (IndexError, KeyError, …) are recorded as WARN-tier findings — the
seed is the repro (`[fuzz]` config: budgets, a scary-name skip-list; Python
repos with type hints, no test suite required). Repro caveat: the seed
reproduces a crash only for targets that are deterministic in their arguments —
functions depending on external state (files, network, globals, time) may not
replay from the recorded seed.
```

- [ ] **Step 2: Full-suite + ruff gate**

Run: `python -m pytest -q`
Expected: 752 base + ~9 new, all green.
Run: `python -m ruff check .` — must equal the recorded baseline.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(fuzz): side-effect repro caveat in README (2c-2 Minor)"
```

After Task 6: whole-branch review (sonnet subagent per project convention), fix wave if needed, then superpowers:finishing-a-development-branch.
