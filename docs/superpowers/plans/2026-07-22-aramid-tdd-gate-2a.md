# Aramid TDD Gate 2a — Mutation-Score Measurement + Persistence — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record a per-function mutation-outcome taxonomy each drain, persist it via `CONSUMER_RUN_FINISHED` extra, and surface it advisory through a read-only analyzer + `aramid mutation-score` command — no gate, no teeth, no arming.

**Architecture:** The drain-time mutation consumer accumulates a per-`"<rel>::<func>"` taxonomy alongside its existing item-global `stats`, computes each killed/confirmed-survivor mutant's fingerprint via one shared helper, and rides the block into `extra["mutation_scores"]`. A new read-only `mutation_score.py` folds that history into `TargetScore`s, derives each target's most-recent-prior fully-mutated baseline by event-stream position, and computes two advisory signals (per-mutant transition + per-function stage-1 rate-delta). A new `aramid mutation-score` command dumps them.

**Tech Stack:** Python 3.14, stdlib `ast`/`dataclasses`, `aramid.fingerprint.compute_fingerprint`, `aramid.ledger`/`aramid.models` event stream, `argparse` CLI, pytest.

## Global Constraints

*(Every task's requirements implicitly include this section. Copied verbatim from the 2a spec.)*

- **Additive / advisory only.** NO changes to `policy.py`, `check.py`, `pipeline.py`, `models.py`, the ledger schema, `[mutation]` config, or the arm surface. NO new `EventType`, NO new store. The consumer's existing findings, `stats`, and `note` behaviour stay UNCHANGED — 2a only *adds* `extra["mutation_scores"]`.
- **extra×extra join invariant (the one correctness rule that silently kills 2a if broken).** Both `killed_fps` and `survivor_fps` are computed INSIDE the consumer via ONE shared helper. The analyzer joins `extra × extra` and MUST NEVER read `Finding.id`.
- **Fingerprint recipe:** `compute_fingerprint("mutation", op, rel, line_content, 0)`, `line_content` = the source line at `m.line` (1-based → index `m.line - 1`) of the pre-mutation `original`, fail-safe to `""` on an out-of-range index. Occurrence pinned to `0`.
- **Rate denominator is stage-1:** `rate = killed_s1 / (killed_s1 + survived_s1)`, timeouts and errors EXCLUDED. `survived_s1` = every putative stage-1 survivor (whatever its later fate: confirmed, killed by the full suite = `killed_s2`, or confirm-capped) = the per-function analog of the existing `stats["survived"]`. Cap-independent.
- **`fully_mutated(F) = (killed_s1(F) + survived_s1(F) == generated(F))`** — a single condition; any budget-drop / timeout / error makes the sum `< generated`.
- **Transition core:** baseline `killed_fps` (= `killed_s1 ∪ killed_s2` fingerprints) ∩ current `survivor_fps` (= CONFIRMED survivors only).
- **Target key:** `"<rel>::<func>"`, `rel` the posix repo-relative path the consumer iterates.
- **Run ordering:** `Ledger.events()` returns events in seq order but exposes NO `seq` attribute — use the 0-based position in the `events()` stream as the run index. "Most-recent-prior fully-mutated" = largest run index `< current` with `fully_mutated`.
- **Schema-gated, fail-open:** taxonomy payloads carry `"schema": 1`; the analyzer SKIPS any payload that is absent, malformed, wrong-schema, or missing keys — it never raises.
- **Metric is code-change-triggered** (only changed functions are re-mutated): document like the 1b spec §10.

---

### Task 1: `Mutant.func` — structured enclosing-function attribution

**Files:**
- Modify: `src/aramid/mutation.py` (dataclass `Mutant`; `generate_mutants` append site ~line 96)
- Test: `tests/unit/test_mutation.py`

**Interfaces:**
- Produces: `Mutant.func: str` — the enclosing eligible function's name (`enc[2]`), `""` default. Task 2 keys the taxonomy on it.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_mutation.py` (import `from aramid import mutation` if not already present):

```python
def test_generated_mutants_carry_enclosing_function():
    src = ("def outer(x):\n"
           "    if x == 1:\n"
           "        return True\n"
           "    return False\n")
    muts = mutation.generate_mutants(src, {2})
    assert muts
    assert all(m.func == "outer" for m in muts)


def test_mutants_attribute_to_their_own_function():
    src = ("def a(x):\n"
           "    return x == 1\n"
           "def b(y):\n"
           "    return y == 2\n")
    muts = mutation.generate_mutants(src, {2, 4})
    assert {m.func for m in muts} == {"a", "b"}
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/unit/test_mutation.py -k "enclosing_function or attribute_to_their_own" -v`
Expected: FAIL (`AttributeError: 'Mutant' object has no attribute 'func'`).

- [ ] **Step 3: Add the field and populate it**

In `src/aramid/mutation.py`, extend the dataclass:

```python
@dataclass
class Mutant:
    file: str          # "" from generate_mutants; the consumer stamps it
    line: int
    op: str
    description: str
    source: str
    func: str = ""     # enclosing eligible function name (enc[2])
```

In `generate_mutants`, the append at ~line 96 (inside `for op, desc, mutate in _mutations_at(node, enc[2]):`, where `enc` is already bound and guaranteed non-`None`):

```python
            mutants.append(Mutant(file="", line=lineno, op=op,
                                  description=desc, source=mutated, func=enc[2]))
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest tests/unit/test_mutation.py -v`
Expected: PASS (all, including pre-existing).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/mutation.py tests/unit/test_mutation.py
git commit -m "feat(mutation): structured enclosing-function on Mutant (2a Task 1)"
```

---

### Task 2: Per-function taxonomy in the mutation consumer

**Files:**
- Modify: `src/aramid/consumers/mutation.py` (module helpers + the `consume` accumulation + the return `extra`)
- Test: `tests/unit/test_mutation.py` (fast unit tests for the pure helpers) and `tests/integration/test_mutation_consumer.py` (wiring)

**Interfaces:**
- Consumes: `Mutant.func` (Task 1).
- Produces: `ConsumerResult.extra["mutation_scores"] = {"schema": 1, "targets": {"<rel>::<func>": {generated, killed_s1, survived_s1, timeouts, errors, fully_mutated, killed_fps:[...], survivor_fps:[...]}}}`. Task 3 parses it. Also produces the module helpers `_mutant_fp`, `_new_target`, `_tgt`, `_finalize_scores`.

- [ ] **Step 1: Write the failing unit tests for the pure helpers**

Add to `tests/unit/test_mutation.py`:

```python
from aramid.consumers import mutation as mut_consumer


def test_mutant_fp_is_stable_and_matches_recipe():
    from aramid.fingerprint import compute_fingerprint
    lines = ["def f(x):", "    return x == 1"]
    fp = mut_consumer._mutant_fp("m.py", "cmp-flip", 2, lines)
    assert fp == compute_fingerprint("mutation", "cmp-flip", "m.py", "    return x == 1", 0)


def test_mutant_fp_out_of_range_line_is_safe():
    # never raises; hashes "" for a line past EOF
    assert isinstance(mut_consumer._mutant_fp("m.py", "cmp-flip", 99, ["a"]), str)


def test_finalize_scores_marks_fully_mutated():
    scores = {"m.py::f": mut_consumer._new_target()}
    scores["m.py::f"].update(generated=3, killed_s1=2, survived_s1=1)
    out = mut_consumer._finalize_scores(scores)
    assert out["schema"] == 1
    assert out["targets"]["m.py::f"]["fully_mutated"] is True


def test_finalize_scores_partial_not_fully_mutated():
    scores = {"m.py::f": mut_consumer._new_target()}
    scores["m.py::f"].update(generated=3, killed_s1=1, survived_s1=1, timeouts=1)
    out = mut_consumer._finalize_scores(scores)
    assert out["targets"]["m.py::f"]["fully_mutated"] is False
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/unit/test_mutation.py -k "mutant_fp or finalize_scores" -v`
Expected: FAIL (`AttributeError` — helpers not defined).

- [ ] **Step 3: Add the module-level helpers**

In `src/aramid/consumers/mutation.py`, add the import and helpers near the top (after the existing imports / `PIN_OCCURRENCE`):

```python
from aramid.fingerprint import compute_fingerprint


def _mutant_fp(rel: str, op: str, line: int, lines: list[str]) -> str:
    lc = lines[line - 1] if 0 <= line - 1 < len(lines) else ""
    return compute_fingerprint("mutation", op, rel, lc, 0)


def _new_target() -> dict:
    return {"generated": 0, "killed_s1": 0, "survived_s1": 0,
            "timeouts": 0, "errors": 0, "killed_fps": [], "survivor_fps": []}


def _tgt(scores: dict, rel: str, func: str) -> dict:
    key = f"{rel}::{func}"
    t = scores.get(key)
    if t is None:
        t = _new_target()
        scores[key] = t
    return t


def _finalize_scores(scores: dict) -> dict:
    for t in scores.values():
        t["fully_mutated"] = (t["killed_s1"] + t["survived_s1"] == t["generated"])
    return {"schema": 1, "targets": scores}
```

- [ ] **Step 4: Run to verify the unit tests pass**

Run: `python -m pytest tests/unit/test_mutation.py -k "mutant_fp or finalize_scores" -v`
Expected: PASS.

- [ ] **Step 5: Write the failing integration tests for the wiring**

Add to `tests/integration/test_mutation_consumer.py` (reuses the existing `_repo`, `_consume`, `ADULT`, `WEAK_TEST`, `STRONG_TEST` fixtures):

```python
def test_mutation_scores_recorded_for_strong_suite(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, STRONG_TEST)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    ms = res.extra["mutation_scores"]
    assert ms["schema"] == 1
    t = ms["targets"]["calc.py::is_adult"]
    assert t["killed_s1"] >= 1
    assert t["survived_s1"] == 0
    assert t["fully_mutated"] is True
    assert t["killed_fps"]           # non-empty
    assert t["survivor_fps"] == []


def test_mutation_scores_records_confirmed_survivor_fps(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    t = res.extra["mutation_scores"]["targets"]["calc.py::is_adult"]
    assert t["survived_s1"] >= 1
    assert t["survivor_fps"]         # confirmed survivor fingerprints present
    assert t["fully_mutated"] is True


def test_mutation_scores_partial_run_not_fully_mutated(tmp_path, monkeypatch):
    # Budget truncation (max_mutants=1) leaves is_adult's >=2 mutants partly
    # untested -> generated > killed_s1 + survived_s1 -> fully_mutated False.
    # Guards spec §11 + the Step 7b "count generated for ALL muts up front"
    # requirement: a mis-wire that counted only tested muts would falsely
    # report fully_mutated True and corrupt baseline selection.
    r, base, head = _repo(tmp_path, WEAK_TEST)
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 1\nconfirm_cap = 1\n",
        encoding="utf-8")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    t = res.extra["mutation_scores"]["targets"]["calc.py::is_adult"]
    assert t["fully_mutated"] is False
    assert t["generated"] > t["killed_s1"] + t["survived_s1"]


def test_mutation_scores_stage1_error_attributed_and_excluded(tmp_path, monkeypatch):
    # A stage-1 usage error (returncode 4) must land in the function's errors
    # bucket, never killed_s1/survived_s1 -> excluded from the rate and
    # fully_mutated False. Guards the 7e/7i error-attribution wiring.
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
    t = res.extra["mutation_scores"]["targets"]["calc.py::is_adult"]
    assert t["errors"] >= 1
    assert t["killed_s1"] == 0 and t["survived_s1"] == 0
    assert t["fully_mutated"] is False
```

*(Both reuse the `mut_consumer` import and `RunnerResult`/`ToolState` pattern already established in this file by `test_stage1_usage_error_counts_error_not_kill`.)*

- [ ] **Step 6: Run to verify they fail**

Run: `python -m pytest tests/integration/test_mutation_consumer.py -k "mutation_scores_recorded_for_strong or records_confirmed_survivor or partial_run_not_fully_mutated or stage1_error_attributed" -v`
Expected: FAIL (`KeyError: 'mutation_scores'`).

- [ ] **Step 7: Wire the accumulation into `consume`**

All edits are inside `consume` (`src/aramid/consumers/mutation.py`). Anchor each on the quoted existing line.

**7a.** After the `stats = {...}` initializer (the block ending `"truncated": False}`), add:

```python
    scores: dict[str, dict] = {}
```

**7b.** Inside `for rel in files:`, right after `muts = mutation.generate_mutants(original, changed[rel])` and its `stats["generated"] += len(muts)`, add:

```python
            lines = original.splitlines()
            for m in muts:
                _tgt(scores, rel, m.func)["generated"] += 1
```

**7c.** At the stage-1 timeout branch — after `stats["timeouts"] += 1` (the one just before `continue` under `if s1.state is ToolState.TIMEOUT:`), add:

```python
                        _tgt(scores, rel, m.func)["timeouts"] += 1
```

**7d.** At the stage-1 kill branch — after `stats["killed_s1"] += 1`, add:

```python
                        t = _tgt(scores, rel, m.func)
                        t["killed_s1"] += 1
                        t["killed_fps"].append(_mutant_fp(rel, m.op, m.line, lines))
```

**7e.** At the stage-1 argv-error branch — after `stats["errors"] += 1` (under `if s1.state is ToolState.OK and s1.returncode not in (0, 5):`), add:

```python
                        _tgt(scores, rel, m.func)["errors"] += 1
```

**7f.** At the putative-survivor branch — after `stats["survived"] += 1`, add:

```python
                    _tgt(scores, rel, m.func)["survived_s1"] += 1
```

**7g.** At the confirmed-survivor branch — after `stats["confirmed"] += 1` (inside the `findings.append(...)` branch; add it right after the `stats["confirmed"] += 1` line, before/after the `findings.append` is fine), add:

```python
                        _tgt(scores, rel, m.func)["survivor_fps"].append(
                            _mutant_fp(rel, m.op, m.line, lines))
```

**7h.** At the stage-2 kill branch — after `stats["killed_s2"] += 1`, add:

```python
                        _tgt(scores, rel, m.func)["killed_fps"].append(
                            _mutant_fp(rel, m.op, m.line, lines))
```

**7i.** At the stage-2 non-verdict branch — after the `else:` `stats["errors"] += 1` (the "Non-verdict full-suite outcome" comment block), add:

```python
                        _tgt(scores, rel, m.func)["errors"] += 1
```

**7j.** In the `finally:` restore block — after the inner `stats["errors"] += 1` (the `except OSError` on the restore write), add:

```python
                        _tgt(scores, rel, m.func)["errors"] += 1
```

**7k.** At the return, change the `extra`:

```python
    extra = dict(stats)
    extra["mutation_scores"] = _finalize_scores(scores)
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=time.monotonic() - started, cost=0.0,
                          note=note, extra=extra)
```

- [ ] **Step 8: Run to verify the integration tests pass**

Run: `python -m pytest tests/integration/test_mutation_consumer.py -k "mutation_scores_recorded_for_strong or records_confirmed_survivor or partial_run_not_fully_mutated or stage1_error_attributed" -v`
Expected: PASS.

- [ ] **Step 9: Run the full mutation-consumer + unit-mutation files (regression guard)**

Run: `python -m pytest tests/unit/test_mutation.py tests/integration/test_mutation_consumer.py -q`
Expected: PASS (existing survivor/kill/stage2 tests unaffected — `stats`, `note`, and `findings` are unchanged).

- [ ] **Step 10: Commit**

```bash
git add src/aramid/consumers/mutation.py tests/unit/test_mutation.py tests/integration/test_mutation_consumer.py
git commit -m "feat(mutation): per-function outcome taxonomy in extra[mutation_scores] (2a Task 2)"
```

---

### Task 3: Analyzer data model + parse (`mutation_score.py`)

**Files:**
- Create: `src/aramid/mutation_score.py`
- Test: `tests/unit/test_mutation_score.py`

**Interfaces:**
- Consumes: the `extra["mutation_scores"]` schema (Task 2) as it appears in `CONSUMER_RUN_FINISHED` payloads.
- Produces: `TargetScore(target, run_index, killed_s1, survived_s1, fully_mutated, killed_fps, survivor_fps)` with a `.rate` property (`None` when the denominator is 0); `iter_target_scores(events) -> list[TargetScore]`. Task 4 consumes both.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_mutation_score.py`:

```python
from aramid import mutation_score
from aramid.models import Event, EventType


def _crf(idx, target, killed_s1, survived_s1, fully,
         killed_fps=(), survivor_fps=()):
    return Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", "t", payload={
        "consumer": "mutation", "item_id": "q",
        "mutation_scores": {"schema": 1, "targets": {target: {
            "generated": killed_s1 + survived_s1, "killed_s1": killed_s1,
            "survived_s1": survived_s1, "timeouts": 0, "errors": 0,
            "fully_mutated": fully, "killed_fps": list(killed_fps),
            "survivor_fps": list(survivor_fps)}}}})


def test_iter_target_scores_parses_and_indexes():
    events = [_crf(0, "f.py::g", 2, 1, True, killed_fps=["a", "b"])]
    scores = mutation_score.iter_target_scores(events)
    assert len(scores) == 1
    s = scores[0]
    assert s.target == "f.py::g"
    assert s.killed_s1 == 2 and s.survived_s1 == 1
    assert s.rate == 2 / 3
    assert s.run_index == 0
    assert s.killed_fps == frozenset({"a", "b"})


def test_run_index_is_event_stream_position():
    other = Event(EventType.RUN_FINISHED, "r", "t", payload={})
    events = [other, _crf(1, "f.py::g", 1, 0, True)]
    scores = mutation_score.iter_target_scores(events)
    assert scores[0].run_index == 1   # position in the stream, not the CRF count


def test_rate_none_when_no_verdicts():
    events = [_crf(0, "f.py::g", 0, 0, False)]
    assert mutation_score.iter_target_scores(events)[0].rate is None


def test_iter_skips_malformed_and_wrong_schema():
    bad_schema = Event(EventType.CONSUMER_RUN_FINISHED, "r", "t",
                       payload={"mutation_scores": {"schema": 99, "targets": {}}})
    no_scores = Event(EventType.CONSUMER_RUN_FINISHED, "r", "t", payload={})
    bad_target = Event(EventType.CONSUMER_RUN_FINISHED, "r", "t", payload={
        "mutation_scores": {"schema": 1, "targets": {"x::y": "not-a-dict"}}})
    assert mutation_score.iter_target_scores([bad_schema, no_scores, bad_target]) == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/unit/test_mutation_score.py -v`
Expected: FAIL (`ModuleNotFoundError: aramid.mutation_score`).

- [ ] **Step 3: Create the analyzer parse layer**

Create `src/aramid/mutation_score.py`:

```python
"""mutation_score -- read-only analyzer over the drain's per-function
mutation-outcome taxonomy (2a design spec). Derives each function's baseline
from CONSUMER_RUN_FINISHED history and computes two advisory signals: a
per-mutant transition (a mutant killed in the prior fully-mutated run that
now survives) and a per-function stage-1 rate-delta. No Verdict, no gate, no
ledger writes; fail-open on malformed/absent/wrong-schema history.

Run ordering is the position of the event in Ledger.events() (which exposes
no seq attribute); it is monotonic in true seq order and compaction-safe."""
from dataclasses import dataclass

from aramid.models import EventType

_SCHEMA = 1


@dataclass(frozen=True)
class TargetScore:
    target: str
    run_index: int
    killed_s1: int
    survived_s1: int
    fully_mutated: bool
    killed_fps: frozenset
    survivor_fps: frozenset

    @property
    def rate(self) -> float | None:
        d = self.killed_s1 + self.survived_s1
        return self.killed_s1 / d if d else None


def iter_target_scores(events) -> list[TargetScore]:
    out: list[TargetScore] = []
    for idx, e in enumerate(events):
        if e.type is not EventType.CONSUMER_RUN_FINISHED:
            continue
        ms = e.payload.get("mutation_scores")
        if not isinstance(ms, dict) or ms.get("schema") != _SCHEMA:
            continue
        targets = ms.get("targets")
        if not isinstance(targets, dict):
            continue
        for key, t in targets.items():
            if not isinstance(t, dict):
                continue
            try:
                out.append(TargetScore(
                    target=key, run_index=idx,
                    killed_s1=int(t["killed_s1"]),
                    survived_s1=int(t["survived_s1"]),
                    fully_mutated=bool(t["fully_mutated"]),
                    killed_fps=frozenset(t.get("killed_fps", [])),
                    survivor_fps=frozenset(t.get("survivor_fps", []))))
            except (KeyError, TypeError, ValueError):
                continue
    return out
```

*(Task 4 adds the `field` import when it introduces `Regression`.)*

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest tests/unit/test_mutation_score.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/mutation_score.py tests/unit/test_mutation_score.py
git commit -m "feat(mutation-score): TargetScore + iter_target_scores parse layer (2a Task 3)"
```

---

### Task 4: Analyzer detection — baseline, transition, rate-delta

**Files:**
- Modify: `src/aramid/mutation_score.py`
- Test: `tests/unit/test_mutation_score.py`

**Interfaces:**
- Consumes: `TargetScore`, `iter_target_scores` (Task 3).
- Produces: `Regression(target, kind, baseline_index, current_index, detail, transition_fps)`; `baseline_for(scores, target, before_index) -> TargetScore | None`; `detect(current, baseline) -> list[Regression]`; `latest_regressions(events) -> list[Regression]`. Task 5 consumes `latest_regressions` + `iter_target_scores`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_mutation_score.py` (reusing `_crf`):

```python
def test_transition_fires_when_killed_mutant_now_survives():
    FP = "deadbeef"
    events = [
        _crf(0, "calc.py::is_adult", 2, 0, True, killed_fps=[FP, "other"]),
        _crf(1, "calc.py::is_adult", 1, 1, True, killed_fps=["other"],
             survivor_fps=[FP]),
    ]
    regs = mutation_score.latest_regressions(events)
    trans = [r for r in regs if r.kind == "transition"]
    assert len(trans) == 1
    assert FP in trans[0].transition_fps
    assert trans[0].baseline_index == 0 and trans[0].current_index == 1


def test_transition_fires_against_partial_current_run():
    # a survivor in a truncated current run still transitions vs a full baseline
    FP = "cafe"
    events = [
        _crf(0, "m.py::f", 2, 0, True, killed_fps=[FP]),
        _crf(1, "m.py::f", 0, 1, False, survivor_fps=[FP]),   # partial current
    ]
    regs = mutation_score.latest_regressions(events)
    assert any(r.kind == "transition" for r in regs)
    assert not any(r.kind == "rate" for r in regs)   # rate skipped: current partial


def test_rate_regression_full_to_partial_kill():
    events = [
        _crf(0, "m.py::f", 3, 0, True),   # rate 1.00
        _crf(1, "m.py::f", 1, 2, True),   # rate 0.33
    ]
    regs = [r for r in mutation_score.latest_regressions(events) if r.kind == "rate"]
    assert len(regs) == 1
    assert regs[0].detail == "1.00 -> 0.33"


def test_partial_current_no_rate_regression():
    events = [
        _crf(0, "m.py::f", 3, 0, True),
        _crf(1, "m.py::f", 1, 2, False),   # partial
    ]
    assert [r for r in mutation_score.latest_regressions(events)
            if r.kind == "rate"] == []


def test_baseline_is_most_recent_prior_fully_mutated():
    events = [
        _crf(0, "m.py::f", 3, 0, True),    # older full, rate 1.00
        _crf(1, "m.py::f", 0, 3, False),   # partial - never a baseline
        _crf(2, "m.py::f", 1, 2, True),    # current, rate 0.33
    ]
    regs = [r for r in mutation_score.latest_regressions(events) if r.kind == "rate"]
    assert len(regs) == 1
    assert regs[0].baseline_index == 0


def test_no_baseline_no_regression():
    events = [_crf(0, "m.py::f", 1, 2, True)]
    assert mutation_score.latest_regressions(events) == []


def test_rate_improvement_is_not_a_regression():
    events = [
        _crf(0, "m.py::f", 1, 2, True),    # rate 0.33
        _crf(1, "m.py::f", 3, 0, True),    # rate 1.00 (better)
    ]
    assert [r for r in mutation_score.latest_regressions(events)
            if r.kind == "rate"] == []


def test_latest_by_target_picks_highest_run_index():
    events = [_crf(0, "a::f", 1, 0, True), _crf(1, "a::f", 0, 1, True),
              _crf(2, "b::g", 1, 0, True)]
    latest = mutation_score.latest_by_target(
        mutation_score.iter_target_scores(events))
    assert latest["a::f"].run_index == 1   # stream position, not the run_id label
    assert latest["b::g"].run_index == 2
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/unit/test_mutation_score.py -k "transition or rate or baseline or no_baseline" -v`
Expected: FAIL (`AttributeError: module ... has no attribute 'latest_regressions'`).

- [ ] **Step 3: Add the detection layer**

First update the import at the top of `src/aramid/mutation_score.py` (add `field`):

```python
from dataclasses import dataclass, field
```

Then append:

```python
@dataclass(frozen=True)
class Regression:
    target: str
    kind: str                    # "transition" | "rate"
    baseline_index: int
    current_index: int
    detail: str
    transition_fps: frozenset = field(default_factory=frozenset)


def baseline_for(scores, target, before_index):
    best = None
    for s in scores:
        if s.target == target and s.fully_mutated and s.run_index < before_index:
            if best is None or s.run_index > best.run_index:
                best = s
    return best


def latest_by_target(scores):
    latest: dict[str, TargetScore] = {}
    for s in scores:
        cur = latest.get(s.target)
        if cur is None or s.run_index > cur.run_index:
            latest[s.target] = s
    return latest


def detect(current, baseline):
    if baseline is None:
        return []
    out = []
    trans = baseline.killed_fps & current.survivor_fps
    if trans:
        out.append(Regression(
            target=current.target, kind="transition",
            baseline_index=baseline.run_index, current_index=current.run_index,
            detail=f"{len(trans)} mutant(s) regressed: " + ", ".join(sorted(trans)),
            transition_fps=frozenset(trans)))
    if current.fully_mutated and baseline.fully_mutated \
            and current.rate is not None and baseline.rate is not None \
            and current.rate < baseline.rate:
        out.append(Regression(
            target=current.target, kind="rate",
            baseline_index=baseline.run_index, current_index=current.run_index,
            detail=f"{baseline.rate:.2f} -> {current.rate:.2f}"))
    return out


def latest_regressions(events):
    scores = iter_target_scores(events)
    out = []
    for target, cur in latest_by_target(scores).items():
        out.extend(detect(cur, baseline_for(scores, target, cur.run_index)))
    return out
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest tests/unit/test_mutation_score.py -v`
Expected: PASS (all, including Task 3's).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/mutation_score.py tests/unit/test_mutation_score.py
git commit -m "feat(mutation-score): transition + rate-delta detection over baselines (2a Task 4)"
```

---

### Task 5: `aramid mutation-score` advisory command

**Files:**
- Create: `src/aramid/commands/mutation_score.py`
- Modify: `src/aramid/cli.py` (import, subparser, dispatch)
- Test: `tests/integration/test_mutation_score_cmd.py`, `tests/integration/test_cli_dispatch.py`

**Interfaces:**
- Consumes: `mutation_score.iter_target_scores`, `mutation_score.latest_regressions` (Tasks 3-4); `Ledger` (`aramid.ledger`).
- Produces: `cmd_mutation_score(root, *, as_json=False) -> int` (0 on a readable ledger, 3 on engine error). Wired as subcommand `mutation-score` with `--json`.

- [ ] **Step 1: Write the failing command tests**

Create `tests/integration/test_mutation_score_cmd.py`:

```python
import json

from aramid.commands.mutation_score import cmd_mutation_score
from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _seed(led, idx, target, killed_s1, survived_s1, fully):
    led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", "t", payload={
        "consumer": "mutation", "item_id": "q",
        "mutation_scores": {"schema": 1, "targets": {target: {
            "generated": killed_s1 + survived_s1, "killed_s1": killed_s1,
            "survived_s1": survived_s1, "timeouts": 0, "errors": 0,
            "fully_mutated": fully, "killed_fps": [], "survivor_fps": []}}}}))


def test_cmd_reports_scores_and_rate_regression(tmp_path, capsys):
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 3, 0, True)
    _seed(led, 1, "m.py::f", 1, 2, True)
    led.close()
    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "m.py::f" in out
    assert "1.00 -> 0.33" in out


def test_cmd_empty_history(tmp_path, capsys):
    rc = cmd_mutation_score(tmp_path)
    assert rc == 0
    assert "no mutation scores recorded" in capsys.readouterr().out


def test_cmd_json_is_latest_per_target(tmp_path, capsys):
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 3, 0, True)
    _seed(led, 1, "m.py::f", 1, 2, True)
    led.close()
    rc = cmd_mutation_score(tmp_path, as_json=True)
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    ms = [t for t in doc["targets"] if t["target"] == "m.py::f"]
    assert len(ms) == 1, "JSON emits latest-per-target (spec §6), not full history"
    assert ms[0]["killed_s1"] == 1   # the latest run's values, not the first
    assert any(r["kind"] == "rate" for r in doc["regressions"])
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/integration/test_mutation_score_cmd.py -v`
Expected: FAIL (`ModuleNotFoundError: aramid.commands.mutation_score`).

- [ ] **Step 3: Create the command**

Create `src/aramid/commands/mutation_score.py`:

```python
"""mutation-score -- read-only advisory report of per-function mutation
scores and detected regressions (2a). Never mutates the ledger, never runs a
gate. Exit 0 on a readable ledger, 3 on engine error."""
import json
import sys
from pathlib import Path

from aramid import mutation_score as analyzer
from aramid.ledger import Ledger


def cmd_mutation_score(root, *, as_json: bool = False) -> int:
    root = Path(root)
    try:
        ledger = Ledger(root / ".aramid" / "ledger.db")
    except Exception as exc:
        print(f"aramid: mutation-score: engine error: {exc}", file=sys.stderr)
        return 3
    try:
        events = ledger.events()
        scores = analyzer.iter_target_scores(events)
        latest = analyzer.latest_by_target(scores)   # current per-target (spec §6)
        regressions = analyzer.latest_regressions(events)
        if as_json:
            print(json.dumps({
                "targets": [
                    {"target": s.target, "run_index": s.run_index,
                     "killed_s1": s.killed_s1, "survived_s1": s.survived_s1,
                     "rate": s.rate, "fully_mutated": s.fully_mutated}
                    for s in (latest[k] for k in sorted(latest))],
                "regressions": [
                    {"target": r.target, "kind": r.kind, "detail": r.detail,
                     "baseline_index": r.baseline_index,
                     "current_index": r.current_index}
                    for r in regressions]}, indent=2))
            return 0
        if not latest:
            print("aramid mutation-score: no mutation scores recorded")
            return 0
        lines = ["aramid mutation-score:"]
        for target in sorted(latest):
            s = latest[target]
            rate = f"{s.rate:.2f}" if s.rate is not None else "n/a"
            fm = "" if s.fully_mutated else " (partial)"
            lines.append(f"  {target}: kill-rate {rate} "
                         f"({s.killed_s1}/{s.killed_s1 + s.survived_s1}){fm}")
        if regressions:
            lines.append("  regressions:")
            for r in sorted(regressions, key=lambda r: (r.target, r.kind)):
                lines.append(f"    {r.target} [{r.kind}]: {r.detail}")
        else:
            lines.append("  regressions: none")
        print("\n".join(lines))
        return 0
    except Exception as exc:
        print(f"aramid: mutation-score: engine error: {exc}", file=sys.stderr)
        return 3
    finally:
        ledger.close()
```

- [ ] **Step 4: Wire the CLI**

In `src/aramid/cli.py`:

Import (with the other `from aramid.commands.*` imports):
```python
from aramid.commands.mutation_score import cmd_mutation_score
```

Subparser (in `build_parser`, e.g. after the `status` parser):
```python
    p_ms = sub.add_parser("mutation-score",
                          help="advisory per-function mutation-score + regression report")
    p_ms.add_argument("--json", action="store_true")
```

Dispatch (in `main`, e.g. after the `status` dispatch):
```python
    if args.command == "mutation-score":
        return cmd_mutation_score(root, as_json=args.json)
```

- [ ] **Step 5: Write the failing dispatch test**

Add to `tests/integration/test_cli_dispatch.py`:

```python
def test_mutation_score_dispatch(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_mutation_score",
                        lambda root, as_json=False: captured.update(root=root, as_json=as_json) or 0)
    assert cli.main(["mutation-score", "--json"]) == 0
    assert captured["as_json"] is True
    assert captured["root"] == Path.cwd()
```

- [ ] **Step 6: Run to verify all Task-5 tests pass**

Run: `python -m pytest tests/integration/test_mutation_score_cmd.py tests/integration/test_cli_dispatch.py -k "mutation_score or dispatch" -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/aramid/commands/mutation_score.py src/aramid/cli.py tests/integration/test_mutation_score_cmd.py tests/integration/test_cli_dispatch.py
git commit -m "feat(cli): aramid mutation-score advisory report command (2a Task 5)"
```

---

### Task 6: Docs, full suite, ruff (final validation)

**Files:**
- Modify: `README.md` (mutation section — add the advisory command + the documented limitations)
- No test file; this task validates the whole branch.

- [ ] **Step 1: Document the command and limitations**

In `README.md`, in the mutation/drain section, add a short subsection describing `aramid mutation-score` as an **advisory** report (no gate, no teeth) and the four documented limitations, matching spec §10:
1. code-change-triggered — silent on test-weakening against unchanged code;
2. rate-delta is a narrow-oracle self-delta — silent on any function whose mutants were budget-dropped / timed out / errored (`fully_mutated == False`);
3. the function-key baseline is lost on a function or file rename (one missed signal at the rename boundary);
4. transition recall is bounded by `confirm_cap` (an unconfirmed survivor fires on a later drain).

(Find the section with: `grep -n "mutation" README.md`. Match the surrounding heading style.)

- [ ] **Step 2: Commit the docs**

```bash
git add README.md
git commit -m "docs: aramid mutation-score command + 2a limitations (2a Task 6)"
```

- [ ] **Step 3: ruff**

Run: `python -m ruff check src/aramid/mutation.py src/aramid/consumers/mutation.py src/aramid/mutation_score.py src/aramid/commands/mutation_score.py src/aramid/cli.py`
Expected: no new findings (baseline was 43 project-wide at 1b; the touched files add none).

- [ ] **Step 4: Full suite (CONTROLLER runs this in background — ~10 min)**

The full suite (`python -m pytest -q`) takes ~10 min (936 tests as of 1b), which exceeds the foreground tool timeout. The **controller** runs it via `run_in_background` and hands the verified counts back; the implementer re-verifies first-hand before finalizing.
Expected: all pass (previous green baseline 936 passed / 3 skipped / 0 failed at 1b, plus the ~20 new tests here).

- [ ] **Step 5: Final commit (if any doc tweaks remain)**

```bash
git add -A
git commit -m "chore(mutation-score): 2a complete — full suite green, ruff clean"
```

---

## Self-Review

**1. Spec coverage:** §2 code-change-triggered → documented in Task 6 + Global Constraints. §3.1 transition → Task 4 `detect`. §3.2 stage-1 rate-delta → Task 4 + Global Constraints denominator. §4 extra×extra invariant → Task 2 (both fp sides in-consumer via `_mutant_fp`) + Task 3/4 (analyzer reads only `extra`). §5.1 `Mutant.func` → Task 1. §5.2 schema → Task 2 `_finalize_scores`. §5.3 `fully_mutated` → Task 2 `_finalize_scores` unit tests **plus** the Task 2 integration truncation + stage-1-error tests that drive `fully_mutated == False` and the timeout/error bucket attribution through the real consumer (per spec §11). §5.4 shared helper → Task 2 `_mutant_fp`. §6 file structure → Tasks 1-5. §7 analyzer API → Tasks 3-4 (`latest_by_target` shared by `latest_regressions` and the command). §8 flow → Task 5 command (text and `--json` both latest-per-target, spec §6). §9 fail-open → Task 3 (`iter_target_scores` skips) + Task 5 (try/except → 3). §10 limitations → Task 6. §11 testing (synthetic seeded history, red-first transition, consumer-side partial-run coverage) → Tasks 2-5. §12 reuse caveat → out of scope for 2a (no findings emitted); no task, correct. §13 non-goals → Global Constraints "additive only".

**2. Placeholder scan:** none — every step carries complete code or an exact command. The only prose-only step is Task 6 Step 1 (README), which is documentation with an exact `grep` locator and the four bullet contents spelled out.

**3. Type consistency:** `Mutant.func` (Task 1) consumed as `m.func` (Task 2). `extra["mutation_scores"]` schema (Task 2) parsed field-for-field in Task 3. `TargetScore`/`Regression` fields (Tasks 3-4) consumed verbatim in Task 5's JSON/text dumps and tests. `run_index` = event-stream position everywhere (Global Constraints + Task 3 `enumerate`). `cmd_mutation_score(root, *, as_json=False)` signature matches the dispatch call and the dispatch-test lambda.

**Cross-task footgun watch (for the whole-branch review):** the `_mutant_fp` recipe in the consumer (Task 2) must stay byte-identical to what the analyzer's join assumes; since the analyzer only ever intersects `extra` fp-sets against each other (never `Finding.id`), a recipe change is self-consistent by construction — but any future change that routes one side through the normalizer reintroduces the silent-zero-detection risk. Called out in Global Constraints.

## Execution Handoff

Plan complete. Execution: **subagent-driven-development** (fresh implementer per task, task review after each, opus whole-branch review at the end), consistent with 1a/1b.
