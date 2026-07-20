# Aramid Cleanup Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 7 verified-backlog cleanup items: compact() de-risk, shared LLM-BLOCK predicate, deps force_refresh wiring, triage scoped-diff, bounded post-kill test, update-rules formal close, pnpm/yarn shape-shift drift guard.

**Architecture:** Small, independent edits across `ledger.py`, `autolearn.py`, `review.py`/`override.py`/`status.py`, `runners/base.py`, `pipeline.py`, `triage.py`, `runners/deps.py`, `commands/update_rules.py`. Each item is one task with its own TDD cycle. Gate-path behavior preserved except items 3 and 7 (intended fixes).

**Tech Stack:** Python stdlib + sqlite3. Tests via `python -m pytest` (Windows: tools in `%APPDATA%\Python\Python314\Scripts`, never bare `pytest`).

**Spec:** `docs/superpowers/specs/2026-07-20-aramid-cleanup-bundle-design.md`

## Global Constraints

- Branch: `feat/cleanup-bundle` off main @ 8390ce9. Never implement on main.
- Ruff parity: `python -m ruff check .` must equal the baseline measured at branch creation (expected 43). Every task matches it.
- Full suite green before merge: `python -m pytest -q` (772 base + new).
- Commit trailer on every commit: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` (omitted below for brevity — always add).
- Ledger events store `payload` as JSON TEXT; `type` column is `str(EventType)` (e.g. `"consumer_run_finished"`). `EventType.CONSUMER_RUN_FINISHED.value == "consumer_run_finished"`.
- Gate-path invariant: no behavior change except item 2 (equivalent refactor), item 3 (`--all` re-audits — intended), item 7 (drift → CRASHED/degraded — intended, fail toward visibility).

---

### Task 1: compact() de-risk (give-up rows + autolearn shrink-safety)

**Files:**
- Modify: `src/aramid/ledger.py:118-166` (compact keep-set), `src/aramid/autolearn.py:234-236` (rollup shrink branch)
- Test: `tests/unit/test_ledger_compact.py`, `tests/unit/test_autolearn_rollup.py` (the rollup-specific autolearn test file)

**Interfaces:**
- No new public API. `compact()` keeps give-up-relevant CONSUMER_RUN_FINISHED rows; `rollup` skips folding on a shrunk ledger.

- [ ] **Step 0: Branch + ruff baseline**

```bash
git checkout -b feat/cleanup-bundle
python -m ruff check . 2>&1 | tail -1   # expect "Found 43 errors." — record it
```

- [ ] **Step 1: Write the compact give-up test (red)**

Append to `tests/unit/test_ledger_compact.py`:

```python
def test_compact_preserves_giveup_consumer_rows(tmp_path):
    # prior_note_count give-up counters read per-(consumer,item) rows; compact
    # must not collapse them to one (that silently resets the counter).
    from aramid.consumers import base as consumer_base
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType
    led = Ledger(tmp_path / "l.db")
    try:
        for i in range(3):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}", "t",
                             payload={"consumer": "mutation", "item_id": "q1",
                                      "state": "degraded",
                                      "note": "baseline failing @ abc123"}))
        assert consumer_base.prior_note_count(led, "mutation", "q1", "baseline failing") == 3
        led.compact()
        assert consumer_base.prior_note_count(led, "mutation", "q1", "baseline failing") == 3
    finally:
        led.close()
```

- [ ] **Step 2: Run it (red)**

Run: `python -m pytest tests/unit/test_ledger_compact.py::test_compact_preserves_giveup_consumer_rows -v`
Expected: FAIL — post-compact count is 1 (latest_singleton collapse).

- [ ] **Step 3: Fix the compact keep-set**

`src/aramid/ledger.py`, widen the SELECT to include payload (line 118-119):

```python
        rows = self._c.execute(
            "SELECT seq,type,finding_id,payload FROM events ORDER BY seq").fetchall()
```

Every `for seq, type_, finding_id in rows:` loop in the method becomes
`for seq, type_, finding_id, _payload in rows:` (there are three such loops — the
`last_detect` loop ~124, the `last_terminal` loop ~135, and the queue/singleton
loop ~159). In the queue/singleton loop, after the existing `latest_singleton`
assignment, add give-up-row preservation:

```python
        for seq, type_, finding_id, _payload in rows:
            if type_ in queue_types and finding_id in queued_ids:
                keep.add(seq)
            if type_ in (EventType.TRIAGE_RECORDED.value,
                         EventType.CONSUMER_RUN_FINISHED.value,
                         EventType.RUN_FINISHED.value):
                latest_singleton[type_] = seq
            if type_ == EventType.CONSUMER_RUN_FINISHED.value:
                # Give-up counters (consumers.base.prior_note_count) read every
                # per-(consumer,item) row, not just the newest -- preserve them
                # all, else llm/mutation give-up history silently resets.
                try:
                    pl = json.loads(_payload)
                except (ValueError, TypeError):
                    pl = {}
                if pl.get("consumer") and pl.get("item_id"):
                    keep.add(seq)
```

- [ ] **Step 4: Run it (green)**

Run: `python -m pytest tests/unit/test_ledger_compact.py -v`
Expected: all PASS (existing compact tests still hold — give-up rows are additive to the keep-set).

- [ ] **Step 5: Write the autolearn shrink test (red)**

Append to `tests/unit/test_autolearn_rollup.py`:

```python
def test_rollup_skips_fold_on_shrunk_ledger_no_double_count():
    # A compacted ledger has fewer events than the stored cursor. Re-folding
    # surviving events onto already-populated posteriors would double-count;
    # rollup must skip the fold instead (correct counts need --rebuild).
    from aramid import autolearn
    state = {"cursors": {"repo": 100},
             "posteriors": {"p/m|A|x": {"misses": 5, "clean": 5}},
             "audits": {"performed": 0, "missed_criticals": 0}}
    out = autolearn.rollup(state, events=[], repo_key="repo")  # 0 events < cursor 100
    assert out["posteriors"]["p/m|A|x"] == {"misses": 5, "clean": 5}  # unchanged
```

- [ ] **Step 6: Run it (red)**

Run: `python -m pytest tests -k "rollup_skips_fold_on_shrunk" -v`
Expected: PASS or FAIL depending — with 0 events the current code sets cursor=0 then folds `events[0:]` = nothing, so posteriors may be unchanged already. To make the test discriminate, use a non-empty surviving list whose re-fold WOULD change posteriors. Replace the test body's `events=[]` with a one-event list that folds into the same cell, and assert no increase. Concretely:

```python
def test_rollup_skips_fold_on_shrunk_ledger_no_double_count():
    from aramid import autolearn
    from aramid.models import Event, EventType
    sel = {"served": {"provider": "p", "model": "m"}, "target_tier": "A",
           "bucket": "x", "audit": {"performed": True, "missed_criticals": 3}}
    ev = Event(EventType.CONSUMER_RUN_FINISHED, "run1", "t",
               payload={"selection": sel})
    state = {"cursors": {"repo": 100},   # cursor 100 >> len([ev]) == 1
             "posteriors": {}, "audits": {"performed": 0, "missed_criticals": 0}}
    out = autolearn.rollup(state, events=[ev], repo_key="repo")
    # shrink detected -> fold skipped -> audits NOT incremented
    assert out["audits"]["performed"] == 0
```

Run: `python -m pytest tests -k "rollup_skips_fold_on_shrunk" -v`
Expected: FAIL — current code resets cursor to 0 and folds `ev`, so `audits.performed` becomes 1.

- [ ] **Step 7: Fix the rollup shrink branch**

`src/aramid/autolearn.py`, replace lines 234-236:

```python
    cursor = int(out.get("cursors", {}).get(repo_key, 0))
    if cursor > len(events):
        # Shrunk/compacted ledger: a correct rebuild is CROSS-REPO (posteriors
        # aggregate across every registered repo, keyed by arm-cell), so a
        # single per-repo rollup cannot re-fold without double-counting the
        # surviving events onto posteriors that already include them. Skip the
        # fold; correct counts after a compaction require a global
        # `aramid autolearn --rebuild`. (Was: cursor=0 then re-fold.)
        return out
```

Also fix the misleading docstring line ~226-227 ("a shorter list than the cursor (rebuilt/compacted ledger) restarts from 0") to say it SKIPS folding pending a `--rebuild`. And update `ledger.py:110-114` compact() LANDMINE comment (1) to reference the skip-and-rebuild contract now in place.

- [ ] **Step 8: Run both suites (green)**

Run: `python -m pytest tests/unit/test_ledger_compact.py tests -k "autolearn or rollup" -q`
Expected: all PASS.

- [ ] **Step 9: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/ledger.py src/aramid/autolearn.py tests/unit/test_ledger_compact.py tests/unit/test_autolearn_rollup.py
git commit -m "fix(ledger,autolearn): de-risk compact() -- keep give-up rows; rollup skips fold on shrunk ledger (no double-count)"
```

---

### Task 2: shared confirmed-critical-LLM BLOCK predicate

**Files:**
- Modify: `src/aramid/review.py` (add helper, use in gate `:479-481`), `src/aramid/commands/override.py:58-62`, `src/aramid/commands/status.py:160-161`
- Test: `tests/unit/test_review_predicate.py` (new file for the helper), `tests/integration/test_override.py` (exists)

**Interfaces:**
- Produces: `review.is_confirmed_critical_llm(rec: dict) -> bool` — `rec.get("source")=="llm" and bool(rec.get("confirmed")) and rec.get("severity")=="critical"`. Never includes `armed`.

- [ ] **Step 1: Write the helper unit test + override armed-independence test (red)**

Create `tests/unit/test_review_predicate.py`:

```python
def test_is_confirmed_critical_llm_predicate():
    from aramid.review import is_confirmed_critical_llm
    yes = {"source": "llm", "confirmed": True, "severity": "critical"}
    assert is_confirmed_critical_llm(yes) is True
    assert is_confirmed_critical_llm({**yes, "confirmed": False}) is False
    assert is_confirmed_critical_llm({**yes, "severity": "high"}) is False
    assert is_confirmed_critical_llm({**yes, "source": "gitleaks"}) is False
    assert is_confirmed_critical_llm({}) is False
```

Append to the override test file (mirror its existing `_seed`/`cmd_override` setup — inspect a passing test there for the exact fixture; the pattern below assumes a seeded ledger rec):

```python
def test_override_refuses_disarmed_confirmed_critical_llm(tmp_path, monkeypatch):
    # override refusal is deliberately armed-INDEPENDENT (retroactive-arm
    # defense): a confirmed+critical llm finding is refused even when the llm
    # block is not armed. This pins that the shared predicate did not fold in
    # `armed`.
    from aramid.commands.override import cmd_override
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.FINDING_DETECTED, "r1", "t", finding_id="F1",
                         payload={"source": "llm", "confirmed": True,
                                  "severity": "critical", "verdict": "warn",
                                  "status": "open", "tool": "llm-review",
                                  "rule": "a01", "file": "x.py", "line": 1,
                                  "message": "m"}))
    finally:
        led.close()
    rc = cmd_override(tmp_path, "F1", "please suppress")
    assert rc == 3   # refused
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests -k "is_confirmed_critical_llm or override_refuses_disarmed" -v`
Expected: helper test FAILs (ImportError); override test may already pass (verdict=="warn" but is_llm_confirmed_critical currently True → refused) — that's fine, it becomes the regression lock for the refactor.

- [ ] **Step 3: Add the helper + rewire the three sites**

`src/aramid/review.py`, add near `llm_fingerprint` (top-level function):

```python
def is_confirmed_critical_llm(rec: dict) -> bool:
    """The raw-rec BLOCK-tier predicate shared by the gate (review), the
    override refusal, and the status count. Deliberately does NOT include
    `armed` -- the override refusal is armed-independent (retroactive-arm
    defense, see override.py) and the gate ANDs `armed` on top of this."""
    return (rec.get("source") == "llm"
            and bool(rec.get("confirmed"))
            and rec.get("severity") == "critical")
```

In the gate (`review.py:479-481`), replace the verdict expression:

```python
            verdict = (Verdict.BLOCK
                       if armed and is_confirmed_critical_llm(rec)
                       else Verdict.WARN)
```

(Equivalent: `rec["severity"]=="critical"` iff the parsed enum is `CRITICAL`; a malformed severity is non-critical either way → WARN. The Finding is still built with the parsed `severity` enum; the per-rec try/except fail-safe stays.)

`src/aramid/commands/override.py`, add `from aramid import review` with the other imports and replace lines 58-62:

```python
        is_llm_confirmed_critical = review.is_confirmed_critical_llm(rec)
```

`src/aramid/commands/status.py`, add `from aramid import review` (verify no import cycle: `python -c "import aramid.commands.status"` — if it errors with a cycle, use a function-local `from aramid import review` inside `_llm_lines` instead) and replace line 160-161:

```python
    confirmed = sum(1 for r in recs if review.is_confirmed_critical_llm(r))
```

- [ ] **Step 4: Run tests (green)**

Run: `python -m pytest tests -k "review or override or status or llm" -q`
Expected: all PASS — existing gate WARN/BLOCK tests still hold (behavior-equivalent refactor).

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/review.py src/aramid/commands/override.py src/aramid/commands/status.py tests/unit/test_review_predicate.py tests/integration/test_override.py
git commit -m "refactor(review): shared is_confirmed_critical_llm predicate for gate/override/status (drift guard)"
```

---

### Task 3: deps force_refresh wiring

**Files:**
- Modify: `src/aramid/runners/base.py:26` (RunContext field), `src/aramid/pipeline.py:256-259` (run_gate), `src/aramid/runners/deps.py:31-33` (docstring)
- Test: `tests/unit/test_runner_base.py` or `tests/unit/test_runner_deps.py`

**Interfaces:**
- Produces: `RunContext.force_refresh: bool = False` (additive field).

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_runner_deps.py`:

```python
def test_runcontext_has_force_refresh_default_false():
    from aramid.runners.base import RunContext
    from pathlib import Path
    assert RunContext(root=Path(".")).force_refresh is False


def test_run_gate_sets_force_refresh_for_all_mode(monkeypatch, tmp_path):
    # mode=="all" must build a RunContext with force_refresh=True so check --all
    # re-audits instead of serving a stale deps cache.
    import aramid.pipeline as pipeline
    captured = {}
    real_select = pipeline._select_runners
    monkeypatch.setattr(pipeline, "_select_runners",
                        lambda gate, ctx: captured.setdefault("ctx", ctx) or real_select(gate, ctx))
    from aramid import config as config_mod
    from aramid.ledger import Ledger
    from aramid.models import Gate
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    cfg = config_mod.load_config(tmp_path)
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    try:
        pipeline.run_gate(tmp_path, Gate.ALL, "all", cfg, led)
    finally:
        led.close()
    assert captured["ctx"].force_refresh is True
```

(If `run_gate` needs a git repo to not raise, wrap the tmp_path in `git init` first — mirror `_repo` from `tests/integration/test_rebaseline.py`. Adjust if `_select_runners` isn't the exact hook name — confirm via `grep "_select_runners\|_run_selected" src/aramid/pipeline.py`.)

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_runner_deps.py -k "force_refresh" -v`
Expected: FAIL — RunContext has no `force_refresh` attribute / run_gate doesn't set it.

- [ ] **Step 3: Implement**

`src/aramid/runners/base.py`, add the field to `RunContext` (after `extra_semgrep_configs`, keep it additive with a default):

```python
    force_refresh: bool = False
```

Also add a docstring line under RunContext describing it: `force_refresh: bypass the deps audit cache (set by run_gate for mode=="all" full audits).`

`src/aramid/pipeline.py`, in `run_gate` extend the RunContext construction (lines 256-259):

```python
    ctx = RunContext(root=root, files=files, rng=rng,
                      pkg_manager=detect_package_manager(root),
                      stacks=detect_stacks(root, root),
                      extra_semgrep_configs=extra_configs,
                      force_refresh=(mode == "all"))
```

`src/aramid/runners/deps.py`, fix the stale docstring (lines 31-33): replace "(an optional, undeclared RunContext attribute -- Task 5.3's pipeline isn't implemented yet)" with "(a RunContext field, default False; run_gate sets it True for mode=='all')".

- [ ] **Step 4: Run tests (green)**

Run: `python -m pytest tests/unit/test_runner_deps.py tests/unit/test_runner_base.py -q`
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/runners/base.py src/aramid/pipeline.py src/aramid/runners/deps.py tests/unit/test_runner_deps.py
git commit -m "fix(deps): wire force_refresh into RunContext + run_gate(all) so check --all re-audits"
```

---

### Task 4: triage content_signal scoped diff

**Files:**
- Modify: `src/aramid/triage.py:151`
- Test: `tests/unit/test_triage.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_triage.py` (mirror the file's existing `_fake_git`/monkeypatch setup — inspect `test_score_filters_graphite_artifacts_from_signals` for the exact harness; the new test must feed a NON-empty risky diff body attributed to a tracked graphite path):

```python
def test_content_signal_ignores_filtered_graphite_diff_body(tmp_path, monkeypatch):
    # A tracked graphite artifact (filtered out of `paths`) must not feed
    # content_signal: the diff must be scoped to the filtered paths, and when
    # every changed file is filtered out the diff must be empty (NOT a fallback
    # to the full diff).
    from aramid import triage, gitutil, config as config_mod

    monkeypatch.setattr(gitutil, "diff_paths",
                        lambda root, base, head: ["graph-out/graph.json"])

    def fake_diff_text(root, base, head, paths=None):
        # If scoped to the (empty, post-filter) path set, git returns nothing.
        # The bug returns the full body when paths is falsy -> assert the fix
        # never calls us with an empty/❲None❳ pathspec that yields the risky body.
        if not paths:
            return "+ exec(payload)\n"   # the dangerous full-diff fallback
        return ""                          # scoped to graphite path -> filtered

    monkeypatch.setattr(gitutil, "diff_text", fake_diff_text)
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(tmp_path)   # default graphite excludes apply
    # ... drive triage.score(...) per the file's existing harness ...
    score, reasons = triage.score(tmp_path, "BASE", "HEAD", cfg, _fake_ledger())
    assert not any("risky-content" in r for r in reasons)
```

(Adapt the exact `triage.score`/`run_triage` signature and ledger fixture to the file's existing tests — the assertion is the invariant: no `risky-content` reason from a filtered graphite body.)

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_triage.py -k "content_signal_ignores_filtered" -v`
Expected: FAIL — current `diff = gitutil.diff_text(root, base, head)` is unscoped, so the risky body reaches content_signal and a `risky-content` reason appears.

- [ ] **Step 3: Implement the scoped diff with empty-paths guard**

`src/aramid/triage.py:151`, replace:

```python
    # Scope the diff to the post-filter paths so a tracked graphite artifact's
    # body can't feed content_signal. EMPTY-PATHS GUARD: diff_text's pathspec
    # is `["--", *paths] if paths else []`, so passing an empty `paths` would
    # fall back to the FULL diff -- reintroducing the bug at its worst on an
    # all-graphite changeset. When everything is filtered out, use "".
    diff = gitutil.diff_text(root, base, head, paths=paths) if paths else ""
```

Also update the "Known residual" comment (triage.py:145-149) — the residual is now fixed; note content_signal is scoped to the filtered paths.

- [ ] **Step 4: Run tests (green)**

Run: `python -m pytest tests/unit/test_triage.py -q`
Expected: all PASS (existing triage tests pass `""` diffs, unaffected; the new one passes).

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/triage.py tests/unit/test_triage.py
git commit -m "fix(triage): scope content_signal diff to filtered paths (empty-paths guard, no full-diff fallback)"
```

---

### Task 5: bounded post-kill drain test

**Files:**
- Modify: `src/aramid/runners/base.py:99-105` (extract constant)
- Test: `tests/unit/test_runner_base.py`

**Interfaces:**
- Produces: `runners.base._POST_KILL_DRAIN_S = 5.0` (module constant).

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_runner_base.py`:

```python
def test_failed_kill_tree_bounds_the_post_kill_wait(tmp_path, monkeypatch):
    # The safety branch the bounded wait exists for: if _kill_tree fails to
    # reap the child, the post-kill communicate(timeout=_POST_KILL_DRAIN_S)
    # must cap the wait, not hang for the child's full sleep.
    import sys
    import time as _time
    from aramid.runners import base
    monkeypatch.setattr(base, "_kill_tree", lambda proc: None)   # kill "fails"
    monkeypatch.setattr(base, "_POST_KILL_DRAIN_S", 1.0)          # shrink the cap
    child = [sys.executable, "-c", "import time; time.sleep(30)"]
    start = _time.monotonic()
    result = base.run_subprocess(child, tmp_path, timeout_s=0.5)
    elapsed = _time.monotonic() - start
    assert result.state is base.ToolState.TIMEOUT
    assert elapsed < 10, f"post-kill wait was not bounded: {elapsed:.1f}s"
    child_proc = None  # reaped by the fallback proc.kill()
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_runner_base.py::test_failed_kill_tree_bounds_the_post_kill_wait -v`
Expected: FAIL — `_POST_KILL_DRAIN_S` doesn't exist yet (AttributeError on monkeypatch).

- [ ] **Step 3: Extract the constant**

`src/aramid/runners/base.py`, add near the top (after `_WIN`):

```python
_POST_KILL_DRAIN_S = 5.0   # cap on the post-_kill_tree reap wait (test seam)
```

In `run_subprocess`'s timeout handler (line 102), replace `proc.communicate(timeout=5)`:

```python
        try:
            proc.communicate(timeout=_POST_KILL_DRAIN_S)
        except subprocess.TimeoutExpired:
            proc.kill()
```

- [ ] **Step 4: Run tests (green)**

Run: `python -m pytest tests/unit/test_runner_base.py -q`
Expected: all PASS (the new test runs in ~1-2s, bounded by the shrunk cap).

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/runners/base.py tests/unit/test_runner_base.py
git commit -m "test(runners): reproduce the bounded post-kill wait on a failed _kill_tree (extract _POST_KILL_DRAIN_S)"
```

---

### Task 6: update-rules formal close

**Files:**
- Modify: `src/aramid/commands/update_rules.py:1-41` (docstring + message)
- Test: `tests/unit/test_update_rules.py` (or wherever; find via `python -m pytest tests -k update_rules --collect-only -q`)

- [ ] **Step 1: Write the failing test**

Add to the update-rules test file (create `tests/unit/test_update_rules.py` if none exists):

```python
def test_update_rules_reports_offline_by_design_not_stub(capsys):
    from aramid.commands.update_rules import cmd_update_rules
    rc = cmd_update_rules()
    out = capsys.readouterr().out
    assert rc == 0
    assert "STUB" not in out
    assert "vendored at build time" in out
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests -k "offline_by_design" -v`
Expected: FAIL — output still says "STUB".

- [ ] **Step 3: Reword the message + docstring**

`src/aramid/commands/update_rules.py`, replace line 41:

```python
    print("aramid: update-rules: the OWASP ruleset is vendored at build time "
          "(offline by design). To refresh, re-vendor from a pinned "
          "semgrep-rules ref and rebuild the package.")
```

Update the module docstring's opening (lines 4-16): replace the "STUB, network-fetch not performed..." framing with an "offline by design" statement — the ruleset is vendored at build time; refreshing is a re-vendor + rebuild step, not a runtime fetch. Keep the pinned-source / target-path reporting and the VENDORED_RULES_PATH-absent WARNING branch unchanged.

Add a one-line note to `README.md` under the gate/toolchain description: "The vendored OWASP semgrep ruleset ships in the wheel; `aramid update-rules` reports its pinned source and install path (refresh is a re-vendor + rebuild, not a runtime fetch)."

- [ ] **Step 4: Run tests (green)**

Run: `python -m pytest tests -k "update_rules" -q`
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/commands/update_rules.py tests/unit/test_update_rules.py README.md
git commit -m "docs(update-rules): formally close as offline-by-design (drop STUB framing)"
```

---

### Task 7: pnpm/yarn shape-shift drift guard + fixture provenance

**Files:**
- Modify: `src/aramid/runners/deps.py` (add shape guards, apply in `run_js`), `tests/fixtures/pnpm-audit.json`, `tests/fixtures/yarn-audit.json` (header-comment provenance — see note)
- Test: `tests/unit/test_runner_deps.py`

**Interfaces:**
- Produces: `deps._pnpm_shape_recognized(raw: str) -> bool`, `deps._yarn_shape_recognized(raw: str) -> bool`. `run_js` downgrades an OK result to CRASHED when the shape is present-but-unrecognized.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_runner_deps.py`:

```python
def test_pnpm_shape_recognized_good_and_drifted():
    from aramid.runners.deps import _pnpm_shape_recognized
    assert _pnpm_shape_recognized('{"report":{"advisories":{}}}') is True   # clean
    assert _pnpm_shape_recognized('{"advisories":{}}') is True              # clean alt
    assert _pnpm_shape_recognized("{}") is True                            # empty/no output
    assert _pnpm_shape_recognized('{"metadata":{"vulnerabilities":3}}') is False  # drift


def test_yarn_shape_recognized_good_and_drifted():
    from aramid.runners.deps import _yarn_shape_recognized
    good = '{"value":"pkg@1","children":{"ID":"X","Severity":"high","Issue":"i"}}'
    assert _yarn_shape_recognized(good) is True
    assert _yarn_shape_recognized("") is True   # clean (no output)
    assert _yarn_shape_recognized('{"value":"pkg@1","summary":"changed"}') is False  # drift


def test_run_js_drifted_pnpm_payload_is_crashed(monkeypatch, tmp_path):
    from aramid.runners import deps
    from aramid.runners.base import RunnerResult, ToolState
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: 6.0\n", encoding="utf-8")
    monkeypatch.setattr(deps, "detect_package_manager", lambda root: "pnpm")
    monkeypatch.setattr(deps, "run_subprocess",
                        lambda argv, cwd, t, env=None: RunnerResult(
                            "pnpm", ToolState.OK, raw='{"metadata":{"vulnerabilities":3}}',
                            returncode=1))
    result = deps.run_js(type("Ctx", (), {"root": tmp_path, "pkg_manager": "pnpm",
                                          "force_refresh": True})())
    assert result.state is ToolState.CRASHED
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_runner_deps.py -k "shape_recognized or drifted_pnpm" -v`
Expected: FAIL — helpers don't exist; run_js doesn't downgrade.

- [ ] **Step 3: Implement the shape guards**

`src/aramid/runners/deps.py`, add after `parse_yarn` (or near the JS section):

```python
def _pnpm_shape_recognized(raw: str) -> bool:
    """A clean pnpm audit carries an empty-but-PRESENT advisories container;
    an unrecognized shape (drift) has neither container key. Absent-key on a
    non-empty payload -> drift (return False)."""
    try:
        data = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return True   # non-JSON is handled by json_or_crashed, not here
    if not isinstance(data, dict) or not data:
        return True   # empty/no output = clean, let parse handle
    return "advisories" in data.get("report", {}) or "advisories" in data


def _yarn_shape_recognized(raw: str) -> bool:
    """Yarn Berry audit is NDJSON of advisory objects with a `children` dict.
    If there are parseable object lines but NONE carry `children`, the wire
    format drifted (return False). No lines = clean."""
    saw_line = saw_recognized = False
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        saw_line = True
        if isinstance(obj, dict) and isinstance(obj.get("children"), dict):
            saw_recognized = True
    return saw_recognized or not saw_line
```

In `run_js`, after the `_or_crashed` normalization and BEFORE the cache write (lines 197-202), insert the shape guard:

```python
    result = run_subprocess(_JS_AUDIT_ARGV[pm], ctx.root, TIMEOUT_S)
    if pm == "yarn":
        result = _ndjson_or_crashed(pm, result, _OK_RETURNCODES)
    else:
        result = json_or_crashed(pm, result, _OK_RETURNCODES, empty="{}")
    if result.state is ToolState.OK:
        recognized = (_yarn_shape_recognized(result.raw) if pm == "yarn"
                      else _pnpm_shape_recognized(result.raw) if pm == "pnpm"
                      else True)
        if not recognized:
            # Present-but-unrecognized audit shape: fail toward VISIBILITY
            # (degraded, manual check) rather than a silent 0-findings pass
            # that could hide CVEs. npm's shape is authoritative -> not guarded.
            result = RunnerResult(pm, ToolState.CRASHED, result.raw, result.stderr,
                                  result.duration_s, result.returncode)
    if result.state is ToolState.OK:
        _write_cache(cache_path, result.raw)
    return result
```

(`RunnerResult` and `ToolState` are already imported in deps.py.)

- [ ] **Step 4: Pin fixture provenance**

Fixtures are `.json` (no comment syntax). Add provenance as a sibling one-line note in the test file's module docstring OR — simpler and machine-clean — add a top-level `"_provenance"` key the parsers ignore. In `tests/fixtures/pnpm-audit.json` and `yarn-audit.json`, only a JSON file can't carry comments; instead add a comment block at the top of `tests/unit/test_runner_deps.py`:

```python
# Fixture provenance (Task 7 / spec §8): tests/fixtures/pnpm-audit.json and
# yarn-audit.json are HAND-AUTHORED from documented shapes (pnpm {"report":
# {"advisories"}}, yarn Berry >=4.0.1 NDJSON), NOT live captures. A live
# capture + reconcile is deferred until pnpm v8/9 and yarn Berry are
# installable. The shape guards above surface a drift as CRASHED rather than
# a silent [].
```

- [ ] **Step 5: Run tests (green)**

Run: `python -m pytest tests/unit/test_runner_deps.py -q`
Expected: all PASS — the known-good fixtures still parse to their expected findings (regression-lock, no false-positive), drifted payloads → CRASHED.

- [ ] **Step 6: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/runners/deps.py tests/unit/test_runner_deps.py
git commit -m "fix(deps): shape-shift drift guard for pnpm/yarn audit (unrecognized shape -> CRASHED, not silent [])"
```

---

### Task 8: final gate + review

- [ ] **Step 1: Full suite + ruff**

Run: `python -m pytest -q` — expect 772 base + ~15 new, all green.
Run: `python -m ruff check .` — must equal the recorded baseline.

- [ ] **Step 2: Whole-branch review + finish**

Dispatch the sonnet whole-branch review (project convention), apply any fix wave, then use superpowers:finishing-a-development-branch.

---

## Self-Review notes (author)

- **Spec §2 (compact)** → Task 1 (both sub-bugs). **§3 (predicate)** → Task 2. **§4 (force_refresh)** → Task 3. **§5 (triage)** → Task 4. **§6 (post-kill test)** → Task 5. **§7 (update-rules)** → Task 6. **§8 (pnpm/yarn)** → Task 7.
- **Placeholder scan:** test harnesses for Tasks 2/4 reference "mirror the file's existing setup" — that's a real instruction to match existing fixtures (the assertion/invariant is concrete), not a code placeholder. Every code step shows full code.
- **Type consistency:** `is_confirmed_critical_llm(rec)` identical across Task 2 sites; `force_refresh` field name identical in base/pipeline/deps (Task 3); `_POST_KILL_DRAIN_S` identical in impl+test (Task 5); `_pnpm_shape_recognized`/`_yarn_shape_recognized` identical in impl+test (Task 7).
- **Invariants:** gate path changes only in Tasks 2 (equivalent), 3 (intended), 7 (intended). Tasks 1/5/6 touch no live gate path.
