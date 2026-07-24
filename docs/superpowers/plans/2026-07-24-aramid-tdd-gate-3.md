# Aramid TDD Gate 3 — Red-First Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify at pre-push that the range's new tests were actually red against the pre-change tree, with bake-then-arm teeth (`aramid arm --red-proof`).

**Architecture:** A synchronous producer (`src/aramid/red_proof.py`, mirroring `tdd.py`'s integration exactly) runs each changed test file's **head** version against a throwaway worktree at the range **base**; a file whose tests all pass there was never red → one WARN-tier finding under distinct tool `"red-proof"`. Findings join `all_raws` before `normalize()`, so `policy.classify` is the single verdict authority (no seam, no twin rule), overrides/suppressions apply, and the disarmed WARN gets a ratchet exemption alongside `tdd`.

**Tech Stack:** Python 3.11+ stdlib, pytest, ruff. Windows-first: every tool as `python -m <tool>`.

**Spec:** `docs/superpowers/specs/2026-07-24-aramid-tdd-gate-3-red-first-proof-design.md` (approved 2026-07-24).

## Global Constraints

Every task's requirements implicitly include ALL of these:

- **Branch:** all work on `feat/tdd-gate-3` (branched off `main` by the controller before Task 1). NEVER commit to `main`.
- **Do NOT modify:** `src/aramid/check.py`, `src/aramid/models.py`, `src/aramid/tdd.py` (import `_split_range` from it — import only), `src/aramid/mutation_gate.py`, `src/aramid/mutation_score_gate.py`, `src/aramid/mutation_score.py`, all consumers, the ledger schema. No new `EventType`, no ledger writes in new code, no persistence beyond the normal finding stream.
- **Single verdict authority:** the producer emits `RawFinding`s with NO verdict anywhere; `policy.classify`'s `tool == "red-proof"` branch is the only place BLOCK-vs-WARN is decided: `BLOCK iff cfg.red_proof.get("red_proof_block_armed", False)`, else WARN. There is no inline twin to keep in agreement.
- **Fail-open (spec §8):** `red_proof.scan` NEVER raises into `run_gate`. Any exception, git failure, worktree-add failure, timeout, or budget exhaustion yields zero findings for the affected scope. Worktree cleanup in `finally` with the stderr leak-warning fallback.
- **Verdict mapping (spec §3.6):** pytest rc on base — `0` → finding; `1`/`2` → red proven, nothing; `5` → nothing collected, nothing; timeout/other → nothing. `line=0` always (fingerprint = tool+rule+path, the 1a stability trick).
- **Zero-cost guard:** when the range adds no test lines, `scan` returns `[]` BEFORE any worktree or subprocess work. `ctx.rng` falsy (first-push `FULL_HISTORY_RNG` `""`, or modes `staged`/`all` passing `None`) → `[]` immediately.
- **Exit-code contract:** a BLOCK finding drives `cmd_check` exit 1; e2e tests assert `rc == 1` for block, `rc != 1` for not-blocked.
- **Tests:** run ONLY the focused test files named in your task, as `python -m pytest <files> -q`. NEVER run the bare full suite (~14 min, looks like a hang; the controller runs it at the end).
- **Graphite:** before editing the shared files `pipeline.py` or `policy.py`, run `python -m graphite context src/aramid/pipeline.py` (resp. `policy.py`) and skim it. Never edit `graph-out/`.
- **Commits:** commit after each green cycle with the task's exact message. No backticks in commit messages (shell expansion on this machine).

---

### Task 1: The producer — `red_proof.py` + config surface

**Files:**
- Create: `src/aramid/red_proof.py`
- Create: `tests/unit/test_red_proof.py`
- Modify: `src/aramid/config.py` (Config field ~line 49; loader ~line 116)
- Modify: `src/aramid/data/defaults.toml` (after the `[tdd]` table, currently lines 131-132)
- Modify: `tests/unit/test_config.py` (append one test)

**Interfaces:**
- Consumes: `tdd._split_range(rng) -> (base|None, head)`; `gitutil.diff_new_lines(root, base, head) -> dict[str, set[int]]`; `gitutil.is_test_file(rel) -> bool`; `gitutil.read_blob(root, ref, rel) -> str` ("" on failure); `gitutil._run(root, *args) -> CompletedProcess`; `run_subprocess(argv, cwd, timeout_s) -> RunnerResult` (`.state: ToolState`, `.returncode`); `RawFinding(tool, rule, severity_raw, file, line, message)`; `RunContext` fields `root`, `files`, `rng`.
- Produces: `red_proof.scan(ctx, cfg) -> list[RawFinding]` and constants `RULE = "test-not-red"`, `_TOOL = "red-proof"` — Task 2's classify branch and Task 3's pipeline call rely on exactly these. `cfg.red_proof: dict` exists on `Config` after this task.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_red_proof.py`:

```python
"""red_proof (sub-project 3): unit tests for the pre-push red-first-proof
producer. Monkeypatch style mirrors tests/unit/test_tdd.py -- the plumbing
(diff_new_lines/read_blob/_run/run_subprocess) is faked; real-git coverage
lives in tests/integration/test_red_proof_gate.py (Task 3)."""
from pathlib import Path
from types import SimpleNamespace

from aramid import gitutil, red_proof
from aramid.runners.base import RunContext, RunnerResult, ToolState


def _ctx(files, rng="base..HEAD", root=Path("/x")):
    return RunContext(root=root, files=files, rng=rng)


def _cfg(enabled=True, wall_budget_s=120, test_timeout_s=60):
    return SimpleNamespace(red_proof={
        "enabled": enabled, "wall_budget_s": wall_budget_s,
        "test_timeout_s": test_timeout_s})


class _CP:
    def __init__(self, rc=0):
        self.returncode, self.stdout, self.stderr = rc, "", ""


def _plumb(monkeypatch, new_lines, pytest_rcs, worktree_rc=0,
           blob="def test_x():\n    assert True\n"):
    """Fake the full plumbing. pytest_rcs is consumed one rc per subject run;
    returns the list of pytest argv invocations for assertions."""
    runs = []
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: new_lines)
    monkeypatch.setattr(gitutil, "read_blob", lambda root, ref, rel: blob)
    monkeypatch.setattr(gitutil, "_run", lambda root, *a: _CP(worktree_rc))
    rcs = list(pytest_rcs)

    def fake_run(argv, cwd, timeout_s):
        runs.append(argv)
        rc = rcs.pop(0)
        if rc == "timeout":
            return RunnerResult("pytest", ToolState.TIMEOUT)
        return RunnerResult("pytest", ToolState.OK, returncode=rc)

    monkeypatch.setattr(red_proof, "run_subprocess", fake_run)
    return runs


def test_never_red_file_yields_finding(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    findings = red_proof.scan(
        _ctx(["tests/test_foo.py"], root=tmp_path), _cfg())
    assert len(findings) == 1
    f = findings[0]
    assert (f.tool, f.rule, f.severity_raw, f.file, f.line) == \
        ("red-proof", "test-not-red", "medium", "tests/test_foo.py", 0)
    assert "never red" in f.message


def test_red_on_base_yields_nothing(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [1])
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_collection_error_counts_as_red(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [2])
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_nothing_collected_yields_nothing(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/helpers_test.py": {3}}, [5])
    assert red_proof.scan(_ctx(["tests/helpers_test.py"], root=tmp_path), _cfg()) == []


def test_timeout_is_fail_open(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, ["timeout"])
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_per_file_verdicts_are_independent(monkeypatch, tmp_path):
    _plumb(monkeypatch,
           {"tests/test_a.py": {1}, "tests/test_b.py": {1}}, [0, 1])
    findings = red_proof.scan(
        _ctx(["tests/test_a.py", "tests/test_b.py"], root=tmp_path), _cfg())
    assert [f.file for f in findings] == ["tests/test_a.py"]


def test_no_new_test_lines_skips_all_plumbing(monkeypatch, tmp_path):
    """Prod-only diff: [] BEFORE any worktree/subprocess (zero-cost guard)."""
    calls = []
    monkeypatch.setattr(gitutil, "diff_new_lines",
                        lambda root, b, h: {"src/foo.py": {1}})
    monkeypatch.setattr(gitutil, "_run",
                        lambda root, *a: calls.append(a) or _CP(0))
    findings = red_proof.scan(_ctx(["src/foo.py"], root=tmp_path), _cfg())
    assert findings == []
    assert calls == []          # no worktree was ever created


def test_subject_outside_ctx_files_is_ignored(monkeypatch, tmp_path):
    """A test file in the diff but ignore-filtered out of ctx.files is not run."""
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    assert red_proof.scan(_ctx(["src/other.py"], root=tmp_path), _cfg()) == []


def test_falsy_rng_skips(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    assert red_proof.scan(
        _ctx(["tests/test_foo.py"], rng="", root=tmp_path), _cfg()) == []
    assert red_proof.scan(
        _ctx(["tests/test_foo.py"], rng=None, root=tmp_path), _cfg()) == []


def test_rangeless_rng_without_base_skips(monkeypatch, tmp_path):
    """rng without '..' gives base None -- no base tree to prove against."""
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    assert red_proof.scan(
        _ctx(["tests/test_foo.py"], rng="HEAD", root=tmp_path), _cfg()) == []


def test_disabled_returns_nothing(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    assert red_proof.scan(
        _ctx(["tests/test_foo.py"], root=tmp_path), _cfg(enabled=False)) == []


def test_exhausted_wall_budget_skips_subjects(monkeypatch, tmp_path):
    """wall_budget_s=-1 makes the budget check true on the first iteration --
    deterministic exhaustion without sleeping."""
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    assert red_proof.scan(
        _ctx(["tests/test_foo.py"], root=tmp_path),
        _cfg(wall_budget_s=-1)) == []


def test_worktree_add_failure_is_fail_open(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0], worktree_rc=1)
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_unreadable_head_blob_skips_file(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0], blob="")
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_scan_is_fail_open(monkeypatch, tmp_path):
    def boom(root, b, h):
        raise RuntimeError("git exploded")
    monkeypatch.setattr(gitutil, "diff_new_lines", boom)
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_missing_red_proof_config_defaults_on(monkeypatch, tmp_path):
    """cfg without a red_proof attr: enabled by default, still functions."""
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    findings = red_proof.scan(
        _ctx(["tests/test_foo.py"], root=tmp_path), SimpleNamespace())
    assert [f.file for f in findings] == ["tests/test_foo.py"]
```

Append to `tests/unit/test_config.py` (follow that file's existing test style; it already imports the config module):

```python
def test_red_proof_defaults_present(tmp_path):
    cfg = config.load_config(tmp_path)
    assert cfg.red_proof.get("enabled") is True
    assert cfg.red_proof.get("red_proof_block_armed") is False
    assert cfg.red_proof.get("wall_budget_s") == 120
    assert cfg.red_proof.get("test_timeout_s") == 60
```

(If `test_config.py` imports the module under a different name — e.g. `from aramid import config as config_mod` — match its existing import name; the assertions stay identical. If its loader tests monkeypatch `_user_config_path`, mirror that in this test too.)

- [ ] **Step 2: Run to verify the tests fail**

Run: `python -m pytest tests/unit/test_red_proof.py tests/unit/test_config.py -q`
Expected: `test_red_proof.py` dies at collection (`ImportError`/`ModuleNotFoundError`: no `aramid.red_proof`); `test_red_proof_defaults_present` FAILS (`Config` has no `red_proof` attribute); all pre-existing config tests pass.

- [ ] **Step 3: Implement**

(a) Create `src/aramid/red_proof.py`:

```python
"""red_proof -- synchronous red-first-proof producer for the pre-push gate
(sub-project 3, spec sections 3-4). The range's changed test files (head
version) are run against a throwaway worktree at the range BASE: a file
whose tests all pass on the pre-change tree was never red, so it proves
nothing about the change -- one WARN-tier RawFinding per such file (tool
"red-proof", rule "test-not-red", line=0 so the fingerprint is stable per
tool+rule+path, the 1a trick).

Per-file verdict (pytest rc on the base tree): 0 -> never-red FINDING;
1/2 -> red proven, nothing (a collection error IS red -- a test importing
a brand-new module fails on base; documented lenient, spec s10.2-3);
5 -> nothing collected, nothing to prove; timeout/other -> unattributable,
nothing. The whole scan is bounded by [red_proof].wall_budget_s and each
file by test_timeout_s; budget exhaustion skips the remainder silently.

ctx.rng falsy (first-push FULL_HISTORY_RNG, or modes staged/all which pass
rng None) -> no meaningful base -> silent skip. Zero cost when the range
adds no test lines: [] before any worktree or subprocess (that push is
tdd.scan's business, 1a). Head content is materialized via git show
(gitutil.read_blob) -- exact even under a dirty working tree.

Never raises into run_gate (fail-open, the whole-file discipline);
worktree cleanup in finally with the consumers/mutation.py leak-warning
fallback. Limitations (spec s10): whole-file verdict -- an old test in a
changed file failing on base masks a never-red new test (recall loss only,
never a false positive); only subject files are materialized at head, so a
new test depending on head changes to non-test files it imports usually
collection-errors -> counts as red; single run, no flake retries."""
import shutil
import sys
import tempfile
import time
from pathlib import Path

from aramid import gitutil
from aramid.normalizer import RawFinding
from aramid.runners.base import ToolState, run_subprocess
from aramid.tdd import _split_range

RULE = "test-not-red"
_TOOL = "red-proof"
_MESSAGE = "new test lines pass against the pre-change tree (never red)"


def scan(ctx, cfg) -> list[RawFinding]:
    """Red-first proof for the pre-push range (PRE_PUSH caller-gated, like
    tdd.scan). Fail-open: any error yields no findings -- a broken producer
    must never block a push or crash the gate."""
    try:
        rcfg = getattr(cfg, "red_proof", None) or {}
        if not rcfg.get("enabled", True):
            return []
        if not ctx.rng:
            return []       # no meaningful base: first push / staged / all
        wall_budget = float(rcfg.get("wall_budget_s", 120))
        test_timeout = float(rcfg.get("test_timeout_s", 60))
        base, head = _split_range(ctx.rng)
        if base is None:
            return []       # rangeless rng: no base tree to prove against
        in_scope = set(ctx.files)
        new_lines = gitutil.diff_new_lines(ctx.root, base, head)
        subjects = sorted(
            path for path, lines in new_lines.items()
            if lines and gitutil.is_test_file(path) and path in in_scope)
        if not subjects:
            return []       # zero-cost guard: no worktree, no subprocess
        started = time.monotonic()
        out: list[RawFinding] = []
        tmp = Path(tempfile.mkdtemp(prefix="aramid-red-"))
        wt = tmp / "wt"
        try:
            cp = gitutil._run(ctx.root, "worktree", "add", "--detach",
                              str(wt), base)
            if cp.returncode != 0:
                return []
            for rel in subjects:
                if time.monotonic() - started > wall_budget:
                    break   # budget exhausted: skip remainder silently
                content = gitutil.read_blob(ctx.root, head, rel)
                if not content:
                    continue        # unreadable/empty head blob: fail-open
                dest = wt / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
                res = run_subprocess(
                    [sys.executable, "-m", "pytest", "-q", rel],
                    wt, test_timeout)
                if res.state is ToolState.OK and res.returncode == 0:
                    out.append(RawFinding(
                        tool=_TOOL, rule=RULE, severity_raw="medium",
                        file=rel, line=0, message=_MESSAGE))
                # rc 1/2: red proven. rc 5: nothing collected. timeout /
                # other rc: unattributable. All -> nothing (spec s3.6).
        finally:
            try:
                gitutil._run(ctx.root, "worktree", "remove", "--force", str(wt))
                gitutil._run(ctx.root, "worktree", "prune")
                shutil.rmtree(tmp, ignore_errors=True)
            except Exception:
                print(f"aramid: red-proof: worktree cleanup leaked at {wt}",
                      file=sys.stderr)
        return out
    except Exception:
        return []
```

(b) In `src/aramid/config.py`, add to the `Config` dataclass directly under the `tdd: dict = field(default_factory=dict)` line:

```python
    red_proof: dict = field(default_factory=dict)
```

and in `load_config`'s `Config(...)` construction, directly under `tdd=merged.get("tdd", {}),`:

```python
        red_proof=merged.get("red_proof", {}),
```

(c) In `src/aramid/data/defaults.toml`, directly after the `[tdd]` table (`[tdd]` / `enabled = true`), add:

```toml

# --- TDD gate sub-project 3: red-first proof at pre-push ---
[red_proof]
enabled = true
red_proof_block_armed = false   # bake-then-arm; `aramid arm --red-proof` flips it
wall_budget_s = 120             # whole-scan wall clock (all changed test files)
test_timeout_s = 60             # per pytest invocation against the base tree
```

- [ ] **Step 4: Run to verify all pass**

Run: `python -m pytest tests/unit/test_red_proof.py tests/unit/test_config.py tests/unit/test_tdd.py -q`
Expected: all pass (16 new producer tests + 1 config test; `test_tdd.py` untouched-green — `_split_range` is imported, not moved).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/red_proof.py src/aramid/config.py src/aramid/data/defaults.toml tests/unit/test_red_proof.py tests/unit/test_config.py
git commit -m "feat(red-proof): red-first-proof producer + [red_proof] config surface (3 Task 1)"
```

---

### Task 2: The classify branch

**Files:**
- Modify: `src/aramid/policy.py` (insert after the `tool == "mutation-score"` branch, before the `ruff_block = ...` line)
- Modify: `tests/unit/test_policy.py` (append)

**Interfaces:**
- Consumes: `policy.classify(tool, rule, severity_raw, gate, cfg)`; `cfg.red_proof` dict (Task 1).
- Produces: the `tool == "red-proof"` verdict rule that Task 3's e2e (armed block, fresh-clone survival via `_has_genuine_block`) depends on.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_policy.py`:

```python
# --- classify: red-proof (sub-project 3) ------------------------------------

def _rp_cfg(armed: bool):
    # classify reads cfg.block_rules early, then the tool branch; a minimal
    # namespace with the attributes classify touches is enough.
    return SimpleNamespace(block_rules={},
                           red_proof={"red_proof_block_armed": armed})


def test_red_proof_disarmed_is_warn():
    sev, verdict = policy.classify("red-proof", "test-not-red", "medium",
                                   Gate.PRE_PUSH, _rp_cfg(armed=False))
    assert sev is Severity.MEDIUM
    assert verdict is Verdict.WARN


def test_red_proof_armed_is_block():
    sev, verdict = policy.classify("red-proof", "test-not-red", "medium",
                                   Gate.PRE_PUSH, _rp_cfg(armed=True))
    assert sev is Severity.MEDIUM       # assert severity in BOTH (1a T2a lesson)
    assert verdict is Verdict.BLOCK
```

- [ ] **Step 2: Run to verify the armed test fails**

Run: `python -m pytest tests/unit/test_policy.py -q`
Expected: `test_red_proof_armed_is_block` FAILS (classify falls through to the default `return severity, Verdict.WARN`); the disarmed test passes coincidentally (the fall-through default is WARN — the armed test is the red tooth). All pre-existing policy tests pass.

- [ ] **Step 3: Add the branch**

In `src/aramid/policy.py`, insert directly AFTER the `tool == "mutation-score"` branch's final `return`, BEFORE the `ruff_block = block_rules.get(...)` line:

```python
    # Red-first proof (TDD gate sub-project 3): the pre-push producer that
    # runs the range's changed test files against the range base -- a file
    # whose tests all pass there was never red. Findings join the raw stream
    # pre-normalize (the 1a path), so this branch is the SINGLE verdict
    # authority -- there is no seam computing an inline twin. WARN during the
    # bake; BLOCK once the repo opts in via [red_proof].red_proof_block_armed.
    # Routing through classify makes _has_genuine_block treat an armed BLOCK
    # as genuine, so it survives the fresh-clone downgrade (1a s2.2).
    if tool == "red-proof":
        armed = cfg.red_proof.get("red_proof_block_armed", False)
        return severity, Verdict.BLOCK if armed else Verdict.WARN
```

- [ ] **Step 4: Run to verify all pass**

Run: `python -m pytest tests/unit/test_policy.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/policy.py tests/unit/test_policy.py
git commit -m "feat(policy): red-proof classify branch, armed BLOCK / baking WARN (3 Task 2)"
```

---

### Task 3: Pipeline wiring + ratchet exemption + real-git integration/e2e

**Files:**
- Modify: `src/aramid/pipeline.py` (import line 29; the `tdd.scan` PRE_PUSH block, lines 274-278; the ratchet exclusion, line 311)
- Create: `tests/integration/test_red_proof_gate.py`

**Interfaces:**
- Consumes: `red_proof.scan(ctx, cfg)` (Task 1); the classify branch (Task 2); `cmd_check(root, gate, mode) -> int`.
- Produces: the wired gate — Tasks 4-5 only add CLI/docs surface.

- [ ] **Step 1: Write the failing integration/e2e tests**

Create `tests/integration/test_red_proof_gate.py`:

```python
"""Real-git integration for red_proof (sub-project 3): producer-level tests
on real repos (mirrors tests/integration/test_tdd_gate.py) plus cmd_check
e2e for arming/ratchet/fresh-clone (mirrors the 1b/2b e2e pattern:
GATE_RUNNER_KEYS emptied so the exit code reflects only the gate
producers). The DISARMED e2e is also the ratchet-exemption red-proof:
without the "red-proof" ratchet exemption the new WARN would escalate to
BLOCK and rc would be 1."""
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import gitutil, pipeline, red_proof
from aramid.commands.check import cmd_check
from aramid.models import Gate
from aramid.runners.base import RunContext


def _no_runners(monkeypatch):
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True,
                   capture_output=True, text=True)


def _repo_with_upstream(tmp_path) -> Path:
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True,
                   capture_output=True, text=True)
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "tests").mkdir()
    (r / "src" / "foo.py").write_text("def foo():\n    return 1\n",
                                      encoding="utf-8")
    # NOTE: fixture test bodies insert os.getcwd() -- run_subprocess runs
    # pytest with cwd = the worktree, so this resolves `from src.foo import
    # foo` against the tree under test (base or head) regardless of pytest's
    # own rootdir/sys.path insertion rules.
    (r / "tests" / "test_foo.py").write_text(
        "import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
        "from src.foo import foo\n\n\ndef test_foo():\n    assert foo() == 1\n",
        encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "initial")
    _git(r, "remote", "add", "origin", str(bare))
    _git(r, "push", "-u", "origin", "main")
    return r


def _commit_change_and_test(r, *, test_body):
    """Change src/foo.py to return 2 and rewrite the test file with test_body."""
    (r / "src" / "foo.py").write_text("def foo():\n    return 2\n",
                                      encoding="utf-8")
    (r / "tests" / "test_foo.py").write_text(test_body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "change foo + test")


NEVER_RED = ("import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
             "from src.foo import foo\n\n\ndef test_foo():\n"
             "    assert foo() == 1\n\n\ndef test_trivial():\n"
             "    assert True\n")
GENUINELY_RED = ("import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
                 "from src.foo import foo\n\n\ndef test_foo():\n"
                 "    assert foo() == 2\n")


def _scan(r):
    rng = gitutil.resolve_range(r)
    files = gitutil.changed_files(r, rng)
    assert rng, "resolve_range returned no upstream range -- plumbing degenerated"
    assert any(gitutil.is_test_file(f) for f in files), \
        "no test file in the real diff -- result would be vacuous"
    ctx = RunContext(root=r, files=files, rng=rng)
    return red_proof.scan(ctx, SimpleNamespace(red_proof={"enabled": True}))


def _no_leaked_worktrees(r):
    cp = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                        capture_output=True, text=True)
    assert len([ln for ln in cp.stdout.splitlines() if ln.strip()]) == 1


def test_real_never_red_push_flags(tmp_path):
    r = _repo_with_upstream(tmp_path)
    _commit_change_and_test(r, test_body=NEVER_RED)
    # NEVER_RED asserts the OLD behavior (foo() == 1) -- it passes on base.
    findings = _scan(r)
    assert [f.file for f in findings] == ["tests/test_foo.py"]
    assert findings[0].tool == "red-proof" and findings[0].line == 0
    _no_leaked_worktrees(r)


def test_real_genuinely_red_push_is_clean(tmp_path):
    r = _repo_with_upstream(tmp_path)
    _commit_change_and_test(r, test_body=GENUINELY_RED)
    # GENUINELY_RED asserts the NEW behavior (foo() == 2) -- red on base.
    assert _scan(r) == []
    _no_leaked_worktrees(r)


def test_new_test_importing_new_module_is_red(tmp_path):
    r = _repo_with_upstream(tmp_path)
    (r / "src" / "bar.py").write_text("def bar():\n    return 3\n",
                                      encoding="utf-8")
    (r / "tests" / "test_bar.py").write_text(
        "import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
        "from src.bar import bar\n\n\ndef test_bar():\n    assert bar() == 3\n",
        encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "new module + its test")
    # src/bar.py does not exist on base -> collection error -> red -> clean.
    assert _scan(r) == []
    _no_leaked_worktrees(r)


def test_fingerprint_stable_across_pushes(tmp_path):
    """Same never-red file -> same tool/rule/file/line inputs (id is derived
    from exactly these at normalize time; line=0 pins content-independence)."""
    r = _repo_with_upstream(tmp_path)
    _commit_change_and_test(r, test_body=NEVER_RED)
    first = _scan(r)[0]
    assert (first.tool, first.rule, first.file, first.line) == \
        ("red-proof", "test-not-red", "tests/test_foo.py", 0)


def _arm(r):
    (r / "aramid.toml").write_text(
        "schema_version = 1\n\n[red_proof]\nred_proof_block_armed = true\n",
        encoding="utf-8")


def test_e2e_disarmed_warns_never_blocks(tmp_path, monkeypatch):
    """ALSO the ratchet-exemption red-proof: a new disarmed red-proof WARN
    must not auto-escalate at pre-push (without the exemption rc would be 1)."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _commit_change_and_test(r, test_body=NEVER_RED)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1


def test_e2e_armed_never_red_blocks(tmp_path, monkeypatch):
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm(r)
    _commit_change_and_test(r, test_body=NEVER_RED)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1


def test_e2e_armed_genuinely_red_passes(tmp_path, monkeypatch):
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm(r)
    _commit_change_and_test(r, test_body=GENUINELY_RED)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1


def test_e2e_armed_block_survives_fresh_baseline(tmp_path, monkeypatch):
    """First-ever cmd_check on the repo (fresh ledger, no baseline): the armed
    red-proof BLOCK is genuine via classify -> _has_genuine_block -> survives
    the fresh-clone downgrade."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm(r)
    _commit_change_and_test(r, test_body=NEVER_RED)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1
```

- [ ] **Step 2: Run to verify the red state**

Run: `python -m pytest tests/integration/test_red_proof_gate.py -q`
Expected: the four producer-level tests PASS (Task 1 shipped the producer — they exercise it directly, not the wiring). The four e2e tests are the red teeth: `test_e2e_armed_never_red_blocks` and `test_e2e_armed_block_survives_fresh_baseline` FAIL (`rc != 1` — nothing calls the producer inside `run_gate` yet); the disarmed and genuinely-red e2e tests pass vacuously (they assert `rc != 1`, true while unwired — their post-green teeth come from the armed tests proving the wiring exists, leaving verdict and ratchet behavior as what they pin).

- [ ] **Step 3: Wire the pipeline**

In `src/aramid/pipeline.py`:

(a) extend the import line 29 (alphabetical — `red_proof` sorts before `redact`):

```python
from aramid import gitutil, mutation_gate, mutation_score_gate, policy, red_proof, redact, tdd
```

(b) extend the PRE_PUSH producer block (currently `if gate is Gate.PRE_PUSH: all_raws.extend(tdd.scan(ctx, cfg))`):

```python
    # TDD gate (1a): synchronous git-fact code-without-test producer. PRE_PUSH
    # only; joins the raw stream so classify/fingerprint/ratchet/overrides all
    # apply. Fail-open inside tdd.scan -- never raises here.
    if gate is Gate.PRE_PUSH:
        all_raws.extend(tdd.scan(ctx, cfg))
        # Red-first proof (sub-project 3): the range's changed test files run
        # against the range base -- rc 0 there means the test was never red.
        # Same pre-normalize seam as tdd.scan; fail-open inside red_proof.scan.
        # ctx.rng falsy (first push / staged / all) makes it a silent no-op.
        all_raws.extend(red_proof.scan(ctx, cfg))
```

(c) extend the ratchet exclusion (currently `and f.tool != "tdd"`):

```python
                and f.tool not in ("tdd", "red-proof")
```

- [ ] **Step 4: Run to verify all pass**

Run: `python -m pytest tests/integration/test_red_proof_gate.py tests/integration/test_tdd_gate.py tests/unit/test_pipeline.py -q`
Expected: all pass (8 new + neighbors untouched-green).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/pipeline.py tests/integration/test_red_proof_gate.py
git commit -m "feat(pipeline): wire red-proof producer at pre-push + ratchet exemption (3 Task 3)"
```

---

### Task 4: `aramid arm --red-proof` + CLI wiring

**Files:**
- Modify: `src/aramid/commands/arm.py`
- Modify: `src/aramid/cli.py` (arm help/group, lines 114-120; dispatch, lines ~222-226)
- Create: `tests/unit/test_arm_red_proof.py`
- Modify: `tests/integration/test_cli_dispatch.py` (append two tests + widen the SIX existing cmd_arm lambdas)

**Interfaces:**
- Consumes: `_armed_sub(key_re, new_line, text, count=0)`; the existing `cmd_arm` structure (`cmd_arm(root, llm=False, autolearn=False, tdd=False, mutation=False, mutation_score=False)`).
- Produces: `cmd_arm(..., red_proof: bool = False)` and the `--red-proof` flag.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_arm_red_proof.py`:

```python
"""arm --red-proof (sub-project 3): sets red_proof_block_armed = true INSIDE
the [red_proof] table -- mirrors the section-scoped arm --mutation-score
path; must never touch other tables or the root tdd_block_armed key."""
import tomllib

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def test_arm_red_proof_writes_into_section(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n\n[red_proof]\nenabled = true\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, red_proof=True) == 0

    text = toml.read_text(encoding="utf-8")
    assert "red_proof_block_armed = true" in text
    assert text.index("[red_proof]") < text.index("red_proof_block_armed = true")
    cfg = config_mod.load_config(tmp_path)
    assert cfg.red_proof["red_proof_block_armed"] is True


def test_arm_red_proof_appends_fresh_section_when_absent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, red_proof=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["red_proof"]["red_proof_block_armed"] is True


def test_arm_red_proof_idempotent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[red_proof]\nred_proof_block_armed = false\n",
                    encoding="utf-8")

    cmd_arm(tmp_path, red_proof=True)
    cmd_arm(tmp_path, red_proof=True)

    text = toml.read_text(encoding="utf-8")
    assert text.count("red_proof_block_armed") == 1
    assert "red_proof_block_armed = true" in text
    tomllib.loads(text)                  # no duplicate-key corruption


def test_arm_red_proof_preserves_inline_comment(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[red_proof]\nred_proof_block_armed = false  # bake note\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, red_proof=True) == 0

    got = toml.read_text(encoding="utf-8")
    assert "red_proof_block_armed = true  # bake note" in got
    assert tomllib.loads(got)["red_proof"]["red_proof_block_armed"] is True


def test_arm_red_proof_missing_toml_errors(tmp_path):
    assert cmd_arm(tmp_path, red_proof=True) == 3


def test_cmd_arm_red_proof_reports(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n",
                                          encoding="utf-8")

    assert cmd_arm(tmp_path, red_proof=True) == 0

    out = capsys.readouterr().out
    assert "red_proof_block_armed=true" in out
    assert "red-first bake ended" in out


def test_arm_red_proof_and_tdd_do_not_interfere(tmp_path):
    """red_proof_block_armed ([red_proof] table) and tdd_block_armed (root
    key) are independent: arming one never rewrites the other."""
    toml = tmp_path / "aramid.toml"
    toml.write_text("tdd_block_armed = false\n\n"
                    "[red_proof]\nred_proof_block_armed = false\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, red_proof=True) == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["tdd_block_armed"] is False
    assert parsed["red_proof"]["red_proof_block_armed"] is True

    assert cmd_arm(tmp_path, tdd=True) == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["tdd_block_armed"] is True
    assert parsed["red_proof"]["red_proof_block_armed"] is True
```

Append to `tests/integration/test_cli_dispatch.py` (after the mutation-score dispatch tests, following the file's exact patterns):

```python
def test_arm_dispatch_with_red_proof_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False,
                        mutation=False, mutation_score=False, red_proof=False:
                        captured.update(llm=llm, autolearn=autolearn,
                                        tdd=tdd, mutation=mutation,
                                        mutation_score=mutation_score,
                                        red_proof=red_proof) or 0)

    assert cli.main(["arm", "--red-proof"]) == 0
    assert captured["red_proof"] is True
    assert captured["mutation_score"] is False
    assert captured["mutation"] is False
    assert captured["llm"] is False
    assert captured["autolearn"] is False
    assert captured["tdd"] is False


def test_arm_dispatch_red_proof_and_tdd_mutually_exclusive():
    rc = subprocess.run([sys.executable, "-m", "aramid", "arm",
                         "--red-proof", "--tdd"],
                        capture_output=True, text=True)
    assert rc.returncode == 3
```

Also widen the SIX existing `cmd_arm` monkeypatch lambdas in that file — `test_arm_dispatch`, `test_arm_dispatch_with_llm_flag`, `test_arm_dispatch_with_autolearn_flag`, `test_arm_dispatch_with_tdd_flag`, `test_arm_dispatch_with_mutation_flag`, `test_arm_dispatch_with_mutation_score_flag` — appending `red_proof=False` to each lambda's parameter list (bodies unchanged; the 2b-lesson edit, third time around). Harmless in the red phase: the extra defaulted kwarg is unused until Step 3 changes the dispatch.

- [ ] **Step 2: Run to verify the red state**

Run: `python -m pytest tests/unit/test_arm_red_proof.py "tests/integration/test_cli_dispatch.py::test_arm_dispatch_with_red_proof_flag" "tests/integration/test_cli_dispatch.py::test_arm_dispatch_red_proof_and_tdd_mutually_exclusive" -q`
Expected: 8 failed, 1 passed — the 7 unit tests fail with `cmd_arm() got an unexpected keyword argument 'red_proof'`; `test_arm_dispatch_with_red_proof_flag` fails (`cli.main` returns 3, not 0 — argparse rejects the unknown `--red-proof` flag). `test_arm_dispatch_red_proof_and_tdd_mutually_exclusive` passes VACUOUSLY — an unknown flag already exits 3 via cli.main's argparse-to-3 remap, the same code the implemented mutually-exclusive group produces; its teeth are post-green (the companion flag test pins that `--red-proof` parses with rc 0, leaving the exclusion conflict as the only remaining exit-3 cause).

- [ ] **Step 3: Implement arm + CLI**

In `src/aramid/commands/arm.py`:

(a) after the `_SCORE_KEY_RE` definition, add:

```python
_RP_KEY_RE = re.compile(
    r"(?m)^red_proof_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_RP_SECTION_RE = re.compile(r"(?m)^\[red_proof\]\s*$")
```

(b) after `_arm_mutation_score_text`, add:

```python
def _arm_red_proof_text(text: str) -> str:
    """Comment-preserving single-key rewrite into the [red_proof] table
    (mirrors _arm_mutation_score_text): key exists -> substitute; [red_proof]
    section exists -> insert the key under the header; neither -> append a
    fresh [red_proof] section. red_proof_block_armed is a globally unique
    key name, so no section scoping is needed."""
    if _RP_KEY_RE.search(text):
        return _armed_sub(_RP_KEY_RE, "red_proof_block_armed = true", text)
    m = _RP_SECTION_RE.search(text)
    if m:
        insert_at = m.end()
        return text[:insert_at] + "\nred_proof_block_armed = true" + text[insert_at:]
    prefix = "" if not text or text.endswith("\n") else "\n"
    return text + prefix + "[red_proof]\nred_proof_block_armed = true\n"
```

(c) change the `cmd_arm` signature to:

```python
def cmd_arm(root, llm: bool = False, autolearn: bool = False, tdd: bool = False,
            mutation: bool = False, mutation_score: bool = False,
            red_proof: bool = False) -> int:
```

(d) after the `if mutation_score:` block's `return 0`, add:

```python
    if red_proof:
        toml_path.write_text(_arm_red_proof_text(text), encoding="utf-8")
        print(f"aramid: arm: red_proof_block_armed=true written to {toml_path}")
        print("aramid: arm: red-first bake ended -- never-red test findings "
              "now BLOCK at pre-push.")
        return 0
```

In `src/aramid/cli.py`:

(e) replace the arm help string and add the flag to the group (currently lines 114-120):

```python
    p_arm = sub.add_parser("arm", help="end a WARN-only bake (semgrep default, --llm for the LLM reviewer, --autolearn for learned uplift, --tdd for code-without-test findings, --mutation for surviving-mutant findings, --mutation-score for score-regression transitions, --red-proof for never-red test findings)")
    arm_which = p_arm.add_mutually_exclusive_group()
    arm_which.add_argument("--llm", action="store_true")
    arm_which.add_argument("--autolearn", action="store_true")
    arm_which.add_argument("--tdd", action="store_true")
    arm_which.add_argument("--mutation", action="store_true")
    arm_which.add_argument("--mutation-score", action="store_true")
    arm_which.add_argument("--red-proof", action="store_true")
```

(f) replace the arm dispatch with:

```python
    if args.command == "arm":
        return cmd_arm(root, llm=args.llm, autolearn=args.autolearn,
                       tdd=args.tdd, mutation=args.mutation,
                       mutation_score=args.mutation_score,
                       red_proof=args.red_proof)
```

- [ ] **Step 4: Run to verify all pass, including neighbors**

Run: `python -m pytest tests/unit/test_arm_red_proof.py tests/unit/test_arm_mutation_score.py tests/unit/test_arm_mutation.py tests/unit/test_arm_llm.py tests/integration/test_cli_dispatch.py -q`
Expected: all pass (new 7 + 2 dispatch; the six widened lambdas keep every pre-existing arm/dispatch test green).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/arm.py src/aramid/cli.py tests/unit/test_arm_red_proof.py tests/integration/test_cli_dispatch.py
git commit -m "feat(cli): aramid arm --red-proof ends the red-first bake (3 Task 4)"
```

---

### Task 5: README + ruff + full-suite handoff

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: everything shipped in Tasks 1-4.
- Produces: user-facing docs; the controller's full-suite verdict gates the branch.

- [ ] **Step 1: Extend the README**

Locate the TDD-gate documentation in `README.md` (search for "code-without-test" — the 1a subsection). Append this block after the existing TDD-gate material, heading level matching its siblings:

```markdown
### Red-first proof (TDD gate, sub-project 3)

At every `pre-push`, the test files your range changed are run — head
version — against a throwaway worktree at the range's *base*. A file whose
tests all pass on the pre-change tree was never red, so it proves nothing
about the change: one finding per such file (tool `red-proof`, rule
`test-not-red`, severity medium). Collection errors count as red — a test
importing a brand-new module *is* red on the base tree.

Findings WARN during the bake and BLOCK once the repo opts in with
`aramid arm --red-proof` (sets `[red_proof].red_proof_block_armed = true`).
Disarmed WARNs never auto-escalate, `aramid override` works as the standard
escape hatch, and only files changed in the push are ever examined, so
arming can never wall-block pre-existing repo state. `[red_proof]` also
carries `wall_budget_s` / `test_timeout_s` caps; when the budget runs out,
remaining files are skipped silently.

Limitations:

1. The verdict is per test *file*: an old test in a changed file failing on
   base masks a never-red new test — a missed signal, never a false alarm.
2. Any import failure on base counts as red, including files trivially
   broken on base for unrelated reasons.
3. Only the changed test files themselves are materialized at head — a new
   test depending on head changes to non-test files it imports (a root
   `conftest.py`, a new fixture module) usually collection-errors, which
   counts as red.
4. Range mode only: first pushes and `--all`/`--staged` runs skip silently.
5. Tests run once, no flake retries — bake before arming.
```

- [ ] **Step 2: Ruff over every file the branch touched**

Run: `python -m ruff check src/aramid/red_proof.py src/aramid/config.py src/aramid/policy.py src/aramid/pipeline.py src/aramid/commands/arm.py src/aramid/cli.py tests/unit/test_red_proof.py tests/unit/test_arm_red_proof.py tests/integration/test_red_proof_gate.py`
Expected: clean (fix anything flagged in files this branch created; note pre-existing violations in files it didn't).

- [ ] **Step 3: Commit the docs**

```bash
git add README.md
git commit -m "docs: red-first proof at pre-push + sub-project 3 limitations (3 Task 5)"
```

- [ ] **Step 4: Full suite — CONTROLLER ONLY**

The task subagent STOPS here and reports back. The controller runs the full suite in the background (`python -m pytest -q`, ~14 min, 998+ tests expected) and verifies 0 failures before the whole-branch review. A subagent must never run it.

---

## Self-Review (performed at authoring, 2026-07-24)

- **Spec coverage:** §3 detection rule → T1 (producer + zero-cost guard + verdict table + budgets); §4 arming/ratchet/fresh-clone → T2 (classify) + T3 (wiring, exemption, e2e); §5 file list → T1-T5 exactly; §6 config → T1; §7 flow → T3; §8 fail-open → T1 (tests: fail-open, worktree-add failure, timeout, cleanup); §9 CLI → T4; §10 limitations → T1 docstring + T5 README (all 6; #6 push-time cost is the budget para); §11 testing → every named case has a test (genuinely-red, never-red, no-added-test-lines zero-cost, new-module import, rc 5, budget, fail-open, cleanup, fingerprint stability, classify both + severity, ratchet exemption via the disarmed e2e, arm round-trip + non-interference + dispatch + mutex, defaults parse, e2e armed/disarmed/red/fresh); §12 non-goals — no task exceeds them.
- **Type consistency:** `scan(ctx, cfg)` identical in T1 def, T3 pipeline call, T3 integration `_scan`. `cmd_arm(..., red_proof=False)` identical in T4 impl and dispatch lambda. `RunnerResult(tool, state, returncode=...)` matches `runners/base.py:17-24` (positional `tool, state`; `returncode` keyword). `_split_range` import target verified at `tdd.py:17-25`.
- **Red-phase honesty:** T1 collection-error red; T2 armed-test-only red (disarmed passes coincidentally — annotated); T3 armed e2e red, disarmed/genuinely-red vacuous (annotated); T4 "8 failed, 1 passed" with the vacuous mutex pass annotated (2b precedent).
- **Known intentional deviations:** none.
