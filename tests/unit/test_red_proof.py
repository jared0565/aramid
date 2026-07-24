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
