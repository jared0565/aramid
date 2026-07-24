import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import config as config_mod
from aramid import gitutil, pipeline, red_proof, tdd
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.runners.base import RunContext


def _no_runners(monkeypatch):
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo_with_upstream(tmp_path) -> Path:
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True, text=True)
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "tests").mkdir()
    (r / "src" / "foo.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
    (r / "tests" / "test_foo.py").write_text("def test_foo():\n    assert True\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "initial")
    _git(r, "remote", "add", "origin", str(bare))
    _git(r, "push", "-u", "origin", "main")
    return r


def _scan(r):
    rng = gitutil.resolve_range(r)
    files = gitutil.changed_files(r, rng)
    # Guard against a vacuous pass: if real-git range resolution regressed,
    # `files` would be empty and tdd.scan would early-return [] for the wrong
    # reason. Assert the plumbing actually engaged before trusting the result.
    assert rng, "resolve_range returned no upstream range -- real-git plumbing degenerated"
    assert any(f.endswith(".py") and not gitutil.is_test_file(f) for f in files), \
        "no production file in the real diff -- plumbing degenerated, result would be vacuous"
    ctx = RunContext(root=r, files=files, rng=rng)
    return tdd.scan(ctx, SimpleNamespace(tdd={"enabled": True}))


def test_real_prod_change_without_test_flags(tmp_path):
    r = _repo_with_upstream(tmp_path)
    (r / "src" / "foo.py").write_text("def foo():\n    return 2\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "change foo, no test")
    findings = _scan(r)
    assert [f.file for f in findings] == ["src/foo.py"]


def test_real_prod_change_with_test_is_clean(tmp_path):
    r = _repo_with_upstream(tmp_path)
    (r / "src" / "foo.py").write_text("def foo():\n    return 2\n", encoding="utf-8")
    (r / "tests" / "test_foo.py").write_text(
        "def test_foo():\n    assert True\n\ndef test_foo_two():\n    assert True\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "change foo with a new test")
    findings = _scan(r)
    assert findings == []


# ------------------------------------------------ auto_resolve_tdd (1a-F2) ---

def test_fire_then_resolve_two_push(tmp_path, monkeypatch):
    """spec section 5's discriminating end-to-end test -- the only evidence
    that the adopted module-mapped mechanism does what the rejected
    scope_tools mechanism provably cannot (spec section 2.2(1)).

    Push 1 commits a.py alone (untested) -> tdd finding recorded open. Push 1
    MUST land before push 2 (mirrors test_red_proof_gate.py:136): without it,
    @{u} stays at the pre-push-1 commit, push 2's range spans BOTH commits,
    a.py is still in changed_files, and the finding would resolve through the
    source_touched branch -- passing even with the module-stem mapping
    deleted entirely, and passing equally under the REJECTED scope_tools
    mechanism. Push 2 commits ONLY tests/test_a.py (the mapped test, source
    untouched). red_proof.scan_scoped is faked to a no-op here -- red-proof
    is not what this test is about, and left real it would spin up a real
    worktree + pytest subprocess for tests/test_a.py on every run."""
    _no_runners(monkeypatch)
    monkeypatch.setattr(red_proof, "scan_scoped", lambda ctx, cfg: ([], set()))
    r = _repo_with_upstream(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    cfg = config_mod.load_config(r)
    ledger = Ledger(r / ".aramid" / "ledger.db")
    try:
        (r / "a.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        _git(r, "add", "-A")
        _git(r, "commit", "-m", "add a.py, no test")
        result1 = pipeline.run_gate(r, Gate.PRE_PUSH, "range", cfg, ledger)
        tdd_findings = [f for f in result1.findings
                        if f.tool == "tdd" and f.file == "a.py"]
        assert len(tdd_findings) == 1
        fid = tdd_findings[0].id
        assert ledger.open_findings()[fid]["status"] == "open"

        _git(r, "push", "origin", "main")   # push 1 lands; the range base advances

        (r / "tests" / "test_a.py").write_text(
            "def test_a():\n    assert True\n", encoding="utf-8")
        _git(r, "add", "-A")
        _git(r, "commit", "-m", "add mapped test for a.py")

        rng = gitutil.resolve_range(r)
        assert rng, "resolve_range returned no upstream range -- real-git plumbing degenerated"
        assert "a.py" not in gitutil.changed_files(r, rng), \
            "source file still in range -- resolve would come from source_touched, not the mapped test"

        pipeline.run_gate(r, Gate.PRE_PUSH, "range", cfg, ledger)
        assert ledger.open_findings()[fid]["status"] == "fixed"
    finally:
        ledger.close()
