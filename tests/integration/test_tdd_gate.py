import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import gitutil, tdd
from aramid.runners.base import RunContext


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
