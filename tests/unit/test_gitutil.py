import subprocess
from pathlib import Path
from aramid import gitutil

def _git(root, *a): subprocess.run(["git", *a], cwd=root, check=True,
                                   capture_output=True, text=True)

def _repo(tmp_path) -> Path:
    r = tmp_path / "r"; r.mkdir(); _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t"); _git(r, "config", "user.name", "t")
    return r

def test_repo_root_and_blob(tmp_path):
    r = _repo(tmp_path)
    (r / "a.py").write_text("print(1)\n")
    _git(r, "add", "a.py"); _git(r, "commit", "-m", "x")
    assert gitutil.repo_root(r / ".") == r.resolve()
    assert gitutil.read_blob(r, "HEAD", "a.py") == "print(1)\n"

def test_not_a_repo_raises(tmp_path):
    import pytest
    with pytest.raises(gitutil.NotARepo):
        gitutil.repo_root(tmp_path)

def test_resolve_range_new_branch_no_remote_returns_none(tmp_path):
    # spec §3 invariant: a brand-new branch with no upstream/origin must NOT hard-error;
    # resolve_range returns None meaning "scan all commits reachable from HEAD".
    r = _repo(tmp_path)
    (r / "a.py").write_text("x=1\n"); _git(r, "add", "a.py"); _git(r, "commit", "-m", "c1")
    assert gitutil.resolve_range(r) is None

def test_read_for_fingerprint_untracked_uses_worktree(tmp_path):
    r = _repo(tmp_path)
    (r / "u.py").write_bytes(b"secret=1\r\n")   # untracked, CRLF (write_bytes: avoid
    # Windows text-mode newline translation on write, which would otherwise turn the
    # literal \r\n into \r\r\n before it ever reaches read_for_fingerprint)
    content = gitutil.read_for_fingerprint(r, "HEAD", "u.py")
    assert content == "secret=1\n"            # non-empty, LF-normalized
