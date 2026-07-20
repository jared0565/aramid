import subprocess
from pathlib import Path
from aramid import gitutil

def _git(root, *a): subprocess.run(["git", *a], cwd=root, check=True,
                                   capture_output=True, text=True)

def _repo(tmp_path) -> Path:
    r = tmp_path / "r"; r.mkdir(); _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t"); _git(r, "config", "user.name", "t")
    return r

def _commit(root: Path, name: str, content: str, msg: str) -> None:
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", name], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", msg], cwd=root, check=True, capture_output=True)

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

def test_rev_sha_and_first_parent(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    root_sha = gitutil.rev_sha(r, "HEAD")
    assert root_sha and len(root_sha) == 40
    assert gitutil.first_parent(r, "HEAD") is None  # root commit
    _commit(r, "b.py", "y = 2\n", "second")
    assert gitutil.first_parent(r, "HEAD") == root_sha
    assert gitutil.rev_sha(r, "not-a-rev") is None


def test_diff_paths_single_commit_and_root(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    head1 = gitutil.rev_sha(r, "HEAD")
    assert gitutil.diff_paths(r, None, head1) == ["a.py"]  # root commit: full tree
    _commit(r, "sub/b.py", "y = 2\n", "second")
    head2 = gitutil.rev_sha(r, "HEAD")
    assert gitutil.diff_paths(r, head1, head2) == ["sub/b.py"]


def test_diff_text_contains_added_lines_and_truncates(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    h1 = gitutil.rev_sha(r, "HEAD")
    _commit(r, "a.py", "x = 1\nexec(x)  # обед\n", "second")
    h2 = gitutil.rev_sha(r, "HEAD")
    text = gitutil.diff_text(r, h1, h2)
    assert "+exec(x)" in text
    full = gitutil.diff_text(r, h1, h2)
    full_bytes = len(full.encode("utf-8"))
    assert len(full) < full_bytes  # precondition: multi-byte content present
    cap = full_bytes - 2  # cut lands inside the trailing multi-byte run
    truncated = gitutil.diff_text(r, h1, h2, max_bytes=cap)
    assert len(truncated.encode("utf-8")) <= cap
    assert truncated != full  # naive char-slice would return the FULL text here


def test_diff_text_decodes_utf8_not_locale_codec(tmp_path):
    # FIX 3 regression: _run's subprocess.run(..., text=True) used to decode
    # with the locale-preferred codec (no encoding= kwarg). On this dev box
    # (Windows, cp1252 preferred encoding, UTF-8 mode off) that mojibakes
    # git's UTF-8 output -- reproducing the bug locally. CI (windows-latest,
    # Python 3.12, also cp1252-preferred) is the real proving ground for the
    # harder failure mode: a byte sequence cp1252 can't decode at all raises
    # UnicodeDecodeError and would crash triage's per-commit diff scan.
    r = _repo(tmp_path)
    _commit(r, "a.py", "# café\n", "first")
    h1 = gitutil.rev_sha(r, "HEAD")
    _commit(r, "a.py", "# café\n# Привет\n", "second")
    h2 = gitutil.rev_sha(r, "HEAD")
    text = gitutil.diff_text(r, h1, h2)
    assert "café" in text
    assert "Привет" in text
    assert "Ã©" not in text  # mojibake marker: utf-8 "é" mis-decoded as cp1252


def test_diff_text_paths_scoping(tmp_path):
    # FIX 3 regression: the `paths=` pathspec passed to diff_text scopes the
    # diff to exactly those files -- an unscoped diff of two changed files
    # shows both; scoped to one path shows only that file (no other file's
    # header/hunk text leaks in).
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    h1 = gitutil.rev_sha(r, "HEAD")
    (r / "a.py").write_text("x = 2\n", encoding="utf-8")
    (r / "b.py").write_text("y = 1\n", encoding="utf-8")
    _git(r, "add", "a.py", "b.py")
    _git(r, "commit", "-m", "second")
    h2 = gitutil.rev_sha(r, "HEAD")

    unscoped = gitutil.diff_text(r, h1, h2)
    assert "a.py" in unscoped and "b.py" in unscoped

    scoped = gitutil.diff_text(r, h1, h2, paths=["a.py"])
    assert "a.py" in scoped
    assert "b.py" not in scoped

def test_diff_new_lines_maps_changed_lines(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\ny = 2\nz = 3\n", "c1")
    base = gitutil.rev_sha(r, "HEAD")
    _commit(r, "a.py", "x = 1\ny = 99\nz = 3\nw = 4\n", "c2")
    head = gitutil.rev_sha(r, "HEAD")
    assert gitutil.diff_new_lines(r, base, head) == {"a.py": {2, 4}}

def test_diff_new_lines_root_commit_and_deletion(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "c1")
    head = gitutil.rev_sha(r, "HEAD")
    # base=None (root/bootstrap): whole file counts as new
    assert gitutil.diff_new_lines(r, None, head) == {"a.py": {1}}
    # pure deletion contributes nothing on the new side
    base = head
    _commit(r, "b.py", "q = 1\n", "c2")
    (r / "a.py").unlink()
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "c3")
    head2 = gitutil.rev_sha(r, "HEAD")
    assert "a.py" not in gitutil.diff_new_lines(r, base, head2)
