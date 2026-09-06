"""gitutil.is_ancestor: the one git question the graded-head rule asks."""
import subprocess

from aramid import gitutil


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.txt").write_text("a", encoding="utf-8")
    _git(r, "add", "a.txt")
    _git(r, "commit", "-q", "-m", "c1")
    c1 = _git(r, "rev-parse", "HEAD")
    (r / "b.txt").write_text("b", encoding="utf-8")
    _git(r, "add", "b.txt")
    _git(r, "commit", "-q", "-m", "c2")
    return r, c1, _git(r, "rev-parse", "HEAD")


def test_a_parent_is_an_ancestor_and_a_commit_is_its_own(tmp_path):
    r, c1, c2 = _repo(tmp_path)
    assert gitutil.is_ancestor(r, c1, c2)
    assert gitutil.is_ancestor(r, c2, c2)


def test_a_child_is_not_an_ancestor_of_its_parent(tmp_path):
    r, c1, c2 = _repo(tmp_path)
    assert not gitutil.is_ancestor(r, c2, c1)


def test_an_unknown_rev_reads_as_not_an_ancestor_never_raises(tmp_path):
    r, c1, c2 = _repo(tmp_path)
    assert not gitutil.is_ancestor(r, "0" * 40, c2)
