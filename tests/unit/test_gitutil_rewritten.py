"""gitutil.on_any_ref and gitutil.branches_that_held: the two git questions
the drain asks about a queued head before it consumes it (2026-11-01).

A queued commit that an amend, rebase or reset rewrote away is on no branch,
tag or remote-tracking branch; the local branch whose own reflog recorded it
is where the rewrite left the work. Real git, one scratch repo per test."""
import subprocess

from aramid import gitutil


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


def _repo(tmp_path, name="r"):
    """main: base, then `first`. Returns (repo, base, first)."""
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.txt").write_text("a", encoding="utf-8")
    _git(r, "add", "a.txt")
    _git(r, "commit", "-q", "-m", "base")
    base = _git(r, "rev-parse", "HEAD")
    (r / "b.txt").write_text("b", encoding="utf-8")
    _git(r, "add", "b.txt")
    _git(r, "commit", "-q", "-m", "first")
    return r, base, _git(r, "rev-parse", "HEAD")


def _amend(r):
    (r / "b.txt").write_text("b2", encoding="utf-8")
    _git(r, "commit", "-q", "-a", "--amend", "--no-edit")
    return _git(r, "rev-parse", "HEAD")


def _git_fails(monkeypatch, subcommand):
    """Every `git <subcommand>` answers 128; every other git call is real."""
    real = gitutil._run

    def run(root, *args):
        if args[0] == subcommand:
            return subprocess.CompletedProcess(["git", *args], 128, "", "fatal: stub")
        return real(root, *args)

    monkeypatch.setattr(gitutil, "_run", run)


# ------------------------------------------------------------- on_any_ref ---

def test_a_commit_on_a_branch_is_on_a_ref(tmp_path):
    r, _base, first = _repo(tmp_path)
    assert gitutil.on_any_ref(r, first) is True


def test_an_amended_away_commit_is_on_no_ref(tmp_path):
    r, _base, first = _repo(tmp_path)
    _amend(r)
    assert gitutil.on_any_ref(r, first) is False


def test_a_tag_keeps_an_amended_away_commit_on_a_ref(tmp_path):
    r, _base, first = _repo(tmp_path)
    _git(r, "tag", "kept", first)
    _amend(r)
    assert gitutil.on_any_ref(r, first) is True


def test_a_commit_that_does_not_exist_is_on_no_ref(tmp_path):
    r, _base, _first = _repo(tmp_path)
    assert gitutil.on_any_ref(r, "0" * 40) is False


def test_a_ref_listing_git_could_not_give_is_none_not_gone(tmp_path, monkeypatch):
    r, _base, first = _repo(tmp_path)
    _amend(r)
    _git_fails(monkeypatch, "for-each-ref")
    assert gitutil.on_any_ref(r, first) is None


# ----------------------------------------------------- branches_that_held ---

def test_the_branch_an_amend_rewrote_held_the_old_commit(tmp_path):
    r, _base, first = _repo(tmp_path)
    amended = _amend(r)
    assert gitutil.branches_that_held(r, first) == [("main", amended)]


def test_a_branch_that_is_not_checked_out_still_answers(tmp_path):
    """The case HEAD got wrong: amended on a feature branch, then main
    checked out before the drain."""
    r, base, _first = _repo(tmp_path)
    _git(r, "checkout", "-q", "-b", "feature", base)
    (r / "c.txt").write_text("c", encoding="utf-8")
    _git(r, "add", "c.txt")
    _git(r, "commit", "-q", "-m", "feature work")
    queued = _git(r, "rev-parse", "HEAD")
    (r / "c.txt").write_text("c2", encoding="utf-8")
    _git(r, "commit", "-q", "-a", "--amend", "--no-edit")
    amended = _git(r, "rev-parse", "HEAD")
    _git(r, "checkout", "-q", "main")
    assert gitutil.branches_that_held(r, queued) == [("feature", amended)]


def test_every_branch_whose_reflog_held_it_answers(tmp_path):
    r, base, first = _repo(tmp_path)
    _git(r, "branch", "topic", first)
    _git(r, "branch", "-f", "topic", base)
    amended = _amend(r)
    assert sorted(gitutil.branches_that_held(r, first)) == [("main", amended), ("topic", base)]


def test_a_branch_never_at_the_commit_does_not_answer(tmp_path):
    r, base, first = _repo(tmp_path)
    _git(r, "branch", "unrelated", base)
    amended = _amend(r)
    assert gitutil.branches_that_held(r, first) == [("main", amended)]


def test_heads_own_reflog_is_not_a_branch(tmp_path):
    """HEAD's reflog records every commit made and every checkout; a deleted
    branch takes its own reflog with it. Nothing holds the commit."""
    r, base, _first = _repo(tmp_path)
    _git(r, "checkout", "-q", "-b", "gone", base)
    (r / "c.txt").write_text("c", encoding="utf-8")
    _git(r, "add", "c.txt")
    _git(r, "commit", "-q", "-m", "on a branch about to be deleted")
    orphaned = _git(r, "rev-parse", "HEAD")
    _git(r, "checkout", "-q", "main")
    _git(r, "branch", "-q", "-D", "gone")
    assert orphaned in _git(r, "log", "-g", "--format=%H", "HEAD").split()  # control
    assert gitutil.branches_that_held(r, orphaned) == []


def test_a_force_pushed_rewrite_answers_once_not_twice(tmp_path):
    """Amend, then force-push: the remote-tracking branch logs the old value
    too. Reading it would make the commonest rewrite ambiguous."""
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    r, _base, first = _repo(tmp_path)
    _git(r, "remote", "add", "origin", str(remote))
    _git(r, "push", "-q", "-u", "origin", "main")
    amended = _amend(r)
    _git(r, "push", "-q", "--force", "origin", "main")
    assert first in _git(r, "log", "-g", "--format=%H", "refs/remotes/origin/main").split()  # control
    assert gitutil.branches_that_held(r, first) == [("main", amended)]


def test_a_commit_that_does_not_exist_is_held_by_no_branch(tmp_path):
    r, _base, _first = _repo(tmp_path)
    assert gitutil.branches_that_held(r, "0" * 40) == []


def test_a_branch_listing_git_could_not_give_is_none(tmp_path, monkeypatch):
    r, _base, first = _repo(tmp_path)
    _amend(r)
    _git_fails(monkeypatch, "for-each-ref")
    assert gitutil.branches_that_held(r, first) is None


def test_a_reflog_git_could_not_read_is_none(tmp_path, monkeypatch):
    r, _base, first = _repo(tmp_path)
    _amend(r)
    _git_fails(monkeypatch, "log")
    assert gitutil.branches_that_held(r, first) is None
