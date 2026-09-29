"""FN-17: the leftover sweep removes nothing it cannot see.

`git worktree list` is the sweep's only view of which shells are LOCKED --
a consumer still running in them. When git could not list (it failed, or it
timed out), `_registrations` read as "none registered", and the temp scan
then judged every shell by age alone: a locked shell older than six hours
went. The sweep now stops instead, and the drain says it skipped it."""
import os
import subprocess
import time
from pathlib import Path

import pytest

from aramid import gitutil, leftovers

DAY = 24 * 3600


def _git(root, *a):
    return subprocess.run(["git", "-C", str(root), *a],
                          capture_output=True, text=True, check=False)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "a.py")
    _git(r, "commit", "-q", "-m", "one")
    return r


def _age(path: Path, seconds: float) -> None:
    then = time.time() - seconds
    os.utime(path, (then, then))


def _locked_old_shell(root, temp) -> Path:
    shell = temp / "aramid-fuzz-live1234"
    shell.mkdir(parents=True)
    wt = shell / "wt"
    assert _git(root, "worktree", "add", "--detach", str(wt), "HEAD").returncode == 0
    assert _git(root, "worktree", "lock", "--reason", "aramid fuzz running", str(wt)).returncode == 0
    _age(shell, DAY)
    return shell


def test_a_git_that_cannot_list_worktrees_stops_the_sweep(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    temp = tmp_path / "temp"
    live = _locked_old_shell(root, temp)
    real = gitutil._run

    def failing(r, *a):
        if a[:2] == ("worktree", "list"):
            return subprocess.CompletedProcess(["git", *a], 128, "", "fatal: index file corrupt\n")
        return real(r, *a)
    monkeypatch.setattr(leftovers.gitutil, "_run", failing)

    with pytest.raises(RuntimeError) as caught:
        leftovers.sweep(root, temp=temp)

    assert str(caught.value) == "git worktree list failed (exit 128): fatal: index file corrupt"
    assert live.exists(), "a locked shell went because git could not say it was locked"


def test_a_git_timeout_stops_the_sweep(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    temp = tmp_path / "temp"
    live = _locked_old_shell(root, temp)
    real = gitutil._run

    def hung(r, *a):
        if a[:2] == ("worktree", "list"):
            raise gitutil.GitTimeout("git worktree timed out after 600 s and was killed")
        return real(r, *a)
    monkeypatch.setattr(leftovers.gitutil, "_run", hung)

    with pytest.raises(gitutil.GitTimeout):
        leftovers.sweep(root, temp=temp)
    assert live.exists()
