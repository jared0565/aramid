"""FN-17: a git call is bounded, and the drain's hard deadline stops it.

`gitutil._run` was a bare `subprocess.run` with no timeout and no place in
`runners.base`'s registry, so a hung git hung whatever asked (a gate, a
drain) and a git in flight at the deadline outlived the drain's `os._exit`.
A git that does not answer now RAISES `GitTimeout`: the callers read a
failed git as an empty answer (`staged_files` -> `[]`, `diff_new_lines` ->
`{}`), and a killed git must never read as one. Real child processes here,
through the `_GIT` seam: git itself will not hang on demand."""
import os
import sys
import threading
import time

import pytest

from aramid import gitutil
from aramid.commands.drain import _pid_alive
from aramid.runners import base

_SLEEPER = (sys.executable, "-c", "import time; time.sleep(60)")


def _wait_for(pred, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def _outcome(fn):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 -- the test reads what was raised
        return exc


def test_a_git_that_outlives_its_timeout_is_killed_and_raises(tmp_path, monkeypatch):
    pidfile = tmp_path / "pid"
    monkeypatch.setattr(gitutil, "_GIT", (
        sys.executable, "-c",
        f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(60)"))
    monkeypatch.setattr(gitutil, "GIT_TIMEOUT_S", 5.0)
    started = time.monotonic()

    with pytest.raises(gitutil.GitTimeout) as caught:
        gitutil._run(tmp_path, "worktree", "add")

    assert str(caught.value) == "git worktree timed out after 5 s and was killed"
    assert time.monotonic() - started < 40, "the child ran its full sleep"
    assert not _pid_alive(int(pidfile.read_text())), "the timed-out git is still running"
    assert len(base._LIVE) == 0, "a timed-out git stays registered"


def test_a_git_the_deadline_kills_raises_instead_of_answering(tmp_path, monkeypatch):
    """The main thread runs on between `kill_live` and `os._exit`: a killed
    git that returned its kill's exit code and empty stdout would reach the
    ledger as `nothing changed`."""
    monkeypatch.setattr(base, "_CLOSED", False)
    monkeypatch.setattr(gitutil, "_GIT", _SLEEPER)
    started = time.monotonic()
    out = {}
    t = threading.Thread(target=lambda: out.setdefault(
        "r", _outcome(lambda: gitutil._run(tmp_path, "diff", "--name-only"))), daemon=True)
    t.start()
    assert _wait_for(lambda: len(base._LIVE) == 1), "git was never registered"

    assert base.kill_live(close=True) == 1
    t.join(30)

    assert not t.is_alive(), "_run still waiting: git survived the deadline's kill"
    assert time.monotonic() - started < 40, "git ran its full sleep"
    assert isinstance(out["r"], gitutil.GitTimeout), f"a killed git answered: {out['r']!r}"
    assert str(out["r"]) == "git diff was killed at the drain's hard deadline"
    assert len(base._LIVE) == 0


def test_once_the_deadline_has_passed_git_is_not_started(tmp_path, monkeypatch):
    marker = tmp_path / "started"
    monkeypatch.setattr(base, "_CLOSED", True)
    monkeypatch.setattr(gitutil, "_GIT", (sys.executable, "-c", f"open({str(marker)!r}, 'w')"))

    with pytest.raises(gitutil.GitTimeout) as caught:
        gitutil._run(tmp_path, "show")

    assert str(caught.value) == "git show not started: the drain's hard deadline has passed"
    time.sleep(0.5)
    assert not marker.exists(), "git was started after the deadline"


def test_a_git_that_answers_leaves_nothing_registered(tmp_path):
    before = len(base._LIVE)
    cp = gitutil._run(tmp_path, "--version")
    assert cp.returncode == 0 and cp.stdout.startswith("git version")
    assert len(base._LIVE) == before


def test_a_git_that_fails_still_answers_with_its_exit_code(tmp_path):
    """Only a git that did not ANSWER raises; a git that answered `no` is
    still an answer, as every caller already reads it."""
    cp = gitutil._run(tmp_path, "rev-parse", "--verify", "no-such-rev^{commit}")
    assert cp.returncode != 0


@pytest.mark.skipif(sys.platform == "win32", reason="process sessions are POSIX")
def test_git_runs_in_a_session_of_its_own(tmp_path, monkeypatch):
    """`_kill_tree` kills the child's process GROUP; git in aramid's own
    group would take aramid down with it -- and, inside a hook, `git push`."""
    monkeypatch.setattr(gitutil, "_GIT", (sys.executable, "-c", "import os; print(os.getsid(0))"))
    cp = gitutil._run(tmp_path)
    assert cp.returncode == 0
    assert int(cp.stdout) != os.getsid(0)
