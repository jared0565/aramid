"""A handover is shown beside where the repo is NOW (interop round 337;
operator decision 2026-11-24, "show the live position"). pawscout wrote one
at HEAD 1ee6b49 whose body said "master = origin/master = 3f48275", an older
commit; show, MCP and session-start printed "at 1ee6b49" and compared it
with nothing, and session-start said to resume it without asking. The body
is not parsed -- on aramid's own 259 archived bodies a branch-and-sha rule
flagged 43, mostly true notes about the remote -- so the measured position
is printed next to it instead. Real git, real store."""
import io
import subprocess
from datetime import datetime, timezone

from aramid import handover
from aramid.commands import agent_hook, handover_cmd

NOW = datetime(2026, 10, 6, 10, 0, 0, tzinfo=timezone.utc)
THEN = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)


def _git(r, *a):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a], cwd=r,
                          check=True, capture_output=True, text=True).stdout.strip()


def _commit(r, msg):
    _git(r, "commit", "-q", "--allow-empty", "-m", msg)
    return _git(r, "rev-parse", "HEAD")


def _repo(tmp_path, *, upstream=True):
    """main, two commits; origin/main is the first, as after one unpushed commit."""
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    first = _commit(r, "one")
    second = _commit(r, "two")
    if upstream:
        _git(r, "remote", "add", "origin", "https://example.invalid/r.git")
        _git(r, "update-ref", "refs/remotes/origin/main", first)
        _git(r, "config", "branch.main.remote", "origin")
        _git(r, "config", "branch.main.merge", "refs/heads/main")
    return r, first, second


def test_at_the_recorded_commit_with_an_upstream_behind(tmp_path):
    r, first, second = _repo(tmp_path)

    assert handover.position(r, second) == (
        f"HEAD {second[:12]} on main, the recorded commit;"
        f" upstream origin/main at {first[:12]} (HEAD is ahead 1)")


def test_commits_made_since_are_counted(tmp_path):
    r, first, second = _repo(tmp_path)
    third = _commit(r, "three")
    fourth = _commit(r, "four")

    assert handover.position(r, second) == (
        f"HEAD {fourth[:12]} on main, 2 commits after the recorded commit;"
        f" upstream origin/main at {first[:12]} (HEAD is ahead 3)")
    assert third


def test_one_commit_since_is_singular(tmp_path):
    r, first, second = _repo(tmp_path, upstream=False)
    third = _commit(r, "three")

    assert handover.position(r, second) == (
        f"HEAD {third[:12]} on main, 1 commit after the recorded commit; no upstream")


def test_a_head_that_does_not_descend_from_the_record_says_so(tmp_path):
    """The reported shape: the record and HEAD on different lines."""
    r, first, second = _repo(tmp_path, upstream=False)
    _git(r, "checkout", "-q", "-b", "other", first)
    other = _commit(r, "elsewhere")

    assert handover.position(r, second) == (
        f"HEAD {other[:12]} on other, not a descendant of the recorded commit; no upstream")


def test_a_recorded_commit_this_clone_lacks(tmp_path):
    r, first, second = _repo(tmp_path, upstream=False)

    assert handover.position(r, "0" * 40) == (
        f"HEAD {second[:12]} on main, the recorded commit is not in this clone; no upstream")


def test_a_recorded_head_that_is_not_a_commit_id_never_reaches_git(tmp_path, monkeypatch):
    """Signed by aramid, so this takes a forged key; still, a leading `-`
    would be an option to rev-list and a lone surrogate cannot be spawned."""
    r, first, second = _repo(tmp_path, upstream=False)
    _commit(r, "three")
    spawned = []
    real = subprocess.run
    monkeypatch.setattr(handover.subprocess, "run",
                        lambda *a, **k: spawned.append(a[0]) or real(*a, **k))

    for bad in ("--output=x", "01234\ud83d6789", "", "ABCDEF0123"):
        assert handover.position(r, bad).endswith(
            ", the recorded head is not a commit id; no upstream"), bad

    assert not any("rev-list" in argv for argv in spawned)


def test_nothing_recorded(tmp_path):
    r, first, second = _repo(tmp_path, upstream=False)

    assert handover.position(r, None) == (
        f"HEAD {second[:12]} on main, no commit was recorded; no upstream")


def test_a_detached_head_names_no_branch_and_no_upstream(tmp_path):
    r, first, second = _repo(tmp_path)
    _git(r, "checkout", "-q", "--detach", first)

    assert handover.position(r, second) == (
        f"HEAD {first[:12]} (detached), not a descendant of the recorded commit")


def test_an_upstream_that_is_gone(tmp_path):
    r, first, second = _repo(tmp_path)
    _git(r, "update-ref", "-d", "refs/remotes/origin/main")

    assert handover.position(r, second) == (
        f"HEAD {second[:12]} on main, the recorded commit; upstream origin/main (gone)")


def test_level_with_the_upstream(tmp_path):
    r, first, second = _repo(tmp_path)
    _git(r, "update-ref", "refs/remotes/origin/main", second)

    assert handover.position(r, second).endswith(
        f"; upstream origin/main at {second[:12]} (HEAD is level with it)")


def test_ahead_and_behind(tmp_path):
    r, first, second = _repo(tmp_path)
    _git(r, "checkout", "-q", "-b", "side", first)
    side = _commit(r, "side")
    _git(r, "update-ref", "refs/remotes/origin/main", side)
    _git(r, "checkout", "-q", "main")

    assert handover.position(r, second).endswith(
        f"; upstream origin/main at {side[:12]} (HEAD is ahead 1, behind 1)")


def test_no_commit_yet(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")

    assert handover.position(r, None) == "no commit yet"


def test_outside_git_with_nothing_recorded_there_is_no_position(tmp_path):
    assert handover.position(tmp_path, None) is None


def test_outside_git_with_a_recorded_commit_the_position_is_unknown(tmp_path):
    assert handover.position(tmp_path, "a" * 40) == "unknown (git did not answer)"


def test_one_git_call_at_the_recorded_commit_two_after_it(tmp_path, monkeypatch):
    """Session start pays these only when a handover is pending."""
    r, first, second = _repo(tmp_path)
    calls = []
    real = subprocess.run
    monkeypatch.setattr(handover.subprocess, "run",
                        lambda *a, **k: calls.append(a[0]) or real(*a, **k))

    handover.position(r, second)
    at_record = len(calls)
    _commit(r, "three")
    calls.clear()
    handover.position(r, second)

    assert (at_record, len(calls)) == (1, 2)


def test_every_git_call_is_bounded_at_ten_seconds(tmp_path, monkeypatch):
    """A hung git must not hang `show` or the session-start hook."""
    r, first, second = _repo(tmp_path)
    _commit(r, "three")
    timeouts = []
    real = subprocess.run
    monkeypatch.setattr(handover.subprocess, "run",
                        lambda *a, **k: timeouts.append(k.get("timeout")) or real(*a, **k))

    handover.position(r, second)

    assert timeouts == [10, 10]


def test_a_timed_out_git_reads_as_no_answer(tmp_path, monkeypatch):
    def hung(*a, **k):
        raise subprocess.TimeoutExpired(a[0], k.get("timeout"))
    monkeypatch.setattr(handover.subprocess, "run", hung)

    assert handover.position(tmp_path, second := "a" * 40) == "unknown (git did not answer)"
    assert second


def _write(r, body="step 3 next\n"):
    assert handover_cmd.cmd_handover("write", r, author="claude",
                                     stdin=io.StringIO(body), now=THEN) == 0


def test_show_prints_the_position_under_the_header(tmp_path, capsys):
    r, first, second = _repo(tmp_path)
    _write(r)
    capsys.readouterr()
    third = _commit(r, "three")

    assert handover_cmd.cmd_handover("show", r, now=NOW) == 0

    assert capsys.readouterr().out == (
        f"pending handover (written 2h ago, at {second[:12]}, by claude):\n"
        f"position now: HEAD {third[:12]} on main, 1 commit after the recorded commit;"
        f" upstream origin/main at {first[:12]} (HEAD is ahead 2)\n"
        "step 3 next\n")


def test_write_prints_the_position_it_recorded(tmp_path, capsys):
    r, first, second = _repo(tmp_path)

    _write(r)

    assert capsys.readouterr().out == (
        f"aramid: handover written: {r / '.aramid' / 'handover.json'}\n"
        f"aramid: handover position: HEAD {second[:12]} on main, the recorded commit;"
        f" upstream origin/main at {first[:12]} (HEAD is ahead 1)\n")


def test_the_mcp_show_carries_it_too(tmp_path, capsys):
    r, first, second = _repo(tmp_path)
    _write(r)
    capsys.readouterr()

    assert handover_cmd._show(r, NOW, for_agent=True) == 0

    assert capsys.readouterr().out.splitlines()[1] == (
        f"position now: HEAD {second[:12]} on main, the recorded commit;"
        f" upstream origin/main at {first[:12]} (HEAD is ahead 1)")


def test_the_session_start_block_carries_it_under_its_header(tmp_path):
    r, first, second = _repo(tmp_path)
    _write(r)

    lines = agent_hook._handover_lines(r, NOW)

    assert lines[0].startswith("aramid: PENDING HANDOVER written 2h ago at ")
    assert lines[1] == (
        f"aramid: position now: HEAD {second[:12]} on main, the recorded commit;"
        f" upstream origin/main at {first[:12]} (HEAD is ahead 1)")
    assert lines[2] == "aramid: | step 3 next"


def test_a_cut_body_keeps_the_header_and_the_position(tmp_path):
    lines = ["aramid: PENDING HANDOVER header", "aramid: position now: HEAD x on main",
             *("aramid: | " + "b" * 90 for _ in range(40))]

    fitted = agent_hook._fit_handover(lines, 1200)

    assert fitted[:2] == lines[:2]
    assert fitted[-1] == agent_hook._TRUNCATED
    assert sum(len(ln) + 1 for ln in fitted) <= 1200


def test_too_little_room_for_any_body_still_keeps_the_position(tmp_path):
    """Below `_MIN_EXCERPT` the body goes; the position is header, not body."""
    lines = ["aramid: PENDING HANDOVER header", "aramid: position now: HEAD x on main",
             *("aramid: | " + "b" * 90 for _ in range(40))]

    assert agent_hook._fit_handover(lines, 300) == [*lines[:2], agent_hook._TRUNCATED]
