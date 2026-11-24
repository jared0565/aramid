"""`aramid status` and the session-start block name a drain finding that is
open on a commit the remote default branch does not have yet (interop round
336; operator decision 2026-11-24, "name them in status"). graphite merged a
defect a drain's llm-review had recorded 2 h 45 m earlier, because the
finding was one more count in the ledger and nothing put it in front of the
merge. Real git (a local tracking ref stands in for the remote), real
ledger."""
import subprocess

from aramid import gitutil
from aramid.commands import agent_hook
from aramid.commands import status as status_mod
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict

E, F, G, H = "e" * 64, "f" * 64, "a1" * 32, "b2" * 32
MSG = "a drive root holding .git still enrolls in supervision"


def _git(r, *a):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a], cwd=r,
                          check=True, capture_output=True, text=True).stdout.strip()


def _repo(tmp_path, *, remote="origin", remote_head=True):
    """`main` is on the remote; `feat` was pushed to a branch, not merged."""
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "commit", "-q", "--allow-empty", "-m", "base")
    main = _git(r, "rev-parse", "HEAD")
    _git(r, "update-ref", f"refs/remotes/{remote}/main", main)
    if remote_head:
        _git(r, "symbolic-ref", f"refs/remotes/{remote}/HEAD", f"refs/remotes/{remote}/main")
    _git(r, "checkout", "-q", "-b", "feat")
    _git(r, "commit", "-q", "--allow-empty", "-m", "feature")
    feat = _git(r, "rev-parse", "HEAD")
    (r / ".aramid").mkdir()
    return r, main, feat


def _finding(fid, file, *, line=290, message=MSG, tool="llm-review"):
    return Finding(id=fid, tool=tool, rule="llm/logic", severity_raw="medium",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file, line=line,
                   message=message, evidence="", gate=Gate.ALL)


def _detect(r, run_id, at, head, *findings, gate="drain"):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run(run_id, at, gate, {f.tool for f in findings}, {f.file for f in findings},
                       list(findings), head=head)
    finally:
        led.close()


def _lines(r, limit=5):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        return status_mod._unmerged_drain_lines(r, led, led.open_findings(), limit)
    finally:
        led.close()


def test_a_drain_finding_on_a_commit_the_default_branch_lacks_is_named(tmp_path):
    r, main, feat = _repo(tmp_path)
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", feat, _finding(E, "src/graphite/ingest.py"))

    assert _lines(r) == [
        "drain findings open on commits origin/main does not have: 1",
        f"  {E[:12]} llm-review src/graphite/ingest.py:290 -- {MSG}",
    ]


def test_a_finding_on_a_commit_the_default_branch_has_is_not_named(tmp_path):
    r, main, feat = _repo(tmp_path)
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", main, _finding(E, "a.py"))

    assert _lines(r) == []


def test_once_the_commit_is_merged_the_finding_is_not_named(tmp_path):
    r, main, feat = _repo(tmp_path)
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", feat, _finding(E, "a.py"))
    _git(r, "update-ref", "refs/remotes/origin/main", feat)

    assert _lines(r) == []


def test_the_detection_that_reopened_it_decides(tmp_path):
    """A still-open finding re-reported gets no new detection (the ledger
    only re-detects a closed one), so its commit is the one it was found --
    or found again -- on: fixed on main, then reopened by a drain on feat."""
    r, main, feat = _repo(tmp_path)
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", main, _finding(E, "a.py"))
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.FINDING_RESOLVED, "x", "2026-11-08T08:00:00+00:00",
                         finding_id=E, payload={"auto_resolved": "manual"}))
    finally:
        led.close()
    _detect(r, "d2", "2026-11-08T11:00:00+00:00", feat, _finding(E, "a.py"))

    assert _lines(r)[0] == "drain findings open on commits origin/main does not have: 1"


def test_a_gate_finding_is_not_a_drain_finding(tmp_path):
    """The push already printed it."""
    r, main, feat = _repo(tmp_path)
    _detect(r, "g1", "2026-11-08T07:01:54+00:00", feat, _finding(E, "a.py", tool="ruff"),
            gate="pre-push")

    assert _lines(r) == []


def test_a_finding_no_longer_open_is_not_named(tmp_path):
    r, main, feat = _repo(tmp_path)
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", feat, _finding(E, "a.py"))
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.FINDING_RESOLVED, "x", "2026-11-08T08:00:00+00:00",
                         finding_id=E, payload={"auto_resolved": "manual"}))
    finally:
        led.close()

    assert _lines(r) == []


def test_without_a_remote_default_branch_nothing_is_named(tmp_path):
    r, main, feat = _repo(tmp_path, remote_head=False)
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", feat, _finding(E, "a.py"))

    assert _lines(r) == []


def test_the_only_remote_with_a_head_is_the_line_when_there_is_no_origin(tmp_path):
    r, main, feat = _repo(tmp_path, remote="upstream")
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", feat, _finding(E, "a.py"))

    assert _lines(r)[0] == "drain findings open on commits upstream/main does not have: 1"


def test_a_commit_git_does_not_know_is_not_called_unmerged(tmp_path):
    """Unknown is not unmerged: a head from another clone, or gc'd."""
    r, main, feat = _repo(tmp_path)
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", "0" * 40, _finding(E, "a.py"))

    assert _lines(r) == []


def test_newest_first_capped_with_a_count_of_the_rest(tmp_path):
    r, main, feat = _repo(tmp_path)
    for k, (fid, at) in enumerate(((E, "07"), (F, "09"), (G, "08"), (H, "10"))):
        _detect(r, f"d{k}", f"2026-11-08T{at}:00:00+00:00", feat, _finding(fid, f"m{k}.py"))

    lines = _lines(r, limit=2)

    assert lines == [
        "drain findings open on commits origin/main does not have: 4",
        f"  {H[:12]} llm-review m3.py:290 -- {MSG}",
        f"  {F[:12]} llm-review m1.py:290 -- {MSG}",
        "  ... 2 more: aramid ledger filter --status open",
    ]


def test_the_message_is_its_first_line_cut_to_100_characters(tmp_path):
    r, main, feat = _repo(tmp_path)
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", feat,
            _finding(E, "a.py", message="x" * 120 + "\nsecond line"))

    assert _lines(r)[1] == f"  {E[:12]} llm-review a.py:290 -- {'x' * 97}..."


def test_a_message_of_exactly_100_characters_is_whole(tmp_path):
    r, main, feat = _repo(tmp_path)
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", feat, _finding(E, "a.py", message="y" * 100))

    assert _lines(r)[1] == f"  {E[:12]} llm-review a.py:290 -- {'y' * 100}"


def test_exactly_the_limit_needs_no_count_of_the_rest(tmp_path):
    r, main, feat = _repo(tmp_path)
    for k, fid in enumerate((E, F)):
        _detect(r, f"d{k}", f"2026-11-08T0{k}:00:00+00:00", feat, _finding(fid, f"m{k}.py"))

    lines = _lines(r, limit=2)

    assert len(lines) == 3 and not any("more:" in ln for ln in lines), lines


def test_the_line_helper_names_the_remote_branch_and_its_commit(tmp_path):
    r, main, feat = _repo(tmp_path)

    assert gitutil.remote_default_branch(r) == ("origin/main", main)


def test_a_remote_head_naming_a_pruned_branch_is_no_line(tmp_path):
    r, main, feat = _repo(tmp_path)
    _git(r, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/gone")

    assert gitutil.remote_default_branch(r) is None


def test_origin_wins_over_another_remote_with_a_head(tmp_path):
    r, main, feat = _repo(tmp_path)
    _git(r, "update-ref", "refs/remotes/upstream/trunk", feat)
    _git(r, "symbolic-ref", "refs/remotes/upstream/HEAD", "refs/remotes/upstream/trunk")

    assert gitutil.remote_default_branch(r) == ("origin/main", main)


def test_two_remotes_with_a_head_and_no_origin_are_no_line(tmp_path):
    r, main, feat = _repo(tmp_path, remote="upstream")
    _git(r, "update-ref", "refs/remotes/fork/main", feat)
    _git(r, "symbolic-ref", "refs/remotes/fork/HEAD", "refs/remotes/fork/main")

    assert gitutil.remote_default_branch(r) is None


def test_unreached_by_answers_every_commit_in_one_call(tmp_path, monkeypatch):
    r, main, feat = _repo(tmp_path)
    calls = []
    real = gitutil._run
    monkeypatch.setattr(gitutil, "_run", lambda *a, **k: calls.append(a[1:]) or real(*a, **k))

    got = gitutil.unreached_by(r, {main, feat, "0" * 40}, main)

    assert got == {feat}, "main is reached, feat is not, an unknown commit is neither"
    assert len(calls) == 1
    assert gitutil.unreached_by(r, set(), main) == set() and len(calls) == 1


def test_no_open_drain_finding_asks_git_nothing(tmp_path, monkeypatch):
    """The session-start hook's usual case pays no git spawn."""
    r, main, feat = _repo(tmp_path)
    _detect(r, "g1", "2026-11-08T07:01:54+00:00", feat, _finding(E, "a.py", tool="ruff"),
            gate="pre-push")
    calls = []
    monkeypatch.setattr(gitutil, "_run", lambda *a, **k: calls.append(a) or None)

    assert _lines(r) == [] and calls == []


def test_the_session_start_block_names_at_most_three(tmp_path):
    r, main, feat = _repo(tmp_path)
    for k, fid in enumerate((E, F, G, H)):
        _detect(r, f"d{k}", f"2026-11-08T0{k}:00:00+00:00", feat, _finding(fid, f"m{k}.py"))

    block = agent_hook._posture_context(r)

    assert "aramid: drain findings open on commits origin/main does not have: 4\n" in block
    assert block.count("aramid:   ") >= 3
    assert f"aramid:   {H[:12]} " in block and f"aramid:   {E[:12]} " not in block
    assert "aramid:   ... 1 more: aramid ledger filter --status open\n" in block


def test_status_prints_them(tmp_path, capsys):
    r, main, feat = _repo(tmp_path)
    _detect(r, "d1", "2026-11-08T07:01:54+00:00", feat, _finding(E, "a.py"))

    status_mod.cmd_status(r)

    out = capsys.readouterr().out
    assert "  drain findings open on commits origin/main does not have: 1\n" in out
    assert f"    {E[:12]} llm-review a.py:290 -- {MSG}\n" in out
