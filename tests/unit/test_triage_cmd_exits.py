"""`aramid triage` at unit scope on a real tmp repo with the scorer answered:
the rev and range resolution, the one-line verdict, every refusal and the
watchdog's exit -- each line whole, each exit code.

The drain confirms a mutant against the unit suite alone, and eight of the
command's nine generator mutants sat on lines the unit suite never
executed -- the range split's `1`, `or` -> `and` on the two range shas
(a half-resolved range scored anyway), the seven-char short sha, every
`return 3` and the `return 0` -- plus the watchdog's `os._exit(3)`:
tests/integration/test_triage_cmd.py covers them and the drain never runs
that directory."""
import subprocess
from types import SimpleNamespace

from aramid.commands import triage_cmd


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout.strip()


def _repo(tmp_path, commits=2):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    for i in range(commits):
        (r / "f.py").write_text(f"x = {i}\n", encoding="utf-8")
        _git(r, "add", "f.py")
        _git(r, "commit", "-q", "-m", f"c{i}")
    return r


def _answer(monkeypatch, score=75, reasons=("security-path: src/auth.py",), queued=True):
    calls = []

    def run_triage(repo, cfg, ledger, base, head, now):
        calls.append((repo, base, head))
        return SimpleNamespace(score=score, reasons=list(reasons)), queued
    monkeypatch.setattr(triage_cmd.triage, "run_triage", run_triage)
    return calls


def test_triage_scores_head_against_its_first_parent(tmp_path, capsys, monkeypatch):
    r = _repo(tmp_path)
    calls = _answer(monkeypatch)
    head, parent = _git(r, "rev-parse", "HEAD"), _git(r, "rev-parse", "HEAD^")

    assert triage_cmd.cmd_triage(r) == 0
    assert capsys.readouterr() == (
        f"aramid triage: {head[:7]} score 75 (queued); security-path: src/auth.py\n", "")
    assert calls == [(r.resolve(), parent, head)]


def test_triage_scores_a_range_and_reports_below_threshold(tmp_path, capsys, monkeypatch):
    r = _repo(tmp_path, commits=3)
    calls = _answer(monkeypatch, score=10, reasons=(), queued=False)
    head, base = _git(r, "rev-parse", "HEAD"), _git(r, "rev-parse", "HEAD~2")

    assert triage_cmd.cmd_triage(r, "HEAD~2..HEAD") == 0
    assert capsys.readouterr() == (
        f"aramid triage: {head[:7]} score 10 (below threshold); no signals\n", "")
    assert calls == [(r.resolve(), base, head)]


def test_triage_refuses_a_range_with_either_end_unresolvable(tmp_path, capsys, monkeypatch):
    r = _repo(tmp_path)
    calls = _answer(monkeypatch)
    # a second ".." stays in the head end: the range splits exactly once
    for rng in ("nope..HEAD", "HEAD..nope", "HEAD~1..HEAD..HEAD"):
        assert triage_cmd.cmd_triage(r, rng) == 3
        assert capsys.readouterr() == ("", f"aramid: triage: cannot resolve range {rng!r}\n")
    assert calls == []


def test_triage_refuses_an_unresolvable_rev_and_a_non_repo(tmp_path, capsys, monkeypatch):
    r = _repo(tmp_path)
    calls = _answer(monkeypatch)
    assert triage_cmd.cmd_triage(r, "nope") == 3
    assert capsys.readouterr() == ("", "aramid: triage: cannot resolve rev 'nope'\n")

    plain = tmp_path / "plain"
    plain.mkdir()
    assert triage_cmd.cmd_triage(plain) == 3
    assert capsys.readouterr() == ("", "aramid: triage: not a git repository\n")
    assert calls == []


def test_triage_reports_an_engine_error_on_one_line(tmp_path, capsys, monkeypatch):
    r = _repo(tmp_path)

    def boom(*a, **kw):
        raise RuntimeError("scorer down")
    monkeypatch.setattr(triage_cmd.triage, "run_triage", boom)
    assert triage_cmd.cmd_triage(r) == 3
    assert capsys.readouterr() == ("", "aramid: triage: engine error: scorer down\n")


def test_watchdog_kill_reports_then_exits_3(monkeypatch, capsys):
    exits = []
    monkeypatch.setattr(triage_cmd, "os", SimpleNamespace(_exit=lambda c: exits.append(c)))
    triage_cmd._watchdog_kill(1.5)
    assert capsys.readouterr() == ("", "aramid: triage: watchdog: exceeded 1.5s -- killing\n")
    assert exits == [3]


def test_watchdog_kill_exits_even_when_the_streams_are_broken(monkeypatch):
    exits = []
    monkeypatch.setattr(triage_cmd, "os", SimpleNamespace(_exit=lambda c: exits.append(c)))

    class _Broken:
        def write(self, s):
            raise BrokenPipeError("gone")

        def flush(self):
            raise BrokenPipeError("gone")
    monkeypatch.setattr(triage_cmd.sys, "stderr", _Broken())
    monkeypatch.setattr(triage_cmd.sys, "stdout", _Broken())
    triage_cmd._watchdog_kill(2.0)
    assert exits == [3]
