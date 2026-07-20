import subprocess

from aramid import config as config_mod
from aramid.commands.rebaseline import cmd_rebaseline
from aramid.ledger import Ledger
from aramid.models import EventType


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _baseline_snapshot_count(r):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        return sum(1 for e in led.events() if e.type is EventType.BASELINE_SNAPSHOT)
    finally:
        led.close()


def test_rebaseline_without_yes_refuses_and_writes_nothing(tmp_path, monkeypatch, capsys):
    r = _repo(tmp_path, monkeypatch)
    rc = cmd_rebaseline(r, yes=False)
    assert rc == 3
    assert _baseline_snapshot_count(r) == 0
    out = capsys.readouterr().out.lower()
    assert "--yes" in out  # tells the user how to actually do it


def test_rebaseline_with_yes_writes_a_baseline_snapshot(tmp_path, monkeypatch):
    r = _repo(tmp_path, monkeypatch)
    rc = cmd_rebaseline(r, yes=True)
    assert rc == 0
    assert _baseline_snapshot_count(r) == 1


def test_rebaseline_with_yes_latest_snapshot_supersedes(tmp_path, monkeypatch):
    # Discriminating latest-wins test: the sandbox gate produces zero findings,
    # so control run_gate's finding set directly. Run 1 accepts {A, B}; run 2
    # accepts {B, C}. The baseline must be run 2's set ONLY -- not run 1's
    # ({A, B} = first-wins bug), not the union ({A, B, C} = appends-to bug).
    from types import SimpleNamespace

    from aramid.commands import rebaseline as rb
    r = _repo(tmp_path, monkeypatch)
    seq = [
        SimpleNamespace(run_id="r1", findings=[SimpleNamespace(id="A"),
                                               SimpleNamespace(id="B")]),
        SimpleNamespace(run_id="r2", findings=[SimpleNamespace(id="B"),
                                               SimpleNamespace(id="C")]),
    ]
    calls = {"n": 0}

    def fake_run_gate(root, gate, mode, cfg, ledger):
        res = seq[calls["n"]]
        calls["n"] += 1
        return res

    monkeypatch.setattr(rb, "run_gate", fake_run_gate)
    assert cmd_rebaseline(r, yes=True) == 0
    assert cmd_rebaseline(r, yes=True) == 0
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert _baseline_snapshot_count(r) == 2
        assert led.baseline_ids() == {"B", "C"}   # latest supersedes, not union
    finally:
        led.close()
