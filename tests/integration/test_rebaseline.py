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


def test_rebaseline_with_yes_overwrites_prior_baseline_latest_wins(tmp_path, monkeypatch):
    r = _repo(tmp_path, monkeypatch)
    assert cmd_rebaseline(r, yes=True) == 0
    assert cmd_rebaseline(r, yes=True) == 0
    # baseline_ids is latest-wins; two snapshots exist but the accepted set is
    # the newest one (proving re-baseline supersedes, not appends-to).
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert _baseline_snapshot_count(r) == 2
        snaps = [e for e in led.events() if e.type is EventType.BASELINE_SNAPSHOT]
        assert led.baseline_ids() == set(snaps[-1].payload.get("ids", []))
    finally:
        led.close()
