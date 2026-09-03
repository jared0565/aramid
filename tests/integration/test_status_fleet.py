"""`aramid status` carries the same two line shapes without the prefix,
after `scheduled drain:`."""
import subprocess

import pytest

from aramid import fleet, notices
from aramid.commands import schedule as schedule_mod
from aramid.commands.status import cmd_status

NOW = "2026-09-20T12:00:00+00:00"


def _verdict(**over):
    # tests/integration is not a package: the fixture verdict is repeated
    # from test_agent_hook_fleet.py. Keep the copies identical.
    base = {"schema_version": 1, "computed_at": NOW, "aramid_version": "0.9.0",
            "policy": {"min_days": 14, "min_versions": 2},
            "repos": {"f:/p/aramid": {"name": "aramid", "rows": 41, "latest_at": NOW,
                                      "green": False, "red_criteria": ["dep_audit_ran"],
                                      "criteria": {}},
                      "f:/p/graphite": {"name": "graphite", "rows": 3, "latest_at": NOW,
                                        "green": True, "red_criteria": [], "criteria": {}}},
            "fleet": {"all_green_now": False, "streak_started_at": None, "days_held": 0.0,
                      "versions_in_streak": [], "armed_anywhere": False,
                      "disarm_in_streak": False,
                      "blockers": ["no repo is armed"], "notes": [],
                      "breaking_row": None},
            "verdict": "not-ready",
            "reasons": ["aramid: dep_audit_ran", "no repo is armed"]}
    base.update(over)
    return base


@pytest.fixture(autouse=True)
def _no_real_schtasks(monkeypatch):
    real_run = subprocess.run

    def fake_run(argv, *a, **k):
        if argv and argv[0] == "schtasks":
            class _R:
                returncode = 1
                stdout = ""
                stderr = ""
            return _R()
        return real_run(argv, *a, **k)
    monkeypatch.setattr(schedule_mod.subprocess, "run", fake_run)


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True)
    (r / "aramid.toml").write_text("schema_version = 1\nsemgrep_block_armed = true\n",
                                   encoding="utf-8")
    return r


def _out(root, capsys):
    capsys.readouterr()
    assert cmd_status(root) == 0
    return capsys.readouterr().out.splitlines()


def test_status_fleet_block_follows_scheduled_drain(tmp_path, capsys):
    root = _repo(tmp_path)
    lines = _out(root, capsys)
    i = next(i for i, ln in enumerate(lines) if ln.startswith("scheduled drain:"))
    assert lines[i + 1] == "fleet: no verdict yet -- first drain after promotion computes it"


def test_status_prints_the_verdict_and_a_due_notice_bare(tmp_path, capsys):
    root = _repo(tmp_path)
    fleet.write_verdict(_verdict())
    nid = notices.post("fleet-defect", "defect:f:/p/aramid:resolver:gap_addressed/mutation",
                       title="aramid: resolver gap_addressed/mutation on the last 3 gate runs",
                       body="b", evidence={}, now=NOW)
    lines = _out(root, capsys)
    assert ("fleet: 1.0 readiness NOT READY -- 1/2 repos green, streak 0d, versions 0/2; "
            "red: aramid (dep_audit_ran); no repo is armed") in lines
    assert (f"NOTICE {nid} fleet-defect: aramid: resolver gap_addressed/mutation on the "
            f"last 3 gate runs -- ack: aramid notices ack {nid}") in lines
    assert [e["surface"] for e in notices.read_events() if e["kind"] == "shown"] == ["status"]


def test_an_acked_notice_is_gone_from_status(tmp_path, capsys):
    root = _repo(tmp_path)
    nid = notices.post("fleet-defect", "k", title="t", body="b", evidence={}, now=NOW)
    notices.ack(nid, repo="elsewhere", now=NOW)
    assert not any("NOTICE" in ln for ln in _out(root, capsys))


def test_status_caps_notice_lines_and_says_how_many_remain(tmp_path, capsys):
    root = _repo(tmp_path)
    for i in range(5):
        notices.post("fleet-defect", f"k{i}", title=f"t{i}", body="b", evidence={}, now=NOW)
    lines = _out(root, capsys)
    notice_lines = [ln for ln in lines if ln.startswith("NOTICE ")]
    assert len(notice_lines) == 3
    assert "fleet: ... and 2 more notice(s) pending -- see `aramid notices`" in lines
    shown = [e for e in notices.read_events() if e["kind"] == "shown"]
    assert len(shown) == 3
