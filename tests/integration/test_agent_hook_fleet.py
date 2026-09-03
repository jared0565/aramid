"""The session-start hook is where a notice reaches the operator in the repo
they are working in. Full-line assertions; `shown` events respect
repeat_hours; a broken channel costs the fleet lines and nothing else."""
import subprocess
import sys
from pathlib import Path

from aramid import fleet, notices
from aramid.commands import agent_hook, doctor, init

NOW = "2026-09-20T12:00:00+00:00"


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _fake_present(root):
    return {name: doctor.ToolStatus(name, True, "1.0")
            for name in ("gitleaks", "semgrep", "ruff", "pip-audit")} | {
        "interpreter": doctor.ToolStatus("interpreter", True, sys.executable)}


def _onboarded(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "app.py")
    _git(r, "commit", "-q", "-m", "seed")
    assert init.cmd_init(r) == 0
    return r


def _verdict(**over):
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
                      "blockers": ["no repo has an armed consumer"], "notes": [],
                      "breaking_row": None},
            "verdict": "not-ready",
            "reasons": ["aramid: dep_audit_ran", "no repo has an armed consumer"]}
    base.update(over)
    return base


def _lines(r, capsys):
    capsys.readouterr()
    assert agent_hook.cmd_agent_hook("session-start", root=r) == 0
    return capsys.readouterr().out.splitlines()


def test_ready_line_full_shape():
    # readiness_line's other two shapes (spec section 8) are not reachable
    # through the hook fixtures above, which only ever write a not-ready
    # verdict -- asserted directly against the pure function instead.
    v = _verdict(
        verdict="ready",
        repos={f"f:/p/r{i}": {"name": f"r{i}", "rows": 5, "latest_at": NOW, "green": True,
                              "red_criteria": [], "criteria": {}} for i in range(1, 6)},
        fleet={"all_green_now": True, "streak_started_at": NOW, "days_held": 21.0,
              "versions_in_streak": ["0.8.0", "0.9.0"], "armed_anywhere": True,
              "disarm_in_streak": False, "blockers": [], "notes": [], "breaking_row": None})
    assert fleet.readiness_line(v) == (
        "fleet: 1.0 readiness READY -- 5/5 repos green, streak 21d, versions 2/2")


def test_insufficient_data_line_full_shape():
    v = _verdict(
        verdict="insufficient-data",
        repos={
            "f:/p/aramid": {"name": "aramid", "rows": 41, "latest_at": NOW, "green": True,
                           "red_criteria": [], "criteria": {}},
            "f:/p/bytes": {"name": "bytes", "rows": 7, "latest_at": NOW, "green": True,
                          "red_criteria": [], "criteria": {}},
            "f:/p/demo": {"name": "demo", "rows": 2, "latest_at": NOW, "green": True,
                         "red_criteria": [], "criteria": {}},
            "f:/p/atlas_data": {"name": "atlas_data", "rows": 0, "latest_at": None,
                               "green": False, "red_criteria": [], "criteria": {}},
            "f:/p/graphite": {"name": "graphite", "rows": 0, "latest_at": None,
                             "green": False, "red_criteria": [], "criteria": {}},
        },
        fleet={"all_green_now": False, "streak_started_at": None, "days_held": 0.0,
              "versions_in_streak": [], "armed_anywhere": False,
              "disarm_in_streak": False, "blockers": [], "notes": [], "breaking_row": None})
    assert fleet.readiness_line(v) == (
        "fleet: 1.0 readiness INSUFFICIENT DATA -- 3/5 repos green, streak 0d, "
        "versions 0/2; no rows: atlas_data, graphite")


def test_no_verdict_yet_line_sits_before_the_commands_line(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    lines = _lines(r, capsys)
    assert lines[-2] == "aramid: fleet: no verdict yet -- first drain after promotion computes it"
    assert lines[-1].startswith("aramid: commands:")


def test_not_ready_line_full_shape(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    fleet.write_verdict(_verdict())
    assert ("aramid: fleet: 1.0 readiness NOT READY -- 1/2 repos green, streak 0d, "
            "versions 0/2; red: aramid (dep_audit_ran); no repo has an armed consumer"
            ) in _lines(r, capsys)


def test_a_due_notice_is_shown_once_per_repeat_window(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    fleet.write_verdict(_verdict())
    nid = notices.post("readiness-broken", "run:x",
                       title="Atlas_Data went red at 2026-09-03T10:11:00+00:00 "
                             "(resolvers_ok: file_departed/mutation BLIND)",
                       body="b", evidence={}, now=NOW)
    expected = (f"aramid: NOTICE {nid} readiness-broken: Atlas_Data went red at "
                f"2026-09-03T10:11:00+00:00 (resolvers_ok: file_departed/mutation BLIND)"
                f" -- ack: aramid notices ack {nid}")
    assert expected in _lines(r, capsys)
    shown = [e for e in notices.read_events() if e["kind"] == "shown"]
    assert len(shown) == 1 and shown[0]["surface"] == "session-start"
    assert shown[0]["repo"] == fleet.repo_key(r)
    assert expected not in _lines(r, capsys)         # within repeat_hours: not repeated
    assert any(ln.startswith("aramid: fleet: 1.0 readiness") for ln in _lines(r, capsys))


def test_a_channel_that_is_a_directory_still_prints_the_verdict_line(tmp_path, monkeypatch,
                                                                     capsys):
    # The tolerant reader turns an unreadable notices file into "no events"
    # plus one stderr note; the readiness line survives, the block is whole.
    r = _onboarded(tmp_path, monkeypatch)
    notices.notices_path().mkdir(parents=True)
    lines = _lines(r, capsys)
    assert "aramid: fleet: no verdict yet -- first drain after promotion computes it" in lines
    assert not any("NOTICE" in ln for ln in lines)


def test_an_internal_fleet_error_costs_only_the_fleet_lines(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("injected")
    monkeypatch.setattr(fleet, "read_verdict", boom)
    lines = _lines(r, capsys)
    assert lines[0].startswith("aramid: this repo is GATED")
    assert lines[-1].startswith("aramid: commands:")
    assert not any("fleet" in ln or "NOTICE" in ln for ln in lines)
