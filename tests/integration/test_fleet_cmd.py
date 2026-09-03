"""`aramid fleet` is a report (exit 0 always); `aramid notices` is the ack
surface (exit 3 only for an unknown id, with the pending ids listed)."""
import json

import pytest

from aramid import cli, fleet, notices
from aramid.commands.fleet_cmd import cmd_fleet, cmd_notices

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
                      "blockers": ["no repo has an armed consumer"], "notes": [],
                      "breaking_row": None},
            "verdict": "not-ready",
            "reasons": ["aramid: dep_audit_ran", "no repo has an armed consumer"]}
    base.update(over)
    return base


def _full_verdict():
    v = _verdict()
    v["repos"]["f:/p/aramid"]["criteria"] = {"no_skip_streak": True, "consumers_healthy": True,
                                             "resolvers_ok": True,
                                             "no_self_inflicted_block": True,
                                             "dep_audit_ran": False}
    v["repos"]["f:/p/graphite"] = {"name": "graphite", "rows": 0, "latest_at": None,
                                   "green": False, "red_criteria": [], "criteria": {}}
    return v


def test_fleet_report_full_lines(capsys):
    fleet.write_verdict(_full_verdict())
    assert cmd_fleet() == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "fleet health -- 1.0 readiness (policy: 14 days, 2 versions)"
    assert lines[2] == ("  repo      rows  latest                     skip        consumers   "
                        "resolvers   self-block  dep-audit")
    assert lines[3] == ("  aramid      41  2026-09-20T12:00:00+00:00  ok          ok          "
                        "ok          ok          RED")
    assert lines[4] == ("  graphite     0  (no rows)                  -           -           "
                        "-           -           -")
    assert lines[6] == "  streak: none (fleet not green)"
    assert lines[7] == "  armed anywhere: no"
    assert lines[9] == "verdict: not-ready"
    assert lines[10:] == ["  - aramid: dep_audit_ran", "  - no repo has an armed consumer"]


def test_fleet_report_without_a_verdict(capsys):
    assert cmd_fleet() == 0
    assert capsys.readouterr().out.splitlines()[2] == \
        "  no verdict yet -- first drain after promotion computes it"


def test_fleet_json_prints_the_verdict_verbatim(capsys):
    fleet.write_verdict(_full_verdict())
    assert cmd_fleet(as_json=True) == 0
    assert json.loads(capsys.readouterr().out) == fleet.read_verdict()
    fleet.verdict_path().unlink()
    assert cmd_fleet(as_json=True) == 0
    assert json.loads(capsys.readouterr().out) is None


def test_notices_list_show_ack(tmp_path, capsys):
    nid = notices.post("fleet-defect", "k", title="aramid: resolver x on the last 3 gate runs",
                       body="the body", evidence={"repo": "f:/p/aramid"}, now=NOW)
    assert cmd_notices("list", None, tmp_path) == 0
    assert capsys.readouterr().out == f"{nid} fleet-defect aramid: resolver x on the last 3 gate runs\n"
    assert cmd_notices("show", nid, tmp_path) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == f"{nid} fleet-defect ({NOW})"
    assert "the body" in out and '"repo": "f:/p/aramid"' in out
    assert cmd_notices("ack", nid, tmp_path) == 0
    assert capsys.readouterr().out == f"acked {nid}\n"
    assert notices.pending() == []
    acks = [e for e in notices.read_events() if e["kind"] == "ack"]
    assert acks[0]["repo"] == fleet.repo_key(tmp_path)
    assert cmd_notices("ack", nid, tmp_path) == 0            # idempotent
    assert capsys.readouterr().out == f"acked {nid}\n"
    assert len([e for e in notices.read_events() if e["kind"] == "ack"]) == 1
    assert cmd_notices("list", None, tmp_path) == 0
    assert capsys.readouterr().out == "no pending fleet notices\n"


def test_notices_unknown_id_exits_3_and_lists_pending(tmp_path, capsys):
    nid = notices.post("fleet-defect", "k", title="t", body="b", evidence={}, now=NOW)
    assert cmd_notices("ack", "000000000000", tmp_path) == 3
    assert capsys.readouterr().err == \
        f"aramid: notices: unknown id '000000000000'; pending: {nid}\n"
    assert cmd_notices("show", "000000000000", tmp_path) == 3


@pytest.mark.parametrize("argv", [["fleet"], ["fleet", "--json"], ["notices"],
                                  ["notices", "list"]])
def test_cli_wires_fleet_and_notices(argv, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(argv) == 0
    capsys.readouterr()


def test_cli_notices_ack_dispatch(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    nid = notices.post("fleet-defect", "k", title="t", body="b", evidence={}, now=NOW)
    assert cli.main(["notices", "ack", nid]) == 0
    assert notices.pending() == []
