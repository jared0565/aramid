"""`aramid fleet` / `aramid notices` and `fleet.render_report` at unit scope,
on the isolated fleet store: every printed line whole, every exit code.

The drain confirms a mutant against the unit suite alone, and all 18 of
`commands/fleet_cmd.py`'s generator mutants -- the `list` default, each
subcommand's comparison, the `or ""` on a missing id, every `return 0`
and `return 3`, the JSON indent -- plus five of `render_report`'s six and
the tolerant reader's two skip counters sat on lines the unit suite never
executed: tests/integration/test_fleet_cmd.py covers them and the drain
never runs that directory."""
import json

from aramid import fleet, notices
from aramid.commands.fleet_cmd import cmd_fleet, cmd_notices

NOW = "2026-09-20T12:00:00+00:00"


def _verdict(**over):
    base = {"schema_version": 1, "computed_at": NOW, "aramid_version": "0.9.0",
            "policy": {"min_days": 14, "min_versions": 2},
            "repos": {"f:/p/aramid": {"name": "aramid", "rows": 41, "latest_at": NOW,
                                      "green": False, "red_criteria": ["dep_audit_ran"],
                                      "criteria": {"no_skip_streak": True,
                                                   "consumers_healthy": True,
                                                   "resolvers_ok": True,
                                                   "no_self_inflicted_block": True,
                                                   "dep_audit_ran": False}},
                      "f:/p/graphite": {"name": "graphite", "rows": 0, "latest_at": None,
                                        "green": False, "red_criteria": [], "criteria": {}}},
            "fleet": {"all_green_now": False, "streak_started_at": None, "days_held": 0.0,
                      "versions_in_streak": [], "armed_anywhere": False,
                      "disarm_in_streak": False,
                      "blockers": ["no repo is armed"], "notes": [],
                      "breaking_row": None},
            "verdict": "not-ready",
            "reasons": ["aramid: dep_audit_ran", "no repo is armed"]}
    base.update(over)
    return base


REPORT = (
    "fleet health -- 1.0 readiness (policy: 14 days, 2 versions, 7-day row window)\n"
    "\n"
    "  repo      rows  latest                     skip        consumers   resolvers   "
    "self-block  dep-audit\n"
    "  aramid      41  2026-09-20T12:00:00+00:00  ok          ok          ok          "
    "ok          RED\n"
    "  graphite     0  (no rows)                  -           -           -           "
    "-           -\n"
    "\n"
    "  streak: none (fleet not green)\n"
    "  armed anywhere: no\n"
    "\n"
    "verdict: not-ready\n"
    "  - aramid: dep_audit_ran\n"
    "  - no repo is armed")


# ------------------------------------------------------------ render_report --

def test_render_report_whole():
    assert fleet.render_report(_verdict(), fleet.Policy(), now=NOW) == REPORT


def test_render_report_row_window_wording_at_zero_and_one_day():
    head = fleet.render_report(None, fleet.Policy(max_row_age_days=0)).splitlines()
    assert head == ["fleet health -- 1.0 readiness (policy: 14 days, 2 versions, no row window)",
                    "", "  no verdict yet -- first drain after promotion computes it"]
    assert fleet.render_report(None, fleet.Policy(max_row_age_days=1)).splitlines()[0] == \
        "fleet health -- 1.0 readiness (policy: 14 days, 2 versions, 1-day row window)"


def test_render_report_name_column_is_never_narrower_than_its_heading():
    v = _verdict(repos={"f:/p/ab": {"name": "ab", "rows": 2, "latest_at": NOW,
                                     "green": True, "red_criteria": [],
                                     "criteria": {"no_skip_streak": True}}})
    lines = fleet.render_report(v, fleet.Policy()).splitlines()
    assert lines[2] == ("  repo  rows  latest                     skip        consumers   "
                        "resolvers   self-block  dep-audit")
    assert lines[3] == ("  ab       2  2026-09-20T12:00:00+00:00  ok          -           "
                        "-           -           -")


def test_render_report_streak_lines():
    v = _verdict()
    v["fleet"].update(streak_started_at=NOW, days_held=3.25, versions_in_streak=[])
    assert "  streak: since 2026-09-20T12:00:00+00:00 (3.2d, versions: none)" in \
        fleet.render_report(v, fleet.Policy()).splitlines()
    v["fleet"].update(versions_in_streak=["0.9.0", "0.10.0"], days_held=None,
                      armed_anywhere=True)
    lines = fleet.render_report(v, fleet.Policy()).splitlines()
    assert "  streak: since 2026-09-20T12:00:00+00:00 (0.0d, versions: 0.9.0, 0.10.0)" in lines
    assert "  armed anywhere: yes" in lines


def test_render_report_marks_a_stale_verdict():
    lines = fleet.render_report(_verdict(), fleet.Policy(),
                                now="2026-09-22T12:00:00+00:00").splitlines()
    assert lines[9] == "verdict: not-ready (stale: computed 2026-09-20T12:00:00+00:00)"


# ------------------------------------------------------------- _read_jsonl --

def test_read_jsonl_counts_each_skipped_row_once(tmp_path, capsys):
    p = tmp_path / "rows.jsonl"
    good = {"schema_version": 1, "repo": "r", "at": NOW}
    p.write_text("\n".join([
        json.dumps(good),
        "{torn",                                            # unreadable
        json.dumps({"schema_version": "1", "repo": "r", "at": NOW}),   # version not an int
        json.dumps({"schema_version": True, "repo": "r", "at": NOW}),  # a bool is not a version
        json.dumps({"schema_version": 1, "repo": "r"}),                # a required key missing
        json.dumps({"schema_version": 1, "repo": "r", "at": 7}),       # a required key mistyped
        json.dumps({"schema_version": fleet.SCHEMA_VERSION + 1, "repo": "r", "at": NOW}),
        "",
    ]) + "\n", encoding="utf-8")

    assert fleet._read_jsonl(p, ("repo", "at")) == [good]
    assert capsys.readouterr().err == (
        "aramid: fleet: skipped 5 unreadable row(s) in rows.jsonl\n"
        f"aramid: fleet: ignored 1 row(s) newer than schema {fleet.SCHEMA_VERSION} in rows.jsonl\n")
    assert fleet._read_jsonl(tmp_path / "absent.jsonl", ("repo",)) == []


# ---------------------------------------------------------------- cmd_fleet --

def test_cmd_fleet_prints_the_report_or_the_verdict_json(capsys, monkeypatch):
    monkeypatch.setattr("aramid.commands.fleet_cmd._now", lambda: NOW)
    fleet.write_verdict(_verdict())
    assert cmd_fleet() == 0
    assert capsys.readouterr() == (REPORT + "\n", "")

    assert cmd_fleet(as_json=True) == 0
    assert capsys.readouterr() == (json.dumps(_verdict(), indent=2, sort_keys=True) + "\n", "")

    fleet.verdict_path().unlink()
    assert cmd_fleet() == 0
    assert capsys.readouterr().out.splitlines()[2] == \
        "  no verdict yet -- first drain after promotion computes it"
    assert cmd_fleet(as_json=True) == 0
    assert capsys.readouterr() == ("null\n", "")


def test_cmd_fleet_reports_a_failure_on_one_line_and_still_exits_0(capsys, monkeypatch):
    def boom():
        raise RuntimeError("disk gone")
    monkeypatch.setattr(fleet, "read_verdict", boom)
    assert cmd_fleet() == 0
    assert capsys.readouterr() == ("", "aramid: fleet: report failed (disk gone)\n")


# -------------------------------------------------------------- cmd_notices --

def _post(title="aramid: resolver x on the last 3 gate runs", key="k"):
    return notices.post("fleet-defect", key, title=title, body="the body",
                        evidence={"repo": "f:/p/aramid"}, now=NOW)


def test_notices_list_is_the_default_and_names_each_pending_notice(tmp_path, capsys):
    assert cmd_notices(None, None, tmp_path) == 0
    assert capsys.readouterr() == ("no pending fleet notices\n", "")
    a = _post()
    b = _post(title="second", key="k2")
    assert cmd_notices("list", None, tmp_path) == 0
    assert capsys.readouterr() == (
        f"{a} fleet-defect aramid: resolver x on the last 3 gate runs\n{b} fleet-defect second\n", "")


def test_notices_show_prints_the_whole_notice_and_its_state(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("aramid.commands.fleet_cmd._now", lambda: NOW)
    nid = _post()
    assert cmd_notices("show", nid, tmp_path) == 0
    assert capsys.readouterr() == (
        f"{nid} fleet-defect ({NOW})\n"
        "aramid: resolver x on the last 3 gate runs\n"
        "\n"
        "the body\n"
        "\n"
        "state: pending\n"
        'evidence: {"repo": "f:/p/aramid"}\n', "")

    assert cmd_notices("ack", nid, tmp_path) == 0
    assert capsys.readouterr() == (f"acked {nid}\n", "")
    assert cmd_notices("show", nid, tmp_path) == 0
    assert "state: acked\n" in capsys.readouterr().out

    assert cmd_notices("show", None, tmp_path) == 3, "no id is not the first notice"
    assert capsys.readouterr().err == "aramid: notices: unknown id None; pending: none\n"


def test_notices_ack_records_the_repo_and_is_idempotent(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("aramid.commands.fleet_cmd._now", lambda: NOW)
    nid = _post()
    assert cmd_notices("ack", nid, tmp_path) == 0
    assert capsys.readouterr() == (f"acked {nid}\n", "")
    acks = [e for e in notices.read_events() if e["kind"] == "ack"]
    assert [(e["repo"], e["at"]) for e in acks] == [(fleet.repo_key(tmp_path), NOW)]
    assert notices.pending() == []

    assert cmd_notices("ack", nid, tmp_path) == 0
    assert capsys.readouterr() == (f"acked {nid}\n", "")
    assert len([e for e in notices.read_events() if e["kind"] == "ack"]) == 1

    assert cmd_notices("ack", None, tmp_path) == 3
    assert capsys.readouterr() == ("", "aramid: notices: unknown id None; pending: none\n")


def test_notices_unknown_id_exits_3_listing_the_pending_ids(tmp_path, capsys):
    nid = _post()
    for action in ("ack", "show"):
        assert cmd_notices(action, "000000000000", tmp_path) == 3
        assert capsys.readouterr() == (
            "", f"aramid: notices: unknown id '000000000000'; pending: {nid}\n")


def test_notices_refuses_an_unknown_subcommand_and_never_tracebacks(tmp_path, capsys,
                                                                     monkeypatch):
    assert cmd_notices("bogus", None, tmp_path) == 3
    assert capsys.readouterr() == (
        "", "aramid: notices: a subcommand is required (list|show|ack)\n")

    def boom(events=None):
        raise RuntimeError("channel gone")
    monkeypatch.setattr(notices, "pending", boom)
    assert cmd_notices("list", None, tmp_path) == 3
    assert capsys.readouterr() == ("", "aramid: notices: command failed (channel gone)\n")
