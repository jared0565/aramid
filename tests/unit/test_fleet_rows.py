"""One row per gate run, appended as one line; a store that is missing,
torn, corrupt or newer reads as what it can, with one stderr note; and the
push never raises and never exceeds its budget."""
import json

from aramid import fleet, health
from aramid.fingerprint import normalize_path
from aramid.ledger import Ledger
from aramid.pipeline import GateResult

NOW = "2026-09-03T12:00:00+00:00"


def _result(**kw):
    base = dict(exit_code=0, findings=[], degraded=[], new_ids=[], stale_overrides=[],
                run_id="run-1", tools_ran=("gitleaks", "semgrep"), stacks=("python",))
    base.update(kw)
    return GateResult(**base)


def test_build_row_has_exactly_the_spec_shape(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    h = health.snapshot(None, lg, _result(), gate="pre-push")
    row = fleet.build_row(tmp_path, h, aramid_version="0.9.0", now=NOW)
    assert set(row) == {"schema_version", "at", "repo", "name", "aramid_version", "gate",
                        "run_id", "exit_code", "engine_error", "criteria", "evidence"}
    assert set(row["evidence"]) == {"skip_streaks", "degraded_consumers", "stood_down",
                                    "no_work", "resolver_defects", "bad_tools",
                                    "degraded_block_tier", "armed", "open", "blocking"}
    assert row["schema_version"] == 1
    assert row["repo"] == normalize_path(str(tmp_path.resolve()))
    assert row["name"] == tmp_path.resolve().name
    assert (row["gate"], row["run_id"], row["exit_code"]) == ("pre-push", "run-1", 0)
    assert row["engine_error"] is False
    assert row["criteria"] == {"no_skip_streak": True, "consumers_healthy": True,
                               "resolvers_ok": True, "no_self_inflicted_block": True,
                               "dep_audit_ran": False}
    assert row["evidence"]["armed"] == {}
    lg.close()


def test_append_then_read_round_trips_in_order(tmp_path):
    fleet.append_row({"schema_version": 1, "at": "a", "repo": "r", "criteria": {}, "n": 1})
    fleet.append_row({"schema_version": 1, "at": "b", "repo": "r", "criteria": {}, "n": 2})
    assert [r["n"] for r in fleet.read_rows()] == [1, 2]
    raw = fleet.health_path().read_bytes()
    assert raw.count(b"\n") == 2 and b"\r\n" not in raw


def test_read_rows_on_a_missing_store_is_empty(capsys):
    assert fleet.read_rows() == []
    assert capsys.readouterr().err == ""


def test_read_rows_skips_garbage_and_torn_lines_with_one_note(capsys):
    p = fleet.health_path()
    p.parent.mkdir(parents=True)
    good = json.dumps({"schema_version": 1, "at": "a", "repo": "r", "criteria": {}})
    p.write_text("not json\n" + good + "\n" + good[:20], encoding="utf-8")
    rows = fleet.read_rows()
    assert len(rows) == 1
    err = capsys.readouterr().err
    assert err == "aramid: fleet: skipped 2 unreadable row(s) in fleet_health.jsonl\n"


def test_read_rows_ignores_newer_schema_rows_with_one_note(capsys):
    p = fleet.health_path()
    p.parent.mkdir(parents=True)
    newer = json.dumps({"schema_version": 2, "at": "a", "repo": "r", "criteria": {}})
    good = json.dumps({"schema_version": 1, "at": "a", "repo": "r", "criteria": {}})
    p.write_text(newer + "\n" + good + "\n", encoding="utf-8")
    assert len(fleet.read_rows()) == 1
    assert capsys.readouterr().err == \
        "aramid: fleet: ignored 1 row(s) newer than schema 1 in fleet_health.jsonl\n"


def test_record_health_appends_one_row(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    fleet.record_health(tmp_path, None, lg, _result(), gate="pre-push",
                        aramid_version="0.9.0", now=NOW)
    rows = fleet.read_rows()
    assert len(rows) == 1 and rows[0]["run_id"] == "run-1" and rows[0]["at"] == NOW
    lg.close()


def test_record_health_engine_error_row(tmp_path):
    fleet.record_health(tmp_path, None, None, None, gate="pre-push",
                        aramid_version="0.9.0", now=NOW, engine_error=True)
    (row,) = fleet.read_rows()
    assert row["engine_error"] is True and row["exit_code"] == 3
    assert row["criteria"] == {"no_skip_streak": False, "consumers_healthy": False,
                               "resolvers_ok": False, "no_self_inflicted_block": False,
                               "dep_audit_ran": None}


def test_record_health_fails_open_when_the_store_cannot_be_appended(tmp_path, capsys):
    fleet.health_path().mkdir(parents=True)          # a DIRECTORY where the file goes
    lg = Ledger(tmp_path / "l.db")
    fleet.record_health(tmp_path, None, lg, _result(), gate="pre-push",
                        aramid_version="0.9.0", now=NOW)   # must not raise
    err = capsys.readouterr().err
    assert err.startswith("aramid: fleet: health row not recorded (")
    lg.close()


def test_record_health_skips_the_row_over_budget(tmp_path, monkeypatch, capsys):
    ticks = iter([0.0, 5.0, 5.0])
    monkeypatch.setattr(fleet, "_monotonic", lambda: next(ticks))
    lg = Ledger(tmp_path / "l.db")
    fleet.record_health(tmp_path, None, lg, _result(), gate="pre-push",
                        aramid_version="0.9.0", now=NOW)
    assert fleet.read_rows() == []
    assert capsys.readouterr().err == \
        "aramid: fleet: health row not recorded (over the 2s budget)\n"
    lg.close()
