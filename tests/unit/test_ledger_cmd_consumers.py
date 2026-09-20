"""`aramid ledger consumers` at unit scope: the drain's consumer runs, newest
first, with --consumer / --last / --json. Channel round 243 item 3
(2026-09-20): `ledger filter` reads findings only, so a degraded consumer
row -- an EVENT -- could only be seen in `status` or by opening ledger.db by
hand. Unit scope, not integration: the latent-mutant ratchet and the drain's
stage 1 both measure tests/unit alone, and the first landing of these pins
under tests/integration read as eight latent mutants on the ubuntu/3.12 leg
(CI run 35511911311)."""
import json
from pathlib import Path

from aramid import cli
from aramid.commands import ledger_cmd
from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _ledger(root) -> Ledger:
    return Ledger(root / ".aramid" / "ledger.db")


def _consumer_row(ledger, run_id, at, consumer, state, note, duration=1.0, item="q1"):
    ledger.append(Event(EventType.CONSUMER_RUN_FINISHED, run_id, at,
                        payload={"consumer": consumer, "item_id": item, "state": state,
                                 "duration_s": duration, "cost": 0.0, "finding_count": 0,
                                 "note": note}))


def _three_runs(root):
    ledger = _ledger(root)
    _consumer_row(ledger, "d1", "2026-09-19T18:11:18+00:00", "js_mutation", "degraded",
                  "baseline failing (last seen @ f34e92e7fd00)", 379.196)
    _consumer_row(ledger, "d2", "2026-09-19T22:13:56+00:00", "js_mutation", "degraded",
                  "baseline failing (last seen @ dc668ab8abf0)", 434.338)
    _consumer_row(ledger, "d3", "2026-09-19T22:13:58+00:00", "fuzz", "ok",
                  "250 cases / 5 functions", 12.5)
    ledger.close()


def test_consumers_lists_runs_newest_first_with_state_duration_and_note(tmp_path, capsys):
    root: Path = tmp_path
    _three_runs(root)

    rc = ledger_cmd.cmd_ledger_consumers(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert out.splitlines() == [
        "[ok] 2026-09-19T22:13:58+00:00 fuzz 12.5s item q1 -- 250 cases / 5 functions",
        "[degraded] 2026-09-19T22:13:56+00:00 js_mutation 434.3s item q1"
        " -- baseline failing (last seen @ dc668ab8abf0)",
        "[degraded] 2026-09-19T18:11:18+00:00 js_mutation 379.2s item q1"
        " -- baseline failing (last seen @ f34e92e7fd00)",
    ]


def test_consumers_filters_by_name_and_caps_with_last(tmp_path, capsys):
    root: Path = tmp_path
    _three_runs(root)

    rc = ledger_cmd.cmd_ledger_consumers(root, consumer="js_mutation", last=1)
    out = capsys.readouterr().out

    assert rc == 0
    assert out.splitlines() == [
        "[degraded] 2026-09-19T22:13:56+00:00 js_mutation 434.3s item q1"
        " -- baseline failing (last seen @ dc668ab8abf0)"]


def test_consumers_last_of_zero_or_less_keeps_nothing(tmp_path, capsys):
    """`--last 0` is an empty answer, not "one row"; a negative cap is the
    same answer rather than a Python slice from the wrong end."""
    root: Path = tmp_path
    _three_runs(root)

    for cap in (0, -1):
        rc = ledger_cmd.cmd_ledger_consumers(root, last=cap)
        assert rc == 0
        assert capsys.readouterr().out.strip() == "aramid: ledger consumers: no consumer runs"


def test_consumers_json_emits_every_payload_field_newest_first(tmp_path, capsys):
    root: Path = tmp_path
    _three_runs(root)

    rc = ledger_cmd.cmd_ledger_consumers(root, as_json=True)
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert rc == 0
    assert out == json.dumps(payload, indent=2) + "\n", "the two-space form filter emits"
    assert [r["run_id"] for r in payload] == ["d3", "d2", "d1"]
    assert payload[1] == {
        "at": "2026-09-19T22:13:56+00:00", "run_id": "d2", "consumer": "js_mutation",
        "item_id": "q1", "state": "degraded", "duration_s": 434.338, "cost": 0.0,
        "finding_count": 0, "note": "baseline failing (last seen @ dc668ab8abf0)"}


def test_consumers_on_an_empty_ledger_reports_nothing_without_error(tmp_path, capsys):
    rc = ledger_cmd.cmd_ledger_consumers(tmp_path)
    out = capsys.readouterr().out

    assert rc == 0
    assert out.strip() == "aramid: ledger consumers: no consumer runs"


def test_consumers_json_with_no_rows_emits_an_empty_array(tmp_path, capsys):
    """Prose is not parseable; an empty result stays valid JSON, as `filter`
    already promises."""
    rc = ledger_cmd.cmd_ledger_consumers(tmp_path, as_json=True)

    assert rc == 0
    assert json.loads(capsys.readouterr().out) == []


def test_consumers_is_wired_through_the_cli(tmp_path, monkeypatch, capsys):
    root: Path = tmp_path
    _three_runs(root)
    monkeypatch.chdir(root)

    rc = cli.main(["ledger", "consumers", "--consumer", "js_mutation", "--last", "1", "--json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert [r["run_id"] for r in payload] == ["d2"]
