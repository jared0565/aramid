"""The gate's own output is the cheapest delivery surface: a count, never a
`shown` event. The JSON key is always present so a consumer can tell 'none'
from 'unknown' from 'too old to say'."""
import json

from aramid import reporter
from aramid.ledger import Ledger
from aramid.pipeline import GateResult


def _result(**kw):
    base = dict(exit_code=0, findings=[], degraded=[], new_ids=[], stale_overrides=[],
                run_id="r1")
    base.update(kw)
    return GateResult(**base)


def test_trailer_is_the_last_console_line(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    out = reporter.render_console(_result(fleet_notices_pending=2, fleet_trailer=True), ledger)
    assert out.splitlines()[-1] == "aramid: 2 fleet notice(s) pending -- see `aramid notices`"
    ledger.close()


def test_no_trailer_when_zero_unknown_or_switched_off(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    for kw in ({"fleet_notices_pending": 0, "fleet_trailer": True},
               {"fleet_notices_pending": None, "fleet_trailer": True},
               {"fleet_notices_pending": 3, "fleet_trailer": False},
               {}):
        assert "fleet notice" not in reporter.render_console(_result(**kw), ledger)
    ledger.close()


def test_json_key_is_always_present():
    assert json.loads(reporter.render_json(_result()))["fleet_notices_pending"] is None
    assert json.loads(reporter.render_json(_result(fleet_notices_pending=0)))[
        "fleet_notices_pending"] == 0
    assert json.loads(reporter.render_json(_result(fleet_notices_pending=2, fleet_trailer=False)))[
        "fleet_notices_pending"] == 2
