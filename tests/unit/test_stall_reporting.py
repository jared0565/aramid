"""A stalled tool reads as stalled on every surface that reports a timeout."""
from aramid import fleet, health, pipeline
from aramid.runners.base import RunnerResult, ToolState


def test_degraded_reason_names_a_stall_not_a_timeout():
    rs = [RunnerResult("pip-audit", ToolState.TIMEOUT, duration_s=312.4, stalled_s=301.0),
          RunnerResult("gitleaks", ToolState.TIMEOUT, duration_s=120.0)]
    assert pipeline._degraded_reasons(rs) == {
        "pip-audit": "stalled: no CPU or output for 301 s (killed after 312 s)",
        "gitleaks": "timeout after 120 s",
    }


def test_stalled_tools_come_from_the_field_not_the_text():
    rs = [RunnerResult("pip-audit", ToolState.TIMEOUT, duration_s=312.4, stalled_s=301.0),
          RunnerResult("ruff", ToolState.TIMEOUT, stderr="stalled: (just a message)",
                       duration_s=9.0),
          RunnerResult("semgrep", ToolState.OK)]
    assert pipeline._stalled_tools(rs) == ("pip-audit",)


def test_run_row_records_stalled(tmp_path):
    from aramid.ledger import EventType, Ledger
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        ledger.record_run("r1", "2026-10-06T00:00:00+00:00", "pre-push", set(), set(), [],
                          degraded={"pip-audit": "stalled: ..."}, stalled=["pip-audit"])
        fin = [e for e in ledger.events() if e.type is EventType.RUN_FINISHED][-1]
        assert fin.payload["stalled"] == ["pip-audit"]
    finally:
        ledger.close()


def test_status_last_run_line_names_the_stalled_tool(tmp_path):
    from aramid.commands import status
    from aramid.ledger import Ledger
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        ledger.record_run("r1", "2026-10-06T00:00:00+00:00", "pre-push", set(), set(), [],
                          finished_at="2026-10-06T00:05:00+00:00",
                          degraded={"pip-audit": "stalled: ..."}, stalled=["pip-audit"])
        assert status._last_run_line(ledger) == (
            "last run: 2026-10-06T00:00:00+00:00 (pre-push run r1, 0 blocking, took 300s,"
            " stalled: pip-audit)")
    finally:
        ledger.close()


def test_fleet_red_description_marks_the_stalled_tool():
    # Every other criterion green: _red_detail reports each one not True.
    row = {"criteria": {**{k: True for k in health.CRITERIA}, "no_self_inflicted_block": False},
           "evidence": {"bad_tools": ["gitleaks", "pip-audit"], "stalled_tools": ["pip-audit"]}}
    assert fleet._red_detail(row) == "no_self_inflicted_block: gitleaks, pip-audit (stalled)"
