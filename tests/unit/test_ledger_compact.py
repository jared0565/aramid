from aramid.ledger import Ledger
from aramid.models import Finding, Severity, Verdict, Gate

def _f(fid, tool="ruff", file="a.py"):
    return Finding(fid, tool, "S102", "high", Severity.HIGH, Verdict.WARN,
                   file, 1, "m", "e", Gate.PRE_PUSH)

def test_compact_preserves_open_findings_and_drops_rows(tmp_path):
    led = Ledger(tmp_path / "l.db")
    # 100 redundant detect/resolve cycles: id1 detected then resolved each cycle,
    # id2 stays continuously open (present) across every cycle.
    for i in range(100):
        led.record_run(f"r{i}a", "t", "pre-push", {"ruff"}, {"a.py"},
                        [_f("id1"), _f("id2")])
        led.record_run(f"r{i}b", "t", "pre-push", {"ruff"}, {"a.py"},
                        [_f("id2")])  # id1 absent this run -> resolved

    before = led.open_findings()
    assert before["id1"]["status"] == "fixed"
    assert before["id2"]["status"] == "open"
    rows_before = len(led.events())

    removed = led.compact()

    rows_after = len(led.events())
    after = led.open_findings()

    assert after == before
    assert after["id1"]["status"] == "fixed"
    assert after["id2"]["status"] == "open"
    assert rows_after < rows_before
    assert removed == rows_before - rows_after
    led.close()
