from aramid.ledger import Ledger
from aramid.models import Finding, Severity, Verdict, Gate

def _f(fid, tool="ruff", file="a.py"):
    return Finding(fid, tool, "S102", "high", Severity.HIGH, Verdict.WARN,
                   file, 1, "m", "e", Gate.PRE_PUSH)

def test_absent_finding_resolved_only_when_in_scope(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])
    assert led.open_findings()["id1"]["status"] == "open"
    # next run scopes a.py+ruff, finding gone -> resolved
    led.record_run("r2","t",{"ruff"} and "pre-push",{"ruff"},{"a.py"},[])
    assert led.open_findings()["id1"]["status"] == "fixed"

def test_out_of_scope_absence_does_not_resolve(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1","t","pre-push",{"ruff"},{"a.py"},[_f("id1", file="a.py")])
    led.record_run("r2","t","pre-push",{"ruff"},{"b.py"},[])   # a.py not scanned
    assert led.open_findings()["id1"]["status"] == "open"

def test_new_ids_returned_for_ratchet(tmp_path):
    led = Ledger(tmp_path / "l.db")
    new = led.record_run("r1","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])
    assert new == ["id1"]
    again = led.record_run("r2","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])
    assert again == []   # already seen
