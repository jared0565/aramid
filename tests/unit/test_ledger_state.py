import uuid

from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Severity, Verdict, Gate

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

def test_out_of_tool_scope_absence_does_not_resolve(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])   # ruff finding on a.py
    # next run scans a.py but only with semgrep in scope; the ruff finding must NOT be marked fixed
    led.record_run("r2","t","pre-push",{"semgrep"},{"a.py"},[])
    assert led.open_findings()["id1"]["status"] == "open"

def test_override_reason_materializes(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t", "pre-push", {"ruff"}, {"a.py"}, [_f("id1")])
    led.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, "t2",
                     finding_id="id1", payload={"reason": "vendored test fixture"}))
    rec = led.open_findings()["id1"]
    assert rec["status"] == "overridden"
    assert rec["reason"] == "vendored test fixture"

def test_override_without_reason_key_materializes_empty(tmp_path):
    # Old events appended before --reason was mandatory may lack the key.
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t", "pre-push", {"ruff"}, {"a.py"}, [_f("id1")])
    led.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, "t2",
                     finding_id="id1", payload={}))
    assert led.open_findings()["id1"]["reason"] == ""

def test_redetect_after_override_clears_reason(tmp_path):
    # A re-detect rebuilds state from the detect payload -- the finding is
    # open again and the old override (and its reason) is history. NB: this
    # uses a direct FINDING_DETECTED append (the init history-scan shape);
    # record_run deliberately never re-detects an "overridden" finding
    # (only "fixed" ones), so this is the only reachable re-detect path.
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t", "pre-push", {"ruff"}, {"a.py"}, [_f("id1")])
    led.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, "t2",
                     finding_id="id1", payload={"reason": "was overridden"}))
    led.append(Event(EventType.FINDING_DETECTED, "r2", "t3", finding_id="id1",
                     payload={"tool": "ruff", "rule": "S102", "file": "a.py"}))
    rec = led.open_findings()["id1"]
    assert rec["status"] == "open"
    assert "reason" not in rec

def test_new_ids_returned_for_ratchet(tmp_path):
    led = Ledger(tmp_path / "l.db")
    new = led.record_run("r1","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])
    assert new == ["id1"]
    again = led.record_run("r2","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])
    assert again == []   # already seen
