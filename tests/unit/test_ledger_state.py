import uuid

from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Severity, Verdict, Gate

def _f(fid, tool="ruff", file="a.py", historical=False):
    return Finding(fid, tool, "S102", "high", Severity.HIGH, Verdict.WARN,
                   file, 1, "m", "e", Gate.PRE_PUSH, historical=historical)

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

def test_not_a_secret_materializes_from_historical(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t", "historical-scan", {"gitleaks"}, set(),
                   [_f("hist1", tool="gitleaks", historical=True)])
    assert led.open_findings()["hist1"]["status"] == "historical"
    led.append(Event(EventType.FINDING_NOT_A_SECRET, uuid.uuid4().hex, "t2",
                     finding_id="hist1", payload={"reason": "public shopify client id"}))
    rec = led.open_findings()["hist1"]
    assert rec["status"] == "not_a_secret"
    assert rec["reason"] == "public shopify client id"

def test_not_a_secret_without_prior_detect_is_ignored(tmp_path):
    # matches the `if e.finding_id in state` guard: no detect ever happened
    # for "ghost", so the event must be a no-op -- no KeyError, no phantom
    # entry conjured into open_findings().
    led = Ledger(tmp_path / "l.db")
    led.append(Event(EventType.FINDING_NOT_A_SECRET, uuid.uuid4().hex, "t1",
                     finding_id="ghost", payload={"reason": "no prior detect"}))
    state = led.open_findings()
    assert "ghost" not in state

def test_new_ids_returned_for_ratchet(tmp_path):
    led = Ledger(tmp_path / "l.db")
    new = led.record_run("r1","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])
    assert new == ["id1"]
    again = led.record_run("r2","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])
    assert again == []   # already seen


def test_unreachable_finding_reopens_when_re_detected(tmp_path):
    led = Ledger(tmp_path / "l.db")
    f = _f("id1", tool="ruff")
    led.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [f])
    led.append(Event(EventType.FINDING_UNREACHABLE, "r2", "t2",
                     finding_id="id1", payload={"reason": "ruff not selected"}))
    assert led.open_findings()["id1"]["status"] == "unreachable"

    led.record_run("r3", "t3", "pre-push", {"ruff"}, {"a.py"}, [f])  # tool returns
    assert led.open_findings()["id1"]["status"] == "open"
    led.close()


def test_overridden_rotated_not_a_secret_do_not_reopen_on_redetect(tmp_path):
    """Mirror of the resurrection test above -- spec section 10 item 3.
    Only "fixed"/"unreachable" re-detect; the three human-assertion
    statuses must stay sticky."""
    for i, status_event in enumerate((
        EventType.FINDING_OVERRIDDEN,
        EventType.FINDING_ROTATED,
        EventType.FINDING_NOT_A_SECRET,
    )):
        led = Ledger(tmp_path / f"l-{i}.db")
        historical = status_event != EventType.FINDING_OVERRIDDEN
        f = _f("id1", tool="gitleaks", historical=historical)
        led.record_run("r1", "t1", "historical-scan" if historical else "pre-push",
                       {"gitleaks"}, set() if historical else {"a.py"}, [f])
        led.append(Event(status_event, "r2", "t2", finding_id="id1", payload={"reason": "x"}))
        before = led.open_findings()["id1"]["status"]

        led.record_run("r3", "t3", "pre-push", {"gitleaks"}, {"a.py"}, [f])

        assert led.open_findings()["id1"]["status"] == before, status_event
        led.close()
