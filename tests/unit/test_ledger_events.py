from aramid.ledger import Ledger
from aramid.models import Event, EventType

def test_append_and_read_roundtrip(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.append(Event(EventType.RUN_STARTED, "run1", "2026-07-12T00:00:00Z",
                     payload={"gate": "pre-commit"}))
    got = led.events()
    assert len(got) == 1 and got[0].run_id == "run1"
    assert got[0].payload["gate"] == "pre-commit"
    led.close()

def test_detect_payload_carries_refuted_flag():
    from aramid.ledger import _detect_payload
    from aramid.models import Finding, Gate, Severity, Source, Verdict
    f = Finding(id="x", tool="llm-review", rule="llm/a01", severity_raw="high",
                severity=Severity.HIGH, verdict=Verdict.WARN, file="a.py",
                line=1, message="m", evidence="e", gate=Gate.ALL,
                source=Source.LLM, refuted=True)
    assert _detect_payload(f)["refuted"] is True


def test_refuted_flag_materializes_through_open_findings(tmp_path):
    """T3 gap: the refuted payload key must survive _materialize into the
    open_findings snapshot (autolearn's rollup reads it from there)."""
    led = Ledger(tmp_path / "l.db")
    led.append(Event(EventType.FINDING_DETECTED, "r1", "2026-07-19T00:00:00Z",
                     finding_id="f-refuted",
                     payload={"tool": "llm-review", "refuted": True}))
    led.append(Event(EventType.FINDING_DETECTED, "r1", "2026-07-19T00:00:00Z",
                     finding_id="f-plain",
                     payload={"tool": "llm-review"}))
    state = led.open_findings()
    led.close()
    assert state["f-refuted"]["refuted"] is True
    assert state["f-plain"].get("refuted", False) is False


def test_finding_unreachable_transitions_status(tmp_path):
    from aramid.models import Finding, Gate, Severity, Verdict
    led = Ledger(tmp_path / "l.db")
    f = Finding("id1", "ruff", "F401", "medium", Severity.MEDIUM, Verdict.WARN,
                "a.py", 1, "m", "e", Gate.PRE_PUSH)
    led.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [f])
    led.append(Event(EventType.FINDING_UNREACHABLE, "r2", "t2",
                     finding_id="id1", payload={"reason": "ruff no longer selected"}))
    rec = led.open_findings()["id1"]
    assert rec["status"] == "unreachable"
    assert rec["reason"] == "ruff no longer selected"
    led.close()


def test_finding_unreachable_for_unknown_id_is_ignored_no_phantom_entry(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.append(Event(EventType.FINDING_UNREACHABLE, "r1", "t1",
                     finding_id="ghost-id", payload={"reason": "x"}))
    assert led.open_findings() == {}
    led.close()
