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
