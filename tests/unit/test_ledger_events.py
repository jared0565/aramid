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


def test_record_run_selected_tools_recorded_when_passed(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [],
                   selected_tools={"ruff", "gitleaks"})
    run_started = [e for e in led.events() if e.type is EventType.RUN_STARTED][0]
    assert run_started.payload["selected"] == ["gitleaks", "ruff"]
    led.close()


def test_record_run_selected_key_absent_when_not_passed(tmp_path):
    """T-8 section 8: 'key absent = no information' is a live state -- drain
    and init never pass selected_tools. payload.get("selected", []) would
    collapse "unknown" into "nothing selected"; assert the KEY is missing,
    not merely empty."""
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t1", "drain", set(), set(), [])
    run_started = [e for e in led.events() if e.type is EventType.RUN_STARTED][0]
    assert "selected" not in run_started.payload
    led.close()


# ------------------------------------------- RUN_FINISHED says WHEN it finished ---
# Interop round 130 s3, from a consumer reading its own gate's ledger: every
# event in a run carries the run's `at`, so `run_finished` could not tell a
# ten-minute gate from a one-second one, and the consumer had to establish the
# wall clock from a push log's mtimes. `at` stays the run's identity stamp;
# `finished_at` is the clock read when the run's findings were recorded.

def test_run_finished_carries_finished_at_when_supplied(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "2026-08-29T10:00:00+00:00", "pre-push", {"ruff"}, {"a.py"}, [],
                   finished_at="2026-08-29T10:09:30+00:00")
    fin = [e for e in led.events() if e.type is EventType.RUN_FINISHED]
    led.close()
    assert fin[-1].payload["finished_at"] == "2026-08-29T10:09:30+00:00"
    assert fin[-1].at == "2026-08-29T10:00:00+00:00", "`at` stays the run's identity stamp"


def test_run_finished_omits_finished_at_when_the_caller_cannot_supply_it(tmp_path):
    """Absent, never a copy of `at`: a reader must be able to tell 'too old
    to have recorded it' from 'finished in zero seconds'."""
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "2026-08-29T10:00:00+00:00", "pre-push", {"ruff"}, {"a.py"}, [])
    fin = [e for e in led.events() if e.type is EventType.RUN_FINISHED]
    led.close()
    assert "finished_at" not in fin[-1].payload
