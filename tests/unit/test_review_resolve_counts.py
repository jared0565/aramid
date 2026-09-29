"""`auto_resolve_llm`'s bookkeeping: what it walked, what it skipped, and
whose findings it may look at.

FN-17's edit put the whole function in the drain's mutation scope, and its
stage-1 sweep (with test_llm_gate.py added) found five mutants no unit test
killed: the `considered` and `skipped` counters -- the evidence_gone yield
row and the skipped-record line are how a reader tells a resolver that
walked nothing from one that was never called -- and the source/status
filter, which is what keeps another producer's open finding away from the
evidence-gone rule. With `or` read as `and`, a semgrep finding whose quote
is not in the file would be resolved as fixed."""
from datetime import datetime, timezone

from aramid import review
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Source, Verdict

NOW = datetime(2026, 9, 29, 2, 0, 0, tzinfo=timezone.utc).isoformat()
_LIVE = "def get(order_id):\n    return safe_get(order_id, user)\n"


def _finding(fid, *, source=Source.LLM, tool="llm-review", evidence="return db.get(order_id)"):
    return Finding(id=fid, tool=tool, rule="llm/a01" if source is Source.LLM else "sqli",
                   severity_raw="high", severity=Severity.HIGH, verdict=Verdict.WARN,
                   file="src/auth.py", line=2, message="m", evidence=evidence,
                   gate=Gate.ALL, source=source, confirmed=None)


def _yield(led):
    rows = [e.payload for e in led.events()
            if e.type == EventType.RESOLVER_YIELD and e.payload.get("resolver") == "evidence_gone"]
    assert len(rows) == 1, rows
    return rows[0]


def test_only_open_llm_findings_are_walked_and_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint", lambda root, ref, rel: _LIVE)
    led = Ledger(tmp_path / "l.db")
    try:
        led.record_run("r0", NOW, "drain", set(), set(), [
            _finding("a" * 64),                                           # open, llm: walked
            _finding("b" * 64, source=Source.DETERMINISTIC, tool="semgrep"),  # another producer's
            _finding("c" * 64),                                           # llm, but fixed below
        ])
        led.append(Event(EventType.FINDING_RESOLVED, "r0", NOW, finding_id="c" * 64,
                         payload={"auto_resolved": "evidence_gone"}))
        resolved = review.auto_resolve_llm(tmp_path, led, "r1", NOW)
        state = led.open_findings()
        row = _yield(led)
    finally:
        led.close()
    assert resolved == ["a" * 64]
    assert state["b" * 64]["status"] == "open", "resolved another producer's finding"
    assert row["considered"] == 1 and row["resolved"] == 1


def test_a_clean_walk_says_nothing_and_a_malformed_record_is_counted_once(tmp_path, monkeypatch,
                                                                          capsys):
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint", lambda root, ref, rel: _LIVE)
    led = Ledger(tmp_path / "l.db")
    try:
        led.record_run("r0", NOW, "drain", set(), set(), [_finding("a" * 64)])
        review.auto_resolve_llm(tmp_path, led, "r1", NOW)
        assert capsys.readouterr().err == ""

        led.append(Event(EventType.FINDING_DETECTED, "r0", NOW, finding_id="d" * 64,
                         payload={"source": "llm", "file": "src/auth.py", "evidence": None,
                                  "line": 2, "severity": "high", "confirmed": None}))
        review.auto_resolve_llm(tmp_path, led, "r2", NOW)
        err = capsys.readouterr().err
    finally:
        led.close()
    assert err == "aramid: llm-resolve: skipped 1 malformed record\n"
