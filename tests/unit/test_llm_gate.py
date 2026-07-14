from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import review
from aramid.ledger import Ledger
from aramid.models import (Event, EventType, Finding, Gate, Severity, Source,
                           Verdict)

NOW = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)


def _llm_finding(fid="f" * 64, severity=Severity.CRITICAL, confirmed=True,
                 evidence="return db.get(order_id)"):
    return Finding(id=fid, tool="llm-review", rule="llm/a01",
                   severity_raw=str(severity), severity=severity,
                   verdict=Verdict.WARN, file="src/auth.py", line=2,
                   message="IDOR: no ownership check (fix: verify owner)",
                   evidence=evidence, gate=Gate.ALL, source=Source.LLM,
                   confirmed=confirmed)


def _seed(led, finding):
    led.record_run("r0", NOW.isoformat(), "drain", set(), set(), [finding])


def _seed_raw(led, fid, payload):
    """Append a raw FINDING_DETECTED event so we can inject a MALFORMED rec
    (e.g. evidence/line stored as null) that a typed Finding can never carry.
    _materialize sets status=open when historical is falsy."""
    led.append(Event(EventType.FINDING_DETECTED, "r0", NOW.isoformat(),
                     finding_id=fid, payload=payload))


def _cfg(armed):
    return SimpleNamespace(llm={"llm_block_armed": armed})


def test_gate_blocks_confirmed_critical_when_armed(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _llm_finding())
        got = review.llm_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert len(got) == 1
    assert got[0].verdict is Verdict.BLOCK
    assert got[0].source is Source.LLM


def test_gate_warns_while_baking(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _llm_finding())
        got = review.llm_gate_findings(_cfg(False), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert got[0].verdict is Verdict.WARN


def test_gate_never_blocks_unconfirmed_or_noncritical(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _llm_finding(fid="a" * 64, confirmed=False))
        _seed(led, _llm_finding(fid="b" * 64, severity=Severity.HIGH, confirmed=True))
        got = review.llm_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert {f.verdict for f in got} == {Verdict.WARN}


def test_gate_empty_outside_pre_push_and_ignores_deterministic(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _llm_finding())
        det = Finding(id="c" * 64, tool="semgrep", rule="x", severity_raw="ERROR",
                      severity=Severity.HIGH, verdict=Verdict.WARN, file="a.py",
                      line=1, message="m", evidence="e", gate=Gate.ALL)
        _seed(led, det)
        assert review.llm_gate_findings(_cfg(True), led, Gate.PRE_COMMIT) == []
        got = review.llm_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert [f.tool for f in got] == ["llm-review"]


def test_gate_skips_overridden(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _llm_finding())
        led.append(Event(EventType.FINDING_OVERRIDDEN, "r1", NOW.isoformat(),
                         finding_id="f" * 64, payload={"reason": "accepted"}))
        got = review.llm_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert got == []


def test_auto_resolve_when_evidence_gone(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint",
                        lambda root, ref, f: "return safe_get(order_id, user)\n")
    try:
        _seed(led, _llm_finding())
        resolved = review.auto_resolve_llm(tmp_path, led, "r1", NOW.isoformat())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == ["f" * 64]
    assert state["f" * 64]["status"] == "fixed"


def test_auto_resolve_keeps_live_finding(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint",
                        lambda root, ref, f: "    return  db.get( order_id )\n")
    try:
        _seed(led, _llm_finding())          # ws-normalized quote still present
        resolved = review.auto_resolve_llm(tmp_path, led, "r1", NOW.isoformat())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["f" * 64]["status"] == "open"


def test_auto_resolve_missing_file_counts_as_gone(tmp_path, monkeypatch):
    def boom(root, ref, f):
        raise RuntimeError("path does not exist at HEAD")
    led = Ledger(tmp_path / "l.db")
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint", boom)
    try:
        _seed(led, _llm_finding())
        resolved = review.auto_resolve_llm(tmp_path, led, "r1", NOW.isoformat())
    finally:
        led.close()
    assert resolved == ["f" * 64]


def test_auto_resolve_skips_malformed_rec_without_raising(tmp_path, monkeypatch):
    """A rec with evidence stored as null (`.get('evidence','')` -> None, not
    the default) must be SKIPPED -- never crash re.sub, never silently resolve
    it away. It stays open for manual triage."""
    led = Ledger(tmp_path / "l.db")
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint",
                        lambda root, ref, f: "some other content\n")
    try:
        _seed_raw(led, "d" * 64, {"source": "llm", "file": "src/auth.py",
                                  "evidence": None, "line": 2,
                                  "severity": "critical", "confirmed": True})
        resolved = review.auto_resolve_llm(tmp_path, led, "r1", NOW.isoformat())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []                         # not resolved away
    assert state["d" * 64]["status"] == "open"    # left open for triage


def test_gate_skips_malformed_rec_but_blocks_wellformed(tmp_path):
    """A rec with line stored as null (`int(None)` -> TypeError) is SKIPPED,
    not crashed; a well-formed armed+confirmed+critical rec alongside it still
    yields exactly one BLOCK."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed_raw(led, "d" * 64, {"source": "llm", "file": "src/x.py",
                                  "evidence": "e", "line": None,
                                  "severity": "critical", "confirmed": True})
        _seed(led, _llm_finding())                # well-formed, blockable
        got = review.llm_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert [f.id for f in got] == ["f" * 64]      # malformed rec skipped
    assert got[0].verdict is Verdict.BLOCK


def test_pipeline_pre_push_integration(tmp_path, monkeypatch):
    """run_gate with no runners selected: findings come ONLY from the LLM
    ledger gate. Baking -> exit 0 (WARN); armed -> exit 1 (BLOCK); after the
    evidence disappears -> auto-resolve -> exit 0."""
    import subprocess
    from aramid import pipeline
    from aramid import config as config_mod

    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=r, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=r, check=True)
    (r / "src").mkdir()
    (r / "src" / "auth.py").write_text("def get_order(order_id):\n"
                                       "    return db.get(order_id)\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=r, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "c1"], cwd=r, check=True)

    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        _seed(led, _llm_finding())
        got = pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led)
        assert got.exit_code == 0                      # baking: WARN only
        assert any(f.tool == "llm-review" for f in got.findings)

        cfg.llm["llm_block_armed"] = True
        got = pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led)
        assert got.exit_code == 1                      # armed: BLOCK

        (r / "src" / "auth.py").write_text("def get_order(order_id, user):\n"
                                           "    return safe_get(order_id, user)\n",
                                           encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=r, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "fix"], cwd=r, check=True)
        got = pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led)
        assert got.exit_code == 0                      # auto-resolved
        assert not any(f.tool == "llm-review" for f in got.findings)
    finally:
        led.close()
