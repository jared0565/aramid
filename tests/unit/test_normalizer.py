from datetime import datetime, timezone
from pathlib import Path
from aramid.ledger import Ledger
from aramid.normalizer import RawFinding, normalize
from aramid.models import Gate, Severity, Source, Verdict

NOW = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)

def _classify(tool, rule, sev, gate):
    from aramid.models import Severity, Verdict
    return (Severity.HIGH, Verdict.BLOCK)

def test_two_identical_lines_get_distinct_ids(tmp_path, monkeypatch):
    from aramid import gitutil
    monkeypatch.setattr(gitutil, "read_for_fingerprint", lambda root, ref, f: "exec(x)\n")
    raws = [RawFinding("ruff","S102","high","a.py",1,"exec"),
            RawFinding("ruff","S102","high","a.py",1,"exec")]
    out = normalize(raws, tmp_path, lambda f: "HEAD", b"salt", Gate.PRE_COMMIT, _classify)
    assert len({f.id for f in out}) == 2   # occurrence index disambiguates

def test_secret_is_redacted_into_evidence(tmp_path, monkeypatch):
    from aramid import gitutil
    monkeypatch.setattr(gitutil, "read_for_fingerprint", lambda root, ref, f: "leak\n")
    raws = [RawFinding("gitleaks","aws","high","a.py",1,"leak",secret="AKIA12345678")]
    out = normalize(raws, tmp_path, lambda f: "HEAD", b"salt", Gate.PRE_COMMIT, _classify)
    assert "AKIA12345678" not in out[0].evidence and "…" in out[0].evidence

def test_secret_is_scrubbed_from_message_too(tmp_path, monkeypatch):
    from aramid import gitutil
    monkeypatch.setattr(gitutil, "read_for_fingerprint", lambda root, ref, f: "leak\n")
    secret = "AKIA12345678"
    raws = [RawFinding("gitleaks", "aws", "high", "a.py", 1,
                        f"found secret {secret} in context", secret=secret)]
    out = normalize(raws, tmp_path, lambda f: "HEAD", b"salt", Gate.PRE_COMMIT, _classify)
    assert secret not in out[0].message
    assert secret not in out[0].evidence
    assert "…" in out[0].message

def _write(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")

def test_llm_evidence_and_source_pass_through(tmp_path):
    _write(tmp_path, "src/app.py", "import os\neval(user_input)\n")
    raw = RawFinding(tool="llm-review", rule="llm/a01", severity_raw="critical",
                     file="src/app.py", line=2, message="RCE via eval",
                     evidence="eval(user_input)", source=Source.LLM, confirmed=True)
    # ref_for returning "" makes read_for_fingerprint read the worktree file
    findings = normalize([raw], tmp_path, lambda f: "", b"salt", Gate.ALL, _classify)
    f = findings[0]
    assert f.evidence == "eval(user_input)"   # verbatim quote, NOT the message
    assert f.source is Source.LLM
    assert f.confirmed is True

def test_default_finding_unconfirmed_deterministic(tmp_path):
    _write(tmp_path, "src/app.py", "x = 1\n")
    raw = RawFinding(tool="ruff", rule="S101", severity_raw="error",
                     file="src/app.py", line=1, message="assert used")
    f = normalize([raw], tmp_path, lambda f: "", b"salt", Gate.ALL, _classify)[0]
    assert f.evidence == "assert used"        # unchanged legacy path: message
    assert f.source is Source.DETERMINISTIC
    assert f.confirmed is False

def test_detect_payload_carries_source_and_confirmed(tmp_path):
    _write(tmp_path, "src/app.py", "eval(x)\n")
    raw = RawFinding(tool="llm-review", rule="llm/a01", severity_raw="critical",
                     file="src/app.py", line=1, message="RCE",
                     evidence="eval(x)", source=Source.LLM, confirmed=True)
    findings = normalize([raw], tmp_path, lambda f: "", b"salt", Gate.ALL, _classify)
    led = Ledger(tmp_path / "l.db")
    try:
        led.record_run("r1", NOW.isoformat(), "drain", set(), set(), findings)
        rec = led.open_findings()[findings[0].id]
        assert rec["source"] == "llm"
        assert rec["confirmed"] is True
        assert rec["evidence"] == "eval(x)"
    finally:
        led.close()

def test_pin_occurrence_collapses_duplicates(tmp_path, monkeypatch):
    from aramid import gitutil
    monkeypatch.setattr(gitutil, "read_for_fingerprint", lambda root, ref, f: "x = y[0]\n")
    raws = [RawFinding("mutation", "cmp-flip", "medium", "a.py", 1, "m1"),
            RawFinding("mutation", "cmp-flip", "medium", "a.py", 1, "m2")]
    out = normalize(raws, tmp_path, lambda f: "HEAD", b"salt", Gate.ALL,
                    _classify, pin_occurrence=True)
    assert len({f.id for f in out}) == 1   # one finding per (tool,rule,file,line-content)

def test_pin_occurrence_makes_ids_subset_stable(tmp_path, monkeypatch):
    # THE M5 drift scenario: budget truncation changes batch membership; the
    # nth duplicate's id must not depend on who else is in the batch.
    from aramid import gitutil
    monkeypatch.setattr(gitutil, "read_for_fingerprint", lambda root, ref, f: "x = y[0]\n")
    ra = RawFinding("fuzz", "crash-indexerror", "medium", "a.py", 1, "c1")
    rb = RawFinding("fuzz", "crash-indexerror", "medium", "a.py", 1, "c2")
    full = normalize([ra, rb], tmp_path, lambda f: "HEAD", b"salt", Gate.ALL,
                     _classify, pin_occurrence=True)
    alone = normalize([rb], tmp_path, lambda f: "HEAD", b"salt", Gate.ALL,
                      _classify, pin_occurrence=True)
    assert full[1].id == alone[0].id
