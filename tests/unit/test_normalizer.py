from pathlib import Path
from aramid.normalizer import RawFinding, normalize
from aramid.models import Gate, Verdict

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
