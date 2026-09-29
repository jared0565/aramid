"""FN-17: a git that did not answer is not an unreadable file.

Three review paths catch whatever reading a file raises and carry on under a
policy meant for a file git DID answer about: `auto_resolve_llm` reads it as
gone and resolves the finding, `verify_findings` rejects the candidate as a
hallucination, `build_packet` drops the file and reviews the rest. A
`gitutil.GitTimeout` is none of those -- git said nothing -- so it goes up:
the gate fails loudly, the drain's item stays queued for the next drain, and
the first timeout is the only one paid (every later read would hang too)."""
import subprocess
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from aramid import gitutil, review
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Source, Verdict
from aramid.queue import QueueItem
from aramid.review import Packet

NOW = datetime(2026, 9, 29, 1, 0, 0, tzinfo=timezone.utc)


def _timeout(calls):
    def read(root, ref, rel):
        calls.append(rel)
        raise gitutil.GitTimeout("git show timed out after 600 s and was killed")
    return read


def _llm_finding(fid, file):
    return Finding(id=fid, tool="llm-review", rule="llm/a01", severity_raw="critical",
                   severity=Severity.CRITICAL, verdict=Verdict.WARN, file=file, line=2,
                   message="IDOR: no ownership check (fix: verify owner)",
                   evidence="return db.get(order_id)", gate=Gate.ALL, source=Source.LLM,
                   confirmed=True)


def test_a_git_timeout_resolves_no_llm_finding(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint", _timeout(calls))
    led = Ledger(tmp_path / "l.db")
    try:
        led.record_run("r0", NOW.isoformat(), "drain", set(), set(),
                       [_llm_finding("a" * 64, "src/a.py"), _llm_finding("b" * 64, "src/b.py")])
        with pytest.raises(gitutil.GitTimeout):
            review.auto_resolve_llm(tmp_path, led, "r1", NOW.isoformat())
        state = led.open_findings()
    finally:
        led.close()
    assert state["a" * 64]["status"] == "open"
    assert state["b" * 64]["status"] == "open"
    assert len(calls) == 1, "a second read after git timed out"


def _cand(file):
    return {"title": "IDOR on order endpoint", "owasp": "a01", "severity": "critical",
            "file": file, "line": 2, "evidence": "return db.get(order_id)",
            "explanation": "no ownership check", "fix_hint": "verify owner"}


def test_a_git_timeout_rejects_no_candidate_as_a_hallucination(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint", _timeout(calls))
    body = "def get_order(order_id):\n    return db.get(order_id)\n"
    pkt = Packet(text=f"stuff\n{body}\nmore", files=["src/a.py", "src/b.py"], truncated=False)

    with pytest.raises(gitutil.GitTimeout):
        review.verify_findings([_cand("src/a.py"), _cand("src/b.py")], pkt, tmp_path, "headsha")
    assert calls == ["src/a.py"]


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


def test_a_git_timeout_drops_no_file_from_the_packet(tmp_path, monkeypatch):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    for name in ("a.py", "b.py"):
        (r / "src" / name).write_text("def login(u):\n    return True\n", encoding="utf-8")
    _git(r, "add", "src")
    _git(r, "commit", "-m", "c1")
    base = _sha(r)
    for name in ("a.py", "b.py"):
        (r / "src" / name).write_text("def login(u):\n    return u.ok\n", encoding="utf-8")
    _git(r, "commit", "-am", "c2")
    item = QueueItem(id="q1", base=base, head=_sha(r), score=80, reasons=("risky",),
                     state="queued", created_at=NOW.isoformat(), updated_at=NOW.isoformat())
    cfg = SimpleNamespace(llm={"packet_max_bytes": 120000}, ignore_paths=[".aramid/"])
    calls = []
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint", _timeout(calls))

    with pytest.raises(gitutil.GitTimeout):
        review.build_packet(r, cfg, item)
    assert calls == ["src/a.py"]
