"""llm-review keeps why each provider call failed (operator decision
2026-10-30). From 2026-10-26 every drain degraded with "all providers
unavailable" and nothing said why: two models had retired, and each attempt
recorded a bare `error`.

  - every attempt (served, cascade, audit) and every refute carries the
    provider's `detail`, the one masked line of providers.base.failure_detail;
  - the outage note names each provider with the head of its detail (an HTTP
    status, an exit code) or its error code. Only the head: `status` reads
    the note for "giving up" and the no-work marks by substring, and a
    provider's own text must not be able to say either."""
import json
import subprocess
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from aramid import health
from aramid.consumers import llm_review
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.providers import base as providers_base
from aramid.providers.base import ProviderResponse
from aramid.queue import QueueItem

NOW = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)
LADDER = [
    {"tier": "cheap", "provider": "fake-a", "model": "ma", "effort": "", "min_score": 40},
    {"tier": "frontier", "provider": "fake-b", "model": "mb", "effort": "", "min_score": 80},
]
RETIRED = "HTTP 410: deepseek-v4-flash:0731 was retired on September 25, 2026."


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


def _repo(tmp_path):
    r = tmp_path / "r"
    (r / "src").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "src" / "auth.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", ".")
    _git(r, "commit", "-q", "-m", "c1")
    base_sha = _sha(r)
    (r / "src" / "auth.py").write_text(
        "def get_order(order_id):\n    return db.get(order_id)\n", encoding="utf-8")
    _git(r, "add", ".")
    _git(r, "commit", "-q", "-m", "c2")
    return r, base_sha, _sha(r)


def _finding(severity, line=2, evidence="return db.get(order_id)"):
    return json.dumps({"findings": [{
        "title": "IDOR", "owasp": "a01", "severity": severity, "file": "src/auth.py",
        "line": line, "evidence": evidence, "explanation": "e", "fix_hint": "h"}]})


class _Fake:
    def __init__(self, name, responses):
        self.NAME = name
        self.responses = list(responses)

    def available(self, cfg):
        return True

    def installed(self):
        return True

    def review(self, prompt, model, timeout_s, **kw):
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def _consume(tmp_path, monkeypatch, fakes, score, **autolearn):
    r, base_sha, head_sha = _repo(tmp_path)
    monkeypatch.setattr(providers_base, "PROVIDERS", {f.NAME: f for f in fakes})
    al = {"enabled": True, "armed": False, "audit_every": 0, **autolearn}
    cfg = SimpleNamespace(llm={"enabled": True, "max_items_per_drain": 3, "call_timeout_s": 240,
                               "packet_max_bytes": 120000, "provider_order": ["fake-a", "fake-b"],
                               "ladder": LADDER, "llm_block_armed": False, "autolearn": al},
                          ignore_paths=[".aramid/", "graph-out/", ".git/"])
    item = QueueItem(id="q1", base=base_sha, head=head_sha, score=score, reasons=("x",),
                     state="queued", created_at=NOW.isoformat(), updated_at=NOW.isoformat())
    led = Ledger(tmp_path / "l.db")
    try:
        return llm_review.consume(item, DrainContext(root=r, cfg=cfg, ledger=led,
                                                     clock=lambda: NOW.isoformat()))
    finally:
        led.close()


@pytest.fixture(autouse=True)
def _fresh():
    llm_review.begin_drain()
    yield


def test_each_attempt_keeps_its_detail(tmp_path, monkeypatch):
    a = _Fake("fake-a", [ProviderResponse(text=_finding("high"))])
    b = _Fake("fake-b", [ProviderResponse(text="", error=providers_base.ERR_ERROR,
                                          detail=RETIRED)])
    got = _consume(tmp_path, monkeypatch, [a, b], 90)
    assert [(x["provider"], x["detail"]) for x in got.extra["selection"]["attempts"]] == \
        [("fake-b", RETIRED), ("fake-a", "")]


def test_the_outage_note_names_each_provider_and_its_code(tmp_path, monkeypatch):
    b = _Fake("fake-b", [ProviderResponse(text="", error=providers_base.ERR_ERROR,
                                          detail=RETIRED)])
    a = _Fake("fake-a", [ProviderResponse(text="", error=providers_base.ERR_TIMEOUT)])
    got = _consume(tmp_path, monkeypatch, [a, b], 90)
    assert got.state == "degraded"
    assert got.note == "all providers unavailable -- fake-b: HTTP 410; fake-a: timeout"
    assert [x["detail"] for x in got.extra["selection"]["attempts"]] == [RETIRED, ""]


def test_a_provider_line_cannot_make_status_say_stood_down(tmp_path, monkeypatch):
    said = "exit 1: giving up: no mutants tested"
    b = _Fake("fake-b", [ProviderResponse(text="", error=providers_base.ERR_ERROR, detail=said)])
    a = _Fake("fake-a", [ProviderResponse(text="", error=providers_base.ERR_ERROR, detail=said)])
    got = _consume(tmp_path, monkeypatch, [a, b], 90)
    assert got.note == "all providers unavailable -- fake-b: exit 1; fake-a: exit 1"
    runs = {"llm-review": [(got.state, got.note, 1.0)]}
    assert health._stood_down(runs) == [] and health._no_work(runs) == []
    assert [f.name for f in health._degraded(runs)] == ["llm-review"]


def test_a_provider_that_raises_keeps_the_exception(tmp_path, monkeypatch):
    b = _Fake("fake-b", [RuntimeError("socket closed")])
    a = _Fake("fake-a", [ProviderResponse(text=_finding("high"))])
    got = _consume(tmp_path, monkeypatch, [a, b], 90)
    assert got.extra["selection"]["attempts"][0]["detail"] == "RuntimeError: socket closed"


def test_a_failed_cascade_review_keeps_its_detail(tmp_path, monkeypatch):
    a = _Fake("fake-a", [ProviderResponse(text=_finding("critical"))])
    b = _Fake("fake-b", [ProviderResponse(text="", error=providers_base.ERR_ERROR,
                                          detail="exit 1: login expired"),
                         ProviderResponse(text=json.dumps({"refuted": False, "reason": "real"}))])
    got = _consume(tmp_path, monkeypatch, [a, b], 45, armed=True)
    sel = got.extra["selection"]
    assert sel["cascade"]["triggered"] is True
    assert [(x["provider"], x["detail"]) for x in sel["attempts"]] == \
        [("fake-a", ""), ("fake-b", "exit 1: login expired")]


def test_a_failed_audit_keeps_its_detail(tmp_path, monkeypatch):
    a = _Fake("fake-a", [ProviderResponse(text=_finding("high"))])
    b = _Fake("fake-b", [ProviderResponse(text="", error=providers_base.ERR_ERROR,
                                          detail="HTTP 503: overloaded")])
    got = _consume(tmp_path, monkeypatch, [a, b], 45, audit_every=1, max_audits_per_drain=1)
    sel = got.extra["selection"]
    assert sel["audit"]["performed"] is False
    assert [(x["provider"], x["detail"]) for x in sel["attempts"]] == \
        [("fake-a", ""), ("fake-b", "HTTP 503: overloaded")]


def test_a_failed_refute_keeps_its_detail(tmp_path, monkeypatch):
    a = _Fake("fake-a", [ProviderResponse(text=_finding("critical"))])
    b = _Fake("fake-b", [ProviderResponse(text="", error=providers_base.ERR_QUOTA,
                                          detail="exit 1: usage limit reached")])
    got = _consume(tmp_path, monkeypatch, [a, b], 45)
    refutes = got.extra["selection"]["refutes"]
    assert [(x["outcome"], x["detail"]) for x in refutes] == \
        [("unavailable", "exit 1: usage limit reached")]
