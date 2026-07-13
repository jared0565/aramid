import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid.consumers import llm_review
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Source
from aramid.providers import base as providers_base
from aramid.providers.base import ProviderResponse
from aramid.queue import QueueItem

NOW = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)
FILE_BODY = "def get_order(order_id):\n    return db.get(order_id)\n"
EVIDENCE = "return db.get(order_id)"


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path) -> tuple[Path, str, str]:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "src" / "auth.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "."); _git(r, "commit", "-m", "c1")
    base_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, check=True,
                              capture_output=True, text=True).stdout.strip()
    (r / "src" / "auth.py").write_text(FILE_BODY, encoding="utf-8")
    _git(r, "add", "."); _git(r, "commit", "-m", "c2")
    head_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, check=True,
                              capture_output=True, text=True).stdout.strip()
    return r, base_sha, head_sha


def _item(base, head):
    return QueueItem(id="q1", base=base, head=head, score=80, reasons=("risky",),
                     state="queued", created_at=NOW.isoformat(), updated_at=NOW.isoformat())


def _cfg(**over):
    llm = {"enabled": True, "max_items_per_drain": 3, "call_timeout_s": 240,
           "packet_max_bytes": 120000, "provider_order": ["fake-a", "fake-b"],
           "model_claude": "sonnet", "model_codex": "", "model_openrouter": "m",
           "llm_block_armed": False, **over}
    return SimpleNamespace(llm=llm, ignore_paths=[".aramid/", "graph-out/", ".git/"])


def _finding_json(severity="high"):
    return json.dumps({"findings": [{
        "title": "IDOR", "owasp": "a01", "severity": severity,
        "file": "src/auth.py", "line": 2, "evidence": EVIDENCE,
        "explanation": "no ownership check", "fix_hint": "verify owner"}]})


class _Fake:
    """Scripted provider: pops the next ProviderResponse per call."""
    def __init__(self, name, responses):
        self.NAME = name
        self.responses = list(responses)
        self.calls = []

    def available(self, cfg):
        return True

    def installed(self):
        return True

    def review(self, prompt, model, timeout_s, **kw):
        self.calls.append(prompt)
        return self.responses.pop(0)


def _ctx(r, led):
    return DrainContext(root=r, cfg=_cfg(), ledger=led, clock=lambda: NOW.isoformat())


@pytest.fixture(autouse=True)
def _fresh():
    llm_review.begin_drain()
    yield


def _wire(monkeypatch, *fakes):
    monkeypatch.setattr(providers_base, "PROVIDERS", {f.NAME: f for f in fakes})


def test_happy_path_high_finding_no_refute(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"),
                                          tokens_in=100, tokens_out=20)])
    _wire(monkeypatch, a)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item(base_sha, head_sha), _ctx(r, led))
    finally:
        led.close()
    assert got.state == "ok"
    raw = got.findings[0]
    assert raw.tool == "llm-review" and raw.rule == "llm/a01"
    assert raw.source is Source.LLM and raw.confirmed is False
    assert raw.evidence == EVIDENCE and raw.line == 2
    assert len(a.calls) == 1                              # no refute for high
    assert "provider=fake-a" in got.note and "refutes=0" in got.note


def test_critical_refute_survivor_cross_provider(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [ProviderResponse(
        text=json.dumps({"refuted": False, "reason": "no guard anywhere"}))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item(base_sha, head_sha), _ctx(r, led))
    finally:
        led.close()
    raw = got.findings[0]
    assert raw.confirmed is True and raw.severity_raw == "critical"
    assert len(b.calls) == 1 and "disprove" in b.calls[0]   # refute went cross-provider


def test_critical_refuted_demotes(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [ProviderResponse(
        text=json.dumps({"refuted": True, "reason": "guarded upstream"}))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item(base_sha, head_sha), _ctx(r, led))
    finally:
        led.close()
    raw = got.findings[0]
    assert raw.confirmed is False and raw.severity_raw == "high"


def test_refuter_malformed_treated_as_refuted(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [ProviderResponse(text="cannot decide, sorry")])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item(base_sha, head_sha), _ctx(r, led))
    finally:
        led.close()
    assert got.findings[0].confirmed is False             # ambiguity -> refuted


def test_budget_exhausted_degrades(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json()),
                         ProviderResponse(text=_finding_json())])
    _wire(monkeypatch, a)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(max_items_per_drain=1), ledger=led,
                       clock=lambda: NOW.isoformat())
    try:
        assert llm_review.consume(_item(base_sha, head_sha), ctx).state == "ok"
        second = llm_review.consume(_item(base_sha, head_sha), ctx)
    finally:
        led.close()
    assert second.state == "degraded" and "budget exhausted" in second.note
    llm_review.begin_drain()                              # reset -> works again
    assert len(a.responses) == 1                          # only one review spent


def test_malformed_review_degrades_then_gives_up_after_three(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text="not json at all")])
    _wire(monkeypatch, a)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item(base_sha, head_sha), _ctx(r, led))
        assert got.state == "degraded" and got.note.startswith("malformed response")
        for i in range(3):     # simulate three drain-recorded malformed runs
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}", NOW.isoformat(),
                             payload={"consumer": "llm-review", "item_id": "q1",
                                      "state": "degraded",
                                      "note": "malformed response from fake-a"}))
        llm_review.begin_drain()
        got2 = llm_review.consume(_item(base_sha, head_sha), _ctx(r, led))
    finally:
        led.close()
    assert got2.state == "ok" and "giving up" in got2.note
    assert a.calls and len(a.calls) == 1                  # gave up BEFORE calling again


def test_dedupe_skips_known_open_finding_no_refute_spend(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical")),
                         ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [ProviderResponse(
        text=json.dumps({"refuted": False, "reason": "real"}))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        ctx = _ctx(r, led)
        first = llm_review.consume(_item(base_sha, head_sha), ctx)
        # record like the drain would, so the fingerprint is OPEN in the ledger
        from aramid import policy
        from aramid.models import Gate
        from aramid.normalizer import normalize
        import functools
        from aramid import redact
        salt = redact.load_or_create_salt(r / ".aramid")
        cfg_real = SimpleNamespace(llm=_cfg().llm, ignore_paths=[".git/"],
                                   semgrep_block_armed=False, block_rules={},
                                   pack={"pack_block_armed": True})
        findings = normalize(first.findings, r, lambda f: head_sha, salt, Gate.ALL,
                             functools.partial(policy.classify, cfg=cfg_real))
        led.record_run("r1", NOW.isoformat(), "drain", set(), set(), findings)
        llm_review.begin_drain()
        second = llm_review.consume(_item(base_sha, head_sha), ctx)
    finally:
        led.close()
    assert second.state == "ok" and second.findings == []   # deduped
    assert len(b.calls) == 1                                 # refute NOT re-spent


def test_no_providers_installed_skips_ok(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    ghost = SimpleNamespace(NAME="fake-a", available=lambda cfg: False,
                            installed=lambda: False)
    _wire(monkeypatch, ghost)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item(base_sha, head_sha), _ctx(r, led))
    finally:
        led.close()
    assert got.state == "ok" and "no providers installed" in got.note


def test_installed_but_unavailable_degrades_holds(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    quota = SimpleNamespace(NAME="fake-a", available=lambda cfg: False,
                            installed=lambda: True)
    _wire(monkeypatch, quota)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item(base_sha, head_sha), _ctx(r, led))
    finally:
        led.close()
    assert got.state == "degraded" and "all providers unavailable" in got.note


def test_disabled_skips(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    _wire(monkeypatch)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(enabled=False), ledger=led,
                       clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item(base_sha, head_sha), ctx)
    finally:
        led.close()
    assert got.state == "ok" and got.note == "llm disabled"


def test_registered_in_consumers():
    from aramid.consumers import base as consumers_base
    assert consumers_base.CONSUMERS["llm-review"] is llm_review
