import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import queue, registry
from aramid.commands import drain as drain_mod
from aramid.commands.drain import cmd_drain
from aramid.consumers.base import ConsumerResult
from aramid.ledger import Ledger
from aramid.models import Event, EventType
from aramid.normalizer import RawFinding


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name="r") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    return r


def _commit(root, name, content, msg):
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8")
    _git(root, "add", name)
    _git(root, "commit", "-m", msg)


class _FakeConsumer:
    NAME = "fake"
    calls: list = []

    @classmethod
    def consume(cls, item, ctx):
        cls.calls.append(item)
        raw = RawFinding(tool="semgrep", rule="aramid-regression.warn.deadbeef",
                         severity_raw="WARNING", file="src/auth_login.py", line=1,
                         message="reintroduction")
        return ConsumerResult(consumer=cls.NAME, state="ok", findings=[raw])


@pytest.fixture
def fake_consumer(monkeypatch):
    """Isolate drain tests from the real `regression_pack` consumer, which
    registers itself into the shared `consumers.base.CONSUMERS` dict at
    import time (Task 16) -- and `drain.py` now imports it unconditionally,
    so it is present in CONSUMERS for the rest of this test session. REPLACE
    (not add to) the dict `drain.py` actually iterates so these tests only
    ever run the fake.

    Patched on `drain_mod`, not `aramid.consumers.base`: `drain.py` does
    `from aramid.consumers.base import CONSUMERS`, which binds its own
    module-global name to the dict object at import time. Rebinding
    `base.CONSUMERS` only changes what `base.CONSUMERS` resolves to -- it
    does not touch `drain_mod`'s separate binding, which is the one
    `cmd_drain`'s `_consume_item` loop (`for name, module in
    CONSUMERS.items()`) actually reads. Patching `base.CONSUMERS` here would
    silently leave the real consumer in drain's loop.
    """
    _FakeConsumer.calls = []
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": _FakeConsumer})
    yield _FakeConsumer


@pytest.fixture
def seam(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "central" / "repos.toml")
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "central" / "drain.lock")


def _risky_repo(tmp_path, name="r"):
    r = _repo(tmp_path, name)
    _commit(r, "src/auth_login.py", "def f(x):\n    exec(x)\n", "risky")
    return r


def test_drain_sweeps_pops_consumes_records(tmp_path, seam, fake_consumer):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    rc = cmd_drain([], dry_run=False)  # [] + registry -> --all semantics
    assert rc == 0
    assert len(fake_consumer.calls) == 1  # sweep triaged HEAD, item queued, popped
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        events = led.events()
        assert any(e.type is EventType.CONSUMER_RUN_FINISHED for e in events)
        assert any(e.type is EventType.QUEUE_ITEM_DRAINED for e in events)
        assert queue.queued_item(queue.materialize_queue(events)) is None
        state = led.open_findings()
        assert any(rec.get("rule") == "aramid-regression.warn.deadbeef"
                   for rec in state.values())
    finally:
        led.close()


def test_drain_bootstrap_sweeps_head_only(tmp_path, seam, fake_consumer):
    """Spec section 2 bootstrap rule: no triage history -> triage HEAD only,
    never the whole past."""
    r = _repo(tmp_path)
    _commit(r, "old_secret_config.py", "exec(1)\n", "old risky commit")
    _commit(r, "docs/readme.md", "hi\n", "benign HEAD")
    registry.register(r, "t0")
    cmd_drain([], dry_run=False)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        # benign HEAD scores novelty only (20 < 40): recorded, nothing queued,
        # and the risky OLD commit was never triaged
        assert queue.last_triaged_head(led) is not None
        assert queue.queued_item(queue.materialize_queue(led.events())) is None
        triage_events = [e for e in led.events() if e.type is EventType.TRIAGE_RECORDED]
        assert len(triage_events) == 1
    finally:
        led.close()


def test_drain_dry_run_writes_nothing(tmp_path, seam, fake_consumer):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    rc = cmd_drain([], dry_run=True)
    assert rc == 0
    assert fake_consumer.calls == []
    assert not (r / ".aramid" / "ledger.db").exists()


def test_drain_isolates_broken_repo_exit_2(tmp_path, seam, fake_consumer):
    good = _risky_repo(tmp_path, "good")
    registry.register(tmp_path / "vanished", "t0")  # path does not exist
    registry.register(good, "t0")
    rc = cmd_drain([], dry_run=False)
    assert rc == 2  # degraded: one repo skipped
    assert len(fake_consumer.calls) == 1  # good repo still drained


def test_drain_isolates_repo_with_corrupt_config(tmp_path, seam, fake_consumer):
    broken = _risky_repo(tmp_path, "broken")
    (broken / "aramid.toml").write_text("this is not = valid toml [", encoding="utf-8")
    good = _risky_repo(tmp_path, "good")
    registry.register(broken, "t0")
    registry.register(good, "t0")
    rc = cmd_drain([], dry_run=False)
    assert rc == 2  # degraded, not a crash
    assert len(fake_consumer.calls) == 1  # the good repo still drained fully


def test_drain_lock_contention(tmp_path, seam, fake_consumer):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    lock = drain_mod._acquire_lock(600.0)
    assert lock is not None
    try:
        assert cmd_drain([], dry_run=False) == 3  # engine error: locked
        assert fake_consumer.calls == []
    finally:
        drain_mod._release_lock(lock)


def test_drain_respects_max_items(tmp_path, seam, fake_consumer):
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")
    assert cmd_drain([], dry_run=False, max_items=1) == 0
    assert len(fake_consumer.calls) == 1


# --- FIX 1: degraded consumer results must trip exit 2 and leave the item
#     queued for retry, not be swallowed like a silent "ok". -----------------

class _DegradedConsumer:
    NAME = "degraded"
    calls: list = []

    @classmethod
    def consume(cls, item, ctx):
        cls.calls.append(item)
        # Mirrors regression_pack.consume's real "degraded" case: semgrep
        # TIMEOUT/CRASHED/MISSING -- the ruleset was NOT fully evaluated.
        return ConsumerResult(consumer=cls.NAME, state="degraded",
                              note="semgrep timeout")


def test_drain_degraded_consumer_exits_2_and_leaves_item_queued(tmp_path, seam, monkeypatch):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    _DegradedConsumer.calls = []
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"degraded": _DegradedConsumer})

    rc = cmd_drain([], dry_run=False)

    assert rc == 2  # degraded consumer result must surface as exit 2, not 0
    assert len(_DegradedConsumer.calls) == 1
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        item = queue.queued_item(queue.materialize_queue(led.events()))
        # a not-fully-consumed item must NOT be marked drained -- it must
        # stay queued so the next drain retries it.
        assert item is not None
        assert item.state == queue.QUEUED
    finally:
        led.close()


# --- FIX 2: drain must record its narrow (pack-only) ruleset run with EMPTY
#     scope, so it can only ADD detections and never spuriously resolve an
#     open finding from a different (e.g. OWASP) ruleset that also uses
#     tool="semgrep" and happens to share a scanned file. -------------------

class _PackFakeConsumer:
    NAME = "fake"
    calls: list = []

    @classmethod
    def consume(cls, item, ctx):
        cls.calls.append(item)
        raw = RawFinding(tool="semgrep", rule="aramid-regression.block.deadbeef",
                         severity_raw="ERROR", file="src/api.py", line=1,
                         message="reintroduction")
        return ConsumerResult(consumer=cls.NAME, state="ok", findings=[raw])


def test_drain_pack_only_scan_does_not_resolve_unrelated_open_finding(tmp_path, seam, monkeypatch):
    # Order matters: bootstrap sweep triages HEAD only (spec section 2), so
    # the risky commit (the one that scores >= min_score and gets queued)
    # must be LAST, with the benign src/api.py commit first.
    r = _repo(tmp_path)
    _commit(r, "src/api.py", "def handler():\n    return 1\n", "api handler")
    _commit(r, "src/auth_login.py", "def f(x):\n    exec(x)\n", "risky")
    registry.register(r, "t0")

    # Seed a pre-existing OPEN OWASP-style semgrep finding in src/api.py --
    # a full gate detected it once; the drain (pack ruleset only) must never
    # touch it.
    ledger_path = r / ".aramid" / "ledger.db"
    led = Ledger(ledger_path)
    try:
        led.append(Event(EventType.FINDING_DETECTED, "seed-run",
                         "2020-01-01T00:00:00+00:00", finding_id="owasp-finding-1",
                         payload={"tool": "semgrep", "file": "src/api.py",
                                  "rule": "owasp-top-ten.a03", "verdict": "warn",
                                  "severity": "medium", "line": 1,
                                  "message": "owasp finding", "evidence": "",
                                  "historical": False}))
    finally:
        led.close()

    _PackFakeConsumer.calls = []
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": _PackFakeConsumer})

    rc = cmd_drain([], dry_run=False)
    assert rc == 0

    led = Ledger(ledger_path)
    try:
        state = led.open_findings()
        # the pre-existing OWASP finding must still be open: the drain's
        # narrow pack ruleset never re-detected it and must not resolve it
        assert state["owasp-finding-1"]["status"] == "open"
        # the pack finding itself was still detected
        assert any(rec.get("rule") == "aramid-regression.block.deadbeef"
                   for rec in state.values())
    finally:
        led.close()


def test_consumer_extra_merged_into_event_payload(tmp_path, monkeypatch):
    """ConsumerResult.extra rides into the CONSUMER_RUN_FINISHED payload;
    core keys are never overridden by extra."""
    from aramid.commands import drain as drain_mod
    from aramid.ledger import Ledger
    from aramid.models import EventType
    from aramid.queue import QueueItem

    led = Ledger(tmp_path / "l.db")
    fake = SimpleNamespace(consume=lambda item, ctx: ConsumerResult(
        consumer="fake", state="ok",
        extra={"selection": {"served": {"provider": "p"}},
               "note": "MUST NOT WIN"}))
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": fake})
    item = QueueItem(id="q1", base=None, head="h", score=50, reasons=(),
                     state="queued", created_at="2026-07-18T00:00:00+00:00",
                     updated_at="2026-07-18T00:00:00+00:00")
    try:
        ok = drain_mod._consume_item(tmp_path, SimpleNamespace(llm={}), led,
                                     item, lambda: "2026-07-18T00:00:00+00:00")
        assert ok is True
        evs = [e for e in led.events()
               if e.type is EventType.CONSUMER_RUN_FINISHED]
    finally:
        led.close()
    assert evs[0].payload["selection"] == {"served": {"provider": "p"}}
    assert evs[0].payload["note"] == ""          # core key wins over extra


def test_drain_rolls_up_autolearn_state(tmp_path, monkeypatch):
    """cmd_drain folds drained repos' selection events into the (test-
    isolated) machine-global state; a rollup failure never fails the drain."""
    import json as json_mod

    from aramid import autolearn, config as config_mod, gitutil, queue
    from aramid.commands import drain as drain_mod
    from aramid.ledger import Ledger

    repo = tmp_path / "repo"
    repo.mkdir()

    def _git(*a):
        return subprocess.run(["git", *a], cwd=repo, check=True,
                              capture_output=True, text=True)
    _git("init", "-q", "-b", "main")
    _git("config", "user.email", "t@t")
    _git("config", "user.name", "t")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git("add", ".")
    _git("commit", "-m", "c1")
    (repo / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")

    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")
    monkeypatch.setattr(drain_mod, "_lock_path",
                        lambda: tmp_path / "drain.lock")
    monkeypatch.setattr(drain_mod, "_sweep", lambda *a, **k: None)

    led = Ledger(repo / ".aramid" / "ledger.db")
    try:
        queue.enqueue(led, "2026-07-18T00:00:00+00:00", None,
                      gitutil.rev_sha(repo, "HEAD"), 50, ["risky"])
    finally:
        led.close()

    fake = SimpleNamespace(consume=lambda item, ctx: ConsumerResult(
        consumer="fake", state="ok",
        extra={"selection": {
            "target_tier": "cheap", "bucket": "plain",
            "served": {"tier": "cheap", "provider": "p", "model": "m",
                       "effort": ""},
            "attempts": [], "uplift": {"mode": "shadow", "pick": "cheap",
                                       "applied": False, "sampled_q": 0.1},
            "cascade": {"triggered": False, "trigger": None,
                        "applied": False},
            "audit": {"performed": True, "tier": "frontier",
                      "new_findings": 0, "missed_criticals": 0},
            "refutes": [], "hallucination_rejected": 0,
            "tokens": {"in": 1, "out": 1}}}))
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": fake})

    assert drain_mod.cmd_drain([str(repo)]) == 0

    state = json_mod.loads(autolearn.state_path().read_text(encoding="utf-8"))
    assert state["audits"]["performed"] == 1
    assert state["posteriors"]["p/m|cheap|plain"]["clean"] == 1
    assert list(state["cursors"].values())[0] > 0
