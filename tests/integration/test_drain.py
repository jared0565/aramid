import subprocess
from pathlib import Path

import pytest

from aramid import queue, registry
from aramid.commands import drain as drain_mod
from aramid.commands.drain import cmd_drain
from aramid.consumers.base import CONSUMERS, ConsumerResult
from aramid.ledger import Ledger
from aramid.models import EventType
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
    _FakeConsumer.calls = []
    monkeypatch.setitem(CONSUMERS, "fake", _FakeConsumer)
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
