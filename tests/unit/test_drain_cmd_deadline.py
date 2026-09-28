"""FN-14: how `cmd_drain` drives its hard-deadline watchdog. The watchdog
is replaced by a recorder; what it does when it fires is
tests/unit/test_drain_watchdog.py, and the real-process arm is
tests/integration/test_drain_deadline.py."""
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from aramid import drain_limits, queue, registry
from aramid.commands import drain as drain_mod
from aramid.commands.drain import cmd_drain
from aramid.consumers.base import ConsumerResult
from aramid.ledger import Ledger

_NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)
CLOCK = lambda: _NOW.isoformat()  # noqa: E731


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name="r", toml=None):
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty",
         "-m", "benign HEAD")
    (r / ".aramid").mkdir()
    if toml is not None:
        (r / "aramid.toml").write_text("schema_version = 1\n" + toml, encoding="utf-8")
    registry.register(r, "t0")
    return r


def _enqueue(r, score=45):
    at = (_NOW - timedelta(days=1)).isoformat()
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, check=True,
                              capture_output=True, text=True).stdout.strip()
        queue.record_triage(led, at, head, head, score, True, [])
        return queue.enqueue(led, at, head, head, score, ["t"])
    finally:
        led.close()


class _Dog:
    """Records every call `cmd_drain` makes on its watchdog."""
    made: list = []

    def __init__(self, deadline_s, *, lock, clock):
        self.calls = [("init", deadline_s)]
        self.lock = lock
        _Dog.made.append(self)

    def start(self):
        self.calls.append(("start",))

    def set_deadline(self, s):
        self.calls.append(("set_deadline", s))

    def begin(self, root, item_id, consumer, run_id):
        self.calls.append(("begin", consumer, item_id))

    def finishing(self):
        import contextlib
        self.calls.append(("finishing",))
        return contextlib.nullcontext()

    def cancel(self):
        self.calls.append(("cancel",))


class _Consumer:
    raise_ = False

    @classmethod
    def consume(cls, item, ctx):
        if cls.raise_:
            raise RuntimeError("consumer blew up")
        return ConsumerResult(consumer="c", state="ok")


@pytest.fixture
def seam(tmp_path, monkeypatch):
    _Dog.made, _Consumer.raise_ = [], False
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "central" / "drain.lock")
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"c": _Consumer})
    monkeypatch.setattr(drain_mod, "_Watchdog", _Dog)
    return _Dog


def test_the_watchdog_is_armed_at_the_default_then_set_from_the_candidates(tmp_path, seam):
    r = _repo(tmp_path, toml="[drain]\nhard_deadline_s = 1800\n")
    item = _enqueue(r)
    assert cmd_drain([str(r)], clock=CLOCK) == 0
    [dog] = seam.made
    assert dog.calls[0] == ("init", drain_limits.DEFAULT_HARD_DEADLINE_S)
    assert dog.calls[1] == ("start",)
    assert ("set_deadline", 1800) in dog.calls
    assert ("begin", "c", item.id) in dog.calls
    assert dog.calls.index(("begin", "c", item.id)) < dog.calls.index(("finishing",))
    assert dog.calls[-1] == ("cancel",)
    assert dog.lock == drain_mod._lock_path()


def test_the_watchdog_is_cancelled_when_the_drain_raises(tmp_path, seam):
    """`cancel` is in the same `finally` as the lock release: a drain that
    dies of its own error must not leave a watchdog that later `os._exit`s
    whatever process imported it (a test runner, an MCP server). A
    mistyped `wall_clock_budget_s` is a real way out: the config layer
    warns and passes the value through, and `float()` raises."""
    r = _repo(tmp_path, toml='[drain]\nwall_clock_budget_s = "soon"\n')
    _enqueue(r)
    with pytest.raises(ValueError):
        cmd_drain([str(r)], clock=CLOCK)
    [dog] = seam.made
    assert dog.calls[-1] == ("cancel",)
    assert not drain_mod._lock_path().exists()


def test_a_dry_run_arms_no_watchdog(tmp_path, seam):
    """No lock, no consumers: nothing a deadline would need to stop."""
    r = _repo(tmp_path)
    _enqueue(r)
    assert cmd_drain([str(r)], dry_run=True, clock=CLOCK) == 0
    assert seam.made == []


def test_a_held_lock_arms_no_watchdog(tmp_path, seam):
    import json
    import os
    import time
    lock = drain_mod._lock_path()
    lock.parent.mkdir(parents=True)
    lock.write_text(json.dumps({"pid": os.getpid(), "started_at": time.time()}),
                    encoding="utf-8")
    r = _repo(tmp_path)
    _enqueue(r)
    assert cmd_drain([str(r)], clock=CLOCK) == 3
    assert seam.made == []


def test_a_drain_with_nothing_queued_keeps_the_default(tmp_path, seam):
    r = _repo(tmp_path, toml="[drain]\nhard_deadline_s = 1800\n")
    assert cmd_drain([str(r)], clock=CLOCK) == 0
    [dog] = seam.made
    assert ("set_deadline", drain_limits.DEFAULT_HARD_DEADLINE_S) in dog.calls
    assert not any(c[0] == "begin" for c in dog.calls)


def test_the_installed_task_limit_pulls_the_deadline_under_it(tmp_path, seam, monkeypatch):
    """A task still carrying the pre-FN-14 PT1H: the 90-minute default
    would lose to Task Scheduler's kill, so the deadline sits under it."""
    from aramid.commands import schedule as schedule_mod
    monkeypatch.setattr(schedule_mod, "installed_task_limit_minutes", lambda: 60)
    r = _repo(tmp_path)
    _enqueue(r)
    assert cmd_drain([str(r)], clock=CLOCK) == 0
    [dog] = seam.made
    assert ("set_deadline", 3300) in dog.calls
