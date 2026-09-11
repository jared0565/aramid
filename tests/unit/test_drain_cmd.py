"""`cmd_drain` at unit scope: its decisions, one pin each.

The drain's end-to-end arms live in tests/integration/test_drain.py and
run a real triage per repo. The mutation consumer confirms survivors
against the UNIT suite alone, so a decision that only an integration
test holds is reported as a survivor every time `cmd_drain` is in a
range (2026-09-11 06:00Z drain: 29 mutants generated for it, 3 confirmed,
the rest dropped at the cap). Every arm here drives `cmd_drain` itself --
a tmp git repo whose HEAD is an empty commit (the sweep queues
nothing), a queue item written by hand, the consumers replaced by a fake,
the lock and the registry on tmp_path, the clocks injected."""
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone

import pytest

from aramid import autolearn, queue, registry
from aramid import config as config_mod
from aramid.commands import drain as drain_mod
from aramid.commands.drain import cmd_drain
from aramid.consumers.base import ConsumerResult
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict

# The drain's clock is injected, so item ages are offsets from THIS now, never
# from the wall clock (tests/unit/test_queue_test_hygiene.py).
_NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)
NOW = _NOW.isoformat()
CLOCK = lambda: NOW  # noqa: E731


def _ago(**delta):
    return (_NOW - timedelta(**delta)).isoformat()


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name="r"):
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty",
         "-m", "benign HEAD")
    (r / ".aramid").mkdir()
    registry.register(r, "t0")
    return r


def _head(r):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, check=True,
                          capture_output=True, text=True).stdout.strip()


def _enqueue(r, score=45, at=None):
    """What a triage of HEAD leaves behind: its row (so the drain's sweep
    finds HEAD already triaged and runs no git) and the queued item."""
    at = at or _ago(days=1)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        head = _head(r)
        queue.record_triage(led, at, head, head, score, True, [])
        return queue.enqueue(led, at, head, head, score, ["t"])
    finally:
        led.close()


def _pending_rows(r, n):
    """`n` re-testable pending_retest mutation survivors in the ledger."""
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        ids = [f"{i:064x}" for i in range(n)]
        led.record_run("r1", "2026-09-01T00:00:00+00:00", "drain", {"mutation"}, {"calc.py"},
                       [Finding(id=fid, tool="mutation", rule="int-bound", severity_raw="medium",
                                severity=Severity.MEDIUM, verdict=Verdict.WARN, file="calc.py",
                                line=i + 2, message="mutant survived", evidence="", gate=Gate.ALL)
                        for i, fid in enumerate(ids)])
        for k, fid in enumerate(ids):
            led.append(Event(EventType.FINDING_RESOLVED, "gate", f"2026-09-01T00:01:{k:02d}+00:00",
                             finding_id=fid,
                             payload={"auto_resolved": "gap_addressed", "pending_retest": True}))
    finally:
        led.close()


def _events(r):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        return led.events()
    finally:
        led.close()


def _queued(r):
    return queue.queued_item(queue.materialize_queue(_events(r)))


class _Fake:
    NAME = "fake"
    calls: list = []
    state = "ok"
    lock_seen: list = []

    @classmethod
    def consume(cls, item, ctx):
        cls.calls.append(item)
        cls.lock_seen.append(drain_mod._lock_path().exists())
        return ConsumerResult(consumer=cls.NAME, state=cls.state, findings=[])


@pytest.fixture
def seam(tmp_path, monkeypatch):
    """The lock on tmp_path, the consumers replaced by the fake (patched on
    `drain_mod`, whose own binding of CONSUMERS is the one the loop reads).
    The registry is the autouse tmp_path seam."""
    _Fake.calls, _Fake.lock_seen, _Fake.state = [], [], "ok"
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "central" / "drain.lock")
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": _Fake})
    return _Fake


@pytest.fixture
def bare_config(monkeypatch):
    """The real config with the keys `cmd_drain` defaults removed: a repo
    whose [triage] names no min_score and whose [drain] names no expiry or
    item limit. defaults.toml carries all three, so this is the only way
    the literals in `cmd_drain` are ever read."""
    real = config_mod.load_config

    def bare(root):
        cfg = real(root)
        cfg.triage.pop("min_score", None)
        cfg.drain.pop("item_expiry_days", None)
        cfg.drain.pop("max_items_per_drain", None)
        return cfg
    monkeypatch.setattr(drain_mod.config_mod, "load_config", bare)


# ------------------------------------------------------------------ the lock --

def test_a_real_drain_holds_the_lock_while_consuming_and_releases_it_after(tmp_path, seam):
    r = _repo(tmp_path)
    _enqueue(r)

    rc = cmd_drain([], dry_run=False, clock=CLOCK)

    assert rc == 0
    assert seam.lock_seen == [True], "the consumer ran under the drain lock"
    assert not drain_mod._lock_path().exists(), "released on the way out"


def test_a_lock_held_by_a_live_process_refuses_with_3(tmp_path, seam, capsys):
    r = _repo(tmp_path)
    _enqueue(r)
    p = drain_mod._lock_path()
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"pid": os.getpid(), "started_at": time.time()}), encoding="utf-8")

    rc = cmd_drain([], dry_run=False, clock=CLOCK)

    assert rc == 3
    assert "another drain is running (lock held)" in capsys.readouterr().err
    assert seam.calls == []
    assert p.exists(), "someone else's lock is not ours to release"


# --------------------------------------------------------------- dry-run --

def test_dry_run_previews_the_queued_score_takes_no_lock_and_writes_nothing(
        tmp_path, seam, capsys):
    r = _repo(tmp_path)
    _enqueue(r, score=45)
    _pending_rows(r, 2)  # a queued item wins: the re-test item is for an EMPTY queue
    before = len(_events(r))

    rc = cmd_drain([], dry_run=True, clock=CLOCK)

    out, err = capsys.readouterr()
    assert rc == 0
    assert out == f"aramid drain (dry-run): {r.resolve()} queued=45\n", out
    assert err == ""
    assert seam.calls == []
    assert not (tmp_path / "central" / "drain.lock").exists()
    assert len(_events(r)) == before


def test_dry_run_on_a_repo_with_no_ledger_says_queued_none(tmp_path, seam, capsys):
    r = _repo(tmp_path)
    (r / ".aramid").rmdir()

    rc = cmd_drain([], dry_run=True, clock=CLOCK)

    out, err = capsys.readouterr()
    assert rc == 0
    assert out == f"aramid drain (dry-run): {r.resolve()} queued=none\n", out
    assert err == ""


# ------------------------------------------------------- what gets popped --

def test_nothing_queued_drains_nothing_and_says_so(tmp_path, seam, capsys):
    r = _repo(tmp_path)
    Ledger(r / ".aramid" / "ledger.db").close()

    rc = cmd_drain([], dry_run=False, clock=CLOCK)

    out, err = capsys.readouterr()
    assert rc == 0
    assert seam.calls == []
    assert "skipping" not in err, "no item is not a probe failure"
    assert out.splitlines()[-1] == "aramid drain: 0 item(s) drained, 0 left"


def test_an_item_at_exactly_the_default_min_score_is_popped(tmp_path, seam, bare_config):
    # The loop admits `score >= min_score`, 40 when no [triage] names one --
    # the score the empty-queue re-test item is written at.
    r = _repo(tmp_path)
    _enqueue(r, score=40)

    rc = cmd_drain([], dry_run=False, clock=CLOCK)

    assert rc == 0
    assert [i.score for i in seam.calls] == [40]
    assert _queued(r) is None


def test_an_item_below_min_score_stays_queued(tmp_path, seam):
    r = _repo(tmp_path)
    _enqueue(r, score=39)

    rc = cmd_drain([], dry_run=False, clock=CLOCK)

    assert rc == 0
    assert seam.calls == []
    assert _queued(r) is not None


def test_a_queued_item_expires_after_the_default_30_days(tmp_path, seam, bare_config):
    old = _repo(tmp_path, "old")
    _enqueue(old, at=_ago(days=31))
    fresh = _repo(tmp_path, "fresh")
    _enqueue(fresh, at=_ago(days=29))

    rc = cmd_drain([], dry_run=False, clock=CLOCK)

    assert rc == 0
    assert [i.head for i in seam.calls] == [_head(fresh)]
    assert any(e.type is EventType.QUEUE_ITEM_EXPIRED for e in _events(old))
    assert _queued(old) is None


# ------------------------------------------------------- limit and budget --

def test_the_item_limit_defers_the_rest_naming_the_reason(tmp_path, seam, capsys):
    a = _repo(tmp_path, "a")
    _enqueue(a, score=60)
    b = _repo(tmp_path, "b")
    _enqueue(b, score=50)

    rc = cmd_drain([], dry_run=False, max_items=1, clock=CLOCK)

    out = capsys.readouterr().out
    assert rc == 0
    assert [i.head for i in seam.calls] == [_head(a)], "highest score first, then the limit"
    assert "aramid drain: budget reached; 1 item(s) left queued" in out
    assert out.splitlines()[-1] == "aramid drain: 1 item(s) drained, 1 left"
    left = _queued(b)
    assert left is not None and (left.deferred, left.deferred_reason) == (1, "item limit")


def test_the_default_item_limit_is_10(tmp_path, seam, bare_config):
    first = _repo(tmp_path, "r00")
    _enqueue(first)
    repos = [first]
    for i in range(1, 11):  # eleven registered repos, one queued item each
        r = tmp_path / f"r{i:02d}"
        shutil.copytree(first, r)
        registry.register(r, "t0")
        repos.append(r)

    rc = cmd_drain([], dry_run=False, clock=CLOCK)

    assert rc == 0
    assert len(seam.calls) == 10
    assert sum(1 for r in repos if _queued(r) is not None) == 1


def test_the_wall_clock_budget_stops_between_items_only_once_it_is_spent(
        tmp_path, seam, capsys):
    # Checked BETWEEN items, strictly: at exactly the budget the next item
    # still opens; past it the rest are deferred with "drain budget".
    a = _repo(tmp_path, "a")
    _enqueue(a, score=60)
    b = _repo(tmp_path, "b")
    _enqueue(b, score=50)
    ticks = iter([0.0, 0.0, 600.0])  # started, check before a, check before b

    rc = cmd_drain([], dry_run=False, clock=CLOCK, monotonic=lambda: next(ticks))

    assert rc == 0
    assert len(seam.calls) == 2, "600.0 elapsed of a 600.0 budget: not yet spent"

    seam.calls.clear()
    _enqueue(a, score=60)
    _enqueue(b, score=50)
    ticks = iter([0.0, 0.0, 600.001])

    rc = cmd_drain([], dry_run=False, clock=CLOCK, monotonic=lambda: next(ticks))

    assert rc == 0
    assert [i.head for i in seam.calls] == [_head(a)]
    left = _queued(b)
    assert left is not None and left.deferred_reason == "drain budget"
    assert "1 item(s) drained, 1 left" in capsys.readouterr().out


# ----------------------------------------------------------- exit status --

def test_a_degraded_consumer_exits_2_and_leaves_the_item_queued(tmp_path, seam, capsys):
    r = _repo(tmp_path)
    _enqueue(r)
    seam.state = "degraded"

    rc = cmd_drain([], dry_run=False, clock=CLOCK)

    assert rc == 2
    assert len(seam.calls) == 1
    assert _queued(r) is not None, "not marked drained: the item gets another go"
    assert capsys.readouterr().out.splitlines()[-1] == "aramid drain: 1 item(s) drained, 0 left"


# ------------------------------------------------------- autolearn rollup --

def test_the_autolearn_rollup_runs_for_a_drained_repo_and_not_when_disabled(
        tmp_path, seam, monkeypatch):
    saved = []
    monkeypatch.setattr(autolearn, "save_state", lambda state, at: saved.append(at))
    r = _repo(tmp_path)
    _enqueue(r)

    assert cmd_drain([], dry_run=False, clock=CLOCK) == 0
    assert saved == [NOW]

    (r / "aramid.toml").write_text("[llm.autolearn]\nenabled = false\n", encoding="utf-8")
    _enqueue(r)

    assert cmd_drain([], dry_run=False, clock=CLOCK) == 0
    assert saved == [NOW], "disabled: no rollup, and no error either"
