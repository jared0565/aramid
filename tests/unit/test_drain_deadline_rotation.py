"""FN-16: a deadline-killed item must not come first at every drain.

Read 2026-09-28 while shipping FN-14: the watchdog's `os._exit` skipped
`cmd_drain`'s deferral loop, so the candidates the drain never reached got
no `queue_item_deferred` row and the killed item kept its
`(-deferred, -score)` place; and no consumer's give-up counted the
deadline's row. An item that cannot finish inside the deadline was killed
at every drain while every other repo's item waited to expiry (30 days).
Now the watchdog defers what the drain never reached, and a consumer
stopped at the deadline three times on one item -- at one head, under one
deadline -- gives up the way the other give-ups do: `ok`, loud in
`status`, and a new commit or a new deadline gets a fresh try."""
import json
import os
import threading
import time

import pytest

from aramid import config as config_mod
from aramid import queue
from aramid.commands import drain as drain_mod
from aramid.consumers.base import ConsumerResult
from aramid.fingerprint import normalize_path
from aramid.ledger import Ledger
from aramid.models import Event, EventType

HEAD = "b" * 40
NOW = "2026-09-28T00:00:00+00:00"


def _ledger(root):
    (root / ".aramid").mkdir(parents=True, exist_ok=True)
    return Ledger(root / ".aramid" / "ledger.db")


def _events(root, kind):
    led = _ledger(root)
    try:
        return [e for e in led.events() if e.type == kind]
    finally:
        led.close()


def _dog(tmp_path, deadline_s, now, **kw):
    lock = tmp_path / "drain.lock"
    lock.write_text(json.dumps({"pid": os.getpid(), "started_at": time.time(),
                                "deadline_s": deadline_s}), encoding="utf-8")
    exited = threading.Event()
    dog = drain_mod._Watchdog(deadline_s, lock=lock, clock=lambda: NOW,
                              exit_=lambda code: exited.set(), kill=lambda: 1,
                              poll_s=0.02, monotonic=lambda: now["t"], **kw)
    return dog, exited


# --- the deadline's row -------------------------------------------------------

def test_the_deadline_row_names_the_deadline_and_the_head_it_stopped_at(tmp_path):
    """The give-up counts these rows by prefix, so the prefix carries the
    two things that deserve a fresh try: the head and the deadline."""
    now = {"t": 0.0}
    dog, exited = _dog(tmp_path, 7.0, now)
    root = tmp_path / "r"
    _ledger(root).close()
    dog.begin(root, "item-1", "mutation", "run-1", HEAD)
    dog.start()
    now["t"] = 7.0
    assert exited.wait(10)
    [row] = _events(root, EventType.CONSUMER_RUN_FINISHED)
    assert row.payload["note"] == (
        "stopped at the drain's hard deadline ([drain].hard_deadline_s = 7) "
        "(last seen @ bbbbbbbbbbbb), 7 s into the drain; the item stays queued")
    assert row.payload["note"].startswith(drain_mod.deadline_note_prefix(7.0, HEAD))


# --- deferral rows ------------------------------------------------------------

def test_the_deadline_defers_every_item_the_drain_never_reached(tmp_path):
    now = {"t": 0.0}
    dog, exited = _dog(tmp_path, 7.0, now)
    r1, r2, r3 = (tmp_path / n for n in ("r1", "r2", "r3"))
    for r in (r1, r2, r3):
        _ledger(r).close()
    dog.pending("drain-run", [(r2, "item-2"), (r3, "item-3")], after=[])
    dog.begin(r1, "item-1", "mutation", "run-1", HEAD)
    dog.start()
    now["t"] = 7.0
    assert exited.wait(10)
    for root, item_id in ((r2, "item-2"), (r3, "item-3")):
        [ev] = _events(root, EventType.QUEUE_ITEM_DEFERRED)
        assert ev.finding_id == item_id and ev.run_id == "drain-run"
        assert ev.payload == {"reason": "drain deadline",
                              "after": [normalize_path(str(r1))],
                              "elapsed_s": 7, "budget_s": 7.0}
    assert _events(r1, EventType.QUEUE_ITEM_DEFERRED) == [], \
        "the item in flight was opened; deferring it too would keep it first"


def test_between_items_the_items_not_yet_opened_are_deferred(tmp_path):
    now = {"t": 0.0}
    dog, exited = _dog(tmp_path, 7.0, now)
    r1, r2 = tmp_path / "r1", tmp_path / "r2"
    for r in (r1, r2):
        _ledger(r).close()
    dog.pending("drain-run", [(r2, "item-2")], after=[normalize_path(str(r1))])
    dog.start()
    now["t"] = 7.0
    assert exited.wait(10)
    [ev] = _events(r2, EventType.QUEUE_ITEM_DEFERRED)
    assert ev.payload["after"] == [normalize_path(str(r1))]


def test_a_hung_ledger_in_one_repo_does_not_cost_another_its_deferral(tmp_path):
    never = threading.Event()
    r2, r3 = tmp_path / "r2", tmp_path / "r3"
    for r in (r2, r3):
        _ledger(r).close()

    def open_ledger(root):
        if root == r2:
            never.wait(30)
        return Ledger(root / ".aramid" / "ledger.db")
    now = {"t": 0.0}
    dog, exited = _dog(tmp_path, 7.0, now, open_ledger=open_ledger, write_timeout_s=0.3)
    dog.pending("drain-run", [(r2, "item-2"), (r3, "item-3")], after=[])
    dog.start()
    now["t"] = 7.0
    try:
        assert exited.wait(10), "a stuck ledger held the exit"
        [ev] = _events(r3, EventType.QUEUE_ITEM_DEFERRED)
        assert ev.finding_id == "item-3"
    finally:
        never.set()


# --- the give-up --------------------------------------------------------------

class _Recorder:
    calls: list = []

    @classmethod
    def consume(cls, item, ctx):
        cls.calls.append(item.id)
        return ConsumerResult(consumer="c", state="ok")


def _item(root):
    led = _ledger(root)
    try:
        return queue.enqueue(led, NOW, HEAD, HEAD, 45, ["t"])
    finally:
        led.close()


def _kills(root, item_id, n, *, deadline_s=5400.0, head=HEAD):
    led = _ledger(root)
    try:
        for i in range(n):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"run-{i}", NOW, payload={
                "consumer": "c", "item_id": item_id, "state": "degraded",
                "note": drain_mod.deadline_note(deadline_s, head, deadline_s)}))
    finally:
        led.close()


@pytest.fixture
def consume(tmp_path, monkeypatch):
    _Recorder.calls = []
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"c": _Recorder})
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    root = tmp_path / "r"
    item = _item(root)
    cfg = config_mod.load_config(root)

    def run(watchdog):
        led = _ledger(root)
        try:
            ok = drain_mod._consume_item(root, cfg, led, item, lambda: NOW, watchdog=watchdog)
            rows = [e.payload for e in led.events() if e.type == EventType.CONSUMER_RUN_FINISHED]
            state = queue.materialize_queue(led.events())[item.id].state
        finally:
            led.close()
        return ok, rows, state
    return root, item, run


def _armed(tmp_path, deadline_s=5400.0):
    return drain_mod._Watchdog(deadline_s, lock=tmp_path / "drain.lock", exit_=lambda code: None)


def test_three_deadline_kills_at_one_head_stand_the_consumer_down(tmp_path, consume):
    root, item, run = consume
    _kills(root, item.id, 3)
    ok, rows, state = run(_armed(tmp_path))
    assert _Recorder.calls == [], "it ran a fourth time into the same deadline"
    assert ok is True
    assert rows[-1]["state"] == "ok"
    assert rows[-1]["note"] == (
        "c giving up: stopped at the drain's hard deadline 3 times "
        "([drain].hard_deadline_s = 5400, last seen @ bbbbbbbbbbbb) -- raise "
        "[drain].hard_deadline_s or narrow what c runs; a new commit gets a fresh try")
    assert state == queue.DRAINED, "a give-up is `ok`, so the item leaves the queue"


@pytest.mark.parametrize("kills", [
    {"n": 2},
    {"n": 3, "head": "c" * 40},
    {"n": 3, "deadline_s": 1800.0},
], ids=["two kills", "a new head", "a new deadline"])
def test_short_of_that_the_consumer_runs(tmp_path, consume, kills):
    root, item, run = consume
    n = kills.pop("n")
    _kills(root, item.id, n, **kills)
    run(_armed(tmp_path))
    assert _Recorder.calls == [item.id]


def test_with_no_deadline_armed_there_is_nothing_to_give_up_on(tmp_path, consume):
    root, item, run = consume
    _kills(root, item.id, 3)
    run(None)
    assert _Recorder.calls == [item.id]
