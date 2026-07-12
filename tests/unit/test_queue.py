from datetime import datetime, timedelta, timezone

from aramid import queue
from aramid.ledger import Ledger
from aramid.models import EventType


def _iso(dt) -> str:
    return dt.isoformat()


NOW = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)


def test_new_event_types_exist():
    assert EventType.TRIAGE_RECORDED.value == "triage_recorded"
    assert EventType.QUEUE_ITEM_ADDED.value == "queue_item_added"
    assert EventType.QUEUE_ITEM_COALESCED.value == "queue_item_coalesced"
    assert EventType.QUEUE_ITEM_DRAINED.value == "queue_item_drained"
    assert EventType.QUEUE_ITEM_EXPIRED.value == "queue_item_expired"
    assert EventType.CONSUMER_RUN_FINISHED.value == "consumer_run_finished"


def test_enqueue_then_materialize_roundtrip(tmp_path):
    led = Ledger(tmp_path / "l.db")
    item = queue.enqueue(led, _iso(NOW), "aaa1111", "bbb2222", 55, ["security-path: auth.py"])
    items = queue.materialize_queue(led.events())
    got = items[item.id]
    assert got.state == "queued"
    assert got.base == "aaa1111" and got.head == "bbb2222"
    assert got.score == 55
    assert got.reasons == ("security-path: auth.py",)
    assert got.range_str == "aaa1111..bbb2222"
    led.close()


def test_root_commit_item_has_no_base(tmp_path):
    led = Ledger(tmp_path / "l.db")
    item = queue.enqueue(led, _iso(NOW), None, "bbb2222", 41, ["novelty: 3 new paths"])
    got = queue.materialize_queue(led.events())[item.id]
    assert got.base is None
    assert got.range_str == "bbb2222"
    led.close()


def test_enqueue_coalesces_into_existing_queued_item(tmp_path):
    """Spec §4: at most one queued item per repo; base kept, head advances,
    score is max, reasons union."""
    led = Ledger(tmp_path / "l.db")
    first = queue.enqueue(led, _iso(NOW), "aaa", "bbb", 55, ["security-path: auth.py"])
    second = queue.enqueue(led, _iso(NOW + timedelta(minutes=5)), "bbb", "ccc", 41,
                           ["novelty: 1 new path", "security-path: auth.py"])
    assert second.id == first.id  # same item, coalesced
    items = queue.materialize_queue(led.events())
    assert len([i for i in items.values() if i.state == "queued"]) == 1
    got = items[first.id]
    assert got.base == "aaa" and got.head == "ccc"
    assert got.score == 55  # max(55, 41)
    assert got.reasons == ("novelty: 1 new path", "security-path: auth.py")  # sorted union
    assert got.updated_at == _iso(NOW + timedelta(minutes=5))
    types = [e.type for e in led.events()]
    assert types.count(EventType.QUEUE_ITEM_ADDED) == 1
    assert types.count(EventType.QUEUE_ITEM_COALESCED) == 1
    led.close()


def test_mark_drained_transitions_state(tmp_path):
    led = Ledger(tmp_path / "l.db")
    item = queue.enqueue(led, _iso(NOW), "a", "b", 50, ["r"])
    queue.mark_drained(led, item.id, "run42", _iso(NOW + timedelta(hours=1)))
    got = queue.materialize_queue(led.events())[item.id]
    assert got.state == "drained"
    assert queue.queued_item(queue.materialize_queue(led.events())) is None
    led.close()


def test_drained_item_does_not_block_new_enqueue(tmp_path):
    led = Ledger(tmp_path / "l.db")
    old = queue.enqueue(led, _iso(NOW), "a", "b", 50, ["r"])
    queue.mark_drained(led, old.id, "run1", _iso(NOW))
    new = queue.enqueue(led, _iso(NOW + timedelta(hours=2)), "b", "c", 44, ["r2"])
    assert new.id != old.id
    assert queue.materialize_queue(led.events())[new.id].state == "queued"
    led.close()


def test_expire_stale_only_past_expiry(tmp_path):
    led = Ledger(tmp_path / "l.db")
    old = queue.enqueue(led, _iso(NOW - timedelta(days=31)), "a", "b", 50, ["r"])
    expired = queue.expire_stale(led, _iso(NOW), expiry_days=30)
    assert expired == [old.id]
    assert queue.materialize_queue(led.events())[old.id].state == "expired"
    fresh = queue.enqueue(led, _iso(NOW - timedelta(days=29)), "b", "c", 50, ["r"])
    assert queue.expire_stale(led, _iso(NOW), expiry_days=30) == []
    assert queue.materialize_queue(led.events())[fresh.id].state == "queued"
    led.close()


def test_triage_records_head_and_paths(tmp_path):
    led = Ledger(tmp_path / "l.db")
    assert queue.last_triaged_head(led) is None
    queue.record_triage(led, _iso(NOW), None, "abc123", 12, False, ["a.py", "b.md"])
    queue.record_triage(led, _iso(NOW + timedelta(minutes=1)), "abc123", "def456", 66, True,
                        ["src/auth.py"])
    assert queue.last_triaged_head(led) == "def456"
    assert queue.triaged_paths(led) == {"a.py", "b.md", "src/auth.py"}
    led.close()
