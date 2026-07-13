from aramid.ledger import Ledger
from aramid.models import Finding, Severity, Verdict, Gate
from aramid import queue
from aramid.models import Event, EventType

def _f(fid, tool="ruff", file="a.py"):
    return Finding(fid, tool, "S102", "high", Severity.HIGH, Verdict.WARN,
                   file, 1, "m", "e", Gate.PRE_PUSH)

def test_compact_preserves_open_findings_and_drops_rows(tmp_path):
    led = Ledger(tmp_path / "l.db")
    # 100 redundant detect/resolve cycles: id1 detected then resolved each cycle,
    # id2 stays continuously open (present) across every cycle.
    for i in range(100):
        led.record_run(f"r{i}a", "t", "pre-push", {"ruff"}, {"a.py"},
                        [_f("id1"), _f("id2")])
        led.record_run(f"r{i}b", "t", "pre-push", {"ruff"}, {"a.py"},
                        [_f("id2")])  # id1 absent this run -> resolved

    before = led.open_findings()
    assert before["id1"]["status"] == "fixed"
    assert before["id2"]["status"] == "open"
    rows_before = len(led.events())

    removed = led.compact()

    rows_after = len(led.events())
    after = led.open_findings()

    assert after == before
    assert after["id1"]["status"] == "fixed"
    assert after["id2"]["status"] == "open"
    assert rows_after < rows_before
    assert removed == rows_before - rows_after
    led.close()


def test_compact_keeps_queued_item_events_and_latest_triage(tmp_path):
    led = Ledger(tmp_path / "l.db")
    queue.record_triage(led, "2026-07-13T10:00:00+00:00", None, "aaa", 10, False, ["x.py"])
    queue.record_triage(led, "2026-07-13T11:00:00+00:00", "aaa", "bbb", 55, True, ["auth.py"])
    item = queue.enqueue(led, "2026-07-13T11:00:00+00:00", "aaa", "bbb", 55, ["r1"])
    queue.enqueue(led, "2026-07-13T11:30:00+00:00", "bbb", "ccc", 40, ["r2"])  # coalesce
    led.compact()
    items = queue.materialize_queue(led.events())
    got = items[item.id]
    assert got.state == "queued" and got.base == "aaa" and got.head == "ccc"
    assert got.score == 55
    assert queue.last_triaged_head(led) == "bbb"
    triage_events = [e for e in led.events() if e.type is EventType.TRIAGE_RECORDED]
    assert len(triage_events) == 1  # only the latest survives
    led.close()


def test_compact_drops_terminal_queue_items_keeps_latest_consumer_and_run(tmp_path):
    led = Ledger(tmp_path / "l.db")
    item = queue.enqueue(led, "2026-07-13T10:00:00+00:00", "a", "b", 50, ["r"])
    queue.mark_drained(led, item.id, "run1", "2026-07-13T12:00:00+00:00")
    for i, at in ((1, "2026-07-13T12:00:01+00:00"), (2, "2026-07-13T13:00:00+00:00")):
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"run{i}", at,
                         payload={"consumer": "regression_pack", "finding_count": i}))
        led.append(Event(EventType.RUN_FINISHED, f"run{i}", at, payload={"blocking": 0}))
    led.compact()
    events = led.events()
    assert not any(e.type in (EventType.QUEUE_ITEM_ADDED, EventType.QUEUE_ITEM_DRAINED)
                   for e in events), "terminal item's queue events are redundant"
    consumer = [e for e in events if e.type is EventType.CONSUMER_RUN_FINISHED]
    finished = [e for e in events if e.type is EventType.RUN_FINISHED]
    assert len(consumer) == 1 and consumer[0].payload["finding_count"] == 2
    assert len(finished) == 1 and finished[0].run_id == "run2"
    led.close()
