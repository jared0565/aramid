"""FN-14: the drain's own hard deadline, at unit scope.

2026-09-25 and 09-27 the scheduled drain was killed from OUTSIDE (Task Scheduler's
ExecutionTimeLimit) mid-consumer: no `finally` ran, so no
CONSUMER_RUN_FINISHED row -- consumer health, built only from those rows,
never saw the run -- and ~/.aramid/drain.lock leaked. The watchdog kills
from INSIDE, first, and does the bookkeeping the outside kill skipped: one
`degraded` row naming the consumer it stopped, the children killed, the
lock released, exit 2. Exit, kill and the ledger are injected here; the
real-process arm is tests/integration/test_drain_deadline.py."""
import json
import os
import threading
import time

from aramid.commands import drain as drain_mod
from aramid.ledger import Ledger
from aramid.models import EventType

NOW = "2026-09-28T00:00:00+00:00"
HEAD = "a" * 40


def _rows(root):
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        return [e.payload for e in led.events() if e.type == EventType.CONSUMER_RUN_FINISHED]
    finally:
        led.close()


class _Harness:
    def __init__(self, tmp_path, deadline_s, **kw):
        self.root = tmp_path / "repo"
        (self.root / ".aramid").mkdir(parents=True)
        self.lock = tmp_path / "drain.lock"
        # The lock a real drain hands its watchdog names this process: FN-15
        # releases only a lock its own pid holds.
        self.lock.write_text(json.dumps({"pid": os.getpid(), "started_at": time.time(),
                                         "deadline_s": deadline_s}), encoding="utf-8")
        self.exits, self.kills = [], []
        self.exited = threading.Event()

        def exit_(code):
            self.exits.append(code)
            self.exited.set()
        kw.setdefault("kill", lambda: self.kills.append(1) or 1)
        self.dog = drain_mod._Watchdog(deadline_s, lock=self.lock, clock=lambda: NOW,
                                       exit_=exit_, poll_s=0.02, **kw)


def test_the_deadline_records_the_consumer_it_stops_then_kills_releases_and_exits(tmp_path):
    h = _Harness(tmp_path, 0.2)
    h.dog.begin(h.root, "item-1", "mutation", "run-1", HEAD)
    h.dog.start()
    assert h.exited.wait(10), "the watchdog never fired"
    assert h.exits == [2], "exit 2 is the drain's `degraded`"
    assert h.kills == [1], "the consumer's children were not killed"
    assert not h.lock.exists(), "the lock leaked -- the 2026-09-25 shape"
    [row] = _rows(h.root)
    assert row["consumer"] == "mutation" and row["item_id"] == "item-1"
    assert row["state"] == "degraded"
    assert row["finding_count"] == 0
    assert "[drain].hard_deadline_s" in row["note"]
    assert "stays queued" in row["note"]


def test_the_row_carries_the_consumers_run_id(tmp_path):
    """The rows a consumer writes share one run id; the deadline's row is
    the same run's last word, not a stray."""
    h = _Harness(tmp_path, 0.1)
    h.dog.begin(h.root, "item-1", "fuzz", "run-7", HEAD)
    h.dog.start()
    assert h.exited.wait(10)
    led = Ledger(h.root / ".aramid" / "ledger.db")
    try:
        [ev] = [e for e in led.events() if e.type == EventType.CONSUMER_RUN_FINISHED]
    finally:
        led.close()
    assert ev.run_id == "run-7"


def test_cancel_before_the_deadline_does_nothing(tmp_path):
    # Seconds, not tenths: on a loaded runner a tenth can pass between
    # `start` and `cancel`, and the watchdog would rightly fire.
    h = _Harness(tmp_path, 5.0)
    h.dog.begin(h.root, "item-1", "mutation", "run-1", HEAD)
    h.dog.start()
    h.dog.cancel()
    assert not h.exited.wait(1.0)
    assert h.exits == [] and h.kills == []
    assert h.lock.exists(), "a cancelled watchdog released a lock it does not own"
    assert _rows(h.root) == []


def test_nothing_in_flight_still_exits_but_writes_no_row(tmp_path):
    """Between consumers, or before the first: there is no run to name."""
    h = _Harness(tmp_path, 0.1)
    h.dog.start()
    assert h.exited.wait(10)
    assert h.exits == [2] and not h.lock.exists()
    assert _rows(h.root) == []


def test_a_consumer_writing_its_own_rows_is_not_recorded_twice(tmp_path):
    """The main thread writes a finished consumer's rows inside
    `finishing()`. A deadline that falls inside that window waits for it,
    and then finds nothing in flight: one row per run, never two."""
    h = _Harness(tmp_path, 0.1)
    h.dog.begin(h.root, "item-1", "mutation", "run-1", HEAD)
    # Inside `finishing` BEFORE the watchdog starts: started first, a 0.1 s
    # deadline can fall due before the block is entered on a loaded runner.
    with h.dog.finishing():
        h.dog.start()
        time.sleep(0.5)                 # the deadline passes in here
        assert h.exits == [], "fired while the consumer's own rows were being written"
    assert h.exited.wait(10)
    assert _rows(h.root) == []


def test_a_hung_ledger_write_does_not_stop_the_exit(tmp_path):
    """The row is the point, but not at the price of the exit: a ledger that
    never answers (locked, a stuck disk) must not turn the deadline into
    another hang."""
    never = threading.Event()

    def stuck(_root):
        never.wait(30)
        raise AssertionError("unreachable")
    h = _Harness(tmp_path, 0.1, open_ledger=stuck, write_timeout_s=0.3)
    h.dog.begin(h.root, "item-1", "mutation", "run-1", HEAD)
    h.dog.start()
    try:
        assert h.exited.wait(10), "a stuck ledger write held the exit"
        assert h.exits == [2] and h.kills == [1] and not h.lock.exists()
    finally:
        never.set()


def test_a_failing_kill_does_not_stop_the_exit(tmp_path):
    def boom():
        raise OSError("taskkill missing")
    h = _Harness(tmp_path, 0.1, kill=boom)
    h.dog.start()
    assert h.exited.wait(10)
    assert h.exits == [2] and not h.lock.exists()


def test_the_deadline_can_be_moved_once_the_configs_are_read(tmp_path):
    """Armed at the default before any repo's config is loaded, then set
    from the candidates' `[drain].hard_deadline_s`."""
    h = _Harness(tmp_path, 60.0)
    h.dog.start()
    assert not h.exited.wait(0.3)
    h.dog.set_deadline(0.1)
    assert h.exited.wait(10)
    assert h.exits == [2]


def test_it_fires_once(tmp_path):
    h = _Harness(tmp_path, 0.05)
    h.dog.begin(h.root, "item-1", "mutation", "run-1", HEAD)
    h.dog.start()
    assert h.exited.wait(10)
    time.sleep(0.3)
    assert h.exits == [2] and len(_rows(h.root)) == 1


# --- the watchdog's own clock, injected -----------------------------------------
# Real time never lands a poll exactly on the deadline, so `>=` against `>`
# and the row's rounding were unpinned (the 2026-09-28 06Z drain confirmed
# both as survivors). A parked fake clock pins them.

def test_the_deadline_fires_on_the_instant_it_falls_due(tmp_path):
    """Elapsed EQUAL to the deadline is due. A clock parked there forever
    must fire; a strict comparison would wait for ever."""
    now = {"t": 0.0}
    h = _Harness(tmp_path, 5.0, monotonic=lambda: now["t"])
    h.dog.start()
    now["t"] = 5.0
    assert h.exited.wait(10), "elapsed == deadline did not fire"
    assert h.exits == [2]


def test_the_row_rounds_its_duration_to_milliseconds(tmp_path):
    """The deadline's row reads like every other consumer row
    (`_record_consumer_run` rounds to 3 places): the duration since
    `begin`, not since the drain started."""
    now = {"t": 0.0}
    h = _Harness(tmp_path, 2.0, monotonic=lambda: now["t"])
    now["t"] = 1.0
    h.dog.begin(h.root, "item-1", "mutation", "run-1", HEAD)
    h.dog.start()
    now["t"] = 2.23456
    assert h.exited.wait(10)
    [row] = _rows(h.root)
    assert row["duration_s"] == 1.235


def test_the_deadline_names_the_consumer_and_the_repo_it_stopped(tmp_path, capsys):
    """The stderr line is what the operator reads in the task's log: which
    consumer was stopped, on which repo. Pinned whole -- the 2026-09-28 14Z
    drain confirmed `flight[0]` -> `flight[1]` (the item id in place of the
    repo) as a survivor, because nothing read the line."""
    now = {"t": 0.0}
    h = _Harness(tmp_path, 7.0, monotonic=lambda: now["t"])
    h.dog.begin(h.root, "item-1", "mutation", "run-1", HEAD)
    h.dog.start()
    now["t"] = 7.0
    assert h.exited.wait(10)
    assert capsys.readouterr().err.splitlines() == [
        "aramid drain: hard deadline reached after 7 s ([drain].hard_deadline_s = 7); "
        f"stopped mutation on {h.root}; the item stays queued"]
