"""FN-15: the drain lock has an owner and a lifetime.

Read 2026-09-28 while shipping FN-14: `_acquire_lock` broke a LIVE pid's
lock once it was older than 2 x 600 s -- a probe value from before the drain
had a deadline -- so a second drain 20 minutes into a 90-minute one ran
beside it; and `_release_lock` unlinked whatever lock file was there, so the
first of the two to finish deleted the other's. The lock now records the
deadline its drain is armed with, is held while its pid lives and it is
younger than that deadline plus a margin, and is released only by the pid
it names."""
import json
import os
import time

import pytest

from aramid import drain_limits
from aramid.commands import drain as drain_mod

_OTHER_PID = 4242


@pytest.fixture
def lock(tmp_path, monkeypatch):
    p = tmp_path / "drain.lock"
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: p)
    return p


def _write(p, **data):
    p.write_text(json.dumps(data), encoding="utf-8")


def _read(p):
    return json.loads(p.read_text(encoding="utf-8"))


def test_the_lock_records_the_deadline_its_drain_is_armed_with(lock):
    assert drain_mod._acquire_lock(5400.0) == lock
    data = _read(lock)
    assert data["pid"] == os.getpid()
    assert data["deadline_s"] == 5400.0


def test_a_live_drain_inside_its_deadline_keeps_its_lock(lock, monkeypatch):
    """25 minutes into a 90-minute drain, a drain armed with a shorter
    deadline asks. The HOLDER's deadline decides; the old rule judged it by
    the newcomer's 600 s probe, broke the lock and ran beside it."""
    monkeypatch.setattr(drain_mod, "_pid_alive", lambda pid: True)
    _write(lock, pid=_OTHER_PID, started_at=time.time() - 1500, deadline_s=5400.0)
    assert drain_mod._acquire_lock(600.0) is None
    assert _read(lock)["pid"] == _OTHER_PID


def test_a_live_pid_long_past_its_deadline_is_not_a_drain_any_more(lock, monkeypatch):
    """Its own watchdog stops a drain at the deadline; a pid still holding
    the lock an hour after that will never release it."""
    monkeypatch.setattr(drain_mod, "_pid_alive", lambda pid: True)
    _write(lock, pid=_OTHER_PID, started_at=time.time() - (600 + 3600), deadline_s=600.0)
    assert drain_mod._acquire_lock(5400.0) == lock
    assert _read(lock)["pid"] == os.getpid()


def test_a_lock_from_before_the_deadline_existed_reads_as_the_default(lock, monkeypatch):
    """An aramid <= 0.19.1 wrote no `deadline_s`. Its drain is judged
    against the default deadline: held at 25 minutes, broken well past 90."""
    monkeypatch.setattr(drain_mod, "_pid_alive", lambda pid: True)
    _write(lock, pid=_OTHER_PID, started_at=time.time() - 1500)
    assert drain_mod._acquire_lock(600.0) is None
    _write(lock, pid=_OTHER_PID,
           started_at=time.time() - (drain_limits.DEFAULT_HARD_DEADLINE_S + 3600))
    assert drain_mod._acquire_lock(5400.0) == lock


def test_the_lock_is_stale_on_the_instant_its_deadline_and_margin_are_spent(lock, monkeypatch):
    """Held one tick before `deadline_s + margin`, broken on it: a clock
    parked on the boundary pins the comparison real time never lands on."""
    monkeypatch.setattr(drain_mod, "_pid_alive", lambda pid: True)
    _write(lock, pid=_OTHER_PID, started_at=1000.0, deadline_s=600.0)
    boundary = 1000.0 + 600.0 + drain_mod._LOCK_MARGIN_S
    assert drain_mod._acquire_lock(5400.0, now=lambda: boundary - 0.5) is None
    assert drain_mod._acquire_lock(5400.0, now=lambda: boundary) == lock


@pytest.mark.parametrize("missing", ["pid", "started_at"])
def test_a_lock_missing_its_owner_or_its_start_is_stale(lock, monkeypatch, missing):
    """Nothing can say whose it is or how old: an unreadable lock."""
    monkeypatch.setattr(drain_mod, "_pid_alive", lambda pid: True)
    data = {"pid": _OTHER_PID, "started_at": time.time(), "deadline_s": 5400.0}
    del data[missing]
    _write(lock, **data)
    assert drain_mod._acquire_lock(5400.0) == lock


def test_a_dead_pid_releases_its_lock_at_once(lock, monkeypatch):
    monkeypatch.setattr(drain_mod, "_pid_alive", lambda pid: False)
    _write(lock, pid=_OTHER_PID, started_at=time.time() - 5, deadline_s=5400.0)
    assert drain_mod._acquire_lock(5400.0) == lock


def test_release_leaves_a_lock_another_drain_holds(lock):
    """The 2026-09-28 shape: the first drain to end deleted the second's."""
    _write(lock, pid=_OTHER_PID, started_at=time.time(), deadline_s=5400.0)
    drain_mod._release_lock(lock)
    assert lock.exists()
    assert _read(lock)["pid"] == _OTHER_PID


def test_release_removes_its_own_lock(lock):
    assert drain_mod._acquire_lock(5400.0) == lock
    drain_mod._release_lock(lock)
    assert not lock.exists()


def test_moving_the_deadline_moves_the_locks_lifetime(lock):
    """The watchdog is armed at the default and set from the candidates'
    `[drain].hard_deadline_s`, which may be longer. A lock still reading the
    default would be broken under a live drain an hour before its end."""
    assert drain_mod._acquire_lock(5400.0) == lock
    dog = drain_mod._Watchdog(5400.0, lock=lock, exit_=lambda code: None)
    dog.set_deadline(10800.0)
    data = _read(lock)
    assert data["deadline_s"] == 10800.0
    assert data["pid"] == os.getpid()


def test_moving_the_deadline_leaves_a_lock_it_does_not_own(lock):
    _write(lock, pid=_OTHER_PID, started_at=time.time(), deadline_s=5400.0)
    before = lock.read_text(encoding="utf-8")
    dog = drain_mod._Watchdog(5400.0, lock=lock, exit_=lambda code: None)
    dog.set_deadline(10800.0)
    assert lock.read_text(encoding="utf-8") == before
