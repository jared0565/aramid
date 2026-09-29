"""FN-19: taking, releasing and re-dating the drain lock are atomic.

The 02Z drain's llm-review of 2026-09-29 (`9f62bce6`) read `_acquire_lock`
as check-then-write: two drains starting together both see no lock (or
both judge the same one stale), both write one, and both run. The shape
predates FN-15 -- the lock was introduced that way. `_release_lock`
(read "is it mine?", then unlink) and `set_deadline` (read, then rewrite)
are the same check-then-act. Each now runs under an OS lock on a mutex
file beside the lock -- `msvcrt.locking` on Windows, `flock` elsewhere --
held for the critical section only, so the lock file keeps its meaning:
it exists while a drain runs, and holds that drain's JSON. The threads
below race in ONE process, which the real primitives refuse on both
platforms (a second handle conflicts; POSIX `lockf` would not)."""
import json
import os
import threading
import time
from types import SimpleNamespace

import pytest

from aramid.commands import drain as drain_mod


@pytest.fixture
def lock(tmp_path, monkeypatch):
    p = tmp_path / "drain.lock"
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: p)
    monkeypatch.setattr(drain_mod, "_pid_alive", lambda pid: pid == os.getpid())
    return p


def _read(p):
    return json.loads(p.read_text(encoding="utf-8"))


def _paused(monkeypatch, name, *, before):
    """Make the FIRST call to drain_mod.<name> stop until `go` is set --
    `before` the real call or after it, before it returns."""
    real = getattr(drain_mod, name)
    inside, go = threading.Event(), threading.Event()
    calls = []

    def pause():
        if len(calls) == 1:
            inside.set()
            go.wait(10)

    def wrapper(*a, **k):
        calls.append(a)
        if before:
            pause()
        out = real(*a, **k)
        if not before:
            pause()
        return out
    monkeypatch.setattr(drain_mod, name, wrapper)
    return inside, go


def _thread(fn):
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", fn()), daemon=True)
    t.start()
    return t, out


def test_two_drains_starting_together_get_one_lock(lock, monkeypatch):
    inside, go = _paused(monkeypatch, "_write_lock", before=True)
    first, first_out = _thread(lambda: drain_mod._acquire_lock(5400.0))
    assert inside.wait(10), "the first drain never reached its write"

    second, second_out = _thread(lambda: drain_mod._acquire_lock(5400.0))
    time.sleep(0.3)
    go.set()
    first.join(20)
    second.join(20)

    winners = [r for r in (first_out.get("r"), second_out.get("r")) if r is not None]
    assert winners == [lock], f"both drains took the lock: {first_out}, {second_out}"
    assert (lock.parent / "drain.lock.mutex").exists(), "the mutex file is never deleted"


def test_a_release_cannot_delete_the_lock_a_newer_drain_just_took(lock, monkeypatch):
    """A drain past its deadline plus the margin releases while a new drain
    breaks its lock as stale. Read "mine", new lock written, unlink: the
    new drain's lock went, and a third drain could start beside it."""
    assert drain_mod._acquire_lock(60.0) == lock
    inside, go = _paused(monkeypatch, "_read_own_lock", before=False)
    old, _ = _thread(lambda: drain_mod._release_lock(lock))
    assert inside.wait(10), "the release never read the lock"

    later = time.time() + 60 + drain_mod._LOCK_MARGIN_S + 5
    new, new_out = _thread(lambda: drain_mod._acquire_lock(5400.0, now=lambda: later))
    time.sleep(0.3)
    go.set()
    old.join(20)
    new.join(20)

    assert new_out.get("r") == lock
    assert lock.exists(), "the old drain's release deleted the new drain's lock"
    assert _read(lock)["started_at"] == later


def test_set_deadline_waits_for_the_mutex(lock):
    assert drain_mod._acquire_lock(5400.0) == lock
    watchdog = SimpleNamespace(_lock=lock, _deadline_s=5400.0)
    with drain_mod._lock_mutex(lock) as held:
        assert held
        t, _ = _thread(lambda: drain_mod._Watchdog.set_deadline(watchdog, 900.0))
        time.sleep(0.3)
        assert _read(lock)["deadline_s"] == 5400.0, "re-dated the lock inside another's critical section"
    t.join(20)
    assert _read(lock)["deadline_s"] == 900.0


def test_a_busy_mutex_starts_no_drain(lock, monkeypatch):
    """A mutex held past the timeout is a process hung inside a critical
    section: no drain starts, not even over a lock that is stale."""
    monkeypatch.setattr(drain_mod, "_MUTEX_TIMEOUT_S", 0.3)
    lock.write_text(json.dumps({"pid": 4242, "started_at": time.time(), "deadline_s": 60.0}),
                    encoding="utf-8")
    before = lock.read_bytes()
    with drain_mod._lock_mutex(lock) as held:
        assert held
        t, out = _thread(lambda: drain_mod._acquire_lock(5400.0))
        t.join(20)
    assert out["r"] is None, "started a drain without the mutex"
    assert lock.read_bytes() == before


def test_a_busy_mutex_releases_nothing(lock, monkeypatch):
    """No lock is removed without the mutex; one whose pid has died is
    broken as stale by the next drain."""
    monkeypatch.setattr(drain_mod, "_MUTEX_TIMEOUT_S", 0.3)
    assert drain_mod._acquire_lock(5400.0) == lock
    before = lock.read_bytes()
    with drain_mod._lock_mutex(lock) as held:
        assert held
        t, _ = _thread(lambda: drain_mod._release_lock(lock))
        t.join(20)
    assert lock.exists() and lock.read_bytes() == before, "released a lock without the mutex"


def test_the_mutex_is_tried_once_then_every_poll_until_the_timeout(tmp_path, monkeypatch):
    tries, sleeps = [], []
    monkeypatch.setattr(drain_mod, "_try_lock", lambda fd: tries.append(fd) or False)
    monkeypatch.setattr(drain_mod, "_sleep", sleeps.append)
    monkeypatch.setattr(drain_mod, "_MUTEX_TIMEOUT_S", 0.3)
    monkeypatch.setattr(drain_mod, "_MUTEX_POLL_S", 0.05)

    with drain_mod._lock_mutex(tmp_path / "drain.lock") as held:
        assert held is False
    assert len(tries) == 7 and sleeps == [0.05] * 6


class _FakeMsvcrt:
    LK_NBLCK, LK_UNLCK = "NBLCK", "UNLCK"

    def __init__(self, refuse=False):
        self.calls, self.refuse = [], refuse

    def locking(self, fd, mode, n):
        self.calls.append((mode, n, os.lseek(fd, 0, os.SEEK_CUR)))
        if self.refuse:
            raise PermissionError(13, "locked")


class _FakeFcntl:
    LOCK_EX, LOCK_NB, LOCK_UN = 2, 4, 8

    def __init__(self, refuse=False):
        self.calls, self.refuse = [], refuse

    def flock(self, fd, op):
        self.calls.append(op)
        if self.refuse:
            raise BlockingIOError(11, "locked")


@pytest.fixture
def fd(tmp_path):
    f = os.open(tmp_path / "m", os.O_RDWR | os.O_CREAT)
    os.write(f, b"xxxxxx")
    yield f
    os.close(f)


def test_on_windows_the_mutex_is_one_byte_at_offset_zero(fd, monkeypatch):
    """Pinned with a fake so the ubuntu leg runs the Windows branch too."""
    fake = _FakeMsvcrt()
    monkeypatch.setattr(drain_mod, "_WIN", True)
    monkeypatch.setattr(drain_mod, "msvcrt", fake, raising=False)
    assert drain_mod._try_lock(fd) is True
    drain_mod._unlock(fd)
    assert fake.calls == [("NBLCK", 1, 0), ("UNLCK", 1, 0)]
    monkeypatch.setattr(drain_mod, "msvcrt", _FakeMsvcrt(refuse=True), raising=False)
    assert drain_mod._try_lock(fd) is False


def test_on_posix_the_mutex_is_an_exclusive_non_blocking_flock(fd, monkeypatch):
    """flock, not lockf/F_SETLK: POSIX record locks do not conflict within
    one process, and the races above are threads of one."""
    fake = _FakeFcntl()
    monkeypatch.setattr(drain_mod, "_WIN", False)
    monkeypatch.setattr(drain_mod, "fcntl", fake, raising=False)
    assert drain_mod._try_lock(fd) is True
    drain_mod._unlock(fd)
    assert fake.calls == [2 | 4, 8]
    monkeypatch.setattr(drain_mod, "fcntl", _FakeFcntl(refuse=True), raising=False)
    assert drain_mod._try_lock(fd) is False
