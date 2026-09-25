"""ledger.db carries its shape version in SQLite's `user_version` header
(1.0 blocker API-4), so a 1.x can tell a ledger written by a newer aramid
from a corrupt one -- and an event kind a newer 1.x adds never breaks an
older reader or moves the positions autolearn's rollup cursor counts."""
import sqlite3

import pytest

from aramid import ledger as ledger_mod
from aramid.ledger import LEDGER_SCHEMA_VERSION, Ledger, LedgerTooNew, UnknownEventType
from aramid.models import Event, EventType


def _version(db) -> int:
    c = sqlite3.connect(str(db))
    try:
        return c.execute("PRAGMA user_version").fetchone()[0]
    finally:
        c.close()


def _raw(db, *statements):
    c = sqlite3.connect(str(db))
    try:
        for sql, args in statements:
            c.execute(sql, args)
        c.commit()
    finally:
        c.close()


_INSERT = "INSERT INTO events(type,run_id,at,finding_id,payload) VALUES(?,?,?,?,?)"


def test_a_new_ledger_is_stamped_with_the_current_version(tmp_path):
    db = tmp_path / "l.db"
    Ledger(db).close()
    assert _version(db) == LEDGER_SCHEMA_VERSION == 1


def test_an_unversioned_ledger_is_stamped_on_open_and_keeps_its_rows(tmp_path):
    """Every ledger written before 0.19.0 reads user_version 0 over the same
    table: opening one stamps it and changes nothing else."""
    db = tmp_path / "l.db"
    c = sqlite3.connect(str(db))
    c.executescript(ledger_mod._SCHEMA)
    c.close()
    _raw(db, (_INSERT, ("run_started", "r0", "2026-01-01T00:00:00+00:00", None, "{}")))
    assert _version(db) == 0

    led = Ledger(db)
    try:
        assert [(e.type, e.run_id) for e in led.events()] == [(EventType.RUN_STARTED, "r0")]
    finally:
        led.close()
    assert _version(db) == 1


def test_a_current_ledger_reopens_without_writing_its_stamp_again(tmp_path, monkeypatch):
    """The stamp is written once per ledger. A ledger already at this
    version opens like any other -- it is not refused, and the open makes no
    write (gates and drains open the same ledger all day)."""
    db = tmp_path / "l.db"
    led = Ledger(db)
    led.append(Event(EventType.RUN_STARTED, "r1", "2026-01-01T00:00:00+00:00"))
    led.close()
    assert _version(db) == 1

    def must_not_write(conn):
        raise AssertionError("a current ledger was stamped again")

    monkeypatch.setattr(ledger_mod, "_stamp", must_not_write)
    led = Ledger(db)
    try:
        assert [e.run_id for e in led.events()] == ["r1"]
    finally:
        led.close()


def test_a_ledger_from_a_newer_aramid_is_refused_and_left_as_it_was(tmp_path):
    db = tmp_path / "l.db"
    Ledger(db).close()
    _raw(db, ("PRAGMA user_version = 2", ()))

    with pytest.raises(LedgerTooNew) as exc:
        Ledger(db)

    assert str(exc.value) == (
        f"{db} was written by a newer aramid (ledger schema 2; this one reads up "
        f"to 1) -- upgrade aramid to use it")
    assert _version(db) == 2, "never stamped down"


def test_a_stamp_that_cannot_be_written_now_does_not_fail_the_open(tmp_path, monkeypatch):
    """The stamp is the one write an open makes, once per ledger, and gates
    and drains overlap on this machine. A locked database at that moment must
    not fail an open that never used to write: the unstamped ledger reads as
    schema 0 over identical tables, and the next open stamps it."""
    db = tmp_path / "l.db"

    def locked(conn):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(ledger_mod, "_stamp", locked)
    led = Ledger(db)
    led.append(Event(EventType.RUN_STARTED, "r1", "2026-01-01T00:00:00+00:00"))
    led.close()
    assert _version(db) == 0

    monkeypatch.undo()
    Ledger(db).close()
    assert _version(db) == 1


def test_an_event_kind_a_newer_aramid_added_keeps_its_place_and_matches_nothing(tmp_path):
    """A newer 1.x may add event kinds (additive within a schema version).
    The row stays IN the list -- autolearn's rollup cursor is a count of it,
    so dropping rows would shift every position between versions -- typed as
    its own raw text, which no EventType member equals."""
    db = tmp_path / "l.db"
    led = Ledger(db)
    try:
        led.append(Event(EventType.RUN_STARTED, "r1", "2026-01-01T00:00:00+00:00"))
        _raw(db, (_INSERT, ("kind_from_a_newer_aramid", "r2", "2026-01-01T00:00:01+00:00",
                            "f1", '{"x": 1}')))
        led.append(Event(EventType.FINDING_DETECTED, "r3", "2026-01-01T00:00:02+00:00",
                         finding_id="f1", payload={"tool": "ruff"}))

        evs = led.events()

        assert [str(e.type) for e in evs] == [
            "run_started", "kind_from_a_newer_aramid", "finding_detected"]
        unknown = evs[1]
        assert isinstance(unknown.type, UnknownEventType)
        assert unknown.type.value == "kind_from_a_newer_aramid"
        assert not any(unknown.type == t or unknown.type is t for t in EventType)
        assert (unknown.run_id, unknown.finding_id, unknown.payload) == ("r2", "f1", {"x": 1})
        # The materializer compares `.value` on every row; the unknown one
        # must pass through it without effect.
        assert set(led.open_findings()) == {"f1"}
    finally:
        led.close()
