"""The handover store: one never-committed file per repo, archived (never
deleted) when consumed."""
import json
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from aramid import handover

NOW = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)


def _git(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "x", "--no-verify"], cwd=tmp_path, check=True)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True,
                          capture_output=True, text=True).stdout.strip()


def test_write_then_read_round_trips(tmp_path):
    sha = _git(tmp_path)
    path = handover.write(tmp_path, "resume step 3\n", author="claude", now=NOW)
    assert path == tmp_path / ".aramid" / "handover.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "schema": 1, "written_at": "2026-10-06T08:00:00+00:00", "head": sha,
        "author": "claude", "body": "resume step 3\n"}
    assert handover.read(tmp_path) == handover.Pending(
        "2026-10-06T08:00:00+00:00", sha, "claude", "resume step 3\n")


def test_read_with_nothing_pending_is_none(tmp_path):
    assert handover.read(tmp_path) is None


def test_write_refuses_an_empty_body(tmp_path):
    with pytest.raises(handover.EmptyBody):
        handover.write(tmp_path, "  \n\t", now=NOW)
    assert not (tmp_path / ".aramid" / "handover.json").exists()


def test_write_refuses_over_a_pending_one(tmp_path):
    handover.write(tmp_path, "first", now=NOW)
    before = (tmp_path / ".aramid" / "handover.json").read_bytes()
    with pytest.raises(handover.AlreadyPending):
        handover.write(tmp_path, "second", now=NOW)
    assert (tmp_path / ".aramid" / "handover.json").read_bytes() == before


def test_replace_archives_the_old_one_first(tmp_path):
    handover.write(tmp_path, "first", now=NOW)
    handover.write(tmp_path, "second", replace=True, now=NOW + timedelta(minutes=5))
    assert handover.read(tmp_path).body == "second"
    archived = sorted((tmp_path / ".aramid" / "handovers").iterdir())
    assert [json.loads(p.read_text(encoding="utf-8"))["body"] for p in archived] == ["first"]


def test_done_archives_and_returns_the_path(tmp_path):
    handover.write(tmp_path, "x", now=NOW)
    archived = handover.done(tmp_path)
    assert archived == tmp_path / ".aramid" / "handovers" / "2026-10-06T08-00-00+00-00.json"
    assert json.loads(archived.read_text(encoding="utf-8"))["body"] == "x"
    assert handover.read(tmp_path) is None


def test_done_with_nothing_pending_is_none(tmp_path):
    assert handover.done(tmp_path) is None


def test_two_archives_with_the_same_stamp_do_not_overwrite(tmp_path):
    handover.write(tmp_path, "a", now=NOW)
    first = handover.done(tmp_path)
    handover.write(tmp_path, "b", now=NOW)
    second = handover.done(tmp_path)
    assert first != second
    assert {json.loads(p.read_text(encoding="utf-8"))["body"]
            for p in (first, second)} == {"a", "b"}


def test_a_corrupt_file_reads_as_unreadable_not_a_crash(tmp_path):
    (tmp_path / ".aramid").mkdir()
    (tmp_path / ".aramid" / "handover.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(handover.Unreadable) as exc:
        handover.read(tmp_path)
    assert exc.value.path == tmp_path / ".aramid" / "handover.json"


def test_a_file_without_a_body_is_unreadable(tmp_path):
    (tmp_path / ".aramid").mkdir()
    (tmp_path / ".aramid" / "handover.json").write_text('{"schema": 1}', encoding="utf-8")
    with pytest.raises(handover.Unreadable):
        handover.read(tmp_path)


def test_head_is_none_outside_a_commit(tmp_path):
    handover.write(tmp_path, "x", now=NOW)              # not a git repo at all
    assert handover.read(tmp_path).head is None


@pytest.mark.parametrize("delta,expected", [
    (timedelta(seconds=42), "42s"), (timedelta(minutes=5, seconds=59), "5m"),
    (timedelta(hours=3, minutes=1), "3h"), (timedelta(days=2, hours=23), "2d"),
    (timedelta(seconds=0), "0s"),
])
def test_age_uses_the_largest_whole_unit(delta, expected):
    assert handover.age((NOW - delta).isoformat(), NOW) == expected


def test_age_of_a_future_or_garbage_stamp_is_unknown():
    assert handover.age((NOW + timedelta(hours=1)).isoformat(), NOW) == "unknown"
    assert handover.age("yesterday", NOW) == "unknown"


@pytest.mark.parametrize("field,value", [
    ("head", 5), ("head", ["x"]), ("author", 7), ("author", {"a": 1})])
def test_a_head_or_author_of_the_wrong_type_is_unreadable(tmp_path, field, value):
    (tmp_path / ".aramid").mkdir()
    data = {"schema": 1, "written_at": "2026-10-06T08:00:00+00:00", "body": "x", field: value}
    (tmp_path / ".aramid" / "handover.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(handover.Unreadable):
        handover.read(tmp_path)


def test_a_null_head_and_author_are_readable(tmp_path):
    (tmp_path / ".aramid").mkdir()
    data = {"schema": 1, "written_at": "2026-10-06T08:00:00+00:00", "body": "x",
            "head": None, "author": None}
    (tmp_path / ".aramid" / "handover.json").write_text(json.dumps(data), encoding="utf-8")
    assert handover.read(tmp_path) == handover.Pending(
        "2026-10-06T08:00:00+00:00", None, None, "x")
