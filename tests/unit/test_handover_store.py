"""The handover store: one never-committed file per repo, archived (never
deleted) when consumed."""
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


# ---- fix round 1: symlinks, planted (tracked) files, and review minors ----


def _link(monkeypatch, link: Path, target: Path) -> None:
    """A real symlink where the OS allows one, else a stand-in that makes
    Path.is_symlink answer True for that path only (never skipped)."""
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
        return
    except (OSError, NotImplementedError):
        pass
    if target.is_dir():
        link.mkdir()
    else:
        link.write_text("", encoding="utf-8")
    real = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink",
                        lambda self: self == link or real(self))


def test_a_planted_tmp_name_symlink_is_never_written_through(tmp_path, monkeypatch):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    (tmp_path / "repo" / ".aramid").mkdir(parents=True)
    _link(monkeypatch, tmp_path / "repo" / ".aramid" / "handover.json.tmp", victim)
    handover.write(tmp_path / "repo", "x", now=NOW)
    assert victim.read_text(encoding="utf-8") == "precious"
    assert handover.read(tmp_path / "repo").body == "x"


def test_no_temp_file_is_left_after_a_write(tmp_path):
    handover.write(tmp_path, "x", now=NOW)
    assert sorted(p.name for p in (tmp_path / ".aramid").iterdir()) == ["handover.json"]


def test_a_failed_write_removes_its_temp_file(tmp_path, monkeypatch):
    (tmp_path / ".aramid").mkdir()
    monkeypatch.setattr(handover.os, "replace",
                        lambda *a: (_ for _ in ()).throw(OSError("boom")))
    with pytest.raises(OSError):
        handover.write(tmp_path, "x", now=NOW)
    assert list((tmp_path / ".aramid").iterdir()) == []


def test_a_symlinked_aramid_dir_is_refused_on_write(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    _link(monkeypatch, repo / ".aramid", outside)
    with pytest.raises(handover.UnsafePath) as exc:
        handover.write(repo, "x", now=NOW)
    assert exc.value.path == repo / ".aramid" and "symlink" in exc.value.reason
    assert list(outside.iterdir()) == []


def test_a_symlinked_handovers_dir_is_refused_on_archive(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    handover.write(repo, "x", now=NOW)
    outside = tmp_path / "outside"
    outside.mkdir()
    _link(monkeypatch, repo / ".aramid" / "handovers", outside)
    with pytest.raises(handover.UnsafePath):
        handover.done(repo)
    assert list(outside.iterdir()) == []
    assert (repo / ".aramid" / "handover.json").exists()


def test_a_planted_symlink_at_the_archive_name_is_not_written_through(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    handover.write(repo, "x", now=NOW)
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    (repo / ".aramid" / "handovers").mkdir()
    _link(monkeypatch, repo / ".aramid" / "handovers" / "2026-10-06T08-00-00+00-00.json",
          victim)
    archived = handover.done(repo)
    assert victim.read_text(encoding="utf-8") == "precious"
    assert archived.name != "2026-10-06T08-00-00+00-00.json"
    assert json.loads(archived.read_text(encoding="utf-8"))["body"] == "x"


def test_a_symlinked_handover_file_is_refused_on_read_and_write(tmp_path, monkeypatch):
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"body": "planted"}), encoding="utf-8")
    repo = tmp_path / "repo"
    (repo / ".aramid").mkdir(parents=True)
    _link(monkeypatch, repo / ".aramid" / "handover.json", target)
    with pytest.raises(handover.Unreadable) as exc:
        handover.read(repo)
    assert "symlink" in exc.value.reason
    with pytest.raises(handover.UnsafePath):
        handover.write(repo, "x", replace=True, now=NOW)
    assert json.loads(target.read_text(encoding="utf-8")) == {"body": "planted"}


def test_a_non_regular_handover_is_unreadable(tmp_path):
    (tmp_path / ".aramid" / "handover.json").mkdir(parents=True)
    with pytest.raises(handover.Unreadable) as exc:
        handover.read(tmp_path)
    assert "regular file" in exc.value.reason


def test_a_git_tracked_handover_is_unreadable(tmp_path):
    _git(tmp_path)
    handover.write(tmp_path, "planted", now=NOW)
    subprocess.run(["git", "add", "-f", ".aramid/handover.json"], cwd=tmp_path, check=True)
    with pytest.raises(handover.Unreadable) as exc:
        handover.read(tmp_path)
    assert "tracked by git" in exc.value.reason
    assert exc.value.path == tmp_path / ".aramid" / "handover.json"


def test_an_untracked_handover_in_a_git_repo_reads_normally(tmp_path):
    _git(tmp_path)
    handover.write(tmp_path, "mine", now=NOW)
    assert handover.read(tmp_path).body == "mine"


def test_a_handover_outside_a_git_repo_reads_normally(tmp_path):
    handover.write(tmp_path, "mine", now=NOW)
    assert handover.read(tmp_path).body == "mine"


def test_every_unreadable_carries_a_reason(tmp_path):
    (tmp_path / ".aramid").mkdir()
    (tmp_path / ".aramid" / "handover.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(handover.Unreadable) as exc:
        handover.read(tmp_path)
    assert exc.value.reason


@pytest.mark.parametrize("text", ["[]", '"x"', "3", "null"])
def test_a_non_dict_top_level_is_unreadable(tmp_path, text):
    (tmp_path / ".aramid").mkdir()
    (tmp_path / ".aramid" / "handover.json").write_text(text, encoding="utf-8")
    with pytest.raises(handover.Unreadable):
        handover.read(tmp_path)


def test_a_non_ascii_body_round_trips(tmp_path):
    handover.write(tmp_path, "café — 日本", now=NOW)
    assert handover.read(tmp_path).body == "café — 日本"


@pytest.mark.parametrize("secs,expected", [
    (59, "59s"), (60, "1m"), (3599, "59m"), (3600, "1h"), (86399, "23h"), (86400, "1d")])
def test_age_unit_boundaries(secs, expected):
    assert handover.age((NOW - timedelta(seconds=secs)).isoformat(), NOW) == expected


def test_age_accepts_a_naive_now():
    assert handover.age("2026-10-06T07:59:00+00:00", NOW.replace(tzinfo=None)) == "1m"


def test_a_huge_written_at_is_capped_in_the_archive_name(tmp_path):
    p = handover.write(tmp_path, "x", now=NOW)
    data = json.loads(p.read_text(encoding="utf-8"))
    data["written_at"] = "A" * 500
    p.write_text(json.dumps(data), encoding="utf-8")
    assert len(handover.done(tmp_path).name) <= 40 + len("-99.json")


# ---- fix round 2: git matches pathspecs case-sensitively; the FS may not ----

def _index_entry(root, name):
    """Put `name` in the index without needing the file (so the test means the
    same on a case-sensitive and a case-insensitive filesystem)."""
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=root, input="x",
                          check=True, capture_output=True, text=True).stdout.strip()
    subprocess.run(["git", "update-index", "--add", "--cacheinfo",
                    f"100644,{blob},{name}"], cwd=root, check=True)


@pytest.mark.parametrize("name", [
    ".aramid/Handover.json", ".ARAMID/handover.json", ".Aramid/HANDOVER.JSON",
    ".aramid/handover.json"])
def test_a_case_variant_tracked_handover_counts_as_tracked(tmp_path, name):
    _git(tmp_path)
    _index_entry(tmp_path, name)
    assert handover._tracked(tmp_path) is True


def test_a_case_variant_tracked_handover_makes_read_unreadable_where_the_fs_folds_case(
        tmp_path):
    _git(tmp_path)
    handover.write(tmp_path, "planted", now=NOW)
    _index_entry(tmp_path, ".ARAMID/Handover.json")
    if not (tmp_path / ".ARAMID" / "HANDOVER.JSON").exists():
        # case-sensitive FS: the planted name is a different file, so assert
        # the decision itself (the _tracked arms above cover every OS)
        assert handover._tracked(tmp_path) is True
        return
    with pytest.raises(handover.Unreadable) as exc:
        handover.read(tmp_path)
    assert "tracked by git" in exc.value.reason


def test_another_tracked_file_in_aramid_does_not_make_the_handover_tracked(tmp_path):
    _git(tmp_path)
    _index_entry(tmp_path, ".aramid/other.json")
    _index_entry(tmp_path, ".aramid/handover.json.bak")
    _index_entry(tmp_path, "handover.json")
    assert handover._tracked(tmp_path) is False
    handover.write(tmp_path, "mine", now=NOW)
    assert handover.read(tmp_path).body == "mine"
