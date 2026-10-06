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
    stored = json.loads(path.read_text(encoding="utf-8"))
    mac = stored.pop("mac")
    assert len(mac) == 64 and int(mac, 16) >= 0
    assert stored == {
        "schema": 1, "v": 1, "root": os.path.normcase(os.path.realpath(tmp_path)),
        "written_at": "2026-10-06T08:00:00+00:00", "head": sha,
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


# ---- fix round 3: provenance (a signed handover; nothing else is delivered) --

KEY_FILE = "handover.key"


def _hand_signed(root, **changes):
    """A file with a genuine MAC over hand-chosen fields (shape tests)."""
    fields = {"v": 1, "root": os.path.normcase(os.path.realpath(root)),
              "written_at": "2026-10-06T08:00:00+00:00", "head": None,
              "author": None, "body": "x"}
    fields.update(changes)
    key = handover._load_key(create=True)
    data = dict(fields, schema=1, mac=handover._mac(key, fields))
    (Path(root) / ".aramid").mkdir(exist_ok=True)
    (Path(root) / ".aramid" / "handover.json").write_text(json.dumps(data), encoding="utf-8")


def _raw(root, text):
    (Path(root) / ".aramid").mkdir(exist_ok=True)
    (Path(root) / ".aramid" / "handover.json").write_text(text, encoding="utf-8")


def _unreadable(root):
    with pytest.raises(handover.Unreadable) as exc:
        handover.read(root)
    return exc.value


def test_the_key_path_is_isolated_under_tmp_path_for_every_test(tmp_path):
    assert handover.key_path() == tmp_path / KEY_FILE
    assert handover.KEY_ENV == "ARAMID_HANDOVER_KEY_FILE"


def test_the_key_path_defaults_to_the_home_aramid_dir(monkeypatch):
    monkeypatch.delenv(handover.KEY_ENV)
    assert handover.key_path() == Path.home() / ".aramid" / "handover.key"
    monkeypatch.setenv(handover.KEY_ENV, "")
    assert handover.key_path() == Path.home() / ".aramid" / "handover.key"


def test_a_null_head_and_author_read_when_signed(tmp_path):
    _hand_signed(tmp_path)
    assert handover.read(tmp_path) == handover.Pending(
        "2026-10-06T08:00:00+00:00", None, None, "x")


def test_the_key_is_32_random_bytes_created_by_the_first_write(tmp_path):
    assert not handover.key_path().exists()
    handover.write(tmp_path, "x", now=NOW)
    key = handover.key_path().read_bytes()
    assert len(key) == 32
    handover.write(tmp_path, "y", replace=True, now=NOW)
    assert handover.key_path().read_bytes() == key


def test_read_never_creates_the_key(tmp_path):
    assert handover.read(tmp_path) is None
    _raw(tmp_path, json.dumps({"body": "x"}))
    _unreadable(tmp_path)
    assert not handover.key_path().exists()


def test_route_a_hand_written_file_in_a_dir_with_no_git_is_unsigned(tmp_path):
    _raw(tmp_path, json.dumps({"schema": 1, "written_at": "2026-10-06T08:00:00+00:00",
                               "head": None, "author": None, "body": "planted"}))
    err = _unreadable(tmp_path)
    assert "unsigned" in err.reason and "not written by aramid on this machine" in err.reason
    assert err.pending == handover.Pending("2026-10-06T08:00:00+00:00", None, None, "planted")


def test_route_a_force_committed_file_in_a_git_repo_is_unsigned(tmp_path):
    _git(tmp_path)
    _raw(tmp_path, json.dumps({"schema": 1, "written_at": "2026-10-06T08:00:00+00:00",
                               "body": "planted"}))
    subprocess.run(["git", "add", "-f", ".aramid/handover.json"], cwd=tmp_path, check=True)
    assert "unsigned" in _unreadable(tmp_path).reason


@pytest.mark.parametrize("name", [".aramid/Handover.json", ".ARAMID/handover.json"])
def test_route_a_case_variant_tracked_entry_is_unsigned(tmp_path, name):
    _git(tmp_path)
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=tmp_path, input="x",
                          check=True, capture_output=True, text=True).stdout.strip()
    subprocess.run(["git", "update-index", "--add", "--cacheinfo", f"100644,{blob},{name}"],
                   cwd=tmp_path, check=True)
    _raw(tmp_path, json.dumps({"written_at": "2026-10-06T08:00:00+00:00", "body": "planted"}))
    assert "unsigned" in _unreadable(tmp_path).reason


def test_route_a_gitlink_aramid_dir_is_unsigned(tmp_path):
    _git(tmp_path)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True,
                         capture_output=True, text=True).stdout.strip()
    subprocess.run(["git", "update-index", "--add", "--cacheinfo", f"160000,{sha},.aramid"],
                   cwd=tmp_path, check=True)
    _raw(tmp_path, json.dumps({"written_at": "2026-10-06T08:00:00+00:00", "body": "planted"}))
    assert "unsigned" in _unreadable(tmp_path).reason


def test_route_a_genuine_handover_copied_into_another_repo_is_refused(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    handover.write(a, "from a", now=NOW)
    (b / ".aramid").mkdir(parents=True)
    (b / ".aramid" / "handover.json").write_bytes((a / ".aramid" / "handover.json").read_bytes())
    err = _unreadable(b)
    assert "written for another repo" in err.reason
    assert os.path.normcase(os.path.realpath(a)) in err.reason
    assert err.pending.body == "from a"


def test_route_a_flipped_body_byte_fails_the_signature(tmp_path):
    p = handover.write(tmp_path, "do the safe thing", now=NOW)
    data = json.loads(p.read_text(encoding="utf-8"))
    data["body"] = "do the evil thing"
    p.write_text(json.dumps(data), encoding="utf-8")
    err = _unreadable(tmp_path)
    assert "signature does not match" in err.reason and err.pending.body == "do the evil thing"


def test_route_a_deleted_key_cannot_verify(tmp_path):
    handover.write(tmp_path, "x", now=NOW)
    handover.key_path().unlink()
    err = _unreadable(tmp_path)
    assert "no handover key on this machine" in err.reason
    assert err.pending.body == "x"
    assert not handover.key_path().exists()


def test_route_a_corrupt_key_cannot_verify_and_is_never_regenerated(tmp_path):
    handover.write(tmp_path, "x", now=NOW)
    handover.key_path().write_bytes(b"k" * 31)
    assert "key corrupt" in _unreadable(tmp_path).reason
    assert handover.key_path().read_bytes() == b"k" * 31


def test_write_refuses_over_a_corrupt_key_naming_it(tmp_path):
    handover.key_path().write_bytes(b"short")
    with pytest.raises(handover.KeyCorrupt) as exc:
        handover.write(tmp_path, "x", now=NOW)
    assert exc.value.path == handover.key_path()
    assert str(handover.key_path()) in str(exc.value) and "new key" in str(exc.value)
    assert handover.key_path().read_bytes() == b"short"
    assert not (tmp_path / ".aramid" / "handover.json").exists()


def test_route_an_oversized_file_is_unreadable_too_large(tmp_path):
    _raw(tmp_path, "x" * (1_048_576 + 1))
    err = _unreadable(tmp_path)
    assert "too large" in err.reason and err.pending is None


def test_a_file_at_exactly_the_cap_is_read_not_refused_as_large(tmp_path):
    _raw(tmp_path, " " * (1_048_576 - 2) + "[]")
    assert "too large" not in _unreadable(tmp_path).reason


def test_a_corrupt_file_has_no_pending(tmp_path):
    _raw(tmp_path, "{not json")
    assert _unreadable(tmp_path).pending is None


def test_control_a_genuine_write_is_delivered_with_head_and_author(tmp_path):
    sha = _git(tmp_path)
    handover.write(tmp_path, "resume", author="claude", now=NOW)
    assert handover.read(tmp_path) == handover.Pending(
        "2026-10-06T08:00:00+00:00", sha, "claude", "resume")


def test_control_a_genuine_handover_survives_a_reread_and_archive(tmp_path):
    handover.write(tmp_path, "resume", now=NOW)
    assert handover.read(tmp_path).body == handover.read(tmp_path).body == "resume"
    archived = handover.done(tmp_path)
    assert json.loads(archived.read_text(encoding="utf-8"))["body"] == "resume"


def test_an_unverified_pending_file_is_archived_never_deleted(tmp_path):
    _raw(tmp_path, json.dumps({"written_at": "2026-10-06T08:00:00+00:00", "body": "planted"}))
    archived = handover.done(tmp_path)
    assert json.loads(archived.read_text(encoding="utf-8"))["body"] == "planted"
    assert handover.read(tmp_path) is None


def test_a_signature_binds_the_head_and_author_fields(tmp_path):
    _git(tmp_path)
    p = handover.write(tmp_path, "x", author="claude", now=NOW)
    data = json.loads(p.read_text(encoding="utf-8"))
    data["author"] = "operator"
    p.write_text(json.dumps(data), encoding="utf-8")
    assert "signature does not match" in _unreadable(tmp_path).reason
