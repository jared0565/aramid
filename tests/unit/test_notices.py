"""aramid's own channel. Event-sourced like the ledger: nothing is rewritten,
'pending' is materialised, and a condition that re-posts maps to the SAME id
so it is deduplicated by construction."""
import hashlib
import json

from aramid import notices

T0 = "2026-09-03T10:00:00+00:00"
T1 = "2026-09-03T11:00:00+00:00"       # +1h
T2 = "2026-09-04T11:00:00+00:00"       # +25h


def _post(key="streak:x", kind="readiness-broken", now=T0, title="t"):
    return notices.post(kind, key, title=title, body="b", evidence={"k": 1}, now=now)


def test_id_is_the_first_12_hex_of_sha256_kind_colon_key():
    expected = hashlib.sha256(b"readiness-broken:run:abc").hexdigest()[:12]
    assert notices.notice_id("readiness-broken", "run:abc") == expected


def test_post_makes_a_pending_notice_with_the_spec_shape():
    nid = _post(key="run:abc")
    (n,) = notices.pending()
    assert n["id"] == nid
    assert set(n) == {"schema_version", "kind", "id", "notice_kind", "key", "at",
                      "title", "body", "evidence"}
    assert (n["kind"], n["notice_kind"], n["key"]) == ("notice", "readiness-broken", "run:abc")
    assert notices.pending_count() == 1


def test_a_second_post_with_the_same_key_is_deduplicated():
    assert _post(key="run:abc") is not None
    assert _post(key="run:abc") is None
    assert notices.pending_count() == 1
    assert sum(1 for e in notices.read_events() if e["kind"] == "notice") == 1


def test_ack_is_idempotent_and_unknown_id_is_refused():
    nid = _post()
    assert notices.ack(nid, repo="f:/p/a", now=T1) is True
    assert notices.ack(nid, repo="f:/p/b", now=T1) is True
    assert notices.pending() == []
    assert sum(1 for e in notices.read_events() if e["kind"] == "ack") == 1
    assert notices.ack("000000000000", repo="f:/p/a", now=T1) is False


def test_an_acked_condition_is_not_re_posted_while_uncleared():
    nid = _post(key="defect:r:resolver:x", kind="fleet-defect")
    notices.ack(nid, repo="f:/p/a", now=T1)
    assert _post(key="defect:r:resolver:x", kind="fleet-defect", now=T1) is None
    assert notices.pending() == []


def test_clear_then_recurrence_re_posts_under_the_same_id():
    nid = _post(key="defect:r:resolver:x", kind="fleet-defect")
    assert notices.clear(nid, reason="defect absent from latest row", now=T1) is True
    assert notices.pending() == []
    assert notices.clear(nid, reason="again", now=T1) is False
    assert _post(key="defect:r:resolver:x", kind="fleet-defect", now=T2) == nid
    (n,) = notices.pending()
    assert n["at"] == T2


def test_due_respects_repeat_hours_per_repo():
    nid = _post()
    assert [n["id"] for n in notices.due("f:/p/a", T0, 24)] == [nid]
    notices.mark_shown(nid, repo="f:/p/a", surface="session-start", now=T0)
    assert notices.due("f:/p/a", T1, 24) == []
    assert [n["id"] for n in notices.due("f:/p/b", T1, 24)] == [nid]
    assert [n["id"] for n in notices.due("f:/p/a", T2, 24)] == [nid]
    shown = [e for e in notices.read_events() if e["kind"] == "shown"]
    assert shown == [{"schema_version": 1, "kind": "shown", "id": nid, "at": T0,
                      "repo": "f:/p/a", "surface": "session-start"}]


def test_read_events_skips_garbage_with_one_note(capsys):
    p = notices.notices_path()
    p.parent.mkdir(parents=True)
    p.write_text("{oops\n" + json.dumps({"schema_version": 1, "kind": "notice", "id": "a" * 12,
                                          "notice_kind": "fleet-defect", "key": "k",
                                          "at": T0, "title": "t", "body": "b",
                                          "evidence": {}}) + "\n", encoding="utf-8")
    assert len(notices.pending()) == 1
    assert capsys.readouterr().err == \
        "aramid: fleet: skipped 1 unreadable row(s) in notices.jsonl\n"


def test_pending_count_is_none_when_the_store_cannot_be_read(monkeypatch):
    def boom(*a, **k):
        raise OSError("locked")
    monkeypatch.setattr(notices, "read_events", boom)
    assert notices.pending_count() is None


def test_render_line_full_shape():
    nid = _post(key="run:abc", title="Atlas_Data went red at 2026-09-03T10:11:00+00:00 "
                                     "(resolvers_ok: file_departed/mutation BLIND)")
    (n,) = notices.pending()
    assert notices.render_line(n) == (
        f"NOTICE {nid} readiness-broken: Atlas_Data went red at "
        f"2026-09-03T10:11:00+00:00 (resolvers_ok: file_departed/mutation BLIND)"
        f" -- ack: aramid notices ack {nid}")
