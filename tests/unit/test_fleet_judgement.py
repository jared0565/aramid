"""The drain-time orchestration: judge, write the verdict atomically, post
exactly one notice per transition or persistent defect, clear what recovers,
compact old rows once a day, and never raise."""
import json
from datetime import datetime, timedelta, timezone

from aramid import fleet, health, notices

NOW_DT = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
NOW = NOW_DT.isoformat()
LATER = (NOW_DT + timedelta(hours=1)).isoformat()
# tests/unit is not a package, so the row helper is repeated here rather
# than imported from test_fleet_judge.py. Keep the two copies identical.
R_A, R_B = "f:/projects/a", "f:/projects/b"
ARMED = {"semgrep_block_armed": True}


def _at(days_ago: float) -> str:
    return (NOW_DT - timedelta(days=days_ago)).isoformat()


def _row(repo, days_ago, version="0.9.0", *, red=(), armed=None, run_id=None,
         dep=None, defects=()):
    crit = {k: True for k in health.CRITERIA}
    crit["dep_audit_ran"] = dep
    for k in red:
        crit[k] = False
    return {"schema_version": 1, "at": _at(days_ago), "repo": repo,
            "name": repo.rsplit("/", 1)[-1], "aramid_version": version,
            "gate": "pre-push", "run_id": run_id or f"{repo[-1]}-{days_ago}",
            "exit_code": 0, "engine_error": False, "criteria": crit,
            "evidence": {"skip_streaks": {}, "degraded_consumers": [], "stood_down": [],
                         "no_work": [], "resolver_defects": list(defects),
                         "bad_tools": [], "degraded_block_tier": False,
                         "armed": dict(armed or {}), "open": 0, "blocking": 0}}
ENTRIES = [{"path": "F:/projects/a", "registered_at": "t"},
           {"path": "F:/projects/b", "registered_at": "t"}]


def _seed(rows):
    for r in rows:
        fleet.append_row(r)


def _ready_rows():
    # An ACTIVE fleet: both repos push every 6 days (20, 14, 8, 2 days ago),
    # so these rows are ready under the production default window
    # (amendment A1) rather than by silence. Streak since _at(20), 20 days,
    # versions 0.8.0 then 0.9.0.
    return [_row(R_A, 20, "0.8.0", armed=ARMED), _row(R_B, 20, "0.8.0"),
            _row(R_A, 14, "0.8.0", armed=ARMED), _row(R_B, 14, "0.8.0"),
            _row(R_A, 8, "0.9.0", armed=ARMED), _row(R_B, 8, "0.9.0"),
            _row(R_A, 2, "0.9.0", armed=ARMED), _row(R_B, 2, "0.9.0")]


def _registered():
    return {fleet.repo_key(e["path"]): "a" if e["path"].endswith("a") else "b"
            for e in ENTRIES}


def _judge(now=NOW):
    # `registered_repos` resolves paths; the fixture rows use the same keys
    # `repo_key` produces for these entries on this machine.
    return fleet.run_judgement(now, aramid_version="0.9.0", entries=ENTRIES)


def _entries_rows(rows):
    keys = list(_registered())
    for r in rows:
        r["repo"] = keys[0] if r["repo"] == R_A else keys[1]
    return rows


def test_first_judgement_writes_the_verdict_file_atomically():
    _seed(_entries_rows(_ready_rows()))
    v = _judge()
    assert v["verdict"] == "ready"
    on_disk = json.loads(fleet.verdict_path().read_text(encoding="utf-8"))
    assert on_disk["verdict"] == "ready" and on_disk["compacted_at"] == NOW
    assert not fleet.verdict_path().with_name("fleet_verdict.json.tmp").exists()
    assert fleet.read_verdict() == on_disk


def test_reaching_readiness_posts_one_notice_and_only_once():
    _seed(_entries_rows(_ready_rows()))
    _judge()
    _judge(LATER)
    (n,) = notices.pending()
    assert n["notice_kind"] == "readiness-reached"
    assert n["key"] == "streak:" + _ready_rows()[0]["at"]
    assert n["title"] == ("1.0 readiness reached -- streak since " + _ready_rows()[0]["at"]
                          + " (20d, versions 0.8.0, 0.9.0) across 2 repos")


def test_losing_readiness_posts_readiness_broken_keyed_on_the_breaking_run():
    _seed(_entries_rows(_ready_rows()))
    _judge()
    (reached,) = notices.pending()
    assert reached["notice_kind"] == "readiness-reached"
    red = _row(R_A, 0.5, "0.9.0", red=("resolvers_ok",), armed=ARMED, run_id="red-run",
               defects=["file_departed/mutation BLIND"])
    _seed(_entries_rows([red]))
    v = _judge(LATER)
    assert v["verdict"] == "not-ready"
    kinds = sorted(n["notice_kind"] for n in notices.pending())
    assert kinds == ["readiness-broken"]
    broken = next(n for n in notices.pending() if n["notice_kind"] == "readiness-broken")
    assert broken["key"] == "run:red-run"
    assert broken["title"] == (f"a went red at {red['at']} "
                               "(resolvers_ok: file_departed/mutation BLIND)")
    cleared = [e for e in notices.read_events() if e["kind"] == "cleared"]
    assert any(e["id"] == reached["id"] and e["reason"] == "readiness lost" for e in cleared)


def test_regaining_readiness_clears_the_pending_broken_notice():
    """The counterpart transition, driven directly against `_post_transitions`
    (rather than a full row-based recovery streak) so the test stays a
    focused unit test of the clearing behaviour rather than a second
    end-to-end readiness rebuild."""
    broken_id = notices.post("readiness-broken", "run:x", title="t", body="b",
                             evidence={}, now=NOW)
    previous = {"verdict": "not-ready", "fleet": {"streak_started_at": None}}
    verdict = {"verdict": "ready", "repos": {},
              "fleet": {"streak_started_at": LATER, "days_held": 20.0,
                        "versions_in_streak": ["0.8.0", "0.9.0"]}}
    fleet._post_transitions(previous, verdict, LATER)
    kinds = sorted(n["notice_kind"] for n in notices.pending())
    assert kinds == ["readiness-reached"]
    cleared = [e for e in notices.read_events() if e["kind"] == "cleared"]
    assert any(e["id"] == broken_id and e["reason"] == "readiness regained" for e in cleared)


def test_persistent_defect_posts_one_notice_and_clears_on_recovery():
    rows = [_row(R_A, d, armed=ARMED, defects=["gap_addressed/mutation NEVER RAN"],
                 red=("resolvers_ok",)) for d in (4, 3, 2)]
    rows += [_row(R_B, 3)]
    _seed(_entries_rows(rows))
    _judge()
    defects = [n for n in notices.pending() if n["notice_kind"] == "fleet-defect"]
    assert len(defects) == 1
    key_a = list(_registered())[0]
    assert defects[0]["key"] == f"defect:{key_a}:resolver:gap_addressed/mutation"
    assert defects[0]["title"] == "a: resolver gap_addressed/mutation on the last 3 gate runs"
    _judge(LATER)                                    # still present: no second notice
    assert len([n for n in notices.pending() if n["notice_kind"] == "fleet-defect"]) == 1
    _seed(_entries_rows([_row(R_A, 0.1, armed=ARMED)]))   # recovered
    _judge(LATER)
    assert [n for n in notices.pending() if n["notice_kind"] == "fleet-defect"] == []
    cleared = [e for e in notices.read_events() if e["kind"] == "cleared"]
    assert cleared[0]["reason"] == "defect absent from latest row"


def test_two_rows_of_a_defect_are_not_yet_a_notice():
    rows = [_row(R_A, d, armed=ARMED, defects=["gap_addressed/mutation NEVER RAN"],
                 red=("resolvers_ok",)) for d in (3, 2)] + [_row(R_B, 3)]
    _seed(_entries_rows(rows))
    _judge()
    assert notices.pending() == []


def test_compaction_drops_rows_older_than_180_days_once_a_day():
    _seed(_entries_rows(_ready_rows() + [_row(R_A, 200, armed=ARMED)]))
    assert len(fleet.read_rows()) == 9
    _judge()
    assert len(fleet.read_rows()) == 8
    _seed(_entries_rows([_row(R_A, 199, armed=ARMED)]))
    _judge(LATER)                                    # within 24h: not rewritten
    assert len(fleet.read_rows()) == 9
    assert fleet.read_verdict()["compacted_at"] == NOW


def test_compaction_keeps_a_row_it_cannot_read():
    """Today `_maybe_compact` rewrites the store from the PARSED list
    `read_rows()` returns, and `read_rows()` (via `_read_jsonl`) silently
    drops any row whose `schema_version` is newer than this build's own --
    so the newer row is gone on the very first compaction an older aramid
    performs, not merely unjudged. The aged row -- readable, and genuinely
    past the retention window -- is the one meant to be dropped."""
    newer_schema = _row(R_B, 200, armed=ARMED)
    newer_schema["schema_version"] = 99
    aged = _row(R_A, 200, armed=ARMED)
    fresh = _row(R_A, 1, armed=ARMED)
    _seed(_entries_rows([newer_schema, aged, fresh]))
    _judge()
    kept = [json.loads(ln) for ln in
           fleet.health_path().read_text(encoding="utf-8").splitlines()]
    assert any(r.get("run_id") == newer_schema["run_id"] and r.get("schema_version") == 99
              for r in kept)
    assert not any(r.get("run_id") == aged["run_id"] for r in kept)
    assert any(r.get("run_id") == fresh["run_id"] for r in kept)


def test_over_budget_reports_and_writes_no_verdict(monkeypatch, capsys):
    _seed(_entries_rows(_ready_rows()))
    ticks = iter([0.0, 31.0, 31.0, 31.0])
    monkeypatch.setattr(fleet, "_monotonic", lambda: next(ticks))
    assert _judge() is None
    assert not fleet.verdict_path().exists()
    assert notices.pending() == []
    assert capsys.readouterr().err == \
        "aramid: fleet: judgement over the 30s budget; verdict not written\n"


def test_a_corrupt_verdict_file_reads_as_none_and_is_replaced():
    fleet.verdict_path().parent.mkdir(parents=True)
    fleet.verdict_path().write_text("{not json", encoding="utf-8")
    assert fleet.read_verdict() is None
    _seed(_entries_rows(_ready_rows()))
    assert _judge()["verdict"] == "ready"
    assert fleet.read_verdict()["verdict"] == "ready"


def test_an_unwritable_verdict_path_fails_open(capsys):
    fleet.verdict_path().mkdir(parents=True)         # a directory where the file goes
    _seed(_entries_rows(_ready_rows()))
    assert _judge() is None
    assert capsys.readouterr().err.startswith("aramid: fleet: judgement skipped (")


def test_the_no_breaking_row_readiness_broken_key_is_stable_across_retries():
    """A repeated failed write must not mint a new `at:<now>` id every
    retry: key the no-breaking-row fallback on the PRIOR verdict's streak
    start instead, which is stable across retries because the stale prior
    is exactly what keeps re-triggering the READY -> non-READY transition."""
    rows = _entries_rows(_ready_rows())
    registered = fleet.registered_repos(ENTRIES)
    prior = fleet.judge(rows, registered, fleet.load_policy(), NOW, aramid_version="0.9.0")
    assert prior["verdict"] == "ready"
    fleet.write_verdict(prior)
    prev_start = prior["fleet"]["streak_started_at"]
    a_key = next(k for k, n in registered.items() if n == "a")
    _seed([r for r in rows if r["repo"] == a_key])   # b has zero rows: insufficient-data, no breaking row
    tmp = fleet.verdict_path().with_name(fleet.verdict_path().name + ".tmp")
    tmp.mkdir(parents=True)                          # write_verdict's tmp target is a directory: every write fails
    assert fleet.run_judgement(NOW, aramid_version="0.9.0", entries=ENTRIES) is None
    assert fleet.run_judgement(LATER, aramid_version="0.9.0", entries=ENTRIES) is None
    broken = [n for n in notices.pending() if n["notice_kind"] == "readiness-broken"]
    assert len(broken) == 1
    assert broken[0]["key"] == f"streak:{prev_start}"


def test_going_stale_from_ready_posts_readiness_broken_on_the_prior_streak():
    """Amendment A1: a READY fleet left idle past the window reads
    insufficient-data with no breaking row, so the notice keys on the prior
    verdict's streak start (the existing no-breaking-row branch)."""
    _seed(_entries_rows(_ready_rows()))
    prior = _judge()
    assert prior["verdict"] == "ready"
    later = (NOW_DT + timedelta(days=6)).isoformat()      # latest rows are now 8 days old
    v = _judge(later)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["stale: a (8.0d), b (8.0d) -- window 7d"]
    broken = [n for n in notices.pending() if n["notice_kind"] == "readiness-broken"]
    assert len(broken) == 1
    assert broken[0]["key"] == "streak:" + prior["fleet"]["streak_started_at"]
    assert broken[0]["title"] == "fleet readiness lost -- stale: a (8.0d), b (8.0d) -- window 7d"
