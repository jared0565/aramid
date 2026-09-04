"""Streak and verdict math, table-driven on fixture rows with explicit
timestamps and versions. No sleeps: `now` is an argument."""
from datetime import datetime, timedelta, timezone

from aramid import fleet, health

R_A, R_B = "f:/projects/a", "f:/projects/b"
REG = {R_A: "a", R_B: "b"}
NOW_DT = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
NOW = NOW_DT.isoformat()
# The streak-math tests below place rows 10 to 20 days apart on purpose and
# predate amendment A1: they run with the freshness window DISABLED so they
# keep testing streak math alone. The A1 tests at the bottom use the
# production default (7 days).
POLICY = fleet.Policy(min_days=14, min_versions=2, max_row_age_days=0)
DEFAULT = fleet.Policy()


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


ARMED = {"semgrep_block_armed": True}


def _ready_rows():
    return [_row(R_A, 20, "0.8.0", armed=ARMED), _row(R_B, 20, "0.8.0"),
            _row(R_A, 10, "0.9.0", armed=ARMED), _row(R_B, 10, "0.9.0")]


def test_ready_when_every_condition_holds():
    v = fleet.judge(_ready_rows(), REG, POLICY, NOW, aramid_version="0.9.0")
    assert v["verdict"] == "ready"
    assert v["reasons"] == []
    assert v["fleet"]["streak_started_at"] == _at(20)
    assert v["fleet"]["days_held"] == 20.0
    assert v["fleet"]["versions_in_streak"] == ["0.8.0", "0.9.0"]
    assert v["fleet"]["armed_anywhere"] is True
    assert v["fleet"]["all_green_now"] is True
    assert v["repos"][R_A] == {"name": "a", "rows": 2, "latest_at": _at(10), "green": True,
                               "red_criteria": [], "stale": False, "age_days": 10.0,
                               "criteria": {**{k: True for k in health.CRITERIA},
                                            "dep_audit_ran": None}}
    assert v["fleet"]["stale_repos"] == []
    assert v["schema_version"] == 1 and v["computed_at"] == NOW
    assert v["policy"] == {"min_days": 14, "min_versions": 2, "max_row_age_days": 0}


def test_a_red_row_resets_the_streak_and_names_the_criterion():
    rows = _ready_rows() + [_row(R_A, 1, "0.9.0", red=("dep_audit_ran",), armed=ARMED,
                                 run_id="red-run", dep=False)]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["verdict"] == "not-ready"
    assert v["fleet"]["streak_started_at"] is None and v["fleet"]["days_held"] == 0.0
    assert v["reasons"] == ["a: dep_audit_ran"]
    assert v["repos"][R_A]["red_criteria"] == ["dep_audit_ran"]
    assert v["fleet"]["breaking_row"] == {"repo": R_A, "name": "a", "at": _at(1),
                                          "run_id": "red-run",
                                          "red_criteria": ["dep_audit_ran"],
                                          "detail": "dep_audit_ran: pip-audit did not run"}


def test_streak_restarts_on_the_next_green_row():
    rows = _ready_rows() + [_row(R_A, 5, red=("resolvers_ok",), armed=ARMED,
                                 defects=["gap_addressed/mutation NEVER RAN"]),
                            _row(R_A, 2, armed=ARMED)]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["fleet"]["streak_started_at"] == _at(2)
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["streak 2.0d < 14d", "versions 1/2 in streak"]


def test_a_registered_repo_without_rows_is_insufficient_data():
    v = fleet.judge(_ready_rows(), {**REG, "f:/projects/c": "c"}, POLICY, NOW)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["no rows: c"]
    assert v["fleet"]["streak_started_at"] is None
    assert v["repos"]["f:/projects/c"] == {"name": "c", "rows": 0, "latest_at": None,
                                           "green": False, "red_criteria": [],
                                           "criteria": {}, "stale": False, "age_days": None}


def test_versions_count_only_inside_the_streak():
    rows = [_row(R_A, 30, "0.7.0", armed=ARMED), _row(R_B, 30, "0.7.0", red=("no_skip_streak",)),
            _row(R_A, 20, "0.9.0", armed=ARMED), _row(R_B, 20, "0.9.0")]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["fleet"]["streak_started_at"] == _at(20)
    assert v["fleet"]["versions_in_streak"] == ["0.9.0"]
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["versions 1/2 in streak"]


def test_min_days_boundary():
    rows = [_row(R_A, 13.9, "0.8.0", armed=ARMED), _row(R_B, 13.9, "0.8.0"),
            _row(R_A, 1, "0.9.0", armed=ARMED)]
    short = fleet.judge(rows, REG, POLICY, NOW)
    assert short["verdict"] == "not-ready" and short["reasons"] == ["streak 13.9d < 14d"]
    rows[0]["at"] = rows[1]["at"] = _at(14)
    assert fleet.judge(rows, REG, POLICY, NOW)["verdict"] == "ready"


def test_no_armed_consumer_anywhere_blocks_readiness():
    rows = [_row(R_A, 20, "0.8.0"), _row(R_B, 20, "0.8.0"), _row(R_A, 1, "0.9.0")]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["fleet"]["armed_anywhere"] is False
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["no repo is armed"]


def test_a_disarm_inside_the_streak_restarts_it_at_that_row():
    rows = _ready_rows() + [_row(R_A, 3, "0.9.0", armed={"semgrep_block_armed": False},
                                 run_id="disarm"),
                            _row(R_B, 2, "0.9.0", armed=ARMED)]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["fleet"]["streak_started_at"] == _at(3)
    assert v["fleet"]["disarm_in_streak"] is True
    assert v["verdict"] == "not-ready"
    assert v["fleet"]["blockers"] == ["streak 3.0d < 14d", "versions 1/2 in streak"]
    assert v["fleet"]["notes"] == ["streak restarted by a disarming semgrep_block_armed at "
                                   + _at(3)]
    assert v["reasons"] == ["streak 3.0d < 14d", "versions 1/2 in streak",
                            "streak restarted by a disarming semgrep_block_armed at " + _at(3)]


def test_a_disarm_far_enough_back_can_still_reach_ready():
    rows = _ready_rows() + [_row(R_A, 15, "0.8.5", armed={"semgrep_block_armed": False},
                                 run_id="disarm-early")]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["verdict"] == "ready"
    assert v["fleet"]["blockers"] == []
    assert v["fleet"]["notes"] == ["streak restarted by a disarming semgrep_block_armed at "
                                   + _at(15)]
    assert v["fleet"]["disarm_in_streak"] is True


def test_rows_older_than_180_days_and_deregistered_repos_are_ignored():
    rows = _ready_rows() + [_row(R_A, 200, red=("consumers_healthy",)),
                            _row("f:/projects/gone", 1, red=("consumers_healthy",))]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["verdict"] == "ready"
    assert v["repos"][R_A]["rows"] == 2
    assert "f:/projects/gone" not in v["repos"]


def test_no_registered_repos_is_insufficient_data():
    v = fleet.judge([], {}, POLICY, NOW)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["no repos registered"]


def test_breaking_row_detail_names_every_red_criterion():
    row = _row(R_A, 1, red=("no_skip_streak", "consumers_healthy", "no_self_inflicted_block"),
               armed=ARMED, run_id="bad")
    row["evidence"].update({"skip_streaks": {"pre-push": {"semgrep": 2}},
                            "stood_down": ["mutation"], "bad_tools": ["gitleaks"]})
    v = fleet.judge(_ready_rows() + [row], REG, POLICY, NOW)
    assert v["fleet"]["breaking_row"]["detail"] == (
        "no_skip_streak: pre-push/semgrep x2; consumers_healthy: mutation; "
        "no_self_inflicted_block: gitleaks")


def test_a_fresh_verdicts_readiness_line_is_unchanged_by_now():
    v = fleet.judge(_ready_rows(), REG, POLICY, NOW, aramid_version="0.9.0")
    assert fleet.readiness_line(v) == fleet.readiness_line(v, now=NOW)
    assert fleet.readiness_line(v, now=None) == fleet.readiness_line(v, now=NOW)
    assert not fleet.readiness_line(v, now=NOW).endswith(")")


def test_registered_repos_uses_the_registry_key_and_basename(tmp_path):
    entries = [{"path": str(tmp_path / "Atlas_Data"), "registered_at": "t"}]
    assert fleet.registered_repos(entries) == {
        fleet.repo_key(tmp_path / "Atlas_Data"): "Atlas_Data"}


# --- Amendment A1: the freshness window -------------------------------------

def _active_rows(step=6, span=20):
    """Both repos push every `step` days for `span` days (20, 14, 8, 2 days
    ago): the cadence an active fleet has, every gap inside the default
    window, two versions across the run."""
    rows = []
    for days_ago in range(span, -1, -step):
        version = "0.8.0" if days_ago > span / 2 else "0.9.0"
        rows += [_row(R_A, days_ago, version, armed=ARMED), _row(R_B, days_ago, version)]
    return rows


def test_default_window_lets_an_active_fleet_reach_ready():
    v = fleet.judge(_active_rows(), REG, DEFAULT, NOW, aramid_version="0.9.0")
    assert v["verdict"] == "ready"
    assert v["fleet"]["streak_started_at"] == _at(20) and v["fleet"]["days_held"] == 20.0
    assert v["fleet"]["stale_repos"] == []
    assert v["repos"][R_A]["stale"] is False and v["repos"][R_A]["age_days"] == 2.0
    assert v["policy"] == {"min_days": 14, "min_versions": 2, "max_row_age_days": 7}


def test_idle_past_the_window_is_insufficient_data_and_resets_the_streak():
    rows = _ready_rows()      # latest rows 10 days ago: green, two versions, 20 idle-held days
    v = fleet.judge(rows, REG, DEFAULT, NOW)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["stale: a (10.0d), b (10.0d) -- window 7d"]
    assert v["fleet"]["stale_repos"] == ["a", "b"]
    assert v["fleet"]["streak_started_at"] is None and v["fleet"]["days_held"] == 0.0
    assert v["fleet"]["all_green_now"] is False and v["fleet"]["blockers"] == []
    assert v["repos"][R_A]["stale"] is True and v["repos"][R_A]["age_days"] == 10.0
    # The same rows with the window disabled are the spec as first written: ready by silence.
    assert fleet.judge(rows, REG, POLICY, NOW)["verdict"] == "ready"


def test_exactly_window_old_is_still_fresh():
    rows = [_row(R_A, 20, "0.8.0", armed=ARMED), _row(R_B, 20, "0.8.0"),
            _row(R_A, 14, "0.9.0", armed=ARMED), _row(R_B, 14, "0.9.0"),
            _row(R_A, 7, "0.9.0", armed=ARMED), _row(R_B, 7, "0.9.0")]
    v = fleet.judge(rows, REG, DEFAULT, NOW)
    assert v["fleet"]["stale_repos"] == [] and v["verdict"] == "ready"
    rows[-1]["at"] = rows[-2]["at"] = _at(7.01)
    v = fleet.judge(rows, REG, DEFAULT, NOW)
    assert v["verdict"] == "insufficient-data" and v["fleet"]["stale_repos"] == ["a", "b"]


def test_a_cross_repo_gap_inside_the_walk_restarts_the_streak_at_the_return():
    # a pushes every 5 days; b is silent from day 20 to day 2, so the fleet
    # was stale from day 13 to day 2 and the streak cannot predate b's return.
    rows = [_row(R_A, d, "0.9.0", armed=ARMED) for d in (20, 15, 10, 5, 2)]
    rows += [_row(R_B, 20, "0.9.0"), _row(R_B, 2, "0.9.0")]
    v = fleet.judge(rows, REG, DEFAULT, NOW)
    assert v["fleet"]["stale_repos"] == []
    assert v["fleet"]["streak_started_at"] == _at(2)
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["streak 2.0d < 14d", "versions 1/2 in streak"]


def test_a_same_repo_gap_in_a_single_repo_fleet_restarts_the_streak():
    # No row falls inside the gap, so only the pre-apply check can see it.
    reg = {R_A: "a"}
    rows = [_row(R_A, 20, "0.8.0", armed=ARMED), _row(R_A, 2, "0.9.0", armed=ARMED)]
    v = fleet.judge(rows, reg, DEFAULT, NOW)
    assert v["fleet"]["streak_started_at"] == _at(2)
    assert v["fleet"]["versions_in_streak"] == ["0.9.0"]
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["streak 2.0d < 14d", "versions 1/2 in streak"]
    assert fleet.judge(rows, reg, POLICY, NOW)["verdict"] == "ready"


def test_no_rows_beats_stale_and_stale_beats_red():
    stale_and_red = _ready_rows() + [_row(R_A, 9, red=("dep_audit_ran",), armed=ARMED, dep=False)]
    v = fleet.judge(stale_and_red, REG, DEFAULT, NOW)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["a: dep_audit_ran", "stale: a (9.0d), b (10.0d) -- window 7d"]
    assert v["fleet"]["breaking_row"]["run_id"] == "a-9"
    v = fleet.judge(stale_and_red, {**REG, "f:/projects/c": "c"}, DEFAULT, NOW)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["a: dep_audit_ran", "no rows: c"]
    assert v["fleet"]["stale_repos"] == ["a", "b"]


def test_the_readiness_line_names_stale_repos_and_the_window():
    v = fleet.judge(_ready_rows(), REG, DEFAULT, NOW, aramid_version="0.9.0")
    assert fleet.readiness_line(v) == (
        "fleet: 1.0 readiness INSUFFICIENT DATA -- 2/2 repos green, streak 0d, versions 0/2; "
        "stale: a (10.0d), b (10.0d) -- window 7d")


def test_a_verdict_written_before_a1_renders_unchanged():
    v = fleet.judge(_ready_rows(), REG, POLICY, NOW, aramid_version="0.9.0")
    for repo in v["repos"].values():
        del repo["stale"], repo["age_days"]
    del v["fleet"]["stale_repos"], v["policy"]["max_row_age_days"]
    assert fleet.readiness_line(v) == (
        "fleet: 1.0 readiness READY -- 2/2 repos green, streak 20d, versions 2/2")
