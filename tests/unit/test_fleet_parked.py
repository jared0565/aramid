"""Amendment A2, parked repos (spec 2026-11-27): a registered repo whose
latest row is green and older than the freshness window stops counting by
itself, and its next row counts it again and restarts the streak.
Table-driven on explicit timestamps; `now` is an argument, no sleeps. Each
test names the production change that would break it."""
from datetime import datetime, timedelta, timezone

from aramid import fleet, health

# tests/unit is not a package, so the row helper is repeated here rather
# than imported from test_fleet_judge.py. Keep the copies identical.
NOW_DT = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
NOW = NOW_DT.isoformat()
R_A, R_B, R_C, R_D, R_E = (f"f:/projects/{n}" for n in "abcde")
REG3 = {R_A: "a", R_B: "b", R_C: "c"}
REG4 = {**REG3, R_D: "d"}
REG5 = {**REG4, R_E: "e"}
P = fleet.Policy()          # the production default: 7-day window, floor of 3
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


def _weekly(repo, first, last, armed=None):
    """A row every 5 days from `first` to `last` days ago: inside the 7-day
    window throughout. 0.8.0 until 10 days ago, 0.9.0 from then on."""
    return [_row(repo, d, "0.8.0" if d > 10 else "0.9.0", armed=armed)
            for d in range(first, last - 1, -5)]


def _abc(armed=ARMED):
    return sum((_weekly(k, 20, 0, armed) for k in (R_A, R_B, R_C)), [])


def test_a_quiet_green_repo_parks_and_the_streak_carries_on():
    # Breaks if a green row past the window still blocks the verdict (A1).
    v = fleet.judge(_abc() + _weekly(R_D, 20, 10), REG4, P, NOW)
    assert v["verdict"] == "ready" and v["reasons"] == []
    assert v["fleet"]["streak_started_at"] == _at(20)
    assert v["fleet"]["active_repos"] == ["a", "b", "c"] and v["fleet"]["parked_repos"] == ["d"]
    assert v["fleet"]["stale_repos"] == []
    d = v["repos"][R_D]
    assert (d["parked"], d["parked_since"], d["stale"], d["green"]) == (
        True, "2026-09-17T12:00:00+00:00", False, True)
    assert v["repos"][R_A]["parked"] is False and v["repos"][R_A]["parked_since"] is None
    assert v["policy"] == {"min_days": 14, "min_versions": 2, "max_row_age_days": 7,
                           "min_active_repos": 3}


def test_a_returning_repo_restarts_the_streak_at_its_row_and_is_named():
    # Breaks if a parked repo's next row joins the open streak (decision 1).
    rows = _abc() + [_row(R_D, 20, "0.8.0"), _row(R_D, 2, "0.9.0")]
    v = fleet.judge(rows, REG4, P, NOW)
    assert v["fleet"]["streak_started_at"] == _at(2)
    assert v["fleet"]["returned_in_streak"] is True
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["streak 2.0d < 14d", "versions 1/2 in streak",
                            f"streak restarted by d returning at {_at(2)}"]


def test_a_red_return_row_leaves_no_streak():
    # Breaks if a return restarts the streak without asking whether the fleet is green.
    rows = _abc() + [_row(R_D, 20), _row(R_D, 2, red=("resolvers_ok",))]
    v = fleet.judge(rows, REG4, P, NOW)
    assert v["fleet"]["streak_started_at"] is None and v["verdict"] == "not-ready"
    assert v["reasons"] == ["d: resolvers_ok"]
    assert v["fleet"]["returned_in_streak"] is False


def test_a_red_repo_silent_past_the_window_never_parks():
    # Breaks if age alone parks a repo: a red repo would leave the count (decision 2).
    rows = _abc() + [_row(R_D, 9, red=("consumers_healthy",))]
    v = fleet.judge(rows, REG4, P, NOW)
    d = v["repos"][R_D]
    assert (d["parked"], d["parked_since"], d["stale"], d["green"]) == (False, None, True, False)
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["d: consumers_healthy", "stale: d (9.0d) -- window 7d"]
    assert v["fleet"]["stale_repos"] == ["d"] and v["fleet"]["parked_repos"] == []
    assert v["fleet"]["active_repos"] == ["a", "b", "c", "d"]


def test_the_floor_blocks_ready_and_the_policy_key_lowers_it():
    # Breaks if the fleet can shrink its way to `ready` (decision 3).
    rows = _weekly(R_A, 20, 0, ARMED) + _weekly(R_B, 20, 0)
    rows += _weekly(R_C, 20, 10) + _weekly(R_D, 20, 10) + _weekly(R_E, 20, 10)
    v = fleet.judge(rows, REG5, P, NOW)
    assert v["verdict"] == "not-ready" and v["reasons"] == ["active repos 2 < 3"]
    assert v["fleet"]["blockers"] == ["active repos 2 < 3"]
    low = fleet.Policy(min_active_repos=1)
    assert fleet.judge(rows, REG5, low, NOW)["verdict"] == "ready"


def test_three_active_two_parked_held_fourteen_days_is_ready():
    # Breaks if the floor counts registered repos, or a park resets the streak.
    rows = _abc() + _weekly(R_D, 20, 10) + _weekly(R_E, 20, 10)
    v = fleet.judge(rows, REG5, P, NOW)
    assert v["verdict"] == "ready" and v["fleet"]["parked_repos"] == ["d", "e"]
    assert v["fleet"]["all_green_now"] is True


def test_the_only_armed_repo_parking_leaves_nothing_armed():
    # Breaks if `armed_anywhere` reads a parked repo's old row.
    rows = _abc(armed=None) + _weekly(R_D, 20, 10, ARMED)
    v = fleet.judge(rows, REG4, P, NOW)
    assert v["fleet"]["armed_anywhere"] is False
    assert v["verdict"] == "not-ready" and v["reasons"] == ["no repo is armed"]


def test_a_repo_with_no_rows_waits_inside_the_window_and_parks_after_it():
    # Breaks if a never-gated repo blocks for ever, or stops blocking at once (decision 5).
    recent = fleet.judge(_abc(), REG4, P, NOW, registered_at={R_D: _at(3)})
    assert recent["verdict"] == "insufficient-data" and recent["reasons"] == ["no rows: d"]
    assert recent["repos"][R_D]["parked"] is False
    old = fleet.judge(_abc(), REG4, P, NOW, registered_at={R_D: _at(30)})
    assert old["verdict"] == "ready"
    assert old["repos"][R_D]["parked"] is True
    assert old["repos"][R_D]["parked_since"] == "2026-08-28T12:00:00+00:00"   # 30 - 7 days ago
    assert old["fleet"]["parked_repos"] == ["d"]


def test_an_unreadable_registered_at_waits_and_never_raises():
    # Breaks if a registry value of the wrong shape parks a repo or raises.
    future = (NOW_DT + timedelta(days=2)).isoformat()
    for bad in (None, {}, {R_D: ""}, {R_D: "t"}, {R_D: 7}, {R_D: future}):
        v = fleet.judge(_abc(), REG4, P, NOW, registered_at=bad)
        assert v["verdict"] == "insufficient-data" and v["reasons"] == ["no rows: d"], bad
    naive = fleet.judge(_abc(), REG4, P, NOW, registered_at={R_D: "2026-08-01T00:00:00"})
    assert naive["repos"][R_D]["parked"] is True       # a naive time is read as UTC, like a row's


def test_every_repo_parked_is_insufficient_data():
    # Breaks if an idle fleet keeps a streak or reads ready with nothing counted.
    rows = _weekly(R_A, 30, 10, ARMED) + _weekly(R_B, 30, 10)
    reg = {R_A: "a", R_B: "b"}
    v = fleet.judge(rows, reg, P, NOW)
    assert v["verdict"] == "insufficient-data" and v["reasons"] == ["no active repos"]
    assert v["fleet"]["active_repos"] == [] and v["fleet"]["parked_repos"] == ["a", "b"]
    assert v["fleet"]["streak_started_at"] is None and v["fleet"]["all_green_now"] is False
    assert v["fleet"]["days_held"] == 0.0
    zero = fleet.Policy(min_active_repos=0)
    assert fleet.judge(rows, reg, zero, NOW)["reasons"] == ["no active repos"]


def test_a_disabled_window_parks_nothing():
    # Breaks if parking ignores `max_row_age_days = 0`.
    rows = _weekly(R_A, 30, 10, ARMED) + _weekly(R_B, 30, 10) + _weekly(R_C, 30, 10)
    off = fleet.Policy(max_row_age_days=0)
    v = fleet.judge(rows, REG3, off, NOW, registered_at={R_A: _at(60)})
    assert v["verdict"] == "ready" and v["fleet"]["parked_repos"] == []
    assert all(r["parked"] is False and r["parked_since"] is None for r in v["repos"].values())
    # ...and a repo with no rows blocks however long ago it was registered.
    v = fleet.judge(rows, REG4, off, NOW, registered_at={R_D: _at(60)})
    assert v["reasons"] == ["no rows: d"]


def test_exactly_the_window_old_is_still_active():
    # Breaks if the comparison becomes `<` (A1's boundary).
    rows = _abc() + [_row(R_D, 7)]
    assert fleet.judge(rows, REG4, P, NOW)["repos"][R_D]["parked"] is False
    rows[-1]["at"] = _at(7.01)
    assert fleet.judge(rows, REG4, P, NOW)["repos"][R_D]["parked"] is True


def test_a_worktree_row_is_the_parked_repos_return():
    # Breaks if a worktree's row is not credited before membership is worked out.
    rows = _abc() + [_row(R_D, 20)]
    wt = {**_row("f:/projects/d-wt", 2), "worktree_of": R_D}
    v = fleet.judge(rows + [wt], REG4, P, NOW)
    assert v["repos"][R_D]["parked"] is False and v["fleet"]["streak_started_at"] == _at(2)


def test_a_vanished_repo_with_old_green_rows_is_missing_path_not_parked():
    # Breaks if a repo whose path is gone slips out of the verdict as parked.
    rows = _abc() + _weekly(R_D, 20, 10)
    v = fleet.judge(rows, REG4, P, NOW, vanished={R_D})
    d = v["repos"][R_D]
    assert (d["missing_path"], d["parked"], d["parked_since"]) == (True, False, None)
    assert v["fleet"]["parked_repos"] == [] and v["verdict"] == "insufficient-data"
    assert v["fleet"]["active_repos"] == ["a", "b", "c"]


def test_registration_times_maps_the_registry_key_to_its_time(tmp_path):
    # Breaks if the judge is handed a key the rows do not use, or a non-string time.
    entries = [{"path": str(tmp_path / "a"), "registered_at": "2026-09-01T00:00:00+00:00"},
               {"path": str(tmp_path / "b")},
               {"path": str(tmp_path / "c"), "registered_at": 5}]
    assert fleet.registration_times(entries) == {
        fleet.repo_key(tmp_path / "a"): "2026-09-01T00:00:00+00:00"}


# --- surfaces: the readiness line and `aramid fleet` -------------------------

def test_the_readiness_line_counts_active_repos_and_names_the_parked():
    # Breaks if a parked repo is counted in the line, or parked without being named.
    rows = _weekly(R_A, 20, 0, ARMED) + _weekly(R_B, 20, 0, ARMED)
    rows += [_row(R_C, 1, red=("consumers_healthy",))] + _weekly(R_D, 20, 10)
    rows += [_row(R_E, 20), _row(R_E, 9)]
    v = fleet.judge(rows, REG5, P, NOW, aramid_version="0.9.0")
    assert fleet.readiness_line(v) == (
        "fleet: 1.0 readiness NOT READY -- 2/3 active repos green, streak 0.0d, versions 0/2; "
        "red: c (consumers_healthy); parked: d (since 2026-09-17), e (since 2026-09-18)")


def test_the_readiness_line_of_a_fleet_with_nothing_parked_says_active_repos():
    # Breaks if the wording depends on whether something happens to be parked.
    v = fleet.judge(_abc(), REG3, P, NOW, aramid_version="0.9.0")
    assert fleet.readiness_line(v) == (
        "fleet: 1.0 readiness READY -- 3/3 active repos green, streak 20.0d, versions 2/2")


def test_the_fleet_report_annotates_a_parked_repo_and_prints_the_floor():
    # Breaks if `aramid fleet` shows a parked repo as an ordinary green row.
    v = fleet.judge(_abc() + _weekly(R_D, 20, 10), REG4, P, NOW)
    lines = fleet.render_report(v, P, now=NOW).splitlines()
    at = next(i for i, ln in enumerate(lines) if ln.startswith("  d "))
    assert lines[at + 1] == ("        (parked since 2026-09-17T12:00:00+00:00 -- no gate run in "
                             "7 days; its next one restarts the streak)")
    assert lines[lines.index("  armed anywhere: yes") + 1] == "  active repos: 3 (floor 3)"


def test_a_parked_repo_without_a_date_still_renders():
    # Breaks if either renderer indexes a parked_since that a torn verdict lacks.
    v = fleet.judge(_abc() + _weekly(R_D, 20, 10), REG4, P, NOW)
    v["repos"][R_D]["parked_since"] = None
    assert fleet.readiness_line(v).endswith("versions 2/2; parked: d")
    assert "        (parked -- its next gate run restarts the streak)" in fleet.render_report(
        v, P, now=NOW).splitlines()
