"""A registered repo whose path has gone is named `missing path:` whether or
not it ever recorded a row.

FN-1 named only a vanished repo with NO rows. Two scratch repos registered
on 2026-10-21 each wrote one row and were then deleted with their temp dir:
`aramid fleet` listed both as all `ok`, the verdict called them `stale
(9.3d)`, and every scheduled drain exited 2 skipping them, which only the
drain's discarded stderr said (2026-10-30). While such a repo's rows were
fresh it counted as green and could hold a streak."""
from datetime import datetime, timedelta, timezone

from aramid import fleet, health

R_A, R_B = "f:/projects/a", "f:/projects/b"
REG = {R_A: "a", R_B: "b"}
NOW_DT = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)
NOW = NOW_DT.isoformat()
DEFAULT = fleet.Policy()
GONE_B = "missing path: b (`aramid fleet deregister b`)"


def _row(repo, days_ago, version="0.20.10"):
    crit = {k: True for k in health.CRITERIA}
    crit["dep_audit_ran"] = None
    return {"schema_version": 1, "at": (NOW_DT - timedelta(days=days_ago)).isoformat(),
            "repo": repo, "name": repo.rsplit("/", 1)[-1], "aramid_version": version,
            "gate": "pre-push", "run_id": f"{repo[-1]}-{days_ago}", "exit_code": 0,
            "engine_error": False, "criteria": crit,
            "evidence": {"skip_streaks": {}, "degraded_consumers": [], "stood_down": [],
                         "no_work": [], "resolver_defects": [], "bad_tools": [],
                         "degraded_block_tier": False, "armed": {"semgrep_block_armed": True},
                         "open": 0, "blocking": 0}}


def _fresh_rows():
    """Both repos green every 6 days for 20 days, two versions: ready."""
    rows = []
    for days_ago in (20, 14, 8, 2):
        version = "0.20.9" if days_ago > 10 else "0.20.10"
        rows += [_row(R_A, days_ago, version), _row(R_B, days_ago, version)]
    return rows


def test_a_vanished_repo_with_fresh_green_rows_is_missing_path_not_green():
    assert fleet.judge(_fresh_rows(), REG, DEFAULT, NOW)["verdict"] == fleet.READY  # control

    v = fleet.judge(_fresh_rows(), REG, DEFAULT, NOW, vanished={R_B})

    assert v["verdict"] == fleet.INSUFFICIENT
    assert v["reasons"] == [GONE_B]
    assert v["repos"][R_B]["missing_path"] is True and v["repos"][R_B]["green"] is False
    assert v["repos"][R_B]["rows"] == 4
    assert "missing_path" not in v["repos"][R_A] and v["repos"][R_A]["green"] is True
    assert v["fleet"]["all_green_now"] is False
    assert v["fleet"]["streak_started_at"] is None and v["fleet"]["days_held"] == 0.0


def test_a_vanished_repo_with_old_rows_is_missing_path_not_stale():
    rows = [_row(R_A, 2), _row(R_B, 9.3)]
    assert fleet.judge(rows, REG, DEFAULT, NOW)["reasons"] == [
        "stale: b (9.3d) -- window 7d"]  # control: what the 10-30 verdict said

    v = fleet.judge(rows, REG, DEFAULT, NOW, vanished={R_B})

    assert v["verdict"] == fleet.INSUFFICIENT
    assert v["reasons"] == [GONE_B]


def test_the_readiness_line_names_the_missing_path_and_not_its_old_row():
    v = fleet.judge([_row(R_A, 2), _row(R_B, 9.3)], REG, DEFAULT, NOW, vanished={R_B})

    assert fleet.readiness_line(v) == (
        "fleet: 1.0 readiness INSUFFICIENT DATA -- 1/2 repos green, streak 0.0d, versions 0/2; "
        + GONE_B)


def test_the_readiness_line_names_a_vanished_repo_without_rows_as_missing_path():
    """FN-1's own case: the verdict said `missing path:` and the line every
    surface prints (status, the hooks) still said `no rows:`."""
    reg = {**REG, "f:/projects/c": "c"}
    v = fleet.judge(_fresh_rows(), reg, DEFAULT, NOW, vanished={"f:/projects/c"})

    line = fleet.readiness_line(v)

    assert line.endswith("; missing path: c (`aramid fleet deregister c`)"), line
    assert "no rows" not in line


def test_the_fleet_report_shows_a_missing_path_instead_of_its_old_cells():
    v = fleet.judge(_fresh_rows(), REG, DEFAULT, NOW, vanished={R_B})

    report = fleet.render_report(v, DEFAULT, now=NOW).splitlines()

    [b_line] = [ln for ln in report if ln.startswith("  b ")]
    assert "(missing path)" in b_line and "ok" not in b_line, b_line
    [a_line] = [ln for ln in report if ln.startswith("  a ")]
    assert "ok" in a_line, a_line
    assert f"  - {GONE_B}" in report
