"""Gate runs in a registered repo's linked `git worktree` count for the repo
(interop round 343, operator decision 2026-11-23).

Measured on 0.20.19: a gate run in a worktree wrote its row under the
worktree's own path, which no registry entry names, so the judge dropped it
-- pivot-parlor read red and stale while every commit for nine days went
through its worktree pp-showcase. A row now records the main checkout of a
worktree (`worktree_of`); the judge counts it as that registered repo's row,
the newest row winning as always, and says which worktree it came from."""
import subprocess
from datetime import datetime, timedelta, timezone

from aramid import fleet, health
from aramid.fingerprint import normalize_path
from aramid.ledger import Ledger
from aramid.pipeline import GateResult

NOW_DT = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)
NOW = NOW_DT.isoformat()
MAIN, WT = "f:/projects/pivot-parlor", "f:/projects/pp-showcase"
REG = {MAIN: "pivot-parlor"}
POLICY = fleet.Policy(min_days=14, min_versions=2, max_row_age_days=7)


def _row(repo, days_ago, *, red=(), worktree_of=None):
    crit = {k: True for k in health.CRITERIA}
    crit["dep_audit_ran"] = None
    for k in red:
        crit[k] = False
    row = {"schema_version": 1, "at": (NOW_DT - timedelta(days=days_ago)).isoformat(),
           "repo": repo, "name": repo.rsplit("/", 1)[-1], "aramid_version": "0.20.20",
           "gate": "pre-push", "run_id": f"{repo[-1]}-{days_ago}", "exit_code": 0,
           "engine_error": False, "criteria": crit,
           "evidence": {"skip_streaks": {}, "degraded_consumers": [], "stood_down": [],
                        "no_work": [], "resolver_defects": [], "bad_tools": [],
                        "degraded_block_tier": False, "armed": {}, "open": 0,
                        "blocking": 0}}
    if worktree_of is not None:
        row["worktree_of"] = worktree_of
    return row


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _snapshot(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    result = GateResult(exit_code=0, findings=[], degraded=[], new_ids=[],
                        stale_overrides=[], run_id="run-1", tools_ran=("gitleaks",),
                        stacks=("python",))
    h = health.snapshot(None, lg, result, gate="pre-push")
    lg.close()
    return h


# ------------------------------------------------------------------ the row --

def test_a_worktree_s_row_names_its_main_checkout(tmp_path):
    m = tmp_path / "main"
    m.mkdir()
    for a in (["init", "-q", "-b", "main"], ["config", "user.email", "t@t"],
              ["config", "user.name", "t"], ["commit", "-q", "--allow-empty", "-m", "s"],
              ["worktree", "add", "-q", str(tmp_path / "wt"), "-b", "feature"]):
        _git(m, *a)
    h = _snapshot(tmp_path)

    row = fleet.build_row(tmp_path / "wt", h, aramid_version="0.20.20", now=NOW)
    main_row = fleet.build_row(m, h, aramid_version="0.20.20", now=NOW)

    assert row["repo"] == normalize_path(str((tmp_path / "wt").resolve()))
    assert row["worktree_of"] == normalize_path(str(m.resolve()))
    assert "worktree_of" not in main_row


def test_a_git_that_cannot_answer_leaves_the_row_whole(tmp_path, monkeypatch):
    """The row is written all the same, uncredited: a timed-out git must not
    cost the row (`record_health` would skip it on a raise)."""
    from aramid import gitutil

    def hung(root):
        raise gitutil.GitTimeout("git rev-parse timed out")
    monkeypatch.setattr(gitutil, "main_checkout", hung)

    row = fleet.build_row(tmp_path, _snapshot(tmp_path), aramid_version="0.20.20", now=NOW)

    assert "worktree_of" not in row and row["repo"]


# ---------------------------------------------------------------- the judge --

def test_the_judge_counts_a_worktree_row_for_the_registered_repo():
    rows = [_row(MAIN, 9, red=("no_skip_streak",)), _row(WT, 1, worktree_of=MAIN)]

    v = fleet.judge(rows, REG, POLICY, NOW)

    repo = v["repos"][MAIN]
    assert (repo["name"], repo["rows"], repo["green"], repo["stale"]) == (
        "pivot-parlor", 2, True, False)
    assert repo["latest_at"] == rows[1]["at"]
    assert repo["from_worktree"] == "pp-showcase"
    assert v["fleet"]["stale_repos"] == []


def test_the_newest_row_wins_whichever_checkout_wrote_it():
    rows = [_row(WT, 3, worktree_of=MAIN), _row(MAIN, 1, red=("no_skip_streak",))]

    repo = fleet.judge(rows, REG, POLICY, NOW)["repos"][MAIN]

    assert (repo["rows"], repo["green"], repo["red_criteria"]) == (
        2, False, ["no_skip_streak"])
    assert "from_worktree" not in repo


def test_a_worktree_of_an_unregistered_repo_counts_for_nothing():
    rows = [_row(MAIN, 1), _row(WT, 0, red=("no_skip_streak",),
                                worktree_of="f:/projects/elsewhere")]

    v = fleet.judge(rows, REG, POLICY, NOW)

    assert set(v["repos"]) == {MAIN}
    assert v["repos"][MAIN]["green"] is True and v["repos"][MAIN]["rows"] == 1


def test_a_registered_worktree_keeps_its_own_rows():
    """A worktree that is itself registered (an older aramid could do it) is
    a member of its own: its rows stay its own."""
    rows = [_row(MAIN, 1), _row(WT, 0, red=("no_skip_streak",), worktree_of=MAIN)]

    v = fleet.judge(rows, {**REG, WT: "pp-showcase"}, POLICY, NOW)

    assert (v["repos"][MAIN]["rows"], v["repos"][MAIN]["green"]) == (1, True)
    assert (v["repos"][WT]["rows"], v["repos"][WT]["green"]) == (1, False)


def test_a_row_written_before_worktree_of_counts_for_nothing():
    rows = [_row(MAIN, 9), _row(WT, 1)]

    repo = fleet.judge(rows, REG, POLICY, NOW)["repos"][MAIN]

    assert (repo["rows"], repo["stale"]) == (1, True)


def test_the_report_names_the_worktree_a_counted_row_came_from():
    v = fleet.judge([_row(WT, 1, worktree_of=MAIN)], REG, POLICY, NOW)

    out = fleet.render_report(v, POLICY, now=NOW)

    lines = out.splitlines()
    at = next(i for i, ln in enumerate(lines) if ln.startswith("  pivot-parlor "))
    assert lines[at + 1].strip() == "(latest row from worktree pp-showcase)"
