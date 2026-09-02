"""The release workflow must not publish a commit that CI has not vetted.

`release.yml` runs its own artifact gates -- tag/version match, packaged data,
twine, wheel and sdist smoke tests -- but until now never asked whether the
`aramid` workflow (the seven-leg test matrix) had passed on the commit being
released. RELEASING.md step 4 said "wait for CI to be green"; that was a human
step. The v0.8.0 tag's own `aramid` run went red (a macOS runner was never
acquired) and the release proceeded regardless. Harmless that time, because
the same commit had been green on main two hours earlier -- but the coupling
was by convention, and a convention is not a gate.

`.github/scripts/require_green_ci.py` makes it mechanical. The `verify-ci`
job runs it before `release`, and it exits non-zero unless the `aramid`
workflow has a COMPLETED run with conclusion SUCCESS on the exact commit sha.
Any run on that sha counts -- the main-branch push or the tag push -- because
the verdict is about the commit's content, not about which ref carried it.

Run as a subprocess against a `--runs-json` snapshot so the CLI contract the
workflow invokes is what is pinned, not an importable function. `--timeout-
minutes 0` means "evaluate once"; the polling loop is exercised only by the
real workflow, where a matrix still running is the normal case.
"""
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "require_green_ci.py"
RELEASE_WF = ROOT / ".github" / "workflows" / "release.yml"
SCRIPT_REL = ".github/scripts/require_green_ci.py"

SHA = "501ed1e" + "0" * 33          # 40 hex characters, like a real head_sha
OTHER_SHA = "deadbee" + "0" * 33


def _run(runs, tmp_path, sha=SHA):
    snapshot = tmp_path / "runs.json"
    snapshot.write_text(json.dumps({"workflow_runs": runs}), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo", "jared0565/aramid", "--sha", sha,
         "--runs-json", str(snapshot), "--timeout-minutes", "0"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60, check=False)


def _r(status="completed", conclusion="success", sha=SHA, run_id=1, event="push"):
    return {"id": run_id, "status": status, "conclusion": conclusion,
            "head_sha": sha, "event": event,
            "html_url": f"https://github.com/jared0565/aramid/actions/runs/{run_id}"}


def test_the_script_exists_where_the_workflow_calls_it():
    """Non-vacuity. Every other test here shells out to this path."""
    assert SCRIPT.is_file(), f"no verifier at {SCRIPT}"


def test_a_completed_success_run_on_the_sha_passes(tmp_path):
    r = _run([_r(run_id=33507157788)], tmp_path)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "33507157788" in r.stdout          # names the run it is trusting


def test_a_red_tag_run_beside_a_green_main_run_on_the_same_sha_passes(tmp_path):
    """The exact v0.8.0 shape: the tag push's run lost its macOS runner and
    concluded `failure`; the main push of the same commit was green. The
    commit's content was vetted, so this must pass -- and must say which run
    it is trusting rather than the one it is ignoring."""
    runs = [_r(conclusion="failure", run_id=33518166859, event="push"),
            _r(conclusion="success", run_id=33507157788, event="push")]

    r = _run(runs, tmp_path)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "33507157788" in r.stdout


def test_only_failed_runs_fail_loudly(tmp_path):
    runs = [_r(conclusion="failure", run_id=7), _r(conclusion="cancelled", run_id=8)]

    r = _run(runs, tmp_path)

    assert r.returncode == 1
    assert "::error::" in r.stdout + r.stderr
    assert "failure" in r.stdout + r.stderr    # the conclusions are named
    assert "cancelled" in r.stdout + r.stderr


def test_no_runs_at_all_is_not_a_pass(tmp_path):
    """An empty list is what the API returns when the `aramid` workflow has
    not been queued for this sha yet, or when the sha is wrong. Neither is a
    reason to publish."""
    r = _run([], tmp_path)

    assert r.returncode == 1
    assert "::error::" in r.stdout + r.stderr
    assert "no " in (r.stdout + r.stderr).lower()


def test_a_still_running_matrix_is_reported_as_waiting_not_as_failed(tmp_path):
    """With the budget exhausted and the matrix still running the exit is
    non-zero, but the message must say the run is unfinished. `failed` here
    would send the operator to look for a red leg that does not exist."""
    r = _run([_r(status="in_progress", conclusion=None, run_id=9)], tmp_path)

    assert r.returncode == 1
    text = (r.stdout + r.stderr).lower()
    assert "in_progress" in text
    assert "timed out" in text
    assert "failed" not in text


def test_a_green_run_on_a_different_sha_does_not_count(tmp_path):
    """The API is asked to filter by head_sha; the script must not TRUST that
    it did. If the parameter were ignored, or the wrong sha handed in, a green
    run for some other commit would authorise this release."""
    r = _run([_r(conclusion="success", sha=OTHER_SHA, run_id=3)], tmp_path)

    assert r.returncode == 1


def test_a_success_conclusion_on_an_unfinished_run_does_not_count(tmp_path):
    """Both fields, not one. A run is vetted when it is COMPLETED with
    conclusion SUCCESS; a stray `success` on a queued run is malformed data,
    and malformed data must fail closed."""
    r = _run([_r(status="queued", conclusion="success", run_id=4)], tmp_path)

    assert r.returncode == 1


# --------------------------------------------------------- workflow wiring ---

def _jobs() -> dict:
    return yaml.safe_load(RELEASE_WF.read_text(encoding="utf-8"))["jobs"]


def _needs(job: dict) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def test_release_job_cannot_start_before_verify_ci():
    jobs = _jobs()
    assert "verify-ci" in jobs, "release.yml has no verify-ci job"
    assert "verify-ci" in _needs(jobs["release"]), (
        "the `release` job does not `needs: verify-ci`; the artifact gates "
        "would run -- and the GitHub Release be created -- on an unvetted commit")


def test_verify_ci_runs_the_tested_script_with_read_access_to_actions():
    """It must call THIS script (the one the tests above pin), and it needs
    `actions: read` to list workflow runs -- the workflow's top-level grant is
    `contents: write` only, so a job without its own grant gets a 403 that
    would read as 'no runs found'."""
    job = _jobs()["verify-ci"]
    commands = " ".join(str(s.get("run", "")) for s in job["steps"])
    assert SCRIPT_REL in commands
    assert job["permissions"]["actions"] == "read"


def test_the_irreversible_publish_transitively_depends_on_verify_ci():
    """`publish-pypi` needs `release`, which needs `verify-ci`. Walk it rather
    than assert the literal chain, so a job inserted between them keeps the
    guard honest."""
    jobs = _jobs()
    seen, frontier = set(), ["publish-pypi"]
    while frontier:
        name = frontier.pop()
        for dep in _needs(jobs[name]):
            if dep not in seen:
                seen.add(dep)
                frontier.append(dep)
    assert "verify-ci" in seen
