"""Refuse to release a commit the `aramid` CI matrix has not passed on.

WHY THIS EXISTS. `release.yml` gates the ARTIFACT -- tag matches version,
packaged data present, twine check, wheel and sdist smoke-tested in clean
venvs -- but it never asked whether the CODE had passed CI. RELEASING.md step 4
said "wait for CI to be green", which is a human step. The v0.8.0 tag's own
`aramid` run went red (GitHub never acquired a macOS runner) and the release
published regardless. Harmless that time: the same commit had been green on
main two hours earlier. But nothing in the pipeline knew that, and nothing
would have stopped a tag on a commit that had never been green at all.

WHAT IT CHECKS. The `aramid` workflow's runs for the EXACT commit sha, via the
Actions API. Green means at least one run with `status == completed` AND
`conclusion == success`. Any run on that sha counts -- the main push, the tag
push, a re-run -- because the verdict is about the commit's content, not the
ref that carried it. A red run beside a green one is not a contradiction: the
v0.8.0 shape above is exactly a lost runner on one attempt and a full pass on
another. All runs finished and none green is terminal and fails at once; a
matrix still running is waited for, up to the budget.

WHY A FILE AND NOT AN INLINE STEP. So `tests/unit/test_require_green_ci.py`
can run it as a subprocess against a `--runs-json` snapshot and pin every
branch: the pass, the mixed case, all-red, nothing-yet, a run for a different
sha, and a `success` on a run that has not completed. A gate that only ever
runs on a release tag is a gate whose first real exercise is a release.

EXIT CODES. 0 -- a green run exists. 1 -- everything else: no green run within
the budget, every run red, the API refused. Nothing here exits 0 on "could not
tell"; that is the shape this repository exists to prevent.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote


def evaluate(runs: list, sha: str):
    """('green', run) | ('unfinished', runs) | ('red', runs), for runs on `sha`.

    Filters by head_sha itself even though the API was asked to: a gate that
    trusts its own query parameter would accept a green run for another commit
    if the parameter were ever ignored or mis-passed. Both fields are required
    for green -- a `success` on a run that is not `completed` is malformed data
    and fails closed.
    """
    mine = [r for r in runs if r.get("head_sha") == sha]
    for r in mine:
        if r.get("status") == "completed" and r.get("conclusion") == "success":
            return "green", r
    if not mine or any(r.get("status") != "completed" for r in mine):
        return "unfinished", mine
    return "red", mine


def describe(runs: list) -> str:
    if not runs:
        return "no run of the workflow exists for this sha yet"
    parts = []
    for r in runs:
        state = r.get("conclusion") if r.get("status") == "completed" else r.get("status")
        parts.append(f"run {r.get('id')} ({r.get('event')}) -> {state}")
    return "; ".join(parts)


def runs_url(api: str, repo: str, workflow: str, sha: str) -> str:
    """Percent-encode every caller-supplied component.

    Fuzz finding 771657b5: a non-ASCII workflow name made urllib raise
    UnicodeEncodeError from inside the request, i.e. the gate crashed on its
    own arguments. The real inputs are ASCII, but the failure class is
    'unhandled path', and that error is a ValueError, which main() would have
    retried as transient until the budget ran out -- a network problem that
    did not exist. `repo` keeps its one slash (owner/name); nothing else does.
    """
    return (f"{api}/repos/{quote(repo, safe='/')}/actions/workflows/"
            f"{quote(workflow, safe='')}/runs?head_sha={quote(sha, safe='')}&per_page=100")


def fetch(repo: str, workflow: str, sha: str) -> list:
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    url = runs_url(api, repo, workflow, sha)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "aramid-release-gate",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # S310 justification (both lines): the URL is https, assembled from
    # GitHub's own GITHUB_API_URL and the repo/workflow/sha this job was given
    # -- no user-controlled scheme reaches the request or the open.
    req = urllib.request.Request(url, headers=headers)  # noqa: S310
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        return json.load(resp).get("workflow_runs", [])


def load_snapshot(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh).get("workflow_runs", [])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="exit 0 only if the named workflow has a completed, successful "
                    "run on exactly this commit sha")
    ap.add_argument("--repo", required=True, help="owner/name")
    ap.add_argument("--sha", required=True, help="the full 40-character commit sha being released")
    ap.add_argument("--workflow", default="aramid.yml",
                    help="workflow file whose runs must be green (default: aramid.yml)")
    ap.add_argument("--timeout-minutes", type=float, default=75.0,
                    help="how long to wait for an unfinished matrix; 0 evaluates once")
    ap.add_argument("--interval-seconds", type=float, default=60.0)
    ap.add_argument("--runs-json",
                    help="evaluate this saved API response instead of calling the API")
    args = ap.parse_args(argv)

    if len(args.sha) != 40:
        print(f"::error::--sha must be the full 40-character commit sha, got {args.sha!r}")
        return 1

    deadline = time.monotonic() + args.timeout_minutes * 60
    while True:
        report = "the API could not be read"
        try:
            runs = load_snapshot(args.runs_json) if args.runs_json else fetch(
                args.repo, args.workflow, args.sha)
        except urllib.error.HTTPError as exc:
            if 400 <= exc.code < 500:
                print(f"::error::GitHub refused the workflow-runs query ({exc.code} "
                      f"{exc.reason}). A 403 here usually means this job lacks "
                      f"`actions: read`; a 404 means the workflow file name is wrong.")
                return 1
            report = f"GitHub API returned {exc.code}; will retry"
            print(f"::warning::{report}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            report = f"could not read workflow runs ({exc}); will retry"
            print(f"::warning::{report}")
        else:
            verdict, detail = evaluate(runs, args.sha)
            if verdict == "green":
                print(f"OK: {args.workflow} run {detail.get('id')} completed with "
                      f"conclusion success on {args.sha}: {detail.get('html_url')}")
                return 0
            report = describe(detail)
            if verdict == "red":
                print(f"::error::{args.workflow} has no green run on {args.sha} and every "
                      f"run has finished: {report}. Re-run the red workflow to green (or "
                      f"fix and re-tag), then re-run this release workflow.")
                return 1
        if time.monotonic() >= deadline:
            print(f"::error::timed out after {args.timeout_minutes:g} min waiting for a "
                  f"green {args.workflow} run on {args.sha}: {report}. Wait for the "
                  f"matrix to finish green, then re-run this release workflow.")
            return 1
        print(f"waiting: {report}; next check in {args.interval_seconds:g}s")
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    sys.exit(main())
