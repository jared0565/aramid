"""FN-56, live: a git failure inside gitleaks is a failed scan. With the blob
that holds a committed secret deleted from the object store, the range still
resolves, and a raw gitleaks run -- the control -- logs git's error, finds
nothing and exits 0; the runner reports the scan as failed. A range whose base
does not resolve is not scanned at all. Skips where gitleaks is absent (local
dev); runs in CI, which provisions gitleaks on PATH.

The secret-shaped value is built at run time, so this file holds none."""
import json
import os
import re
import secrets
import shutil
import stat
import string
import subprocess

import pytest

from aramid.runners import gitleaks
from aramid.runners.base import RunContext, ToolState

_GITLEAKS = shutil.which("gitleaks")
_SKIP = "gitleaks binary not on PATH (installed in CI, skipped in local dev)"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout.strip()


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "readme.txt").write_text("clean\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "clean base")
    alnum = string.ascii_letters + string.digits
    token = "ghp_" + "".join(secrets.choice(alnum) for _ in range(36))
    (r / "cfg.py").write_text(f'TOKEN = "{token}"\n', encoding="utf-8")
    _git(r, "add", "cfg.py")
    _git(r, "commit", "-q", "-m", "leak")
    return r


def _raw(r, report, *scan, env=None):
    """A raw gitleaks git scan: (rc, the rule ids it reported, its log)."""
    cp = subprocess.run([_GITLEAKS, "git", *scan, "--report-format", "json", "--report-path",
                         str(report)], cwd=r, capture_output=True, text=True,
                        env={**os.environ, **(env or {})})
    rules = sorted(i["RuleID"] for i in json.loads(report.read_text() or "[]"))
    return cp.returncode, rules, _ANSI.sub("", cp.stdout + cp.stderr)


def _drop_blob(r, rev_path):
    sha = _git(r, "rev-parse", rev_path)
    obj = r / ".git" / "objects" / sha[:2] / sha[2:]
    os.chmod(obj, stat.S_IWRITE)
    obj.unlink()


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_a_blob_missing_from_the_object_store_fails_the_range_scan(tmp_path):
    r = _repo(tmp_path)
    ctx = RunContext(root=r, rng="HEAD~1..HEAD")
    assert [f.rule for f in gitleaks.parse(gitleaks.run(ctx), ctx)] == ["github-pat"]
    _drop_blob(r, "HEAD:cfg.py")

    # The control: gitleaks itself logs git's failure and calls the scan clean.
    report = tmp_path / "raw.json"
    cp = subprocess.run([_GITLEAKS, "git", "--log-opts", "HEAD~1..HEAD", "--report-format", "json",
                         "--report-path", str(report)], cwd=r, capture_output=True, text=True)
    log = _ANSI.sub("", cp.stdout + cp.stderr)
    assert cp.returncode == 0 and json.loads(report.read_text() or "[]") == []
    assert "[git]" in log, "control: gitleaks no longer logs git's error"

    result = gitleaks.run(ctx)
    assert result.state is ToolState.CRASHED, result.stderr


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_a_range_whose_base_does_not_resolve_is_not_reported_clean(tmp_path):
    r = _repo(tmp_path)
    # The control: handed it, gitleaks logs git's error and exits 0.
    cp = subprocess.run([_GITLEAKS, "git", "--log-opts", "nosuchref..HEAD", "--report-format", "json",
                         "--report-path", str(tmp_path / "raw.json")], cwd=r, capture_output=True,
                        text=True)
    assert cp.returncode == 0 and "[git]" in _ANSI.sub("", cp.stdout + cp.stderr)

    result = gitleaks.run(RunContext(root=r, rng="nosuchref..HEAD"))
    assert result.state is ToolState.CRASHED
    assert "nosuchref..HEAD" in result.stderr


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_init_s_history_scan_reads_every_branch(tmp_path):
    # init's history scan hands gitleaks `--log-opts --all` (`commands/init.py`):
    # git log's own option, not a range, so there is nothing to resolve first.
    r = _repo(tmp_path)
    _git(r, "branch", "side")
    _git(r, "reset", "-q", "--hard", "HEAD~1")
    # The controls: HEAD's history no longer holds the secret; `--all` finds it.
    assert _raw(r, tmp_path / "head.json", "--log-opts", "HEAD")[:2] == (0, [])
    assert _raw(r, tmp_path / "all.json", "--log-opts", "--all")[:2] == (1, ["github-pat"])

    ctx = RunContext(root=r, files=[], rng="--all")
    result = gitleaks.run(ctx)
    assert result.state is ToolState.OK, result.stderr
    assert [f.rule for f in gitleaks.parse(result, ctx)] == ["github-pat"]


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_init_s_history_scan_of_a_repo_with_no_commit_is_clean(tmp_path):
    r = tmp_path / "e"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    # The control: git log has nothing to say, so gitleaks logs no git line.
    rc, rules, log = _raw(r, tmp_path / "raw.json", "--log-opts", "--all")
    assert (rc, rules) == (0, []) and "[git]" not in log

    ctx = RunContext(root=r, files=[], rng="--all")
    result = gitleaks.run(ctx)
    assert result.state is ToolState.OK, result.stderr
    assert gitleaks.parse(result, ctx) == []


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_git_trace_in_the_environment_never_reads_as_a_clean_scan(tmp_path, monkeypatch):
    # GIT_TRACE makes git write trace lines to stderr, and gitleaks drops the
    # whole scan on any git stderr line it does not know.
    r = _repo(tmp_path)
    rng = ("--log-opts", "HEAD~1..HEAD")
    assert _raw(r, tmp_path / "plain.json", *rng)[:2] == (1, ["github-pat"])
    # The control is a race: gitleaks 8.30.1 sends git's stderr error only when
    # git exits, and returns on it without waiting for the file scans already
    # running, so a run can still report the secret (CI 40214385369, one leg of
    # four alike). Up to five runs, and one must be blinded.
    for attempt in range(5):
        rc, rules, log = _raw(r, tmp_path / f"traced{attempt}.json", *rng,
                              env={"GIT_TRACE": "1"})
        if (rc, rules) == (0, []) and "[git]" in log:
            break
    else:
        pytest.fail("control: GIT_TRACE no longer blinds gitleaks in five runs")

    monkeypatch.setenv("GIT_TRACE", "1")
    ctx = RunContext(root=r, rng="HEAD~1..HEAD")
    result = gitleaks.run(ctx)
    # Failed, or (once aramid clears git's variables for gitleaks) found.
    found = [f.rule for f in gitleaks.parse(result, ctx)] if result.state is ToolState.OK else None
    assert result.state is ToolState.CRASHED or found == ["github-pat"], result.stderr
