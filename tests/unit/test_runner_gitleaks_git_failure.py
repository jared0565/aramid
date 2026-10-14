"""FN-56: a git failure inside gitleaks is a failed scan, never a clean one.

gitleaks prints its own git run's stderr as `[git] ...` lines at error level,
adds `error="stderr is not empty"`, and goes on to report what it read -- with
a failed git, nothing -- and exits 0 (measured, gitleaks 8.30.1: a range
whose base does not resolve, and a blob missing from the object store). A
git warning is logged the same way and loses the scan all the same. So the
runner checks what it hands gitleaks' git scan first (each end of the range
resolves; an index git named exists) and reads gitleaks' log after every
run.

These tests answer gitleaks with a fake that writes gitleaks' own log lines;
the real binary and a real broken object store are
tests/integration/test_gitleaks_git_failure_live.py."""
import json
import subprocess
from pathlib import Path

import pytest

from aramid.runners import gitleaks, inline
from aramid.runners.base import RunContext, RunnerResult, ToolState

# gitleaks' log lines as it writes them, colours and all (8.30.1).
_GIT_FATAL = ("\x1b[90m9:59PM\x1b[0m \x1b[31mERR\x1b[0m \x1b[1m[git] fatal: unable to read "
              "7ded13b6323304308ecf8f201e0c88a0e35fe94f\x1b[0m\n")
_NOT_EMPTY = ("\x1b[90m9:59PM\x1b[0m \x1b[31mERR\x1b[0m \x1b[36merror=\x1b[0m"
              "\x1b[31m\x1b[1m\"stderr is not empty\"\x1b[0m\x1b[0m\n")
_CLEAN = ("\x1b[90m9:59PM\x1b[0m \x1b[32mINF\x1b[0m \x1b[1m1 commits scanned.\x1b[0m\n"
          "\x1b[90m9:59PM\x1b[0m \x1b[32mINF\x1b[0m \x1b[1mno leaks found\x1b[0m\n")
_FOUND = "\x1b[90m9:59PM\x1b[0m \x1b[33mWRN\x1b[0m \x1b[1mleaks found: 1\x1b[0m\n"
# A git WARNING is logged the same way, and the scan is lost all the same
# (measured: a committed secret in `dup..HEAD`, `dup` a branch and a tag, was
# not reported, rc 0).
_GIT_WARNING = ("\x1b[90m9:59PM\x1b[0m \x1b[31mERR\x1b[0m \x1b[1m[git] warning: refname 'dup' "
                "is ambiguous.\x1b[0m\n")
# What gitleaks scans past: its own short list of git messages, such as the
# rename limit, logged at WRN with no `[git]` (measured: the secret still
# reported).
_RENAME_LIMIT = ("\x1b[90m9:59PM\x1b[0m \x1b[33mWRN\x1b[0m \x1b[1mwarning: exhaustive rename "
                 "detection was skipped due to too many files.\x1b[0m\n")
_HIT = {"RuleID": "github-pat", "File": "cfg.py", "StartLine": 1, "Commit": "",
        "Fingerprint": "cfg.py:github-pat:1", "Secret": "placeholder", "Description": "a test rule"}


def _git(r, *a):
    return subprocess.run(["git", *a], cwd=r, check=True, capture_output=True, text=True).stdout


def _repo(tmp_path, commits=2):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    for k in range(commits):
        (r / f"f{k}.txt").write_text(f"{k}\n")
        _git(r, "add", "-A")
        _git(r, "commit", "-q", "-m", str(k))
    return r


class _Fake:
    """Answers the runs by their flags (the scan, the marker pass with
    --ignore-gitleaks-allow, the file pass with --config), each with the log
    given for it; the scan reports `items`."""

    def __init__(self, logs=None, items=()):
        self.logs = logs or {}
        self.items = list(items)
        self.calls = []

    def __call__(self, argv, cwd, timeout_s, env=None):
        which = ("files" if "--config" in argv
                 else "markers" if "--ignore-gitleaks-allow" in argv else "own")
        self.calls.append(which)
        found = self.items if which == "own" else []
        Path(argv[argv.index("--report-path") + 1]).write_text(json.dumps(found))
        return RunnerResult("gitleaks", ToolState.OK, "", self.logs.get(which, _CLEAN), 0.01,
                            1 if found else 0)


def _run(monkeypatch, ctx, fake):
    monkeypatch.setattr(gitleaks, "run_subprocess", fake)
    return gitleaks.run(ctx)


@pytest.mark.parametrize("log", [_GIT_FATAL + _NOT_EMPTY, _GIT_FATAL, _NOT_EMPTY,
                                 _GIT_WARNING + _NOT_EMPTY],
                         ids=["both", "git-line", "not-empty", "git-warning"])
@pytest.mark.parametrize("rng", [None, "HEAD~1..HEAD"], ids=["staged", "range"])
def test_a_git_error_in_the_log_fails_the_scan(tmp_path, monkeypatch, log, rng):
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    result = _run(monkeypatch, RunContext(root=_repo(tmp_path), rng=rng),
                  _Fake(logs={"own": _CLEAN + log}))
    assert result.state is ToolState.CRASHED
    assert "[git]" in result.stderr or "stderr is not empty" in result.stderr


def test_a_git_error_fails_the_scan_even_with_leaks_found(tmp_path, monkeypatch):
    # What git did read is not the whole change: a partial report is not a scan.
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    result = _run(monkeypatch, RunContext(root=_repo(tmp_path), rng="HEAD~1..HEAD"),
                  _Fake(logs={"own": _GIT_FATAL + _FOUND}, items=[_HIT]))
    assert result.state is ToolState.CRASHED


@pytest.mark.parametrize("log,items", [(_CLEAN, []), (_FOUND, [_HIT])], ids=["clean", "found"])
def test_a_log_without_a_git_error_is_not_a_failure(tmp_path, monkeypatch, log, items):
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    ctx = RunContext(root=_repo(tmp_path), rng="HEAD~1..HEAD")
    result = _run(monkeypatch, ctx, _Fake(logs={"own": log}, items=items))
    assert result.state is ToolState.OK
    assert [f.rule for f in gitleaks.parse(result, ctx)] == [i["RuleID"] for i in items]


def test_a_git_message_gitleaks_scans_past_is_not_a_failure(tmp_path, monkeypatch):
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    ctx = RunContext(root=_repo(tmp_path), rng="HEAD~1..HEAD")
    result = _run(monkeypatch, ctx, _Fake(logs={"own": _RENAME_LIMIT + _FOUND}, items=[_HIT]))
    assert result.state is ToolState.OK
    assert [f.rule for f in gitleaks.parse(result, ctx)] == ["github-pat"]


def test_a_git_error_in_the_marker_pass_fails_that_pass(tmp_path, monkeypatch):
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    result = _run(monkeypatch, RunContext(root=_repo(tmp_path), inline_pass=True),
                  _Fake(logs={"markers": _GIT_FATAL}))
    own, second = result.sub_results
    assert own.state is ToolState.OK
    assert (second.tool, second.state) == (inline.GITLEAKS, ToolState.CRASHED)


def test_a_git_error_in_the_file_pass_fails_that_pass(tmp_path, monkeypatch):
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    r = _repo(tmp_path)
    (r / ".gitleaks.toml").write_text("")
    fake = _Fake(logs={"files": _NOT_EMPTY})
    result = _run(monkeypatch, RunContext(root=r, inline_pass=True), fake)
    assert fake.calls == ["own", "markers", "files"]
    assert (result.sub_results[1].tool, result.sub_results[1].state) == (inline.GITLEAKS,
                                                                       ToolState.CRASHED)


@pytest.mark.parametrize("rng", ["nosuchref..HEAD", "HEAD..nosuchref", "@{u}..HEAD"])
def test_a_range_that_does_not_resolve_is_not_scanned(tmp_path, monkeypatch, rng):
    # `@{u}..HEAD` here: the branch has no upstream.
    fake = _Fake()
    result = _run(monkeypatch, RunContext(root=_repo(tmp_path), rng=rng), fake)
    assert fake.calls == []
    assert result.state is ToolState.CRASHED
    assert rng in result.stderr


def test_a_range_that_resolves_is_scanned(tmp_path, monkeypatch):
    r = _repo(tmp_path, commits=3)
    base = _git(r, "rev-parse", "HEAD~2").strip()
    for rng in (f"{base}..HEAD", "HEAD~1...HEAD", ""):   # "" walks HEAD (the first push)
        fake = _Fake()
        result = _run(monkeypatch, RunContext(root=r, rng=rng), fake)
        assert (fake.calls, result.state) == (["own"], ToolState.OK), rng


@pytest.mark.parametrize("commits", [2, 0], ids=["commits", "no-commit"])
def test_init_s_all_history_scan_is_scanned(tmp_path, monkeypatch, commits):
    # `--all` is git log's own option (init's history scan, `commands/init.py`),
    # not a range: there is nothing to resolve, and a repo with no commit has
    # no history to fail on. A git error there still shows in the log.
    fake = _Fake()
    ctx = RunContext(root=_repo(tmp_path, commits=commits), files=[], rng="--all")
    result = _run(monkeypatch, ctx, fake)
    assert (fake.calls, result.state) == (["own"], ToolState.OK)


def test_a_full_history_scan_of_a_repo_with_no_commit_is_not_scanned(tmp_path, monkeypatch):
    fake = _Fake()
    result = _run(monkeypatch, RunContext(root=_repo(tmp_path, commits=0), rng=""), fake)
    assert fake.calls == [] and result.state is ToolState.CRASHED


def test_an_index_git_named_that_does_not_exist_is_not_scanned(tmp_path, monkeypatch):
    # git hands a hook an index that exists (`.git/index`, or the
    # `next-index-*.lock` of `commit -a`); one that names no file is not git's.
    r = _repo(tmp_path)
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "no-such-index"))
    fake = _Fake()
    result = _run(monkeypatch, RunContext(root=r), fake)
    assert fake.calls == []
    assert result.state is ToolState.CRASHED
    assert "no-such-index" in result.stderr


@pytest.mark.parametrize("index", [None, ".git/index"], ids=["unset", "relative"])
def test_an_index_that_exists_or_none_named_is_scanned(tmp_path, monkeypatch, index):
    r = _repo(tmp_path)
    if index is None:
        monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    else:
        monkeypatch.setenv("GIT_INDEX_FILE", index)
    fake = _Fake()
    result = _run(monkeypatch, RunContext(root=r), fake)
    assert (fake.calls, result.state) == (["own"], ToolState.OK)


def test_the_all_scan_is_not_held_to_the_index(tmp_path, monkeypatch):
    # `--all` scans a copy of the tracked files, not the index.
    r = _repo(tmp_path)
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "no-such-index"))
    fake = _Fake()
    result = _run(monkeypatch, RunContext(root=r, files=["f0.txt"], full_tree=True), fake)
    assert (fake.calls, result.state) == (["own"], ToolState.OK)
