"""`gitleaks.rescan`, with a stand-in for the scan itself: what the copy holds,
the line each hit carries, the inline twin of an own hit, and which labels it
vouches for (Re-scan before closing, OPERATOR 2026-10-25). The real binary's
arms are in tests/integration/test_gitleaks_rescan_live.py."""
import dataclasses
import json
import subprocess
from pathlib import Path

import pytest

from aramid.runners import gitleaks, inline
from aramid.runners.base import CONTENT_UNREADABLE, RunnerResult, ToolState

_BOTH = frozenset((gitleaks.NAME, inline.GITLEAKS))
_COMMITTED = "A = 1\nTOKEN = 'committed'\nB = 2\n"
_STAGED = "A = 1\nTOKEN = 'staged'\nB = 2\n"


def _git(r, *a):
    subprocess.run(["git", *a], cwd=r, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    """cfg.py committed, a different cfg.py staged, a third on disk; both
    gitleaks files on disk only."""
    empty = tmp_path / "no-hooks"
    empty.mkdir()
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", f"--template={empty}")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "cfg.py").write_text(_COMMITTED, encoding="utf-8")
    _git(r, "add", "cfg.py")
    _git(r, "commit", "-q", "-m", "base")
    (r / "cfg.py").write_text(_STAGED, encoding="utf-8")
    _git(r, "add", "cfg.py")
    (r / "cfg.py").write_text("A = 1\nTOKEN = 'disk'\nB = 2\n", encoding="utf-8")
    (r / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    (r / ".gitleaksignore").write_text("cfg.py:github-pat:2\n", encoding="utf-8")
    return r


def _scan(monkeypatch, own=(), hidden=(), own_state=ToolState.OK,
          second_state=ToolState.OK, seen=None):
    """`own`/`hidden`: (file, line) hits the stand-in reports from the copy."""
    def report(ctx, hits):
        return json.dumps([{"RuleID": "github-pat", "File": str(Path(ctx.root) / f),
                            "StartLine": line, "Secret": "s", "Description": "d"}
                           for f, line in hits])

    def run(ctx):
        if seen is not None:
            seen.append((ctx, {p.relative_to(ctx.root).as_posix(): p.read_text(encoding="utf-8")
                               for p in Path(ctx.root).rglob("*") if p.is_file()}))
        if own_state is not ToolState.OK:
            return RunnerResult(gitleaks.NAME, own_state, stderr="injected")
        first = RunnerResult(gitleaks.NAME, ToolState.OK, raw=report(ctx, own))
        second = RunnerResult(inline.GITLEAKS, second_state,
                              raw=report(ctx, hidden) if second_state is ToolState.OK else "")
        combined = dataclasses.replace(first)
        combined.sub_results = (first, second)
        return combined

    monkeypatch.setattr(gitleaks, "run", run)


@pytest.mark.parametrize("rev, held", [(":", _STAGED), ("HEAD", _COMMITTED)])
def test_the_copy_holds_what_git_has_at_the_revision_and_the_repo_rules(repo, monkeypatch,
                                                                        rev, held):
    seen = []
    _scan(monkeypatch, seen=seen)
    assert gitleaks.rescan(repo, ["cfg.py"], rev) == ([], _BOTH)
    (ctx, copy), = seen
    assert copy == {"cfg.py": held, ".gitleaks.toml": "[extend]\nuseDefault = true\n"}
    assert (ctx.files, ctx.full_tree, ctx.inline_pass) == (["cfg.py", ".gitleaks.toml"],
                                                            True, True)


def test_each_hit_carries_the_line_it_was_found_on(repo, monkeypatch):
    _scan(monkeypatch, own=[("cfg.py", 1), ("cfg.py", 2), ("cfg.py", 3), ("cfg.py", 0),
                            ("cfg.py", 4)])
    raws, _ = gitleaks.rescan(repo, ["cfg.py"], ":")
    own = [(r.line, r.line_content) for r in raws if r.tool == gitleaks.NAME]
    assert own == [(1, "A = 1"), (2, "TOKEN = 'staged'"), (3, "B = 2"),
                   (0, CONTENT_UNREADABLE), (4, CONTENT_UNREADABLE)]


def test_an_own_hit_is_also_returned_under_the_inline_label(repo, monkeypatch):
    _scan(monkeypatch, own=[("cfg.py", 2)], hidden=[("cfg.py", 3)])
    raws, vouched = gitleaks.rescan(repo, ["cfg.py"], ":")
    assert [(r.tool, r.rule, r.line, r.line_content, r.subject) for r in raws] == [
        (gitleaks.NAME, "github-pat", 2, "TOKEN = 'staged'", None),
        (inline.GITLEAKS, inline.RULE, 3, "B = 2", (gitleaks.NAME, "github-pat")),
        (inline.GITLEAKS, inline.RULE, 2, "TOKEN = 'staged'", (gitleaks.NAME, "github-pat"))]
    assert vouched == _BOTH


def test_a_hit_in_a_file_not_asked_about_is_dropped(repo, monkeypatch):
    _scan(monkeypatch, own=[(".gitleaks.toml", 1), ("cfg.py", 2)])
    raws, _ = gitleaks.rescan(repo, ["cfg.py"], ":")
    assert {r.file for r in raws} == {"cfg.py"}


@pytest.mark.parametrize("state", [ToolState.TIMEOUT, ToolState.CRASHED])
def test_a_second_pass_that_did_not_run_clean_vouches_for_the_own_label_only(repo, monkeypatch,
                                                                             state):
    _scan(monkeypatch, own=[("cfg.py", 2)], second_state=state)
    _, vouched = gitleaks.rescan(repo, ["cfg.py"], ":")
    assert vouched == frozenset({gitleaks.NAME})


@pytest.mark.parametrize("state", [ToolState.CRASHED, ToolState.TIMEOUT, ToolState.MISSING])
def test_an_own_pass_that_did_not_run_clean_vouches_for_nothing(repo, monkeypatch, state):
    _scan(monkeypatch, own=[("cfg.py", 2)], own_state=state)
    assert gitleaks.rescan(repo, ["cfg.py"], ":") == ([], frozenset())


@pytest.mark.parametrize("rev", [":", "HEAD"])
def test_a_file_git_holds_no_blob_for_vouches_for_nothing(repo, monkeypatch, rev):
    """No blob is "git could not say", not "nothing there"; the scan never runs."""
    seen = []
    _scan(monkeypatch, seen=seen)
    assert gitleaks.rescan(repo, ["cfg.py", "absent.py"], rev) == ([], frozenset())
    assert seen == []
