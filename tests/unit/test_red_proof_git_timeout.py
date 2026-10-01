"""FN-21: a git that did not answer is not "no finding".

`red_proof.scan_scoped` swallowed every error into `([], set())`
(fail-open), `GitTimeout` included, so with `red_proof_block_armed` a git
that hung let the push through unchecked by the red-first proof. The
timeout now goes up -- from the diff and from the worktree it builds --
and `run_gate` decides by arming
(tests/unit/test_pipeline_producer_git_timeout.py). Any other error is
still no finding.
"""
from types import SimpleNamespace

import pytest

from aramid import gitutil, red_proof

_TEST = "tests/test_a.py"


def _ctx(tmp_path):
    return SimpleNamespace(files=[_TEST], rng="base..HEAD", root=tmp_path)


def _cfg():
    return SimpleNamespace(red_proof={})


def test_a_diff_that_did_not_answer_goes_up(tmp_path, monkeypatch):
    def hung(*a, **k):
        raise gitutil.GitTimeout("git diff did not answer")
    monkeypatch.setattr(red_proof.gitutil, "diff_new_lines", hung)

    with pytest.raises(gitutil.GitTimeout):
        red_proof.scan_scoped(_ctx(tmp_path), _cfg())


def test_a_worktree_that_did_not_answer_goes_up(tmp_path, monkeypatch):
    monkeypatch.setattr(red_proof.gitutil, "diff_new_lines",
                        lambda root, base, head: {_TEST: {1}})
    # the cleanup's own git calls raise too, so its rmtree never runs:
    # keep the scratch dir inside tmp_path rather than the system temp
    scratch = tmp_path / "red"
    scratch.mkdir()
    monkeypatch.setattr(red_proof.tempfile, "mkdtemp", lambda prefix: str(scratch))
    calls = []

    def hung(root, *args):
        calls.append(args[:2])
        raise gitutil.GitTimeout("git worktree did not answer")
    monkeypatch.setattr(red_proof.gitutil, "_run", hung)

    with pytest.raises(gitutil.GitTimeout):
        red_proof.scan_scoped(_ctx(tmp_path), _cfg())
    assert calls[0] == ("worktree", "add")


def test_any_other_error_is_still_no_finding(tmp_path, monkeypatch):
    def broken(*a, **k):
        raise OSError("disk")
    monkeypatch.setattr(red_proof.gitutil, "diff_new_lines", broken)

    assert red_proof.scan_scoped(_ctx(tmp_path), _cfg()) == ([], set())
