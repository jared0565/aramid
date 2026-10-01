"""FN-21: a git that did not answer is not "no finding".

`tdd.scan` swallowed every error into `[]` (fail-open), `GitTimeout`
included, so with `tdd_block_armed` a git that hung past
`gitutil.GIT_TIMEOUT_S` let the push through unchecked by the tdd gate.
The timeout now goes up and `run_gate` decides by arming
(tests/unit/test_pipeline_producer_git_timeout.py). Any other error is
still no finding.
"""
from types import SimpleNamespace

import pytest

from aramid import gitutil, tdd


def _ctx(tmp_path):
    return SimpleNamespace(files=["a.py"], rng="base..HEAD", root=tmp_path)


def test_a_git_that_did_not_answer_goes_up(tmp_path, monkeypatch):
    def hung(*a, **k):
        raise gitutil.GitTimeout("git diff did not answer")
    monkeypatch.setattr(tdd.gitutil, "diff_new_lines", hung)

    with pytest.raises(gitutil.GitTimeout):
        tdd.scan(_ctx(tmp_path), SimpleNamespace(tdd={}))


def test_any_other_error_is_still_no_finding(tmp_path, monkeypatch):
    def broken(*a, **k):
        raise OSError("disk")
    monkeypatch.setattr(tdd.gitutil, "diff_new_lines", broken)

    assert tdd.scan(_ctx(tmp_path), SimpleNamespace(tdd={})) == []
