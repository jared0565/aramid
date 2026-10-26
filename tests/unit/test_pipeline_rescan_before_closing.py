"""Re-scan before closing (OPERATOR 2026-10-25), without the binary: which open
gitleaks rows `pipeline._rescan_before_closing` keeps open, across every
revision a push certifies. The live arms are in tests/integration/
test_gitleaks_rescan_live.py; these pin what one revision cannot show, and
`gitleaks.rescan` itself is tests/unit/test_gitleaks_rescan.py."""
from types import SimpleNamespace

import pytest

from aramid import gitutil, pipeline
from aramid.ledger import Ledger
from aramid.models import Gate, Severity, Verdict
from aramid.normalizer import RawFinding, normalize
from aramid.runners import gitleaks, inline

_A, _B = "a" * 40, "b" * 40
_BOTH = frozenset((gitleaks.NAME, inline.GITLEAKS))
_CERTIFIED = SimpleNamespace(refs=[SimpleNamespace(local_sha=_A)], head_at_start=_B)


def _classify(tool, rule, severity_raw, gate):
    return Severity.HIGH, Verdict.BLOCK


def _raw(tool):
    hidden = tool == inline.GITLEAKS
    return RawFinding(tool=tool, rule=inline.RULE if hidden else "github-pat",
                      severity_raw="high", file="cfg.py", line=2, message="m",
                      line_content='TOKEN = "placeholder"',
                      subject=(gitleaks.NAME, "github-pat") if hidden else None)


def _open_row(tmp_path, tool):
    ledger = Ledger(tmp_path / "l.db")
    found = normalize([_raw(tool)], tmp_path, lambda f: "HEAD", b"salt", Gate.PRE_PUSH,
                      _classify)
    ledger.record_run("leak", "2026-10-25T00:00:00Z", "pre-push", {tool}, {"cfg.py"}, found)
    return ledger, found[0].id


def _ask(tmp_path, monkeypatch, tool, answers, mode="range", scope=frozenset({"cfg.py"})):
    """`answers`: rev -> what `gitleaks.rescan` returns there. The revisions
    asked, in order, ride on the result."""
    ledger, fid = _open_row(tmp_path, tool)
    asked = []

    def rescan(root, files, rev, gate_deadline):
        asked.append(rev)
        raws, ok = answers[rev]
        return [_raw(t) for t in raws], ok

    monkeypatch.setattr(gitleaks, "rescan", rescan)
    kept = pipeline._rescan_before_closing(
        tmp_path, mode, _CERTIFIED, ledger, [], {tool}, set(scope), lambda f: "HEAD",
        b"salt", Gate.PRE_PUSH, _classify, None)
    return kept, fid, asked


@pytest.mark.parametrize("holds", [_A, _B])
def test_a_hit_any_certified_revision_still_holds_keeps_the_row_open(tmp_path, monkeypatch,
                                                                     holds):
    answers = {rev: (([gitleaks.NAME] if rev == holds else []), _BOTH) for rev in (_A, _B)}
    kept, fid, asked = _ask(tmp_path, monkeypatch, gitleaks.NAME, answers)
    assert kept == {fid} and asked == [_A, _B]


@pytest.mark.parametrize("short", [_A, _B])
def test_a_label_any_revision_could_not_vouch_for_keeps_its_rows_open(tmp_path, monkeypatch,
                                                                      short):
    answers = {rev: ([], frozenset({gitleaks.NAME}) if rev == short else _BOTH)
               for rev in (_A, _B)}
    kept, fid, _ = _ask(tmp_path, monkeypatch, inline.GITLEAKS, answers)
    assert kept == {fid}


def test_a_row_no_revision_still_holds_may_close(tmp_path, monkeypatch):
    kept, _, _ = _ask(tmp_path, monkeypatch, gitleaks.NAME, {_A: ([], _BOTH), _B: ([], _BOTH)})
    assert kept == frozenset()


def test_pre_commit_asks_the_index_alone(tmp_path, monkeypatch):
    kept, fid, asked = _ask(tmp_path, monkeypatch, gitleaks.NAME,
                            {":": ([gitleaks.NAME], _BOTH)}, mode="staged")
    assert kept == {fid} and asked == [":"]


def test_all_scans_whole_files_already_and_asks_nothing(tmp_path, monkeypatch):
    kept, _, asked = _ask(tmp_path, monkeypatch, gitleaks.NAME, {}, mode="all")
    assert kept == frozenset() and asked == []


def test_a_row_whose_file_the_change_leaves_alone_asks_nothing(tmp_path, monkeypatch):
    """`record_run` cannot close it on this run, so there is nothing to vouch for."""
    kept, _, asked = _ask(tmp_path, monkeypatch, gitleaks.NAME, {}, scope={"other.py"})
    assert kept == frozenset() and asked == []


def test_a_rescan_that_raises_keeps_every_row_open_and_says_so(tmp_path, monkeypatch, capsys):
    ledger, fid = _open_row(tmp_path, gitleaks.NAME)

    def rescan(root, files, rev, gate_deadline):
        raise gitutil.GitTimeout("git show timed out")

    monkeypatch.setattr(gitleaks, "rescan", rescan)
    kept = pipeline._rescan_before_closing(
        tmp_path, "staged", None, ledger, [], {gitleaks.NAME}, {"cfg.py"}, lambda f: ":",
        b"salt", Gate.PRE_COMMIT, _classify, None)
    assert kept == {fid}
    assert ("aramid: gitleaks could not re-scan 1 file(s) before closing their rows "
            "(GitTimeout); 1 row(s) stay open\n") == capsys.readouterr().err
