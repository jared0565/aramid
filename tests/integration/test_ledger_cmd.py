"""integration: `aramid ledger list|show|filter|mark-rotated|mark-not-a-secret`."""
from pathlib import Path

from aramid import cli
from aramid.commands.ledger_cmd import (
    cmd_ledger_filter,
    cmd_ledger_list,
    cmd_ledger_mark_not_a_secret,
    cmd_ledger_mark_rotated,
    cmd_ledger_show,
)
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Verdict


def _f(fid, tool="ruff", rule="S102", verdict=Verdict.WARN, file="a.py", historical=False):
    return Finding(fid, tool, rule, "high", Severity.HIGH, verdict, file, 1, "m", "e",
                    Gate.PRE_PUSH, historical=historical)


def _ledger(root) -> Ledger:
    return Ledger(root / ".aramid" / "ledger.db")


# ------------------------------------------------------------------- list ---

def test_list_prints_every_open_finding(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py", "b.py"},
                       [_f("f1"), _f("f2", file="b.py")])
    ledger.close()

    rc = cmd_ledger_list(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "f1" in out
    assert "f2" in out


def test_list_on_empty_ledger_reports_nothing_without_error(tmp_path, capsys):
    root: Path = tmp_path
    rc = cmd_ledger_list(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "no findings" in out.lower()


# ------------------------------------------------------------------- show ---

def test_show_prints_finding_detail(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1")])
    ledger.close()

    rc = cmd_ledger_show(root, "f1")
    out = capsys.readouterr().out

    assert rc == 0
    assert "f1" in out
    assert "ruff" in out
    assert "S102" in out


def test_show_unknown_id_errors(tmp_path, capsys):
    root: Path = tmp_path
    rc = cmd_ledger_show(root, "nope")
    err = capsys.readouterr().err

    assert rc == 3
    assert "nope" in err


# ----------------------------------------------------------------- filter ---

def test_filter_by_tool_returns_only_matches(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff", "eslint"}, {"a.py", "b.py"},
                       [_f("f1", tool="ruff"), _f("f2", tool="eslint", file="b.py")])
    ledger.close()

    rc = cmd_ledger_filter(root, tool="ruff")
    out = capsys.readouterr().out

    assert rc == 0
    assert "f1" in out
    assert "f2" not in out


def test_filter_with_no_matches_reports_nothing_without_error(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.close()

    rc = cmd_ledger_filter(root, tool="nonexistent-tool")
    out = capsys.readouterr().out

    assert rc == 0
    assert "no matching" in out.lower()


# ----------------------------------------------------------- mark-rotated ---

def test_mark_rotated_requires_historical_status(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"gitleaks"}, {"a.py"},
                       [_f("f1", tool="gitleaks", verdict=Verdict.BLOCK, historical=False)])
    ledger.close()

    rc = cmd_ledger_mark_rotated(root, "f1", "rotated in AWS")
    err = capsys.readouterr().err

    assert rc == 3
    assert "historical" in err.lower()

    ledger = _ledger(root)
    assert ledger.open_findings()["f1"]["status"] == "open"
    ledger.close()


def test_mark_rotated_appends_finding_rotated_event(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                       [_f("hist1", tool="gitleaks", rule="aws-key", verdict=Verdict.BLOCK,
                           historical=True)])
    ledger.close()

    rc = cmd_ledger_mark_rotated(root, "hist1", "rotated in AWS console")

    assert rc == 0

    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["hist1"]["status"] == "rotated"
        rotated_events = [e for e in ledger.events() if e.type.value == "finding_rotated"]
        assert len(rotated_events) == 1
        assert rotated_events[0].finding_id == "hist1"
        assert rotated_events[0].payload["reason"] == "rotated in AWS console"
    finally:
        ledger.close()


def test_mark_rotated_unknown_id_errors(tmp_path, capsys):
    root: Path = tmp_path
    rc = cmd_ledger_mark_rotated(root, "nope", "some reason")
    err = capsys.readouterr().err

    assert rc == 3
    assert "nope" in err


def test_mark_rotated_requires_reason(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                       [_f("hist1", tool="gitleaks", historical=True)])
    ledger.close()

    rc = cmd_ledger_mark_rotated(root, "hist1", "")
    err = capsys.readouterr().err

    assert rc == 3
    assert "reason" in err.lower()


# ----------------------------------------------------- mark-not-a-secret ---

def test_mark_not_a_secret_transitions_historical_finding(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                       [_f("hist1", tool="gitleaks", rule="generic-api-key",
                           verdict=Verdict.BLOCK, historical=True)])
    ledger.close()

    rc = cmd_ledger_mark_not_a_secret(root, "hist1", "public shopify client id")

    assert rc == 0

    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["hist1"]["status"] == "not_a_secret"
        nas_events = [e for e in ledger.events() if e.type.value == "finding_not_a_secret"]
        assert len(nas_events) == 1
        assert nas_events[0].finding_id == "hist1"
        assert nas_events[0].payload["reason"] == "public shopify client id"
    finally:
        ledger.close()


def test_mark_not_a_secret_refuses_open_finding_and_appends_nothing(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"gitleaks"}, {"a.py"},
                       [_f("f1", tool="gitleaks", verdict=Verdict.BLOCK, historical=False)])
    events_before = len(ledger.events())
    ledger.close()

    rc = cmd_ledger_mark_not_a_secret(root, "f1", "looks like a fixture key")
    err = capsys.readouterr().err

    assert rc == 3
    assert ".aramid-suppressions.toml" in err
    assert "aramid override" in err

    ledger = _ledger(root)
    try:
        assert len(ledger.events()) == events_before
        assert ledger.open_findings()["f1"]["status"] == "open"
    finally:
        ledger.close()


def test_mark_not_a_secret_unknown_id_errors(tmp_path, capsys):
    root: Path = tmp_path
    rc = cmd_ledger_mark_not_a_secret(root, "nope", "some reason")
    err = capsys.readouterr().err

    assert rc == 3
    assert "nope" in err


def test_mark_not_a_secret_requires_reason(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                       [_f("hist1", tool="gitleaks", historical=True)])
    ledger.close()

    rc_empty = cmd_ledger_mark_not_a_secret(root, "hist1", "")
    err_empty = capsys.readouterr().err
    rc_blank = cmd_ledger_mark_not_a_secret(root, "hist1", "   ")
    err_blank = capsys.readouterr().err

    assert rc_empty == 3
    assert "reason" in err_empty.lower()
    assert rc_blank == 3
    assert "reason" in err_blank.lower()


def test_mark_not_a_secret_missing_reason_flag_exits_3_via_argparse():
    # Omitting --reason entirely is an argparse path (required=True raises
    # SystemExit(2), remapped to 3 by cli.main) -- distinct from the
    # empty/whitespace case above, which the command function handles itself.
    # Must go through cli.main, not a direct call to the command function.
    rc = cli.main(["ledger", "mark-not-a-secret", "hist1"])
    assert rc == 3


def test_mark_not_a_secret_twice_refuses_second_time(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                       [_f("hist1", tool="gitleaks", historical=True)])
    ledger.close()

    rc1 = cmd_ledger_mark_not_a_secret(root, "hist1", "first reason")
    capsys.readouterr()
    rc2 = cmd_ledger_mark_not_a_secret(root, "hist1", "second reason")
    err2 = capsys.readouterr().err

    assert rc1 == 0
    assert rc2 == 3
    assert "already marked not-a-secret" in err2


def test_mark_not_a_secret_then_mark_rotated_succeeds(tmp_path, capsys):
    """Constraint 5: discovering a supposed false positive is actually a real
    credential, then rotating it, is strictly safety-improving and must
    never be blocked."""
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                       [_f("hist1", tool="gitleaks", historical=True)])
    ledger.close()

    rc1 = cmd_ledger_mark_not_a_secret(root, "hist1", "thought it was a fixture")
    rc2 = cmd_ledger_mark_rotated(root, "hist1", "actually a real key, rotated")

    assert rc1 == 0
    assert rc2 == 0

    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["hist1"]["status"] == "rotated"
    finally:
        ledger.close()


def test_mark_rotated_then_mark_not_a_secret_refused(tmp_path, capsys):
    """Constraint 5: no path from `rotated` back to `not_a_secret` -- that
    would rewrite a safety assertion. The ledger is append-only."""
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                       [_f("hist1", tool="gitleaks", historical=True)])
    ledger.close()

    rc1 = cmd_ledger_mark_rotated(root, "hist1", "rotated in AWS")
    capsys.readouterr()
    rc2 = cmd_ledger_mark_not_a_secret(root, "hist1", "actually fine on reflection")
    err2 = capsys.readouterr().err

    assert rc1 == 0
    assert rc2 == 3
    assert "already retired by rotation" in err2

    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["hist1"]["status"] == "rotated"
    finally:
        ledger.close()


def test_show_prints_reason_for_not_a_secret_finding(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                       [_f("hist1", tool="gitleaks", historical=True)])
    ledger.close()

    rc = cmd_ledger_mark_not_a_secret(root, "hist1", "public shopify client id")
    assert rc == 0
    capsys.readouterr()

    rc = cmd_ledger_show(root, "hist1")
    out = capsys.readouterr().out

    assert rc == 0
    assert "public shopify client id" in out
