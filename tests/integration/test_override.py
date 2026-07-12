"""integration: `aramid override <id> --reason` -- WARN-only local
suppression (design doc section 6). A BLOCK-tier finding must error and
direct the user to .aramid-suppressions.toml instead.
"""
from pathlib import Path

from aramid.commands.override import cmd_override
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Verdict


def _f(fid, tool="ruff", rule="F401", verdict=Verdict.WARN, file="a.py"):
    return Finding(fid, tool, rule, "medium", Severity.MEDIUM, verdict, file, 1, "m", "e",
                    Gate.PRE_PUSH)


def _ledger(root) -> Ledger:
    return Ledger(root / ".aramid" / "ledger.db")


def test_warn_id_is_overridden_and_recorded(tmp_path):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("warn1")])
    ledger.close()

    rc = cmd_override(root, "warn1", "known false positive, tracked in JIRA-123")

    assert rc == 0
    ledger = _ledger(root)
    try:
        state = ledger.open_findings()
        assert state["warn1"]["status"] == "overridden"
        events = [e for e in ledger.events() if e.type.value == "finding_overridden"]
        assert len(events) == 1
        assert events[0].finding_id == "warn1"
    finally:
        ledger.close()


def test_block_id_errors_and_directs_to_suppressions_file(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"gitleaks"}, {"a.py"},
                       [_f("block1", tool="gitleaks", rule="aws-key", verdict=Verdict.BLOCK)])
    ledger.close()

    rc = cmd_override(root, "block1", "please just let me push")
    err = capsys.readouterr().err

    assert rc == 3
    assert ".aramid-suppressions.toml" in err

    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["block1"]["status"] == "open"
    finally:
        ledger.close()


def test_unknown_id_errors(tmp_path, capsys):
    root: Path = tmp_path
    rc = cmd_override(root, "nope", "some reason")
    err = capsys.readouterr().err

    assert rc == 3
    assert "nope" in err


def test_missing_reason_errors(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("warn1")])
    ledger.close()

    rc = cmd_override(root, "warn1", "")
    err = capsys.readouterr().err

    assert rc == 3
    assert "reason" in err.lower()
