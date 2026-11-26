"""`aramid ledger reopen <id> --reason R` (channel round 352; operator
decision 2026-11-25): undo a `resolve --fixed` close that carries no red
proof.

Such a close goes through in a repo where the red-proof hook is not armed,
and until this command nothing could take it back: the ledger is append-only
and hand edits are forbidden. Reopen is for that close alone. A close that
showed the test failing without the fix stays, and so does every other way
a finding stops being open.

No git here: the command reads and writes the ledger only. The close is
appended as `resolve --fixed` writes it (test_ledger_resolve_fixed.py
asserts that event whole)."""
import pytest

from aramid import cli
from aramid.commands import ledger_cmd as lc
from aramid.commands.ledger_cmd import cmd_ledger_reopen
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Source, Verdict

FID = "llm1"
SHA = "c" * 40
AT = "2026-11-25T12:00:00+00:00"
_PROOF = {"at": "head", "base": "b" * 40, "control_rc": 0, "pre_fix_rc": 1, "backed_out": 2}


def _finding(tool="llm-review"):
    return Finding(FID, tool, "llm/logic", "high", Severity.HIGH, Verdict.WARN,
                   "calc.py", 2, "route ignores CN", "return 'EU'", Gate.PRE_PUSH,
                   source=Source.LLM if tool == "llm-review" else Source.DETERMINISTIC)


def _ledger(root):
    return Ledger(root / ".aramid" / "ledger.db")


def _seed(root, *events, tool="llm-review"):
    """The finding, detected once, then `events` appended to it in order."""
    led = _ledger(root)
    try:
        finding = _finding(tool)
        led.record_run("r1", "2026-11-20T00:00:00+00:00", "pre-push",
                       {finding.tool}, {finding.file}, [finding], head="a" * 40)
        for k, (kind, payload) in enumerate(events):
            led.append(Event(kind, f"e{k}", f"2026-11-21T0{k}:00:00+00:00",
                             finding_id=FID, payload=payload))
    finally:
        led.close()


def _close(red_proof=None):
    return (EventType.FINDING_RESOLVED,
            {"auto_resolved": lc.EVIDENCED_CLOSE, "commit": SHA, "test_argv": ["pytest"],
             "test_rc": 0, "reason": "fixed it", "head": "d" * 40, "red_proof": red_proof,
             "via": "cli"})


_PROOF_ADDED = (EventType.FINDING_RED_PROOF_ADDED,
                {"commit": SHA, "test_argv": ["pytest"], "test_rc": 0, "head": "d" * 40,
                 "red_proof": _PROOF, "via": "cli", "reason": "proved"})


def _events(root):
    led = _ledger(root)
    try:
        return [e for e in led.events() if e.finding_id == FID]
    finally:
        led.close()


def _status(root):
    led = _ledger(root)
    try:
        return led.open_findings()[FID]["status"]
    finally:
        led.close()


def _refused(capsys, root, rc, line, status):
    """One refusal: exit 3, exactly this line on stderr, nothing appended."""
    before = len(_events(root))
    assert rc == 3
    assert capsys.readouterr() == ("", f"aramid: ledger reopen: {line}\n")
    assert (len(_events(root)), _status(root)) == (before, status)


def test_a_close_without_red_proof_is_reopened_with_the_reason(tmp_path, capsys, monkeypatch):
    _seed(tmp_path, _close())
    monkeypatch.setattr(lc, "_now", lambda: AT)
    detected = _events(tmp_path)[0].payload

    rc = cmd_ledger_reopen(tmp_path, FID, "the test never failed without the fix")

    assert (rc, capsys.readouterr()) == (0, (
        f"aramid: ledger: {FID} is open again -- its close as fixed in {SHA[:12]} carried "
        f"no red proof (the test never failed without the fix)\n", ""))
    assert _status(tmp_path) == "open"
    last = _events(tmp_path)[-1]
    assert (last.type, last.at) == (EventType.FINDING_DETECTED, AT)
    # The detection as it was first recorded, and why it is back.
    assert last.payload == {**detected, "line": 2, "reopened": "weak_close",
                            "reopen_reason": "the test never failed without the fix",
                            "closed_in": SHA, "via": "cli"}


@pytest.mark.parametrize("events", [[_close(_PROOF)], [_close(), _PROOF_ADDED]],
                         ids=["closed with it", "added afterwards"])
def test_a_close_that_carries_red_proof_is_not_reopened(tmp_path, capsys, events):
    _seed(tmp_path, *events)

    rc = cmd_ledger_reopen(tmp_path, FID, "r")

    _refused(capsys, tmp_path, rc,
             f"{FID}'s close as fixed in {SHA[:12]} carries red proof -- reopen undoes "
             f"only a close made without it. A review that raises the finding again "
             f"reopens it", "fixed")


def test_a_finding_something_else_closed_is_not_reopened(tmp_path, capsys):
    _seed(tmp_path, (EventType.FINDING_RESOLVED, {"auto_resolved": "evidence_gone"}))

    rc = cmd_ledger_reopen(tmp_path, FID, "r")

    _refused(capsys, tmp_path, rc,
             f"{FID} was not closed by `ledger resolve --fixed` (status=fixed) -- reopen "
             f"undoes only such a close, made without red proof", "fixed")


def test_an_open_finding_is_not_reopened(tmp_path, capsys):
    _seed(tmp_path)

    rc = cmd_ledger_reopen(tmp_path, FID, "r")

    _refused(capsys, tmp_path, rc,
             f"{FID} was not closed by `ledger resolve --fixed` (status=open) -- reopen "
             f"undoes only such a close, made without red proof", "open")


@pytest.mark.parametrize("reason", ["", "   ", None])
def test_reopen_requires_a_reason(tmp_path, capsys, reason):
    _seed(tmp_path, _close())

    rc = cmd_ledger_reopen(tmp_path, FID, reason)

    _refused(capsys, tmp_path, rc, "--reason is required", "fixed")


def test_reopen_refuses_an_unknown_id(tmp_path, capsys):
    _seed(tmp_path, _close())

    rc = cmd_ledger_reopen(tmp_path, "nope", "r")

    _refused(capsys, tmp_path, rc, "unknown finding id nope", "fixed")


def test_ledger_show_says_who_reopened_it_and_why(tmp_path, capsys, monkeypatch):
    _seed(tmp_path, _close())
    monkeypatch.setattr(lc, "_now", lambda: AT)
    assert cmd_ledger_reopen(tmp_path, FID, "no red run") == 0
    capsys.readouterr()

    assert lc.cmd_ledger_show(tmp_path, FID) == 0

    lines = capsys.readouterr().out.splitlines()
    at = next(i for i, line in enumerate(lines) if line.startswith(f"  {AT}  finding_detected"))
    assert lines[at + 1] == (f"      reopened (cli): its close as fixed in {SHA} carried no "
                             f"red proof: no red run")


def test_the_cli_reaches_reopen(tmp_path, capsys, monkeypatch):
    _seed(tmp_path, _close())
    monkeypatch.chdir(tmp_path)

    rc = cli.main(["ledger", "reopen", FID, "--reason", "no red run"])

    assert rc == 0
    assert _status(tmp_path) == "open"
    assert capsys.readouterr().out.startswith(f"aramid: ledger: {FID} is open again")
