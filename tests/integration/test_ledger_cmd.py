"""integration: `aramid ledger list|show|filter|mark-rotated|mark-not-a-secret|
mark-unreachable`."""
import json
import os
import subprocess
import sys
from pathlib import Path

from aramid import cli
from aramid.commands.ledger_cmd import (
    _render_row,
    cmd_ledger_filter,
    cmd_ledger_list,
    cmd_ledger_mark_not_a_secret,
    cmd_ledger_mark_rotated,
    cmd_ledger_mark_unreachable,
    cmd_ledger_show,
)
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Verdict


def _f(fid, tool="ruff", rule="S102", verdict=Verdict.WARN, file="a.py", historical=False,
        message="m"):
    return Finding(fid, tool, rule, "high", Severity.HIGH, verdict, file, 1, message, "e",
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


# ------------------------------------------------------ filter --json ---
# Round 64 item 5a. The one-line text row puts id, tool:rule, file:line and
# the free-text message on a single line, so a consumer splitting on
# whitespace swallows the message into the file field. That silently
# mis-tagged a downstream repo's first batch of 26 overrides.

def test_filter_json_emits_parseable_records(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"},
                       [_f("f1", message="SQL query built via string concat")])
    ledger.close()

    rc = cmd_ledger_filter(root, tool="ruff", as_json=True)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert len(payload) == 1
    rec = payload[0]
    # The whole point: every field a consumer needs is separately addressable.
    assert rec["id"] == "f1"
    assert rec["tool"] == "ruff"
    assert rec["rule"] == "S102"
    assert rec["file"] == "a.py"
    assert rec["message"] == "SQL query built via string concat"


def test_filter_json_survives_a_message_containing_the_text_delimiter(tmp_path, capsys):
    """The text format's actual failure mode, pinned.

    A message containing ` -- ` (or a colon, or a space) is indistinguishable
    from the row's own structure once rendered. In JSON it round-trips exactly,
    which is the property the downstream parser needed and did not have.
    """
    root: Path = tmp_path
    nasty = "a.py:1 -- looks like another row: really it is the message"
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"},
                       [_f("f1", message=nasty)])
    ledger.close()

    cmd_ledger_filter(root, tool="ruff", as_json=True)
    payload = json.loads(capsys.readouterr().out)

    assert payload[0]["message"] == nasty
    assert payload[0]["file"] == "a.py"


def test_filter_json_with_no_matches_emits_an_empty_array(tmp_path, capsys):
    """`no matching findings` is prose, and a consumer cannot parse it. An
    empty result must still be valid JSON or every caller needs a special
    case -- which is exactly where a parser starts guessing."""
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1")])
    ledger.close()

    rc = cmd_ledger_filter(root, tool="nonexistent-tool", as_json=True)

    assert rc == 0
    assert json.loads(capsys.readouterr().out) == []


def test_filter_json_flag_is_wired_through_the_cli(tmp_path, monkeypatch, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1")])
    ledger.close()
    monkeypatch.chdir(root)

    rc = cli.main(["ledger", "filter", "--tool", "ruff", "--json"])

    assert rc == 0
    assert json.loads(capsys.readouterr().out)[0]["id"] == "f1"


# ------------------------------------------- redirected output is UTF-8 ---
# Round 64 item 5b, reported by a consumer whose parser got mojibake off a
# redirected `ledger filter`. THESE MUST BE SUBPROCESS TESTS. Under pytest,
# captured stdout is already UTF-8, so an in-process assertion passes whether
# or not the bug is present -- it would be a test that cannot fail.
#
# `PYTHONIOENCODING=cp1252` reproduces, on every platform, what Windows does
# natively when stdout is a pipe or a file (measured on this machine:
# `sys.stdout.encoding` is `cp1252` when redirected). Without it these would
# pass vacuously on the Linux and macOS legs, which is precisely the shape of
# green that hid the original defect.

def _run_cli(root: Path, *args: str) -> bytes:
    """Run the real CLI with stdout REDIRECTED, under a legacy encoding, and
    return the raw bytes it wrote. Redirection is the whole point: it is what
    makes Python pick the locale encoding instead of the console's."""
    env = dict(os.environ, PYTHONIOENCODING="cp1252")
    out_path = root / "cli-stdout.bin"
    with open(out_path, "wb") as fh:
        subprocess.run([sys.executable, "-m", "aramid", *args],
                       cwd=root, stdout=fh, stderr=subprocess.PIPE, env=env)
    return out_path.read_bytes()


def test_redirected_ledger_output_is_valid_utf8(tmp_path):
    """A finding whose message is non-ASCII must still come back as UTF-8.

    Falsifiability: before the fix this raises UnicodeDecodeError on byte
    0x93/0x94 (cp1252's curly quotes); the assertion cannot pass by accident,
    because strict decoding either succeeds on the whole stream or raises.
    """
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"},
                       [_f("f1", message="unsafe “query” built in café.py")])
    ledger.close()

    raw = _run_cli(root, "ledger", "list")

    text = raw.decode("utf-8")          # strict: raises on any invalid byte
    assert "f1" in text
    assert "café" in text


def test_render_row_separator_is_ascii(tmp_path):
    """The separator itself was the reported defect: a literal U+2014 that
    cp1252 encodes as the bare byte 0x97, which is not valid UTF-8 at all.

    Asserted on the row function rather than through the CLI so it stays true
    regardless of stream encoding -- the house style everywhere else in this
    codebase is a plain `--`, and this line was the one exception.
    """
    row = _render_row("f1", {"status": "open", "tool": "ruff", "rule": "S102",
                             "file": "a.py", "line": 1, "message": "m"})

    row.encode("ascii")                 # raises if a non-ASCII char crept back
    assert "--" in row


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


def test_mark_not_a_secret_refuses_fixed_finding_generic_tail(tmp_path, capsys):
    # Covers the "anything else" branch (status neither open, not_a_secret,
    # nor rotated) -- the one any future/unexpected status silently lands in.
    # A "fixed" finding gets here: detect it open, then re-run with the same
    # tool/file in scope but the finding absent, which resolves it to fixed.
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"gitleaks"}, {"a.py"},
                       [_f("f1", tool="gitleaks", verdict=Verdict.BLOCK, historical=False)])
    ledger.record_run("r2", "t2", "pre-push", {"gitleaks"}, {"a.py"}, [])
    assert ledger.open_findings()["f1"]["status"] == "fixed"
    events_before = len(ledger.events())
    ledger.close()

    rc = cmd_ledger_mark_not_a_secret(root, "f1", "trying to mark a fixed finding")
    err = capsys.readouterr().err

    assert rc == 3
    assert ("mark-not-a-secret only applies to historical secrets from "
            "init's full-history scan.") in err
    # Discriminate from the `open`-specific tail, which starts with the same
    # sentence but continues with suppression-path guidance -- if the
    # "else" branch ever fell through to (or was merged with) the `open`
    # branch, this would catch it.
    assert "aramid override" not in err
    assert ".aramid-suppressions.toml" not in err

    ledger = _ledger(root)
    try:
        assert len(ledger.events()) == events_before
        assert ledger.open_findings()["f1"]["status"] == "fixed"
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


def test_mark_not_a_secret_missing_reason_flag_exits_3_via_argparse(capsys):
    # Omitting --reason entirely is an argparse path (required=True raises
    # SystemExit(2), remapped to 3 by cli.main) -- distinct from the
    # empty/whitespace case above, which the command function handles itself.
    # Must go through cli.main, not a direct call to the command function.
    # Asserting only rc == 3 is not enough: a regressed `required=False`
    # would let argparse hand the function reason=None, which the function's
    # OWN "if not reason: return 3" guard also satisfies with rc == 3 -- for
    # the wrong reason, never touching the ledger. Assert on argparse's own
    # error text so the two mechanisms are distinguishable.
    rc = cli.main(["ledger", "mark-not-a-secret", "hist1"])
    err = capsys.readouterr().err

    assert rc == 3
    assert "the following arguments are required" in err


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


# ----------------------------------------------------- mark-unreachable ---

def test_mark_unreachable_transitions_open_finding_whose_tool_left_selection(
        tmp_path, capsys, monkeypatch):
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.close()

    rc = cmd_ledger_mark_unreachable(root, "f1", "ruff no longer selected for this repo")

    assert rc == 0
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["f1"]["status"] == "unreachable"
        events = [e for e in ledger.events() if e.type.value == "finding_unreachable"]
        assert len(events) == 1
        assert events[0].payload["reason"] == "ruff no longer selected for this repo"
    finally:
        ledger.close()


def test_mark_unreachable_refuses_when_tool_still_selected(tmp_path, capsys, monkeypatch):
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    (root / "pyproject.toml").write_text("[tool.x]\n", encoding="utf-8")  # keeps ruff selected
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.close()

    rc = cmd_ledger_mark_unreachable(root, "f1", "trying anyway")
    err = capsys.readouterr().err

    assert rc == 3
    assert "still runs in this repo" in err
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["f1"]["status"] == "open"
    finally:
        ledger.close()


def test_mark_unreachable_refuses_producer_tool_finding(tmp_path, capsys, monkeypatch):
    """Spec section 10 item 6 requires BOTH an llm-review finding AND a
    mutation finding to be attempted and refused -- these are the two
    named gate-surface producers (review.llm_gate_findings,
    mutation_gate.mutation_gate_findings) that materialize BLOCK-tier
    findings straight from status=="open"; a silent retire on either would
    drop a gate block."""
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "drain", set(), set(), [
        _f("f1", tool="mutation"),
        _f("f2", tool="llm-review"),
    ])
    ledger.close()

    rc1 = cmd_ledger_mark_unreachable(root, "f1", "trying anyway")
    err1 = capsys.readouterr().err
    rc2 = cmd_ledger_mark_unreachable(root, "f2", "trying anyway")
    err2 = capsys.readouterr().err

    assert rc1 == 3
    assert "never by hand" in err1
    assert rc2 == 3
    assert "never by hand" in err2
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["f1"]["status"] == "open"
        assert ledger.open_findings()["f2"]["status"] == "open"
    finally:
        ledger.close()


def test_mark_unreachable_refuses_historical_finding_redirects_to_gitleaks_commands(
        tmp_path, capsys, monkeypatch):
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                       [_f("hist1", tool="gitleaks", verdict=Verdict.BLOCK, historical=True)])
    ledger.close()

    rc = cmd_ledger_mark_unreachable(root, "hist1", "trying anyway")
    err = capsys.readouterr().err

    assert rc == 3
    assert "mark-rotated" in err
    assert "mark-not-a-secret" in err


def test_mark_unreachable_unknown_id_errors(tmp_path, capsys, monkeypatch):
    from aramid import config as config_mod
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    rc = cmd_ledger_mark_unreachable(tmp_path, "nope", "some reason")
    err = capsys.readouterr().err
    assert rc == 3
    assert "nope" in err


def test_mark_unreachable_requires_reason(tmp_path, capsys):
    rc = cmd_ledger_mark_unreachable(tmp_path, "hist1", "")
    err = capsys.readouterr().err
    assert rc == 3
    assert "reason" in err.lower()


def test_mark_unreachable_missing_reason_flag_exits_3_via_argparse(capsys):
    # Mirrors test_mark_not_a_secret_missing_reason_flag_exits_3_via_argparse
    # (:283-297) -- must go through cli.main, not a direct function call.
    rc = cli.main(["ledger", "mark-unreachable", "hist1"])
    err = capsys.readouterr().err
    assert rc == 3
    assert "the following arguments are required" in err


def test_mark_unreachable_twice_refuses_second_time(tmp_path, capsys, monkeypatch):
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.close()

    rc1 = cmd_ledger_mark_unreachable(root, "f1", "first reason")
    capsys.readouterr()
    rc2 = cmd_ledger_mark_unreachable(root, "f1", "second reason")
    err2 = capsys.readouterr().err

    assert rc1 == 0
    assert rc2 == 3
    assert "already marked unreachable" in err2


def test_unreachable_finding_reopens_when_tool_returns_via_real_dispatch(
        tmp_path, capsys, monkeypatch):
    """End-to-end through cli.main + record_run, not just the ledger unit
    test in Task 2 -- proves the whole command chain, not just _materialize.
    cli.main resolves `root` from Path.cwd(), so this must chdir into
    tmp_path -- unlike the direct cmd_ledger_mark_unreachable(root, ...)
    calls elsewhere in this file, which take root explicitly."""
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    monkeypatch.chdir(tmp_path)
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.close()

    rc = cli.main(["ledger", "mark-unreachable", "f1", "--reason", "ruff not selected"])
    assert rc == 0
    capsys.readouterr()

    ledger = _ledger(root)
    ledger.record_run("r2", "t2", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    try:
        assert ledger.open_findings()["f1"]["status"] == "open"
    finally:
        ledger.close()


# -------- adjudicated vs never-examined are not the same row (R80-2) --------
# Reported from a downstream repo: `ledger filter --status open` returned 20
# BLOCK-verdict rows, 19 of them with written, committed, reviewed entries in
# `.aramid-suppressions.toml` and one that had never been looked at -- a real
# S105 in a file a range-scoped gate had never had in scope. All twenty were
# shape-identical (`status: open`, `verdict: block`, `reason: null`), so the
# one nobody had adjudicated was camouflaged by the nineteen everybody had.
#
# `check` already distinguishes them (a suppressed finding renders `info`).
# `ledger filter` is the surface you reach for when asking "what is
# outstanding", and it did not -- a field answering a different question than
# the reader is asking.


def _suppressions(root: Path, *entries) -> None:
    body = "".join(
        f'[[suppress]]\nid = "{fid}"\ntool = "ruff"\nrule = "S102"\n'
        f'path = "a.py"\nreason = "{reason}"\n\n'
        for fid, reason in entries)
    (root / ".aramid-suppressions.toml").write_text(body, encoding="utf-8")


def test_filter_json_marks_which_open_findings_are_adjudicated(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"},
                       [_f("adjudicated1", verdict=Verdict.BLOCK),
                        _f("nobody_looked", verdict=Verdict.BLOCK)])
    ledger.close()
    _suppressions(root, ("adjudicated1", "reviewed: fixture key, not well-formed"))

    assert cmd_ledger_filter(root, status="open", as_json=True) == 0
    rows = {r["id"]: r for r in json.loads(capsys.readouterr().out)}

    assert rows["adjudicated1"]["suppressed"] is True
    assert "fixture key" in rows["adjudicated1"]["suppressed_reason"]
    # The whole point: the un-adjudicated one must be distinguishable, and the
    # verdict field cannot do it -- both are BLOCK.
    assert rows["nobody_looked"]["suppressed"] is False
    assert rows["nobody_looked"]["suppressed_reason"] is None
    assert rows["adjudicated1"]["verdict"] == rows["nobody_looked"]["verdict"] == "block"


def test_filter_text_row_marks_an_adjudicated_finding(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"},
                       [_f("adjudicated2", verdict=Verdict.BLOCK),
                        _f("unexamined2", verdict=Verdict.BLOCK)])
    ledger.close()
    _suppressions(root, ("adjudicated2", "reviewed: test canary"))

    assert cmd_ledger_filter(root, status="open") == 0
    out = capsys.readouterr().out
    adj = next(ln for ln in out.splitlines() if "adjudicated2" in ln)
    une = next(ln for ln in out.splitlines() if "unexamined2" in ln)

    assert "suppressed" in adj
    assert "suppressed" not in une, \
        "the never-examined finding must not wear the adjudicated marker"
