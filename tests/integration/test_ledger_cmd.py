"""integration: `aramid ledger list|show|filter|mark-rotated|mark-not-a-secret|
mark-unreachable`."""
import json
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

def _run_cli(root: Path, base_env: dict, *args: str) -> bytes:
    """Run the real CLI with stdout REDIRECTED, under a legacy encoding, and
    return the raw bytes it wrote. Redirection is the whole point: it is what
    makes Python pick the locale encoding instead of the console's.
    `base_env` is `checkout_env` (tests/conftest.py): without it the child
    resolves the installed wheel, not this checkout."""
    env = dict(base_env, PYTHONIOENCODING="cp1252")
    out_path = root / "cli-stdout.bin"
    with open(out_path, "wb") as fh:
        subprocess.run([sys.executable, "-P", "-m", "aramid", *args],
                       cwd=root, stdout=fh, stderr=subprocess.PIPE, env=env)
    return out_path.read_bytes()


def test_redirected_ledger_output_is_valid_utf8(tmp_path, checkout_env):
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

    raw = _run_cli(root, checkout_env, "ledger", "list")

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


# ------------------------------------------------- verdict_now (compute-on-read) ---
#
# The stored `verdict` is frozen at detection and stays that way on purpose --
# an auditor still needs "what would this be if the suppression were
# withdrawn". What was missing is the OTHER half: what tier is it now. Arming
# is retroactive, so a row can read `warn` while the finding blocks today, and
# nothing on the row said so (interop rounds 80, 82, 87 section 6).

def _mutation_f(fid="mut1"):
    return Finding(fid, "mutation", "survived", "medium", Severity.MEDIUM, Verdict.WARN,
                    "src/pay.py", 7, "surviving mutant", "e", Gate.PRE_PUSH)


def test_filter_json_carries_verdict_now_on_every_row(tmp_path, capsys):
    """UNCONDITIONAL, and that is the whole point of the field's shape.

    graphite withdrew their own `verdict_gate` proposal on exactly this
    reasoning: a field present on some rows and absent on others invites the
    reader to infer meaning from its absence, and that inference is
    unverifiable from the row. So `verdict_now` appears on the row whose tier
    moved AND on the row whose tier did not.
    """
    root: Path = tmp_path
    (root / "aramid.toml").write_text("[mutation]\nmutation_block_armed = true\n",
                                       encoding="utf-8")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation", "ruff"}, {"src/pay.py", "a.py"},
                       [_mutation_f(), _f("ruff1", rule="F401")])
    ledger.close()

    assert cmd_ledger_filter(root, as_json=True) == 0
    rows = {r["id"]: r for r in json.loads(capsys.readouterr().out)}

    # The moved row: stored value untouched, current tier reported beside it.
    assert rows["mut1"]["verdict"] == "warn"
    assert rows["mut1"]["verdict_now"] == "block"
    # The unmoved row carries the key too, or absence becomes a signal.
    # `F401` deliberately, not this module's default `S102`: S102 is BLOCK-tier
    # under the shipped block_rules while `_f` stores WARN, so it is a MOVED
    # row and would make a useless control here. That the fixture could store a
    # verdict `classify` disagrees with is not a fixture bug -- it is the exact
    # drift this field exists to surface, arrived at from the other direction.
    assert "verdict_now" in rows["ruff1"], "verdict_now must be on EVERY row"
    assert rows["ruff1"]["verdict_now"] == rows["ruff1"]["verdict"] == "warn"


def test_show_reports_verdict_now_beside_the_stored_verdict(tmp_path, capsys):
    root: Path = tmp_path
    (root / "aramid.toml").write_text("[mutation]\nmutation_block_armed = true\n",
                                       encoding="utf-8")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, {"src/pay.py"}, [_mutation_f()])
    ledger.close()

    assert cmd_ledger_show(root, "mut1") == 0
    out = capsys.readouterr().out

    assert "verdict: warn" in out
    assert "verdict_now: block" in out


def test_text_row_flags_a_moved_tier_and_stays_quiet_when_it_has_not_moved(tmp_path, capsys):
    """Two arms in one test on purpose: the marker is only meaningful if its
    ABSENCE is also verified. An implementation that appended `[now: ...]`
    unconditionally would pass a one-armed version of this and turn every row
    into noise."""
    root: Path = tmp_path
    (root / "aramid.toml").write_text("[mutation]\nmutation_block_armed = true\n",
                                       encoding="utf-8")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation", "ruff"}, {"src/pay.py", "a.py"},
                       [_mutation_f(), _f("ruff1", rule="F401")])
    ledger.close()

    assert cmd_ledger_filter(root, status="open") == 0
    out = capsys.readouterr().out
    moved = next(ln for ln in out.splitlines() if "mut1" in ln)
    unmoved = next(ln for ln in out.splitlines() if "ruff1" in ln)

    assert "[now: block]" in moved
    assert "now:" not in unmoved, "an unmoved tier must not be annotated"


def test_an_unreadable_config_fails_the_query_rather_than_reporting_null_tiers(
        tmp_path, capsys):
    """Refuse, do not fabricate. `verdict_now` is on every row, so a config we
    cannot read means the command cannot deliver what it now promises --
    printing rows with a null tier invites exactly the misreading this field
    exists to remove. Mirrors `aramid override`, which refuses on the same
    reasoning: being unable to read the config is being unable to answer.

    Note this deliberately differs from the suppressions handling above, where
    a malformed file leaves the per-row marker ABSENT rather than false. That
    is a marker whose absence is meaningful; this is a value on every row.
    """
    root: Path = tmp_path
    (root / "aramid.toml").write_text("this is not = valid = toml\n", encoding="utf-8")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, {"src/pay.py"}, [_mutation_f()])
    ledger.close()

    rc = cmd_ledger_filter(root, as_json=True)
    err = capsys.readouterr().err

    assert rc == 3
    assert "config" in err.lower()


def test_mark_unreachable_refuses_a_superseded_finding_and_points_at_its_successor(
        tmp_path, capsys, monkeypatch):
    """Round 135 s3: a rewritten line resolves as `superseded`, not `fixed`.
    The old id is not open, so retiring it by hand is refused -- and the
    refusal names the sibling that replaced it, which is the row that now
    needs a decision."""
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("old", tool="ruff")])
    ledger.record_run("r2", "t2", "pre-push", {"ruff"}, {"a.py"}, [_f("new", tool="ruff")])
    ledger.close()

    rc = cmd_ledger_mark_unreachable(root, "old", "a reason")
    err = capsys.readouterr().err

    assert rc == 3
    assert "status=superseded" in err
    assert "new" in err, "the refusal must name the successor"


def _resolve(root, finding_id, out_of_scope, reason):
    """Lazy import: while the command does not exist yet this reads as a
    failing test, not a broken file."""
    from aramid.commands.ledger_cmd import cmd_ledger_resolve
    return cmd_ledger_resolve(root, finding_id, out_of_scope=out_of_scope, reason=reason)


# --- resolve --out-of-scope: a runner that no longer EXAMINES the path ----------
# Interop rounds 139/144/145. The typecheck runner used to hand mypy every file
# in range; once scoped to .py/.pyi, a `mypy:syntax` row recorded against
# `ci.yml` can never resolve -- resolution needs a run that EXAMINES the file,
# and this runner never will again -- and `mark-unreachable` refuses because
# mypy is still selected. The consumer chose (ii): a resolution that records
# WHY as its own event kind, refusing while a selected runner can still
# examine the path so it cannot become a general-purpose silencer.

def _python_repo(tmp_path, monkeypatch) -> Path:
    from aramid import config as config_mod
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    (tmp_path / "pyproject.toml").write_text("[tool.x]\n", encoding="utf-8")  # ruff selected
    return tmp_path


def test_resolve_out_of_scope_retires_a_finding_its_runner_no_longer_examines(
        tmp_path, capsys, monkeypatch):
    root = _python_repo(tmp_path, monkeypatch)
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {".github/workflows/ci.yml"},
                      [_f("f1", tool="ruff", file=".github/workflows/ci.yml")])
    ledger.close()

    rc = _resolve(root, "f1", out_of_scope=True,
                            reason="runner scoped to .py/.pyi in 0.6.1")
    out = capsys.readouterr()

    assert rc == 0, out.err
    ledger = _ledger(root)
    try:
        rec = ledger.open_findings()["f1"]
        assert rec["status"] == "out_of_scope"
        assert rec["reason"] == "runner scoped to .py/.pyi in 0.6.1"
        events = [e for e in ledger.events() if e.type.value == "finding_out_of_scope"]
        assert len(events) == 1 and events[0].payload["tool"] == "ruff"
    finally:
        ledger.close()


def test_resolve_out_of_scope_refuses_while_the_runner_still_examines_the_path(
        tmp_path, capsys, monkeypatch):
    """The guard the consumer asked for: a `.py` path is still ruff's to
    examine, so the next run that looks resolves or re-reports it -- by hand
    is a silencer."""
    root = _python_repo(tmp_path, monkeypatch)
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff", file="a.py")])
    ledger.close()

    rc = _resolve(root, "f1", out_of_scope=True, reason="please")
    err = capsys.readouterr().err

    assert rc == 3
    assert "still examines" in err and "a.py" in err
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["f1"]["status"] == "open"
    finally:
        ledger.close()


def test_resolve_out_of_scope_refuses_a_tool_that_examines_every_file(
        tmp_path, capsys, monkeypatch):
    """gitleaks has no suffix scope, so no path can be out of ITS scope;
    a vanished secret resolves on the next run like any other finding."""
    root = _python_repo(tmp_path, monkeypatch)
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"gitleaks"}, {"ci.yml"},
                      [_f("f1", tool="gitleaks", file="ci.yml")])
    ledger.close()

    rc = _resolve(root, "f1", out_of_scope=True, reason="please")
    err = capsys.readouterr().err

    assert rc == 3
    assert "gitleaks" in err and "every file" in err


def test_resolve_out_of_scope_redirects_to_mark_unreachable_when_the_tool_left(
        tmp_path, capsys, monkeypatch):
    """No pyproject: ruff is not selected at all. That is the OTHER retire
    path's case, and the two must not blur into each other."""
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"ci.yml"}, [_f("f1", tool="ruff", file="ci.yml")])
    ledger.close()

    rc = _resolve(root, "f1", out_of_scope=True, reason="please")
    err = capsys.readouterr().err

    assert rc == 3
    assert "mark-unreachable" in err


def test_resolve_without_a_kind_is_refused(tmp_path, capsys, monkeypatch):
    root = _python_repo(tmp_path, monkeypatch)
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"ci.yml"}, [_f("f1", tool="ruff", file="ci.yml")])
    ledger.close()

    rc = _resolve(root, "f1", out_of_scope=False, reason="please")
    err = capsys.readouterr().err

    assert rc == 3
    assert "--out-of-scope" in err


def test_resolve_out_of_scope_requires_a_reason_and_an_open_finding(tmp_path, capsys, monkeypatch):
    root = _python_repo(tmp_path, monkeypatch)
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"ci.yml"}, [_f("f1", tool="ruff", file="ci.yml")])
    ledger.close()

    assert _resolve(root, "f1", out_of_scope=True, reason="  ") == 3
    assert "--reason is required" in capsys.readouterr().err
    assert _resolve(root, "f1", out_of_scope=True, reason="ok") == 0
    capsys.readouterr()
    assert _resolve(root, "f1", out_of_scope=True, reason="again") == 3
    assert "status=out_of_scope" in capsys.readouterr().err


def test_an_out_of_scope_finding_reopens_if_its_runner_reports_it_again(tmp_path, capsys, monkeypatch):
    """Like `fixed`, `unreachable` and `superseded`: a resting state a
    re-detect leaves. If a future runner ever examines the path and reports
    the same content, the row is open again."""
    root = _python_repo(tmp_path, monkeypatch)
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"ci.yml"}, [_f("f1", tool="ruff", file="ci.yml")])
    ledger.close()
    assert _resolve(root, "f1", out_of_scope=True, reason="scoped") == 0
    ledger = _ledger(root)
    try:
        ledger.record_run("r2", "t2", "pre-push", {"ruff"}, {"ci.yml"}, [_f("f1", tool="ruff", file="ci.yml")])
        assert ledger.open_findings()["f1"]["status"] == "open"
    finally:
        ledger.close()


def test_mark_unreachable_reports_an_unreadable_config_as_an_engine_error(tmp_path, capsys, monkeypatch):
    """The `return 3` on the config-load path had no test; the drain found
    it mutable 3 -> 4 (0074afbe). An unreadable config is exit 3 with the
    error named, never a silent 0 or a traceback."""
    from aramid import config as config_mod
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.close()

    def boom(_root):
        raise RuntimeError("aramid.toml: unreadable")
    monkeypatch.setattr(config_mod, "load_config", boom)

    rc = cmd_ledger_mark_unreachable(root, "f1", "a reason")
    err = capsys.readouterr().err

    assert rc == 3
    assert "engine error" in err and "unreadable" in err


def test_resolve_out_of_scope_accepts_a_python_path_outside_mypys_own_files_scope(
        tmp_path, capsys, monkeypatch):
    """Round 149 (b)/(c): 683 mypy rows on files a repo's `[tool.mypy]
    files = [...]` deliberately leaves untyped. With the runner honouring
    that scope, those paths are ones mypy will never examine here, so the
    retire path must accept them -- the same guard, now config-aware."""
    from aramid import config as config_mod
    root: Path = tmp_path
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    (root / "pyproject.toml").write_text('[tool.mypy]\nfiles = ["src"]\n', encoding="utf-8")   # mypy selected, scoped
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mypy"}, {"tests/test_a.py", "src/a.py"},
                      [_f("t1", tool="mypy", file="tests/test_a.py"), _f("s1", tool="mypy", file="src/a.py")])
    ledger.close()

    assert _resolve(root, "t1", out_of_scope=True, reason="outside [tool.mypy] files") == 0
    capsys.readouterr()
    assert _resolve(root, "s1", out_of_scope=True, reason="please") == 3
    assert "still examines" in capsys.readouterr().err


# ------------------------------------------------------ filter vocabulary ---
# `aramid status` prints the status vocabulary with hyphens (`pending-retest`,
# `not-a-secret`, `out-of-scope`); the ledger stores underscores; and
# `filter --status` compared the raw string. So the spelling `status` itself
# teaches returned "no matching findings" for rows that existed -- an empty
# answer indistinguishable from a real absence, on the one surface the release
# checklist reads. Same shape for `--severity`, whose vocabulary is also fixed.
# A value outside the vocabulary is a usage error and is refused (exit 3, the
# config/engine code), never answered with an empty match.

def _not_a_secret_row(root):
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "historical-scan", {"gitleaks"}, set(),
                      [_f("hist1", tool="gitleaks", rule="generic-api-key",
                          verdict=Verdict.BLOCK, historical=True)])
    ledger.close()
    assert cmd_ledger_mark_not_a_secret(root, "hist1", "a public client id") == 0


def test_filter_status_accepts_the_spelling_status_prints(tmp_path, capsys):
    root: Path = tmp_path
    _not_a_secret_row(root)
    capsys.readouterr()

    rc = cmd_ledger_filter(root, status="not-a-secret")
    out = capsys.readouterr().out

    assert rc == 0
    assert "hist1" in out
    assert "no matching" not in out.lower()


def test_filter_status_is_case_insensitive(tmp_path, capsys):
    root: Path = tmp_path
    _not_a_secret_row(root)
    capsys.readouterr()

    rc = cmd_ledger_filter(root, status="NOT_A_SECRET")
    out = capsys.readouterr().out

    assert rc == 0
    assert "hist1" in out


def test_filter_refuses_an_unknown_status_rather_than_answering_empty(tmp_path, capsys):
    root: Path = tmp_path
    _not_a_secret_row(root)
    capsys.readouterr()

    rc = cmd_ledger_filter(root, status="pending-retset")
    captured = capsys.readouterr()

    assert rc == 3
    assert "no matching" not in captured.out.lower()
    assert "pending-retset" in captured.err          # echoes what it was given
    assert "pending_retest" in captured.err          # and lists the vocabulary


def test_filter_json_refuses_an_unknown_status_rather_than_printing_an_empty_list(
        tmp_path, capsys):
    root: Path = tmp_path
    _not_a_secret_row(root)
    capsys.readouterr()

    rc = cmd_ledger_filter(root, status="nonsense", as_json=True)
    captured = capsys.readouterr()

    assert rc == 3
    assert captured.out.strip() != "[]"


def test_filter_severity_is_case_insensitive(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1")])   # HIGH
    ledger.close()

    rc = cmd_ledger_filter(root, severity="HIGH")
    out = capsys.readouterr().out

    assert rc == 0
    assert "f1" in out


def test_filter_refuses_an_unknown_severity(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1")])
    ledger.close()

    rc = cmd_ledger_filter(root, severity="urgent")
    captured = capsys.readouterr()

    assert rc == 3
    assert "urgent" in captured.err
    assert "critical" in captured.err
