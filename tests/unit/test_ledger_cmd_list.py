"""`commands.ledger_cmd`'s READ side at unit scope -- list, show, filter's two
exits, `_render_row`'s moved-tier marker and the two refuse-or-answer
helpers -- every printed line asserted whole.

The drain confirms a mutant against the unit suite alone; until this file
`cmd_ledger_list` and `cmd_ledger_show` were executed only by
tests/integration/test_ledger_cmd.py, which the drain never runs, and the
marker condition in `_render_row` (`verdict_now is not None and verdict_now
!= rec["verdict"]`) and both helpers' `return 3` sat on lines no unit test
reached. Twelve generator mutants, survivors by construction.

Seams: a real tmp ledger; the repo's own aramid.toml for the tier (a WARN
mutation row reads `[now: block]` once `mutation_block_armed` is set)."""
import json

from aramid.commands import ledger_cmd as lc
from aramid.commands.ledger_cmd import (
    _render_row,
    cmd_ledger_filter,
    cmd_ledger_list,
    cmd_ledger_show,
)
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Status, Verdict


def _f(fid, tool="ruff", rule="F401", file="a.py", line=1, message="m", verdict=Verdict.WARN,
       severity=Severity.LOW):
    """ruff F401 at low severity classifies WARN under a default config, so
    the stored verdict and `verdict_now` agree and no `[now: ...]` marker
    appears unless a test moves the tier on purpose."""
    return Finding(fid, tool, rule, severity.value, severity, verdict, file, line, message, "e",
                   Gate.PRE_PUSH)


def _seed(root, *findings, at="2026-09-14T00:00:00+00:00", run="r1", files=None):
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        led.record_run(run, at, "pre-push", {f.tool for f in findings} or {"ruff"},
                       files if files is not None else {f.file for f in findings},
                       list(findings))
    finally:
        led.close()


# --------------------------------------------------------------- _render_row --

def test_render_row_marks_only_a_moved_tier():
    rec = {"status": "open", "tool": "ruff", "rule": "F401", "file": "a.py", "line": 7,
           "message": "m", "verdict": "warn"}
    plain = "[open] f1 ruff:F401 a.py:7 -- m"

    assert _render_row("f1", rec) == plain
    assert _render_row("f1", rec, "warn") == plain
    assert _render_row("f1", rec, "block") == plain + "  [now: block]"


# ---------------------------------------------------------------- helpers --

def test_config_or_error_refuses_an_unreadable_config(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("this is not = valid = toml\n", encoding="utf-8")

    assert lc._config_or_error(tmp_path, "list") == (None, 3)
    err = capsys.readouterr().err
    assert err.startswith("aramid: ledger list: cannot read the config (")
    assert err.endswith(") -- refusing. Every row's verdict_now is computed from the config "
                        "in force, so being unable to read it is being unable to answer. "
                        "Fix aramid.toml and retry.\n")


def test_config_or_error_returns_the_config_when_it_reads(tmp_path, capsys):
    cfg, err = lc._config_or_error(tmp_path, "list")

    assert err is None and cfg is not None
    assert capsys.readouterr() == ("", "")


def test_vocab_or_error_refuses_a_value_outside_the_vocabulary(capsys):
    assert lc._vocab_or_error("Pending-Retest", Status, "--status") == ("pending_retest", None)
    assert lc._vocab_or_error(None, Status, "--status") == (None, None)

    assert lc._vocab_or_error("stale", Status, "--status") == (None, 3)
    assert capsys.readouterr() == (
        "", "aramid: ledger filter: unknown --status value 'stale' -- refusing rather than "
            "answering 'no matching findings' for a value no row can carry. Valid: open, "
            "fixed, overridden, historical, rotated, not_a_secret, unreachable, superseded, "
            "out_of_scope, pending_retest (hyphens and case are accepted).\n")


# ------------------------------------------------------------------- list --

def test_list_prints_one_row_per_finding_in_ledger_order(tmp_path, capsys):
    _seed(tmp_path, _f("f1"), _f("f2", file="b.py", line=3, message="second"))

    assert cmd_ledger_list(tmp_path) == 0
    assert capsys.readouterr() == (
        "[open] f1 ruff:F401 a.py:1 -- m\n"
        "[open] f2 ruff:F401 b.py:3 -- second\n", "")


def test_list_on_an_empty_ledger_says_so_and_exits_0(tmp_path, capsys):
    assert cmd_ledger_list(tmp_path) == 0
    assert capsys.readouterr() == ("aramid: ledger: no findings recorded\n", "")


def test_list_refuses_an_unreadable_config(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("this is not = valid = toml\n", encoding="utf-8")
    _seed(tmp_path, _f("f1"))

    assert cmd_ledger_list(tmp_path) == 3
    assert "aramid: ledger list: cannot read the config" in capsys.readouterr().err


def test_list_flags_a_row_whose_tier_moved(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("[mutation]\nmutation_block_armed = true\n",
                                          encoding="utf-8")
    _seed(tmp_path, _f("m1", tool="mutation", rule="survived", file="src/pay.py", line=7,
                       message="surviving mutant"))

    assert cmd_ledger_list(tmp_path) == 0
    assert capsys.readouterr().out == (
        "[open] m1 mutation:survived src/pay.py:7 -- surviving mutant  [now: block]\n")


# ------------------------------------------------------------------- show --

def test_show_prints_the_stored_keys_then_verdict_now_then_only_this_findings_events(
        tmp_path, capsys):
    _seed(tmp_path, _f("f1"), _f("f2", file="b.py"))
    # a second run examines b.py and reports nothing: f2 resolves, f1 is untouched
    _seed(tmp_path, at="2026-09-14T01:00:00+00:00", run="r2", files={"b.py"})

    assert cmd_ledger_show(tmp_path, "f2") == 0
    assert capsys.readouterr() == (
        "id:       f2\n"
        "tool: ruff\n"
        "rule: F401\n"
        "file: b.py\n"
        "line: 1\n"
        "severity: low\n"
        "verdict: warn\n"
        "message: m\n"
        "evidence: e\n"
        "historical: False\n"
        "status: fixed\n"
        "reason: None\n"
        "verdict_now: warn\n"
        "events:\n"
        "  2026-09-14T00:00:00+00:00  finding_detected  run=r1\n"
        "  2026-09-14T01:00:00+00:00  finding_resolved  run=r2\n", "")


def test_show_unknown_id(tmp_path, capsys):
    _seed(tmp_path, _f("f1"))

    assert cmd_ledger_show(tmp_path, "nope") == 3
    assert capsys.readouterr() == ("", "aramid: ledger show: unknown finding id nope\n")


def test_show_refuses_an_unreadable_config(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("this is not = valid = toml\n", encoding="utf-8")

    assert cmd_ledger_show(tmp_path, "f1") == 3
    assert "aramid: ledger show: cannot read the config" in capsys.readouterr().err


# ----------------------------------------------------------------- filter --

def test_filter_text_rows_exit_0(tmp_path, capsys):
    _seed(tmp_path, _f("f1"), _f("f2", tool="semgrep", rule="r", file="b.py"))

    assert cmd_ledger_filter(tmp_path, tool="semgrep") == 0
    assert capsys.readouterr() == ("[open] f2 semgrep:r b.py:1 -- m\n", "")


def test_filter_marks_a_committed_suppression_in_both_output_shapes(tmp_path, capsys):
    """The marker comes from `load_suppressions(root)[0]` -- the records, not
    the second member of the pair (`[0] -> [1]` was a latent survivor: no
    unit test had a suppressions file beside the ledger)."""
    _seed(tmp_path, _f("adjudicated"), _f("unexamined", file="b.py"))
    (tmp_path / ".aramid-suppressions.toml").write_text(
        '[[suppress]]\nid = "adjudicated"\ntool = "ruff"\nrule = "F401"\npath = "a.py"\n'
        'reason = "reviewed: fixture import"\n', encoding="utf-8")

    assert cmd_ledger_filter(tmp_path, status="open") == 0
    assert capsys.readouterr().out == (
        "[open] adjudicated ruff:F401 a.py:1 -- m  [suppressed: reviewed: fixture import]\n"
        "[open] unexamined ruff:F401 b.py:1 -- m\n")

    assert cmd_ledger_filter(tmp_path, status="open", as_json=True) == 0
    rows = {r["id"]: (r["suppressed"], r["suppressed_reason"])
            for r in json.loads(capsys.readouterr().out)["findings"]}
    assert rows == {"adjudicated": (True, "reviewed: fixture import"),
                    "unexamined": (False, None)}


def test_filter_clauses_are_conjoined_and_each_one_is_its_own_gate(tmp_path, capsys):
    """Four rows differing in exactly one field each; every clause alone
    selects its row, two clauses together select their intersection."""
    _seed(tmp_path,
          _f("base"),
          _f("tool", tool="semgrep"),
          _f("rule", rule="E501"),
          _f("sev", severity=Severity.HIGH))
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.FINDING_OVERRIDDEN, "r2", "2026-09-14T01:00:00+00:00",
                         finding_id="rule", payload={"reason": "ok"}))
    finally:
        led.close()

    def ids(**kw):
        assert cmd_ledger_filter(tmp_path, as_json=True, **kw) == 0
        return [r["id"] for r in json.loads(capsys.readouterr().out)["findings"]]

    assert ids() == ["base", "tool", "rule", "sev"]
    assert ids(tool="semgrep") == ["tool"]
    assert ids(rule="E501") == ["rule"]
    assert ids(status="overridden") == ["rule"]
    assert ids(status="OPEN") == ["base", "tool", "sev"]
    assert ids(severity="High") == ["sev"]
    assert ids(tool="ruff", status="open") == ["base", "sev"]
    assert ids(tool="semgrep", rule="E501") == []


def test_filter_json_exits_0_with_every_promised_key(tmp_path, capsys):
    _seed(tmp_path, _f("f1", message="SQL built by concat"))

    assert cmd_ledger_filter(tmp_path, as_json=True) == 0
    out = capsys.readouterr().out
    rows = [{
        "id": "f1", "tool": "ruff", "rule": "F401", "file": "a.py", "line": 1,
        "severity": "low", "verdict": "warn", "message": "SQL built by concat",
        "evidence": "e", "historical": False, "status": "open", "reason": None,
        "verdict_now": "warn", "suppressed": False, "suppressed_reason": None}]
    doc = {"schema_version": 1, "findings": rows}
    assert json.loads(out) == doc
    # pretty-printed at two spaces, key order as promised: a human reads this
    # in a terminal as often as a script parses it
    assert out == json.dumps(doc, indent=2) + "\n"


def test_filter_text_with_no_match_says_so_and_exits_0(tmp_path, capsys):
    _seed(tmp_path, _f("f1"))

    assert cmd_ledger_filter(tmp_path, tool="eslint") == 0
    assert capsys.readouterr() == ("aramid: ledger filter: no matching findings\n", "")


def test_filter_json_with_no_match_is_an_empty_findings_list_and_exit_0(tmp_path, capsys):
    _seed(tmp_path, _f("f1"))

    assert cmd_ledger_filter(tmp_path, tool="eslint", as_json=True) == 0
    assert capsys.readouterr() == (
        json.dumps({"schema_version": 1, "findings": []}, indent=2) + "\n", "")


def test_filter_refuses_a_bad_status_before_opening_the_ledger(tmp_path, capsys):
    assert cmd_ledger_filter(tmp_path, status="stale") == 3
    assert "unknown --status value 'stale'" in capsys.readouterr().err
    assert not (tmp_path / ".aramid" / "ledger.db").exists()
