"""`commands.ledger_cmd`'s four MUTATING subcommands at unit scope --
mark-rotated, mark-not-a-secret, mark-unreachable, resolve --out-of-scope.
Every one writes a permanent row into an append-only ledger, so every
guard, every refusal line and the exact event each success appends is
asserted whole.

The drain confirms a mutant against the unit suite alone, and until this
file nothing in it executed any of the four: tests/integration/
test_ledger_cmd.py covers them and the drain never runs it. Their 41
generator mutants -- every `return 3` -> 4, `!=` -> `==` on a status
guard, `or` -> `and` on the reason default -- were survivors by
construction on the operator's truth surface.

Seams: a real tmp ledger seeded by `record_run` plus the transition event
that materializes each status; the event clock and run id injected
(`_now`, `uuid`) so the appended Event is asserted byte for byte;
`toolset.selected_tool_names` answered by the repo's own files (a
`pyproject.toml` with any table selects ruff, its absence de-selects it),
the isolation fixtures in tests/conftest.py keep the user config out."""
from types import SimpleNamespace

import pytest

from aramid.commands import ledger_cmd as lc
from aramid.commands.ledger_cmd import (
    cmd_ledger_mark_not_a_secret,
    cmd_ledger_mark_rotated,
    cmd_ledger_mark_unreachable,
    cmd_ledger_resolve,
)
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict

AT = "2026-09-14T12:00:00+00:00"
RUN = "f" * 32


def _f(fid, tool="ruff", rule="S102", file="a.py", historical=False):
    return Finding(fid, tool, rule, "high", Severity.HIGH, Verdict.WARN, file, 1, "m", "e",
                   Gate.PRE_PUSH, historical=historical)


def _ledger(root):
    return Ledger(root / ".aramid" / "ledger.db")


def _seed(root, *findings, status=None):
    """Record one run carrying `findings`; then append the event that moves
    the FIRST one to `status` (a transition ledger_cmd itself never makes)."""
    led = _ledger(root)
    try:
        led.record_run("r1", "2026-09-14T00:00:00+00:00", "pre-push",
                       {f.tool for f in findings}, {f.file for f in findings}, list(findings))
        fid = findings[0].id
        transition = {
            None: None,
            "fixed": Event(EventType.FINDING_RESOLVED, "r2", AT, finding_id=fid,
                           payload={"auto_resolved": "not_reported"}),
            "pending_retest": Event(EventType.FINDING_RESOLVED, "r2", AT, finding_id=fid,
                                    payload={"auto_resolved": "gap_addressed",
                                             "pending_retest": True}),
            "superseded": Event(EventType.FINDING_RESOLVED, "r2", AT, finding_id=fid,
                                payload={"superseded_by": "sib1"}),
            "overridden": Event(EventType.FINDING_OVERRIDDEN, "r2", AT, finding_id=fid,
                                payload={"reason": "ok"}),
            "rotated": Event(EventType.FINDING_ROTATED, "r2", AT, finding_id=fid,
                             payload={"reason": "rotated"}),
            "not_a_secret": Event(EventType.FINDING_NOT_A_SECRET, "r2", AT, finding_id=fid,
                                  payload={"reason": "fixture"}),
            "unreachable": Event(EventType.FINDING_UNREACHABLE, "r2", AT, finding_id=fid,
                                 payload={"reason": "gone"}),
            "out_of_scope": Event(EventType.FINDING_OUT_OF_SCOPE, "r2", AT, finding_id=fid,
                                  payload={"reason": "scoped", "tool": "ruff", "file": "a.py"}),
        }[status]
        if transition is not None:
            led.append(transition)
    finally:
        led.close()


def _state(root):
    led = _ledger(root)
    try:
        return led.open_findings(), led.events()
    finally:
        led.close()


def _appended(root, kind):
    """The events of `kind` ledger_cmd appended (run id RUN), exactly."""
    _, events = _state(root)
    return [e for e in events if e.type is kind and e.run_id == RUN]


@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(lc, "_now", lambda: AT)
    monkeypatch.setattr(lc, "uuid", SimpleNamespace(uuid4=lambda: SimpleNamespace(hex=RUN)))


def _select_ruff(root):
    (root / "pyproject.toml").write_text("[tool.x]\n", encoding="utf-8")


# ------------------------------------------------------------ mark-rotated --

def test_mark_rotated_appends_exactly_one_event_from_historical(tmp_path, capsys, clock):
    _seed(tmp_path, _f("h1", tool="gitleaks", historical=True))

    assert cmd_ledger_mark_rotated(tmp_path, "h1", "  rotated in vault 2026-09-14  ") == 0

    assert capsys.readouterr() == ("aramid: ledger: h1 marked rotated (rotated in vault 2026-09-14)\n", "")
    state, _ = _state(tmp_path)
    assert state["h1"]["status"] == "rotated"
    assert _appended(tmp_path, EventType.FINDING_ROTATED) == [
        Event(EventType.FINDING_ROTATED, RUN, AT, finding_id="h1",
              payload={"reason": "rotated in vault 2026-09-14"})]


def test_mark_rotated_also_accepts_a_not_a_secret_finding(tmp_path, capsys, clock):
    _seed(tmp_path, _f("h1", tool="gitleaks", historical=True), status="not_a_secret")

    assert cmd_ledger_mark_rotated(tmp_path, "h1", "it was real after all") == 0
    assert _state(tmp_path)[0]["h1"]["status"] == "rotated"


@pytest.mark.parametrize("reason", ["", "   ", None])
def test_mark_rotated_requires_a_reason_before_touching_the_ledger(tmp_path, capsys, reason):
    _seed(tmp_path, _f("h1", historical=True))

    assert cmd_ledger_mark_rotated(tmp_path, "h1", reason) == 3
    assert capsys.readouterr() == ("", "aramid: ledger mark-rotated: --reason is required\n")
    assert _appended(tmp_path, EventType.FINDING_ROTATED) == []


def test_mark_rotated_unknown_id(tmp_path, capsys, clock):
    _seed(tmp_path, _f("h1", historical=True))

    assert cmd_ledger_mark_rotated(tmp_path, "nope", "r") == 3
    assert capsys.readouterr() == ("", "aramid: ledger mark-rotated: unknown finding id nope\n")


@pytest.mark.parametrize("status", [None, "fixed", "rotated", "unreachable"])
def test_mark_rotated_refuses_every_other_status(tmp_path, capsys, clock, status):
    _seed(tmp_path, _f("f1"), status=status)

    assert cmd_ledger_mark_rotated(tmp_path, "f1", "r") == 3
    shown = status or "open"
    assert capsys.readouterr() == (
        "", f"aramid: ledger mark-rotated: f1 is not a historical or not-a-secret finding "
            f"(status={shown}) -- mark-rotated only applies to historical secrets from "
            f"init's full-history scan, or to a finding already marked not-a-secret\n")
    assert _appended(tmp_path, EventType.FINDING_ROTATED) == []


# ------------------------------------------------------- mark-not-a-secret --

def test_mark_not_a_secret_appends_exactly_one_event_from_historical(tmp_path, capsys, clock):
    _seed(tmp_path, _f("h1", tool="gitleaks", historical=True))

    assert cmd_ledger_mark_not_a_secret(tmp_path, "h1", " example key in a fixture ") == 0

    assert capsys.readouterr() == (
        "aramid: ledger: h1 marked not-a-secret (example key in a fixture)\n", "")
    state, _ = _state(tmp_path)
    assert state["h1"]["status"] == "not_a_secret"
    assert state["h1"]["reason"] == "example key in a fixture"
    assert _appended(tmp_path, EventType.FINDING_NOT_A_SECRET) == [
        Event(EventType.FINDING_NOT_A_SECRET, RUN, AT, finding_id="h1",
              payload={"reason": "example key in a fixture"})]


@pytest.mark.parametrize("reason", ["", "   ", None])
def test_mark_not_a_secret_requires_a_reason(tmp_path, capsys, reason):
    _seed(tmp_path, _f("h1", historical=True))

    assert cmd_ledger_mark_not_a_secret(tmp_path, "h1", reason) == 3
    assert capsys.readouterr() == ("", "aramid: ledger mark-not-a-secret: --reason is required\n")


def test_mark_not_a_secret_unknown_id(tmp_path, capsys, clock):
    _seed(tmp_path, _f("h1", historical=True))

    assert cmd_ledger_mark_not_a_secret(tmp_path, "nope", "r") == 3
    assert capsys.readouterr() == ("", "aramid: ledger mark-not-a-secret: unknown finding id nope\n")


@pytest.mark.parametrize("status, tail", [
    (None, "mark-not-a-secret only applies to historical secrets from init's full-history "
           "scan. For a live BLOCK finding use a committed .aramid-suppressions.toml entry; "
           "for a WARN use `aramid override`."),
    ("not_a_secret", "already marked not-a-secret."),
    ("rotated", "already retired by rotation. A rotated finding is never downgraded to "
                "not-a-secret."),
    ("fixed", "mark-not-a-secret only applies to historical secrets from init's "
              "full-history scan."),
    ("unreachable", "mark-not-a-secret only applies to historical secrets from init's "
                    "full-history scan."),
])
def test_mark_not_a_secret_refuses_every_non_historical_status_with_its_own_tail(
        tmp_path, capsys, clock, status, tail):
    _seed(tmp_path, _f("f1"), status=status)

    assert cmd_ledger_mark_not_a_secret(tmp_path, "f1", "r") == 3
    shown = status or "open"
    assert capsys.readouterr() == (
        "", f"aramid: ledger mark-not-a-secret: f1 is not a historical finding "
            f"(status={shown}) -- {tail}\n")
    assert _appended(tmp_path, EventType.FINDING_NOT_A_SECRET) == []


# -------------------------------------------------------- mark-unreachable --

def test_mark_unreachable_appends_exactly_one_event_when_the_tool_left(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1", tool="ruff"))            # no pyproject: ruff is not selected

    assert cmd_ledger_mark_unreachable(tmp_path, "f1", " ruff left with the py tree ") == 0

    assert capsys.readouterr() == (
        "aramid: ledger: f1 marked unreachable (ruff left with the py tree)\n", "")
    state, _ = _state(tmp_path)
    assert state["f1"]["status"] == "unreachable"
    assert state["f1"]["reason"] == "ruff left with the py tree"
    assert _appended(tmp_path, EventType.FINDING_UNREACHABLE) == [
        Event(EventType.FINDING_UNREACHABLE, RUN, AT, finding_id="f1",
              payload={"reason": "ruff left with the py tree"})]


@pytest.mark.parametrize("reason", ["", "   ", None])
def test_mark_unreachable_requires_a_reason(tmp_path, capsys, reason):
    _seed(tmp_path, _f("f1"))

    assert cmd_ledger_mark_unreachable(tmp_path, "f1", reason) == 3
    assert capsys.readouterr() == ("", "aramid: ledger mark-unreachable: --reason is required\n")


def test_mark_unreachable_reports_an_unreadable_config_as_an_engine_error(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1"))
    (tmp_path / "aramid.toml").write_text("this is not = valid = toml\n", encoding="utf-8")

    assert cmd_ledger_mark_unreachable(tmp_path, "f1", "r") == 3
    err = capsys.readouterr().err
    assert err.startswith("aramid: ledger mark-unreachable: engine error: ")
    assert _appended(tmp_path, EventType.FINDING_UNREACHABLE) == []


def test_mark_unreachable_unknown_id(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1"))

    assert cmd_ledger_mark_unreachable(tmp_path, "nope", "r") == 3
    assert capsys.readouterr() == ("", "aramid: ledger mark-unreachable: unknown finding id nope\n")


def test_mark_unreachable_refuses_a_producer_finding(tmp_path, capsys, clock):
    _seed(tmp_path, _f("m1", tool="mutation", rule="survived", file="src/pay.py"))

    assert cmd_ledger_mark_unreachable(tmp_path, "m1", "r") == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger mark-unreachable: m1 is a 'mutation' finding -- producer/consumer "
            "findings (tdd, red-proof, mutation, mutation-score, llm-review, js-mutation, "
            "fuzz, dast) resolve through their own producer's mechanism, never by hand\n")


@pytest.mark.parametrize("status, tail", [
    ("unreachable", "already marked unreachable."),
    ("fixed", "already fixed -- nothing to retire."),
    ("overridden", "already overridden."),
    ("rotated", "already retired by rotation."),
    ("not_a_secret", "already marked not-a-secret."),
    ("superseded", "rewritten -- superseded by sib1 -- decide on that finding instead."),
    ("out_of_scope", "already resolved as out of scope."),
    ("pending_retest", "awaiting a verified re-test -- the mutation consumer closes or "
                       "re-opens it."),
])
def test_mark_unreachable_refuses_every_non_open_status_with_its_own_tail(
        tmp_path, capsys, clock, status, tail):
    _seed(tmp_path, _f("f1"), status=status)

    assert cmd_ledger_mark_unreachable(tmp_path, "f1", "r") == 3
    assert capsys.readouterr() == (
        "", f"aramid: ledger mark-unreachable: f1 is not open (status={status}) -- {tail}\n")
    assert _appended(tmp_path, EventType.FINDING_UNREACHABLE) == []


def test_mark_unreachable_refuses_a_historical_secret_with_the_redirect(tmp_path, capsys, clock):
    _seed(tmp_path, _f("h1", tool="gitleaks", historical=True))

    assert cmd_ledger_mark_unreachable(tmp_path, "h1", "r") == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger mark-unreachable: h1 is not open (status=historical) -- a "
            "historical secret -- use `aramid ledger mark-rotated` or `mark-not-a-secret` "
            "instead.\n")


def test_mark_unreachable_refuses_while_the_tool_still_runs_here(tmp_path, capsys, clock):
    _select_ruff(tmp_path)
    _seed(tmp_path, _f("f1", tool="ruff"))

    assert cmd_ledger_mark_unreachable(tmp_path, "f1", "r") == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger mark-unreachable: f1's tool (ruff) still runs in this repo -- not "
            "a ghost. If it fails every run, that is `aramid doctor`'s problem, not "
            "mark-unreachable's\n")
    assert _state(tmp_path)[0]["f1"]["status"] == "open"


# ------------------------------------------------------------------ resolve --

def test_resolve_out_of_scope_appends_exactly_one_event(tmp_path, capsys, clock):
    _select_ruff(tmp_path)
    _seed(tmp_path, _f("f1", tool="ruff", file=".github/workflows/ci.yml"))

    rc = cmd_ledger_resolve(tmp_path, "f1", True, "  runner scoped to .py/.pyi in 0.6.1  ")

    assert rc == 0
    assert capsys.readouterr() == (
        "aramid: ledger: f1 resolved as out of scope -- ruff no longer examines "
        ".github/workflows/ci.yml (runner scoped to .py/.pyi in 0.6.1)\n", "")
    state, _ = _state(tmp_path)
    assert state["f1"]["status"] == "out_of_scope"
    assert state["f1"]["reason"] == "runner scoped to .py/.pyi in 0.6.1"
    assert _appended(tmp_path, EventType.FINDING_OUT_OF_SCOPE) == [
        Event(EventType.FINDING_OUT_OF_SCOPE, RUN, AT, finding_id="f1",
              payload={"reason": "runner scoped to .py/.pyi in 0.6.1", "tool": "ruff",
                       "file": ".github/workflows/ci.yml"})]


def test_resolve_without_out_of_scope_is_refused_before_the_reason_is_looked_at(
        tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1"))

    assert cmd_ledger_resolve(tmp_path, "f1", False, "") == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger resolve: --out-of-scope is required -- it is the only resolution "
            "a person can record; a finding that is simply gone resolves on the next run "
            "that examines its file\n")


@pytest.mark.parametrize("reason", ["", "   ", None])
def test_resolve_requires_a_reason(tmp_path, capsys, reason):
    _seed(tmp_path, _f("f1"))

    assert cmd_ledger_resolve(tmp_path, "f1", True, reason) == 3
    assert capsys.readouterr() == ("", "aramid: ledger resolve: --reason is required\n")


def test_resolve_reports_an_unreadable_config_as_an_engine_error(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1"))
    (tmp_path / "aramid.toml").write_text("this is not = valid = toml\n", encoding="utf-8")

    assert cmd_ledger_resolve(tmp_path, "f1", True, "r") == 3
    assert capsys.readouterr().err.startswith("aramid: ledger resolve: engine error: ")


def test_resolve_unknown_id(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1"))

    assert cmd_ledger_resolve(tmp_path, "nope", True, "r") == 3
    assert capsys.readouterr() == ("", "aramid: ledger resolve: unknown finding id nope\n")


def test_resolve_refuses_a_producer_finding(tmp_path, capsys, clock):
    _seed(tmp_path, _f("m1", tool="mutation", rule="survived", file="src/pay.py"))

    assert cmd_ledger_resolve(tmp_path, "m1", True, "r") == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger resolve: m1 is a 'mutation' finding -- producer/consumer findings "
            "resolve through their own producer's mechanism, never by hand\n")


@pytest.mark.parametrize("status", ["fixed", "unreachable", "out_of_scope", "pending_retest"])
def test_resolve_refuses_a_finding_that_is_not_open(tmp_path, capsys, clock, status):
    _select_ruff(tmp_path)
    _seed(tmp_path, _f("f1", tool="ruff", file="ci.yml"), status=status)

    assert cmd_ledger_resolve(tmp_path, "f1", True, "r") == 3
    assert capsys.readouterr() == (
        "", f"aramid: ledger resolve: f1 is not open (status={status}) -- resolve "
            f"--out-of-scope only applies to an open finding\n")


def test_resolve_redirects_to_mark_unreachable_when_the_tool_left(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1", tool="ruff", file="ci.yml"))   # no pyproject: ruff not selected

    assert cmd_ledger_resolve(tmp_path, "f1", True, "r") == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger resolve: f1's tool (ruff) no longer runs in this repo at all -- "
            "that is `aramid ledger mark-unreachable f1 --reason ...`, not out-of-scope\n")


def test_resolve_refuses_a_tool_without_a_suffix_scope(tmp_path, capsys, clock):
    _seed(tmp_path, _f("g1", tool="gitleaks", rule="generic-api-key", file="notes.txt"))

    assert cmd_ledger_resolve(tmp_path, "g1", True, "r") == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger resolve: gitleaks examines every file it is handed (no suffix "
            "scope), so no path is out of its scope -- if the finding is gone, the next run "
            "that examines notes.txt resolves it\n")


def test_resolve_refuses_while_the_runner_still_examines_the_path(tmp_path, capsys, clock):
    _select_ruff(tmp_path)
    _seed(tmp_path, _f("f1", tool="ruff", file="pkg/mod.py"))

    assert cmd_ledger_resolve(tmp_path, "f1", True, "r") == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger resolve: ruff still examines pkg/mod.py here -- the next run that "
            "looks at it resolves or re-reports f1; resolving it by hand would be a "
            "silencer\n")
    assert _appended(tmp_path, EventType.FINDING_OUT_OF_SCOPE) == []


def test_resolve_records_an_empty_path_as_empty_not_none(tmp_path, capsys, clock):
    """`path = str(rec.get("file") or "")`: a row with no file must reach the
    scope check as "" (ruff: not a .py -> out of scope), never "None"."""
    _select_ruff(tmp_path)
    _seed(tmp_path, _f("f1", tool="ruff", file=None))

    assert cmd_ledger_resolve(tmp_path, "f1", True, "r") == 0
    assert _appended(tmp_path, EventType.FINDING_OUT_OF_SCOPE)[0].payload == {
        "reason": "r", "tool": "ruff", "file": ""}
