"""The report that reads resolver yield, and the six answers it has to keep apart.

A yield ledger is only worth having if the report over it DISCRIMINATES. The
tempting version -- count fires per resolver, print the counts -- is noise on
day one, because in this repo's real ledger these two rows are both zero:

    mutant_killed  0     <- no js-mutation findings exist here. Permanent,
                            honest, and nothing to do about it.
    gap_addressed  0     <- eleven open mutation findings walked past it.
                            Dead resolver, shipped, undetected for weeks.

Rendered the same they are indistinguishable, the report gets ignored, and the
detector for silent no-ops becomes one. So every row is graded against what
was AVAILABLE to it, and the grades are the product:

    no data          never ran, and its producer has never filed a finding
    no opportunity   ran, saw nothing, producer has nothing open
    no clears yet    saw candidates, cleared none -- reported, not accused
    live             cleared something
    NEVER RAN        no yield events at all, but its producer HAS findings
    BLIND            ran, saw zero candidates, producer has open findings now

The two upper-case ones are defects, and only those two, because only those
two are about the resolver's MECHANISM. Everything else is about outcomes,
and outcomes are confounded: "nothing cleared" is overwhelmingly "nothing was
fixed", which is not a fault in the gate. Measured on this repo -- see
`test_a_resolver_that_sees_candidates_and_clears_none_is_reported_not_accused`
-- treating that as a defect produced three false alarms on a healthy tree,
two of them permanent.

WHY `BLIND` IS A GRADE OF ITS OWN. It is the resolver whose FILTER never
matches -- the shape of an actual near-miss in this repo, where a resolver
keyed on tool "llm" against findings labelled "llm-review" would have run
happily forever, considered nothing, and reported success. Counting clears
cannot catch that: a filter matching nothing produces no candidate to
decline, so `resolved == 0` is never even reached. It needs the join to what
is open RIGHT NOW -- lifetime volume would false-flag a producer whose
findings were all legitimately fixed long ago.
"""
from datetime import datetime, timezone

import pytest

from aramid import yield_report
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Verdict

NOW = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc).isoformat()


def _finding(fid, tool="mutation", file="src/x.py", rule="bool-swap"):
    return Finding(id=fid, tool=tool, rule=rule, severity_raw="medium",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file,
                   line=17, message="m", evidence="", gate=Gate.ALL)


@pytest.fixture
def led(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    try:
        yield lg
    finally:
        lg.close()


def _row(led, resolver, tool):
    rows = {(r.resolver, r.tool): r for r in yield_report.collect(led)}
    assert (resolver, tool) in rows, f"no row for {resolver}/{tool}: {sorted(rows)}"
    return rows[(resolver, tool)]


def _seed_findings(led, *findings):
    led.record_run("r0", NOW, "drain", set(), set(), list(findings))


def _yield(led, resolver, tool, considered, resolved, run="r1"):
    from aramid.ledger import note_yield
    note_yield(led, run, NOW, resolver=resolver, tool=tool,
               considered=considered, resolved=resolved)


def _instrumented(led):
    """Put ONE unrelated resolver's yield in the ledger.

    Grading is suspended entirely on a ledger with no yield events at all --
    see `test_a_ledger_older_than_the_instrumentation_is_not_eleven_defects`
    -- so a test about grades needs a ledger that has been instrumented by
    something. Using a DIFFERENT resolver is not a workaround for that rule
    but the real shape of the thing being tested: `NEVER RAN` means the gate
    ran and this one resolver stayed silent, which is only observable next to
    a resolver that did not."""
    _yield(led, "endpoint_reprobed", "dast", considered=0, resolved=0, run="r-inst")


# ------------------------------------------- the two zeroes, kept apart ---

def test_a_resolver_with_no_producer_and_no_runs_is_not_a_defect(led):
    """js-mutation in a Python-only repo. Zero forever, and correctly so."""
    _yield(led, "gap_addressed", "mutation", considered=0, resolved=0)

    row = _row(led, "mutant_killed", "js-mutation")

    assert row.verdict == "no data"
    assert not row.flagged


def test_a_resolver_that_never_ran_while_its_producer_filed_findings_is(led):
    """The `--all` bug, exactly. `gap_addressed` emitted nothing at all for
    weeks while mutation findings piled up, because the caller had switched
    every range-scoped resolver off. Same zero as the row above; opposite
    meaning."""
    _seed_findings(led, _finding("a" * 64), _finding("b" * 64))
    _instrumented(led)

    row = _row(led, "gap_addressed", "mutation")

    assert row.verdict == "NEVER RAN"
    assert row.flagged


# ------------------------------------------------------- the four others ---

def test_a_resolver_that_ran_and_had_nothing_to_do_is_not_a_defect(led):
    _yield(led, "gap_addressed", "mutation", considered=0, resolved=0)

    row = _row(led, "gap_addressed", "mutation")

    assert row.verdict == "no opportunity"
    assert not row.flagged


def test_a_resolver_whose_filter_never_matches_anything_open_is_blind(led):
    """It ran. It cleared nothing. It never even saw a candidate -- while two
    of its producer's findings sit open. That is a filter that does not match,
    which counting clears structurally cannot detect."""
    _seed_findings(led, _finding("a" * 64), _finding("b" * 64))
    _yield(led, "gap_addressed", "mutation", considered=0, resolved=0)

    row = _row(led, "gap_addressed", "mutation")

    assert row.verdict == "BLIND"
    assert row.flagged


def test_a_resolver_that_sees_candidates_and_clears_none_is_reported_not_accused(led):
    """`no clears yet` is INFORMATIONAL, and the reason is measured rather
    than argued. On the FIRST instrumented gate run in this repo, two rows
    came back with candidates and no clears, and neither is a fault:

      evidence_gone/llm-review  2 considered, 0 resolved
      file_departed/mutation    2 considered, 0 resolved

    The first is two ordinary WARN advisories nobody has fixed yet -- the
    resolver works, there is nothing to clear. The second is near-PERMANENT:
    `file_departed` clears a finding only when its file has left the
    repository, so in a healthy repo it walks the open set every run and
    correctly resolves nothing, forever. Flagging that brands a resolver
    broken for doing a rare job right.

    "Nothing cleared" is overwhelmingly "nothing was fixed", a grade cannot
    tell those apart, and a report that cries wolf on its own tree is one
    nobody reads. The count is still printed -- it is worth seeing -- it just
    does not accuse.

    An earlier draft justified the same decision with the two suppressed
    mutation findings, on the theory that a suppression binds by ID without
    flipping ledger status so its target can never resolve. The first real run
    refuted it: they resolved through `gap_addressed`, because the push
    touched their source file. That prediction came from a replay which had
    hard-coded `resolved=0` rather than deriving it -- asserting the input
    instead of computing it. Conclusion unchanged, reasoning replaced."""
    _seed_findings(led, _finding("a" * 64))
    _yield(led, "gap_addressed", "mutation", considered=3, resolved=0)
    _yield(led, "gap_addressed", "mutation", considered=2, resolved=0, run="r2")

    row = _row(led, "gap_addressed", "mutation")

    assert row.verdict == "no clears yet"
    assert not row.flagged
    assert (row.runs, row.considered, row.resolved) == (2, 5, 0)


def test_a_resolver_that_ever_cleared_something_is_live(led):
    _seed_findings(led, _finding("a" * 64))
    _yield(led, "gap_addressed", "mutation", considered=3, resolved=0)
    _yield(led, "gap_addressed", "mutation", considered=3, resolved=1, run="r2")

    row = _row(led, "gap_addressed", "mutation")

    assert row.verdict == "live"
    assert not row.flagged


def test_a_ledger_older_than_the_instrumentation_is_not_eleven_defects(led):
    """Measured against this repo's own ledger on the day the feature landed:
    every resolver with any finding volume graded NEVER RAN, including
    `evidence_gone`, which the same ledger shows firing twelve times. The
    grade was right about the events and wrong about the world -- there were
    no yield events because no gate had run since the code shipped, not
    because eight resolvers died at once.

    Zero yield events of ANY kind is the discriminator, and it is safe
    precisely because the instrumentation is all-or-nothing: one gate run
    emits several. A single yield event anywhere restores normal grading, so
    this cannot mask a resolver that stops later."""
    _seed_findings(led, _finding("a" * 64))

    rows = yield_report.collect(led)

    assert {r.verdict for r in rows} == {"not instrumented"}
    assert not any(r.flagged for r in rows)
    assert "no yield data recorded yet" in yield_report.render(rows)


def test_one_yield_event_anywhere_restores_normal_grading(led):
    """The other half, and the one that matters: the amnesty is for an
    un-instrumented LEDGER, not for an un-instrumented resolver."""
    _seed_findings(led, _finding("a" * 64))
    _yield(led, "red_proven", "red-proof", considered=0, resolved=0)

    assert _row(led, "gap_addressed", "mutation").verdict == "NEVER RAN"


# ------------------------------------------------------------- plumbing ---

def test_every_known_resolver_gets_a_row_even_with_an_empty_ledger(led):
    """A resolver missing from the report is the failure this whole feature
    exists to prevent, so the registry -- not the observed events -- decides
    which rows exist."""
    rows = {(r.resolver, r.tool) for r in yield_report.collect(led)}

    assert rows == set(yield_report.EXPECTED)


def test_the_suite_resolver_joins_volume_by_marker_not_by_tool_label(led):
    """A suite finding's tool is the test command's argv[0] -- "python" here,
    anything at all elsewhere -- so the row is keyed on the slot name "tests"
    and its producer volume comes from SUITE_MARKER. Joining on the label
    would grade this row `no data` in every repo, permanently."""
    from aramid.tests_gate import SUITE_MARKER
    _seed_findings(led, _finding("c" * 64, tool="python", file=SUITE_MARKER,
                                 rule="tests-failed"))
    _instrumented(led)

    row = _row(led, "suite_completed_clean", "tests")

    assert row.volume == 1
    assert row.verdict == "NEVER RAN"


def test_a_fixed_finding_counts_as_volume_but_not_as_open(led):
    """The distinction the BLIND grade rests on. Lifetime volume answers "has
    this producer ever filed anything" (for NEVER RAN); the open count answers
    "is there anything here right now" (for BLIND). Conflating them makes a
    tidy repo look broken."""
    _seed_findings(led, _finding("a" * 64))
    led.record_run("r1", NOW, "drain", {"mutation"}, {"src/x.py"}, [])
    _yield(led, "gap_addressed", "mutation", considered=0, resolved=0, run="r2")

    row = _row(led, "gap_addressed", "mutation")

    assert (row.volume, row.open_now) == (1, 0)
    assert row.verdict == "no opportunity"


def test_the_render_names_the_defect_and_the_numbers_behind_it(led):
    """Rendered, not substring-probed: a report nobody can read is the same as
    no report, and asserting on fragments is how a notice that names a
    non-existent runner ships green."""
    _seed_findings(led, _finding("a" * 64), _finding("b" * 64))
    _instrumented(led)

    out = yield_report.render(yield_report.collect(led))

    # The WHOLE line, not a fragment of it. A substring assert only confirms
    # what you already believed was there; it is how a notice naming a runner
    # that does not exist ships with thirteen green tests behind it.
    assert ("  NEVER RAN      gap_addressed         mutation     "
            "0 runs   [2 open, 2 ever]") in out
    # Two rows are keyed to the `mutation` producer -- `gap_addressed` and
    # `file_departed` -- so seeding one producer flags exactly two resolvers.
    assert "2 of 11 resolvers flagged" in out


def test_a_clean_report_says_so_rather_than_printing_nothing(led):
    for resolver, tool in yield_report.EXPECTED:
        _yield(led, resolver, tool, considered=1, resolved=1)

    out = yield_report.render(yield_report.collect(led))

    assert "no resolver defects" in out
