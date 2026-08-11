"""Every resolver must record what it SAW, not only what it cleared.

THE CLASS THIS EXISTS FOR. Four times now a resolver in this repo has been
alive by every test and dead in production, and each was found by hand, once,
by someone who happened to count. `gap_addressed` sat at ZERO lifetime fires
with eleven open mutation findings on the books, because `--all` put the gate
in mode "all" and every range-scoped resolver hid behind `if mode == "range"`.
Nothing in the tool noticed. Nothing could: the ledger records resolutions,
and a resolver that resolves nothing writes nothing at all.

WHY COUNTING FIRES IS NOT ENOUGH, and this is the whole design. "Zero fires"
means two incompatible things:

    mutant_killed  0 fires   <- this repo has no js-mutation findings.
                                Honest, permanent, uninteresting.
    gap_addressed  0 fires   <- eleven candidates went past it untouched.
                                A dead resolver.

Rendered identically they are noise, and a report that is noise on day one is
a report nobody reads -- a silent no-op inside the detector for silent no-ops.
The discriminator is OPPORTUNITY, and opportunity cannot be reconstructed from
the event log afterwards: the ledger has no record of the candidates a
resolver considered and declined. So it is recorded at the moment of looking.

THE CONTRACT PINNED HERE: **every invocation emits exactly one yield event**,
including the early returns where the resolver could not look at anything.
That is what lets the absence of an event mean "was never called" -- the one
signal that catches the `if mode == "range"` bug -- rather than "was called
and had nothing to do". Both are legitimate states; conflating them costs the
detector its whole discriminating power.
"""
from datetime import datetime, timezone

import pytest

from aramid import ledger as ledger_mod
from aramid import mutation_gate, red_proof, tdd, tests_gate
from aramid.ledger import Ledger
from aramid.models import EventType, Finding, Gate, Severity, Verdict

NOW = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc).isoformat()
FID = "a" * 64
OTHER = "b" * 64


def _finding(fid=FID, tool="mutation", file="src/x.py", rule="bool-swap"):
    return Finding(id=fid, tool=tool, rule=rule, severity_raw="medium",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file,
                   line=17, message="mutant survived: or -> and",
                   evidence="", gate=Gate.ALL)


@pytest.fixture
def led(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    try:
        yield lg
    finally:
        lg.close()


def _seed(lg, *findings):
    lg.record_run("r0", NOW, "drain", set(), set(), list(findings) or [_finding()])


def _yields(lg, resolver=None):
    out = [e for e in lg.events() if e.type is EventType.RESOLVER_YIELD]
    if resolver is not None:
        out = [e for e in out if e.payload.get("resolver") == resolver]
    return out


def _one(lg, resolver):
    events = _yields(lg, resolver)
    assert len(events) == 1, f"expected exactly one {resolver} yield, got {len(events)}"
    return events[0].payload


# ------------------------------------------------- the discriminating case ---

def test_a_resolver_that_cleared_nothing_records_what_it_declined(led):
    """The whole point. A resolver that looked at candidates and cleared none
    is indistinguishable, in today's ledger, from one that was never called --
    and those two need opposite responses from an operator."""
    _seed(led, _finding())

    ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                reason="mutant_killed", ids={OTHER},
                                present_ids=set())

    assert _one(led, "mutant_killed") == {"resolver": "mutant_killed",
                                          "tool": "mutation",
                                          "considered": 1, "resolved": 0}


def test_a_resolver_with_nothing_to_look_at_is_not_the_same_as_absent(led):
    """`considered: 0` says "I ran, there was nothing here". No event at all
    says "I was never called". Only the second is a defect, so the early
    returns have to emit too."""
    ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                reason="mutant_killed", ids=set(),
                                present_ids=set())

    assert _one(led, "mutant_killed")["considered"] == 0


def test_a_resolver_that_cleared_something_counts_both_sides(led):
    _seed(led, _finding())

    ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                reason="mutant_killed", ids={FID},
                                present_ids=set())

    assert _one(led, "mutant_killed") == {"resolver": "mutant_killed",
                                          "tool": "mutation",
                                          "considered": 1, "resolved": 1}


# ------------------------------------------------------- one per resolver ---

def test_gap_addressed_records_the_candidates_it_walked(led):
    """The resolver that was actually dead. Two open mutation findings, a push
    touching neither: considered 2, resolved 0 -- which is exactly the row
    that would have shown the `--all` bug on the day it shipped."""
    _seed(led, _finding(FID, file="src/x.py"), _finding(OTHER, file="src/y.py"))

    mutation_gate.auto_resolve_mutation(led, "r1", NOW, {"src/unrelated.py"})

    assert _one(led, "gap_addressed") == {"resolver": "gap_addressed",
                                          "tool": "mutation",
                                          "considered": 2, "resolved": 0}


def test_test_added_records_the_candidates_it_walked(led):
    _seed(led, _finding(FID, tool="tdd", file="src/x.py", rule="code-without-test"))

    tdd.auto_resolve_tdd(led, "r1", NOW, {"tests/unit/test_x.py"}, set())

    assert _one(led, "test_added") == {"resolver": "test_added", "tool": "tdd",
                                       "considered": 1, "resolved": 1}


def test_red_proven_records_the_candidates_it_walked(led):
    _seed(led, _finding(FID, tool="red-proof", file="tests/unit/test_x.py",
                        rule="never-red"))

    red_proof.auto_resolve_red_proof(led, "r1", NOW, set(), set())

    assert _one(led, "red_proven") == {"resolver": "red_proven",
                                       "tool": "red-proof",
                                       "considered": 1, "resolved": 0}


def test_file_departed_records_the_candidates_it_walked(led, tmp_path):
    _seed(led, _finding(FID, tool="mutation", file="src/gone.py"))

    ledger_mod.resolve_departed(led, "r1", NOW, root=tmp_path, tool="mutation",
                                present_ids=set())

    assert _one(led, "file_departed") == {"resolver": "file_departed",
                                          "tool": "mutation",
                                          "considered": 1, "resolved": 1}


def test_file_departed_with_no_root_still_says_it_ran(led):
    """`root=None` is the "no repo to check" early return. It clears nothing by
    design -- but silence here would read as the resolver never being wired in
    at all, which is a different and much more serious thing."""
    _seed(led, _finding(FID, tool="mutation", file="src/gone.py"))

    ledger_mod.resolve_departed(led, "r1", NOW, root=None, tool="mutation",
                                present_ids=set())

    assert _one(led, "file_departed")["considered"] == 0


def test_suite_completed_clean_records_the_candidates_it_walked(led):
    _seed(led, _finding(FID, tool="python", file=tests_gate.SUITE_MARKER,
                        rule="tests-failed"))

    tests_gate.auto_resolve_tests(led, "r1", NOW, present_ids=set(),
                                  suite_completed=True)

    assert _one(led, "suite_completed_clean")["resolved"] == 1


def test_an_incomplete_suite_still_says_it_ran(led):
    """`suite_completed=False` means the runner never reached a verdict, so
    this resolver deliberately looks at nothing. It still has to say so --
    same reason as the `root=None` case above."""
    _seed(led, _finding(FID, tool="python", file=tests_gate.SUITE_MARKER,
                        rule="tests-failed"))

    tests_gate.auto_resolve_tests(led, "r1", NOW, present_ids=set(),
                                  suite_completed=False)

    assert _one(led, "suite_completed_clean")["considered"] == 0


# ------------------------------------------------------------ fail-safe ---

def test_a_broken_yield_write_never_reaches_the_caller():
    """A diagnostic that can break the gate is worse than no diagnostic. The
    resolvers this instruments are all documented "never raises into
    run_gate", and adding bookkeeping must not quietly withdraw that."""
    class Exploding:
        def append(self, event):
            raise RuntimeError("ledger is on fire")

    ledger_mod.note_yield(Exploding(), "r1", NOW, resolver="gap_addressed",
                          tool="mutation", considered=3, resolved=1)
