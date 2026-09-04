"""A producer must be able to record that a finding is genuinely REPAIRED.

THE GAP -- and it is narrower than the first draft of this file claimed, which
is worth recording because the wrong version is the more tempting story.
Mutation findings are NOT unresolvable: `mutation_gate.auto_resolve_mutation`
clears them at pre-push. But it is deliberately OPTIMISTIC, resolving on
INTENT -- the push touched the source file, or added a test whose basename is
`test_<module>.py` -- so a dev who wrote the test is not blocked by a stale
finding. Its own docstring names the async re-drain as the authoritative
backstop. The backstop could only ever RE-REPORT; nothing could CONFIRM a
repair, so the ledger recorded a guess (`gap_addressed`), never a proof.

The distance between intent and proof is not theoretical. The mapping matches
only `test_<module>.py` / `<module>_test.py`. Measured here: mutation reported
three survivors in `doctor._version_of`, two were real test gaps, and the
tests were written in `test_doctor_version_parsing.py` -- which the mapping
does not match, so nothing resolved. A resolver keyed on a filename convention
misses every fix that does not follow it.

`resolve_departed` covers a third case (the file LEFT the repo). This covers
the one nothing did.

It is a GENERAL mechanism rather than another bespoke one because three other
producers needed it and needed it differently: `js-mutation`, `fuzz` and
`dast` had no resolver of ANY kind, so a genuine fix cleared nothing at all.
Each proves repair its own way -- a killed mutant's fingerprint, a
deterministic corpus replayed against a function that really ran, a complete
re-scan of an endpoint that actually answered -- and each hands back ids
through this one call.

WHY THIS IS NOT WHAT THE DRAIN COMMENT FORBIDS. Scope-based resolution infers
repair from ABSENCE: the tool ran, it didn't re-report, so assume fixed. That
inference is only as good as the ruleset, which is why the drain refuses it.
This is the opposite direction -- a POSITIVE assertion, per finding id, that
the producer re-derived that exact identity and proved it gone. The mutation
consumer already computes it (`killed_fps`): it re-mutated the same line with
the same operator and the test suite killed it this time. Nothing is inferred
from silence, so a narrow ruleset cannot manufacture a false repair.
"""
from datetime import datetime, timezone

import pytest

from aramid import ledger as ledger_mod
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict

NOW = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc).isoformat()
FID = "a" * 64
OTHER = "b" * 64


def _finding(fid=FID, tool="mutation", file="src/x.py"):
    return Finding(id=fid, tool=tool, rule="bool-swap", severity_raw="medium",
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


# ------------------------------------------------------- the happy path ---

def test_a_proved_repaired_finding_resolves(led):
    _seed(led)

    out = ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                      reason="mutant_killed", ids={FID},
                                      present_ids=set())

    assert out == [FID]
    assert led.open_findings()[FID]["status"] == "fixed"


def test_the_reason_reaches_the_audit_trail(led):
    """An auto-resolution has to say WHY in the ledger itself. "fixed" with no
    recorded cause is indistinguishable from the false-repair class this whole
    module exists to avoid, and the ledger is append-only -- there is no later
    chance to add it."""
    _seed(led)
    ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                reason="mutant_killed", ids={FID},
                                present_ids=set())

    events = [e for e in led.events() if e.type is EventType.FINDING_RESOLVED]

    assert [e.payload.get("auto_resolved") for e in events] == ["mutant_killed"]


# ---------------------------------------------------------- the refusals ---

def test_an_id_this_run_also_reported_is_not_resolved(led):
    """A mutant can be killed in one place and survive in another only if the
    producer is confused, but resolution runs AFTER record_run -- so a
    still-live finding has already been re-detected, and clearing it would
    resolve a finding out from under its own detection. Presence wins."""
    _seed(led)

    out = ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                      reason="mutant_killed", ids={FID},
                                      present_ids={FID})

    assert out == []
    assert led.open_findings()[FID]["status"] == "open"


def test_another_producers_finding_is_never_touched(led):
    """The tool gate is belt-and-braces over the fingerprint, which already
    binds the tool -- but a caller passing the wrong id list is a bug this can
    catch and a sha256 collision is not."""
    _seed(led, _finding(tool="dast", file="GET /login"))

    out = ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                      reason="mutant_killed", ids={FID},
                                      present_ids=set())

    assert out == []
    assert led.open_findings()[FID]["status"] == "open"


def test_an_overridden_finding_is_left_alone(led):
    """Only `open` findings are eligible. Flipping an overridden finding to
    `fixed` would erase an operator's recorded decision, and `open ->
    overridden -> fixed` is a status path nothing else in the ledger produces."""
    _seed(led)
    led.append(Event(EventType.FINDING_OVERRIDDEN, "r0", NOW, finding_id=FID,
                     payload={"reason": "accepted"}))

    ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                reason="mutant_killed", ids={FID},
                                present_ids=set())

    assert led.open_findings()[FID]["status"] == "overridden"


def test_an_unknown_id_resolves_nothing(led):
    """A producer's re-derived identity that matches no open finding is the
    ordinary case -- most killed mutants were never reported in the first
    place. It must be silent, not an error."""
    _seed(led)

    out = ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                      reason="mutant_killed", ids={OTHER},
                                      present_ids=set())

    assert out == []
    assert led.open_findings()[FID]["status"] == "open"


def test_no_ids_is_a_no_op(led):
    _seed(led)

    assert ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                       reason="mutant_killed", ids=set(),
                                       present_ids=set()) == []
    assert led.open_findings()[FID]["status"] == "open"


def test_only_the_listed_id_resolves_when_several_are_open(led):
    """The realistic shape: one mutant of three now killed. Resolving the
    siblings would be the false-repair class, in the direction that hides real
    test gaps."""
    _seed(led, _finding(), _finding(fid=OTHER))

    ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation",
                                reason="mutant_killed", ids={FID},
                                present_ids=set())

    state = led.open_findings()
    assert state[FID]["status"] == "fixed"
    assert state[OTHER]["status"] == "open"


def test_a_pending_retest_finding_resolves_when_the_producer_proves_the_kill(led):
    """`gap_addressed` now leaves a survivor `pending_retest` rather than
    `fixed`; the verified re-test is what closes it. The claim path must
    accept that state, or the pending row could never become `fixed`."""
    _seed(led)
    led.append(Event(EventType.FINDING_RESOLVED, "r1", NOW, finding_id=FID,
                     payload={"auto_resolved": "gap_addressed", "pending_retest": True}))
    assert led.open_findings()[FID]["status"] == "pending_retest"

    got = ledger_mod.resolve_repaired(led, "r2", NOW, tool="mutation",
                                      reason="mutant_killed", ids=[FID], present_ids=set())

    assert got == [FID]
    assert led.open_findings()[FID]["status"] == "fixed"


# ------------------------------- what was EXAMINED counts, claimed or not ---
# Interop round 180: a consumer's resolver census graded `mutant_killed/
# mutation` NEVER RAN after a completed mutation run, because the drain handed
# the ledger a claim only when there was one. A resolver that ran and proved
# nothing must still say what it looked at, or "never ran" and "nothing to
# prove" are the same row -- and the second is not a defect.

def test_examined_ids_count_as_considered_without_being_resolved(led):
    _seed(led, _finding(FID), _finding(OTHER))

    out = ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation", reason="mutant_killed",
                                      ids=(FID,), examined=(FID, OTHER), present_ids=set())

    assert out == [FID]
    assert led.open_findings()[OTHER]["status"] == "open", "examined is not a claim"
    y = [e for e in led.events() if e.type is EventType.RESOLVER_YIELD][-1]
    assert (y.payload["resolver"], y.payload["tool"]) == ("mutant_killed", "mutation")
    assert (y.payload["considered"], y.payload["resolved"]) == (2, 1)


def test_an_empty_claim_still_records_what_was_examined(led):
    _seed(led, _finding(FID))

    out = ledger_mod.resolve_repaired(led, "r1", NOW, tool="mutation", reason="mutant_killed",
                                      ids=(), examined=(FID,), present_ids=set())

    assert out == []
    assert led.open_findings()[FID]["status"] == "open"
    y = [e for e in led.events() if e.type is EventType.RESOLVER_YIELD][-1]
    assert (y.payload["considered"], y.payload["resolved"]) == (1, 0)
