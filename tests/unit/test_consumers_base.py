from pathlib import Path

from aramid.consumers.base import CONSUMERS, ConsumerResult, DrainContext


def test_protocol_shapes():
    ctx = DrainContext(root=Path("."), cfg=None, ledger=None, clock=lambda: "t")
    res = ConsumerResult(consumer="fake", state="ok", findings=[])
    # Assert on ctx rather than merely constructing it: the construction was
    # the point (DrainContext accepts these kwargs and stores them), but an
    # unasserted local proves only that __init__ did not raise.
    assert ctx.root == Path(".") and ctx.clock() == "t"
    assert res.cost == 0.0 and res.duration_s == 0.0 and res.note == ""
    assert isinstance(CONSUMERS, dict)


def test_consumer_result_extra_defaults_empty():
    r = ConsumerResult(consumer="x", state="ok")
    assert r.extra == {}


# --- open_findings_for's two filters ----------------------------------------
#
# Found by aramid's own mutation testing, against code added the same day: both
# `and -> or` and `== -> !=` survived on the one line
#
#     if rec.get("tool") == tool and rec.get("status") == "open"
#
# because every existing test seeded a ledger containing exactly one finding,
# of the right tool, in the right status. A filter is only tested by data it is
# supposed to REJECT, and there wasn't any.
#
# Neither is cosmetic. This helper decides which findings a producer may claim
# it repaired: `and -> or` hands a consumer every OPEN finding in the ledger
# regardless of tool, and `== -> !=` hands it every finding that is already
# fixed or overridden. `resolve_repaired` re-checks the tool and status itself,
# so the blast radius is contained -- but "the caller happens to re-check" is
# not a reason to leave a filter unpinned, and dast builds its whole claim from
# this result.

def _mixed_ledger(tmp_path):
    """One finding per REJECTION reason, plus the one that must survive."""
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict

    def _f(fid, tool):
        return Finding(id=fid, tool=tool, rule="r", severity_raw="medium",
                       severity=Severity.MEDIUM, verdict=Verdict.WARN,
                       file="x.py", line=1, message="m", evidence="",
                       gate=Gate.ALL)

    led = Ledger(tmp_path / "l.db")
    keep, other_tool, not_open = "a" * 64, "b" * 64, "c" * 64
    led.record_run("r0", "2026-08-10T00:00:00+00:00", "drain", set(), set(),
                   [_f(keep, "mutation"), _f(other_tool, "dast"),
                    _f(not_open, "mutation")])
    led.append(Event(EventType.FINDING_OVERRIDDEN, "r0",
                     "2026-08-10T00:00:00+00:00", finding_id=not_open,
                     payload={"reason": "accepted"}))
    return led, keep, other_tool, not_open


def test_open_findings_for_rejects_another_tools_finding(tmp_path):
    """Kills `and -> or`. Under the mutant a dast finding comes back from a
    query for mutation's, and a producer would name it in a repair claim."""
    from aramid.consumers.base import open_findings_for

    led, keep, other_tool, _ = _mixed_ledger(tmp_path)
    try:
        got = open_findings_for(led, "mutation")
    finally:
        led.close()

    assert keep in got
    assert other_tool not in got, "a dast finding was returned for tool=mutation"


def test_open_findings_for_rejects_a_finding_that_is_not_open(tmp_path):
    """Kills `== -> !=`. Under the mutant the OVERRIDDEN finding comes back and
    the open one does not -- so a producer could resolve a finding an operator
    had already decided about, which is the one status transition nothing else
    in the ledger produces."""
    from aramid.consumers.base import open_findings_for

    led, keep, _, not_open = _mixed_ledger(tmp_path)
    try:
        got = open_findings_for(led, "mutation")
    finally:
        led.close()

    assert keep in got
    assert not_open not in got, "an overridden finding was returned as open"


def test_open_findings_for_never_raises_on_an_unreadable_ledger():
    """The docstring promises an empty map rather than an exception -- no
    claims, the safe direction. Pinned because a consumer calls this before it
    has done any work, so a raise here would take the whole drain down."""
    class Boom:
        def open_findings(self):
            raise RuntimeError("ledger is corrupt")

    from aramid.consumers.base import open_findings_for

    assert open_findings_for(Boom(), "mutation") == {}


# --- prior_note_count: the give-up counter --------------------------------
#
# Four consumers read this (dast, js_mutation, mutation, and llm_review via
# _malformed_attempts) to decide whether they have already failed enough times
# on a queue item to stop trying. Its own docstring calls the note strings
# load-bearing.
#
# It had no DIRECT test. Probed 2026-08-11 by applying nine mutants -- each
# conjunct of the four-part filter, both comparisons, the startswith, the
# counter's init and increment, and the event-type guard -- and all nine
# survived this file. Coverage is not absent: the wider suite kills at least
# the inverted guard (four caller integration tests fail). It is INCIDENTAL,
# which is a different thing and a worse one to rely on -- the contract is
# asserted nowhere, so it can be narrowed or widened by editing a consumer.
#
# Both directions matter and neither is theoretical. Count too high and a
# consumer gives up on healthy work; count too low and it retries a poisoned
# item forever. Same shape as the three filter defects found the day before:
# A COMPOUND FILTER IS ONLY TESTED BY DATA IT IS SUPPOSED TO REJECT.

_PREFIX = "giving-up"


def _giveup_ledger(tmp_path):
    """One event that MUST be counted, plus one per rejection reason. Every
    rejector differs from the match in exactly one field, so each conjunct is
    the only thing standing between it and the count."""
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType

    led = Ledger(tmp_path / "l.db")

    def ev(etype, consumer, item_id, note):
        led.append(Event(etype, "r0", "2026-08-11T00:00:00+00:00",
                         payload={"consumer": consumer, "item_id": item_id,
                                  "note": note}))

    ev(EventType.CONSUMER_RUN_FINISHED, "mutation", "q1", "giving-up: baseline")
    # A different event type, everything else identical: the type guard is
    # the only thing rejecting it.
    ev(EventType.QUEUE_ITEM_DRAINED, "mutation", "q1", "giving-up: baseline")
    ev(EventType.CONSUMER_RUN_FINISHED, "dast", "q1", "giving-up: baseline")
    ev(EventType.CONSUMER_RUN_FINISHED, "mutation", "q2", "giving-up: baseline")
    # Prefix present but at the END: separates startswith from endswith/`in`.
    ev(EventType.CONSUMER_RUN_FINISHED, "mutation", "q1", "ran, then giving-up")
    return led


def test_prior_note_count_counts_only_the_fully_matching_event(tmp_path):
    """Kills all three `and -> or`, both `== -> !=`, `startswith -> endswith`,
    the event-type guard, and `n += 1 -> 2` in one assertion: exactly one of
    the five seeded events satisfies every conjunct."""
    from aramid.consumers.base import prior_note_count

    led = _giveup_ledger(tmp_path)
    try:
        got = prior_note_count(led, "mutation", "q1", _PREFIX)
    finally:
        led.close()
    assert got == 1, (
        "expected exactly the one CONSUMER_RUN_FINISHED event for "
        f"consumer=mutation item_id=q1 whose note STARTS with the prefix; got {got}")


def test_prior_note_count_is_zero_when_nothing_matches(tmp_path):
    """Kills `n = 0 -> 1`. A give-up counter that starts at one means every
    consumer begins life one failure closer to abandoning the item, on a
    ledger where it has never run."""
    from aramid.consumers.base import prior_note_count

    led = _giveup_ledger(tmp_path)
    try:
        got = prior_note_count(led, "fuzz", "q1", _PREFIX)
    finally:
        led.close()
    assert got == 0


def test_prior_note_count_accumulates_across_repeated_failures(tmp_path):
    """The counter's actual job -- one more matching event means one more
    strike. Pins the increment as +1 rather than merely non-zero."""
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType

    from aramid.consumers.base import prior_note_count

    led = Ledger(tmp_path / "l.db")
    try:
        for i in range(3):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}",
                             "2026-08-11T00:00:00+00:00",
                             payload={"consumer": "mutation", "item_id": "q1",
                                      "note": f"giving-up: attempt {i}"}))
        got = prior_note_count(led, "mutation", "q1", _PREFIX)
    finally:
        led.close()
    assert got == 3
