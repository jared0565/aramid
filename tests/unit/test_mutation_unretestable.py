"""A mutation survivor no drain item can re-test fails CLOSED.

The gate's `gap_addressed` resolve is optimistic: a push that touches a
survivor's module moves it to `pending_retest`, out of the open count, on the
promise that a drain re-test will verify it. A re-test is atomic -- every
occurrence of the id must die -- and the drain's empty-queue item has room for
min(max_mutants, confirm_cap) occurrences, 3 by default. A survivor with more
can never be verified, so the promise is void, and touching the file was enough
to take a test gap out of the counts for good (llm-review 88b420f9, on
ad415f34: eleven identical `return 3` lines in scripts/promote_live.py).

Now: the gate refuses that move when the survivor's occurrences at HEAD already
exceed the room, rows already parked there are reopened, and `aramid status`
names the way out -- raise the knobs, or override with a reason once the kills
are verified by hand. Hand-built ledgers over a real git repo, so the
occurrence count is the consumer's own regeneration, not a stub."""
import subprocess
from types import SimpleNamespace

from aramid import mutation_gate
from aramid.commands import status as status_mod
from aramid.consumers import mutation as mut_consumer
from aramid.fingerprint import compute_fingerprint
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict

NOW = "2026-10-05T12:00:00+00:00"
FOUR_IDENTICAL = ("def f(x):\n"
                  "    if x == 1:\n        return 3\n"
                  "    if x == 2:\n        return 3\n"
                  "    if x == 5:\n        return 3\n"
                  "    if x == 7:\n        return 3\n"
                  "    return 0\n")
FOUR = compute_fingerprint("mutation", "int-bound", "calc.py", "        return 3", 0)
GONE = "9" * 64      # a survivor whose file git cannot read at HEAD


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True)
    (r / "calc.py").write_text(FOUR_IDENTICAL, encoding="utf-8")
    subprocess.run(["git", "add", "calc.py"], cwd=r, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
                    "-m", "calc"], cwd=r, check=True)
    (r / ".aramid").mkdir()
    return r


def _survivor(fid, file="calc.py", line=3):
    return Finding(id=fid, tool="mutation", rule="int-bound", severity_raw="medium",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file, line=line,
                   message="mutant survived: 3 -> 4 in f", evidence="ev", gate=Gate.ALL)


def _ledger(r, fid=FOUR, *, pending=False, file="calc.py"):
    led = Ledger(r / ".aramid" / "ledger.db")
    led.record_run("d1", "2026-10-05T10:00:00+00:00", "drain", {"mutation"}, {file},
                   [_survivor(fid, file=file)])
    if pending:
        led.append(Event(EventType.FINDING_RESOLVED, "gate", "2026-10-05T11:00:00+00:00",
                         finding_id=fid,
                         payload={"auto_resolved": "gap_addressed", "pending_retest": True}))
    return led


def _cfg(**mutation):
    return SimpleNamespace(mutation={"enabled": True, **mutation})


def _yield(led):
    rows = [e.payload for e in led.events() if e.type is EventType.RESOLVER_YIELD
            and e.payload.get("resolver") == "gap_addressed"]
    assert len(rows) == 1, rows
    return rows[0]


# ------------------------------------------------------- the gate refuses --

def test_the_gate_keeps_a_survivor_no_drain_can_re_test_open(tmp_path):
    r = _repo(tmp_path)
    led = _ledger(r)
    try:
        resolved = mutation_gate.auto_resolve_mutation(
            led, "g1", NOW, {"calc.py"},
            unretestable=mut_consumer.unretestable_check(r, _cfg()))
        status = led.open_findings()[FOUR]["status"]
        y = _yield(led)
    finally:
        led.close()
    assert resolved == []
    assert status == "open"
    assert y == {"resolver": "gap_addressed", "tool": "mutation",
                 "considered": 1, "resolved": 0, "declined": 1}


def test_a_survivor_that_fits_still_moves_to_pending_retest(tmp_path):
    # The knob limb: confirm_cap 4 gives room for all four occurrences.
    r = _repo(tmp_path)
    led = _ledger(r)
    try:
        resolved = mutation_gate.auto_resolve_mutation(
            led, "g1", NOW, {"calc.py"},
            unretestable=mut_consumer.unretestable_check(r, _cfg(confirm_cap=4)))
        status = led.open_findings()[FOUR]["status"]
        y = _yield(led)
    finally:
        led.close()
    assert resolved == [FOUR]
    assert status == "pending_retest"
    assert y["declined"] == 0


def test_a_survivor_git_cannot_read_keeps_the_liberal_rule(tmp_path):
    # Unknown is not too big: only positive evidence refuses the move.
    r = _repo(tmp_path)
    led = _ledger(r, GONE, file="gone.py")
    try:
        resolved = mutation_gate.auto_resolve_mutation(
            led, "g1", NOW, {"gone.py"},
            unretestable=mut_consumer.unretestable_check(r, _cfg()))
    finally:
        led.close()
    assert resolved == [GONE]


# ------------------------------------------- rows already parked reopen --

def test_a_parked_survivor_no_drain_can_re_test_is_reopened_whole(tmp_path):
    r = _repo(tmp_path)
    led = _ledger(r, pending=True)
    try:
        before = dict(led.open_findings()[FOUR])
        reopened = mutation_gate.reopen_unretestable(led, "g1", NOW, root=r, cfg=_cfg())
        after = led.open_findings()[FOUR]
        detects = [e.payload for e in led.events()
                   if e.type is EventType.FINDING_DETECTED and e.finding_id == FOUR]
    finally:
        led.close()
    assert before["status"] == "pending_retest"
    assert reopened == [FOUR]
    # The WHOLE record, not a key list: open again, the parking reason gone,
    # the cause added, and nothing else moved.
    expected = {k: v for k, v in before.items() if k != "reason"}
    expected.update(status="open", reopened="unretestable", occurrences=4, room=3)
    assert after == expected
    assert detects[-1] == {k: v for k, v in expected.items() if k != "status"}


def test_a_reopen_rebuilds_from_the_detection_not_from_later_transitions(tmp_path):
    # An override that was invalidated leaves `invalidated_*` keys on the
    # materialized record; a detect re-asserting them would present an audit
    # note as findings data. A move, the one transition that edits a field
    # the detection owns, must survive.
    r = _repo(tmp_path)
    led = _ledger(r)
    try:
        led.append(Event(EventType.FINDING_OVERRIDDEN, "o", NOW, finding_id=FOUR,
                         payload={"reason": "r"}))
        led.append(Event(EventType.FINDING_OVERRIDE_INVALIDATED, "o", NOW, finding_id=FOUR,
                         payload={"cause": "c"}))
        led.append(Event(EventType.FINDING_MOVED, "m", NOW, finding_id=FOUR,
                         payload={"line": 5}))
        led.append(Event(EventType.FINDING_RESOLVED, "gate", NOW, finding_id=FOUR,
                         payload={"auto_resolved": "gap_addressed", "pending_retest": True}))
        assert "invalidated_cause" in led.open_findings()[FOUR]
        mutation_gate.reopen_unretestable(led, "g1", NOW, root=r, cfg=_cfg())
        after = led.open_findings()[FOUR]
    finally:
        led.close()
    assert after["status"] == "open"
    assert after["line"] == 5
    assert not any(k.startswith("invalidated_") for k in after), after


def test_a_parked_survivor_that_fits_stays_pending(tmp_path):
    r = _repo(tmp_path)
    led = _ledger(r, pending=True)
    try:
        reopened = mutation_gate.reopen_unretestable(led, "g1", NOW, root=r,
                                                     cfg=_cfg(confirm_cap=4))
        status = led.open_findings()[FOUR]["status"]
    finally:
        led.close()
    assert reopened == []
    assert status == "pending_retest"


def test_one_gate_run_does_not_move_a_reopened_survivor_straight_back(tmp_path):
    # The order run_gate uses: reopen, then gap_addressed on a push touching
    # the file. Without the refusal the second step parks it again at once.
    r = _repo(tmp_path)
    led = _ledger(r, pending=True)
    try:
        mutation_gate.reopen_unretestable(led, "g1", NOW, root=r, cfg=_cfg())
        mutation_gate.auto_resolve_mutation(
            led, "g1", NOW, {"calc.py"},
            unretestable=mut_consumer.unretestable_check(r, _cfg()))
        status = led.open_findings()[FOUR]["status"]
    finally:
        led.close()
    assert status == "open"


# --------------------------------------------------- status names the exit --

def test_status_names_an_open_survivor_no_drain_can_re_test_and_its_override(tmp_path):
    r = _repo(tmp_path)
    led = _ledger(r)
    try:
        lines = status_mod._unfittable_retest_lines(r, _cfg(), led)
    finally:
        led.close()
    assert lines == [
        "  mutation re-test impossible: 1 survivor(s) have more occurrences than one "
        "drain item can test (min(max_mutants 20, confirm_cap 3) = 3):",
        f"    {FOUR[:8]} calc.py (open): 4 occurrences -- a re-test needs "
        "[mutation].max_mutants and confirm_cap both >= 4 and wall_budget_s for 5 "
        "full-suite runs (the baseline and one confirm per occurrence)",
        "      or, once every occurrence's kill is verified by hand: "
        f'aramid override {FOUR} --reason "..."',
    ]
