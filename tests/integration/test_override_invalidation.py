"""integration: arming invalidates an override that was granted while the
finding's class was disarmed (interop rounds 84 §2, 87 §5, 89).

An operator who suppressed a WARN was never asked whether they would suppress
a BLOCK. Arming asks a question their override never answered, so the override
stops binding and the finding returns to open for re-adjudication.

Two properties this file exists to pin, both of which a plausible
implementation gets wrong:

* Invalidation is an EVENT, not a predicate computed from config at read time.
  Computed, disarming would silently RESTORE the suppression -- the flag just
  flips back. Recorded, the append-only log makes it one-way for free: nothing
  about disarming emits a counter-event, so re-suppressing costs a new
  decision. (`overridden` is already sticky across re-detection for exactly
  this reason.)
* It is emitted from a sweep at GATE START, never from the detection path.
  `mutation_gate.mutation_gate_findings` skips any rec whose status is not
  "open", so an invalidation that waited for re-detection would be eaten by
  the very filter that makes the defeat terminal.
"""
from pathlib import Path

from aramid.commands.override import cmd_override, invalidate_stale_overrides
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Source, Verdict
from aramid import config as config_mod

ARMED_TOML = "[mutation]\nmutation_block_armed = true\n"


def _mutation_finding(fid="mut1"):
    """A drain-written surviving-mutant row: stored verdict is whatever
    classify computed AT DRAIN TIME, i.e. "warn" while the tool is disarmed,
    and the append-only ledger never rewrites it."""
    return Finding(fid, "mutation", "survived", "medium", Severity.MEDIUM, Verdict.WARN,
                    "src/pay.py", 7, "surviving mutant", "evidence",
                    Gate.PRE_PUSH, source=Source.DETERMINISTIC)


def _ledger(root) -> Ledger:
    return Ledger(root / ".aramid" / "ledger.db")


def _sweep(root):
    """Run the sweep the way a gate start would, returning what it invalidated."""
    cfg = config_mod.load_config(root)
    ledger = _ledger(root)
    try:
        return invalidate_stale_overrides(ledger, cfg, run_id="r-sweep", at="t-sweep")
    finally:
        ledger.close()


def _events(root, kind="finding_override_invalidated"):
    ledger = _ledger(root)
    try:
        return [e for e in ledger.events() if e.type.value == kind]
    finally:
        ledger.close()


def _status(root, fid):
    ledger = _ledger(root)
    try:
        return ledger.open_findings()[fid]["status"]
    finally:
        ledger.close()


def test_arming_invalidates_an_override_recorded_as_made_while_disarmed(tmp_path):
    """The whole mechanism, end to end. The override must SUCCEED first -- if
    it were refused, everything after it would prove nothing."""
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, {"src/pay.py"},
                       [_mutation_finding()])
    ledger.close()

    assert cmd_override(root, "mut1", "accepted as a warn") == 0
    assert _status(root, "mut1") == "overridden"

    (root / "aramid.toml").write_text(ARMED_TOML, encoding="utf-8")
    invalidated = _sweep(root)

    assert [i["id"] for i in invalidated] == ["mut1"]
    assert invalidated[0]["cause"] == "recorded_disarmed"
    assert _status(root, "mut1") == "open", "invalidated override did not re-open"
    assert len(_events(root)) == 1


def test_a_legacy_override_with_no_recorded_state_invalidates_with_its_own_cause(tmp_path):
    """The nine-rows-here population of round 89 -- written before the field
    existed. Treated as UNKNOWN rather than as still-valid: those rows were
    written by a version that had not considered the question, which is the
    population least entitled to the benefit of the doubt.

    Its cause must be distinguishable from `recorded_disarmed`. Without that
    the ledger gains a class of invalidations whose reason is unrecoverable,
    and in six months "were these adjudicated under a wrong assumption, or
    were they just old?" has no answer.
    """
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, {"src/pay.py"},
                       [_mutation_finding()])
    # A pre-field override event: reason only, exactly as the 19 live rows read.
    ledger.append(Event(EventType.FINDING_OVERRIDDEN, "r-old", "t-old",
                        finding_id="mut1", payload={"reason": "legacy"}))
    ledger.close()

    (root / "aramid.toml").write_text(ARMED_TOML, encoding="utf-8")
    invalidated = _sweep(root)

    assert [i["cause"] for i in invalidated] == ["arming_state_unrecorded"]
    assert _status(root, "mut1") == "open"


def test_an_override_of_something_still_warn_tier_is_left_alone(tmp_path):
    """The precision half. The sweep must fire on the config having MOVED
    under a suppression, not on the suppression being old -- a sweep that
    re-opened every override would be a worse gate than no sweep at all.

    READ THIS BEFORE TRUSTING IT ALONE: its expected value is the empty list,
    which is also what a sweep that does nothing at all returns -- it passed
    against the stub. It is only evidence in company: the other tests in this
    file show the sweep firing on the same fixture shape, so a zero HERE is a
    measured zero rather than a dead code path. Never let it be the last
    surviving test of this mechanism.
    """
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, {"src/pay.py"},
                       [_mutation_finding()])
    ledger.close()

    assert cmd_override(root, "mut1", "accepted as a warn") == 0

    # No aramid.toml written: mutation stays disarmed, so nothing moved.
    assert _sweep(root) == []
    assert _status(root, "mut1") == "overridden"
    assert _events(root) == []


def test_the_sweep_is_idempotent_across_gate_runs(tmp_path):
    """It runs at every gate start. Emitting one event per row per run forever
    would turn the ledger into a log of the same decision, and `ledger list`
    into noise."""
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, {"src/pay.py"},
                       [_mutation_finding()])
    ledger.close()

    assert cmd_override(root, "mut1", "accepted as a warn") == 0
    (root / "aramid.toml").write_text(ARMED_TOML, encoding="utf-8")

    assert len(_sweep(root)) == 1
    assert _sweep(root) == [], "second sweep re-invalidated an already-open finding"
    assert len(_events(root)) == 1


def test_disarming_after_an_invalidation_does_not_restore_the_override(tmp_path):
    """The one-way property, and the reason invalidation is an event rather
    than a computed predicate. If the sweep's effect were derived from config
    at read time, removing the armed flag would silently hand the suppression
    back -- a security decision undone by editing a TOML key, with no record
    that it ever applied.
    """
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, {"src/pay.py"},
                       [_mutation_finding()])
    ledger.close()

    assert cmd_override(root, "mut1", "accepted as a warn") == 0
    (root / "aramid.toml").write_text(ARMED_TOML, encoding="utf-8")
    assert len(_sweep(root)) == 1

    # Disarm again.
    (root / "aramid.toml").write_text("[mutation]\nmutation_block_armed = false\n",
                                       encoding="utf-8")

    assert _status(root, "mut1") == "open", "disarming restored a revoked suppression"
    assert _sweep(root) == []
