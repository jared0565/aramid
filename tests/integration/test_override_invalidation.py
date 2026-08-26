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

from aramid.commands.override import (_CAUSE_TEXT, cmd_override,
                                      invalidate_stale_overrides)
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


def test_the_refusal_names_the_sweep_as_the_reason_the_finding_is_back(tmp_path, capsys):
    """The other half of the loop this module tests. The sweep reopens an
    adjudicated finding; the operator's next move is to re-run `aramid
    override` on it, and until now the refusal explained the TIER rule
    without ever saying that a sweep is what put them there.

    Meeting one of these on an unrelated push, the missing sentence is
    causal: "a local override is not permitted" answers a question the
    operator did not ask, while "your earlier override was revoked" answers
    the one they did (interop round 118 section 3).
    """
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, {"src/pay.py"},
                       [_mutation_finding()])
    ledger.close()

    assert cmd_override(root, "mut1", "accepted as a warn") == 0
    (root / "aramid.toml").write_text(ARMED_TOML, encoding="utf-8")
    assert len(_sweep(root)) == 1

    capsys.readouterr()
    rc = cmd_override(root, "mut1", "still fine by me")
    err = capsys.readouterr().err

    assert rc == 3
    assert "sweep" in err, f"refusal never mentions the sweep:\n{err}"
    # ...and the CAUSE, in the same words the gate-start notice used, so the
    # two surfaces describe one event identically rather than inventing a
    # second vocabulary for it.
    assert _CAUSE_TEXT["recorded_disarmed"] in err, (
        f"refusal names the sweep but not why it fired:\n{err}")
    # The redirect it already made must survive the addition.
    assert ".aramid-suppressions.toml" in err
    assert "[[suppress]]" in err


def test_the_refusal_claims_no_sweep_when_no_sweep_reopened_the_finding(tmp_path, capsys):
    """The falsifiability half, and the reason the sentence is conditional.

    A finding that is BLOCK-tier on first detection was never overridden and
    never swept -- telling its operator that "a sweep revoked your earlier
    override" would be a fabricated causal claim, which is the same defect
    class as asserting a staleness result from an arming check (round 112).
    """
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"gitleaks"}, {"a.py"},
                       [Finding("block1", "gitleaks", "aws-key", "high", Severity.HIGH,
                                Verdict.BLOCK, "a.py", 1, "key", "evidence",
                                Gate.PRE_PUSH)])
    ledger.close()

    rc = cmd_override(root, "block1", "please just let me push")
    err = capsys.readouterr().err

    assert rc == 3
    assert ".aramid-suppressions.toml" in err, "the refusal itself regressed"
    assert "sweep" not in err.lower(), (
        f"refusal invented a sweep that never ran:\n{err}")
    for text in _CAUSE_TEXT.values():
        assert text not in err, f"refusal attributed a cause with no sweep:\n{err}"


def test_the_refusal_reports_how_many_findings_that_same_sweep_reopened(tmp_path, capsys):
    """Round 118 section 3's actual complaint was the BATCH: 26 refusals on one
    unrelated push, each reading as its own isolated denial. They are one
    re-adjudication, and the count is what says so. It is read from the
    invalidating events sharing a run_id, so it is the real batch size rather
    than a number the message asserts.
    """
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, {"src/pay.py"},
                       [_mutation_finding("mut1"), _mutation_finding("mut2"),
                        _mutation_finding("mut3")])
    ledger.close()

    for fid in ("mut1", "mut2", "mut3"):
        assert cmd_override(root, fid, "accepted as a warn") == 0
    (root / "aramid.toml").write_text(ARMED_TOML, encoding="utf-8")
    assert len(_sweep(root)) == 3

    capsys.readouterr()
    assert cmd_override(root, "mut2", "still fine by me") == 3
    err = capsys.readouterr().err

    # The exact count, not a bare "3" -- a digit floating anywhere in an id
    # or a snippet would satisfy that and prove nothing.
    assert "reopened 3 findings" in err, (
        f"refusal never reports the batch size:\n{err}")
