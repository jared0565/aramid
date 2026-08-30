from types import SimpleNamespace

from aramid import mutation_gate
from aramid.ledger import Ledger
from aramid.models import (Event, EventType, Finding, Gate, Severity, Source,
                           Verdict)

NOW = "2026-07-21T12:00:00+00:00"


def _mut_finding(fid="m" * 64, file="src/pkg/x.py", line=42, op="flip_comparison"):
    return Finding(id=fid, tool="mutation", rule=op, severity_raw="medium",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file,
                   line=line, message=f"mutant survived: {op}", evidence="",
                   gate=Gate.ALL, source=Source.DETERMINISTIC)


def _seed(led, finding):
    led.record_run("r0", NOW, "drain", set(), set(), [finding])


def _seed_raw(led, fid, payload):
    led.append(Event(EventType.FINDING_DETECTED, "r0", NOW,
                     finding_id=fid, payload=payload))


def _cfg(armed):
    return SimpleNamespace(mutation={"mutation_block_armed": armed})


def test_gate_blocks_open_mutation_when_armed(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        got = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert len(got) == 1
    assert got[0].verdict is Verdict.BLOCK
    assert got[0].tool == "mutation"
    assert got[0].source is Source.DETERMINISTIC
    assert got[0].file == "src/pkg/x.py"
    assert got[0].line == 42


def test_gate_warns_while_baking(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        got = mutation_gate.mutation_gate_findings(_cfg(False), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert [f.verdict for f in got] == [Verdict.WARN]


def test_gate_empty_outside_pre_push(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        assert mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_COMMIT) == []
        assert mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.ALL) == []
    finally:
        led.close()


def test_gate_ignores_non_mutation(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        other = Finding(id="s" * 64, tool="semgrep", rule="x", severity_raw="ERROR",
                        severity=Severity.HIGH, verdict=Verdict.WARN, file="a.py",
                        line=1, message="m", evidence="e", gate=Gate.ALL)
        _seed(led, other)
        got = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert [f.tool for f in got] == ["mutation"]


def test_gate_skips_resolved_and_overridden(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding(fid="a" * 64))
        led.append(Event(EventType.FINDING_RESOLVED, "r1", NOW, finding_id="a" * 64))
        _seed(led, _mut_finding(fid="b" * 64))
        led.append(Event(EventType.FINDING_OVERRIDDEN, "r1", NOW,
                         finding_id="b" * 64, payload={"reason": "accepted"}))
        got = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert got == []


def test_gate_skips_malformed_rec_but_surfaces_wellformed(tmp_path):
    """A rec with line stored as null (int(None) -> TypeError) is SKIPPED, not
    crashed; a well-formed rec alongside it still surfaces."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed_raw(led, "d" * 64, {"tool": "mutation", "file": "src/pkg/y.py",
                                  "line": None, "severity": "medium",
                                  "rule": "flip", "message": "m"})
        _seed(led, _mut_finding())
        got = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert [f.id for f in got] == ["m" * 64]
    assert got[0].verdict is Verdict.BLOCK


def test_resolve_when_source_touched(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())                      # on src/pkg/x.py
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"src/pkg/x.py"})
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == ["m" * 64]
    assert state["m" * 64]["status"] == "pending_retest"


def test_resolve_when_mapped_test_added(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())                      # module stem "x"
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"tests/test_x.py"})        # test_<module>.py
    finally:
        led.close()
    assert resolved == ["m" * 64]


def test_resolve_when_underscore_test_added(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"src/pkg/x_test.py"})      # <module>_test.py
    finally:
        led.close()
    assert resolved == ["m" * 64]


def test_no_resolve_for_unrelated_test(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())                      # module "x"
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"tests/test_y.py"})        # different module
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["m" * 64]["status"] == "open"


def test_no_resolve_for_unrelated_nontest(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"README.md", "src/pkg/other.py"})
    finally:
        led.close()
    assert resolved == []


def test_resolve_skips_malformed_rec_without_raising(tmp_path):
    """A rec with file stored as null must be SKIPPED -- stays open, never
    crashes."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed_raw(led, "d" * 64, {"tool": "mutation", "file": None,
                                  "line": 1, "severity": "medium"})
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"src/pkg/x.py"})
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["d" * 64]["status"] == "open"


def test_resolution_before_materialize_no_double_surface(tmp_path):
    """After auto_resolve_mutation fires, mutation_gate_findings must not
    re-surface the resolved finding (the run_gate ordering: resolve, then
    materialize)."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        mutation_gate.auto_resolve_mutation(led, "r1", NOW, {"tests/test_x.py"})
        got = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert got == []


# --- the mapped-test rule, and what bounds it -------------------------------
#
# `test_<module>.py` / `<module>_test.py` alone cannot express how this repo --
# or most Python repos -- names tests for a module inside a SUBPACKAGE. Two
# conventions it missed, both load-bearing here:
#
#   src/aramid/consumers/base.py    <- tests/unit/test_consumers_base.py
#   src/aramid/commands/doctor.py   <- tests/unit/test_doctor_version_parsing.py
#
# Measured 2026-08-10, and this is not hypothetical: FOUR of aramid's five open
# findings were mutants on those two files that the repo's own tests provably
# KILL -- applying each mutant by hand turns the mapped test file red. They sat
# open only because nothing could map the fix back to the finding, which is the
# state that teaches an operator to ignore the tool.
#
# The rule is deliberately anchored rather than "module name appears anywhere":
# `base` is a stem THREE source files share (consumers/, providers/, runners/),
# so an unanchored rule would let one subpackage's test clear another's finding
# -- and for mutation_score_gate it would suppress an armed BLOCK regression on
# a module nobody tested. Qualifying by the module's own parent directory keeps
# those three apart.

def test_maps_a_package_qualified_test_to_its_module(tmp_path):
    """test_<parent>_<module>.py -- how this repo names tests for a module in
    a subpackage. Was the reason four findings could never resolve."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding(file="src/aramid/consumers/base.py"))
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"tests/unit/test_consumers_base.py"})
    finally:
        led.close()
    assert resolved == ["m" * 64]


def test_maps_a_purpose_suffixed_test_to_its_module(tmp_path):
    """test_<module>_<aspect>.py -- a test file scoped to one aspect of a
    module, which is how the doctor findings' killing tests are named."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding(file="src/aramid/commands/doctor.py"))
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"tests/unit/test_doctor_version_parsing.py"})
    finally:
        led.close()
    assert resolved == ["m" * 64]


def test_a_sibling_subpackages_test_does_not_resolve_the_other_base(tmp_path):
    """THE BOUNDARY, and the only test here that fails under the obvious
    over-wide rule ("module name is a token of the test name"). `base` is
    shared by consumers/, providers/ and runners/ -- so an unanchored rule
    resolves all three findings when any one of their tests changes, and a
    module nobody tested comes back clean."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding(file="src/aramid/consumers/base.py"))
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"tests/unit/test_runners_base.py"})
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["m" * 64]["status"] == "open"


def test_an_unrelated_purpose_suffixed_test_does_not_resolve(tmp_path):
    """The suffix rule is PREFIX-anchored: `test_doctor_*` maps to doctor,
    but `test_predoctor_*` and `test_x_doctor_*` do not. Without the anchor,
    substring matching would make almost every test map to almost every
    module."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding(file="src/aramid/commands/doctor.py"))
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"tests/unit/test_predoctor_helpers.py"})
    finally:
        led.close()
    assert resolved == []


def test_a_longer_modules_test_also_maps_to_the_shorter_prefix_module(tmp_path):
    """A KNOWN COST of the prefix-anchored suffix form, pinned so it is not
    rediscovered as a bug. `test_mutation_gate.py` tests `mutation_gate.py`,
    but it also matches `test_<module>_*` for module `mutation` -- so it maps
    to `mutation.py` too. Live in this repo: `mutation.py`/`mutation_gate.py`
    and `mutation_score.py`/`mutation_score_gate.py` are both such pairs.

    Accepted because it errs the direction this resolver's docstring licenses
    -- a wrong resolve lets a test gap slip until the re-drain re-reports it,
    which is never a security hole. The dangerous direction, one subpackage's
    test clearing another's finding, is rejected: see the sibling test above.
    Tighten this only with evidence that a real gap slipped through it."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding(file="src/aramid/mutation.py"))
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"tests/unit/test_mutation_gate.py"})
    finally:
        led.close()
    assert resolved == ["m" * 64], (
        "if this now returns [] the mapping was tightened -- that may be an "
        "improvement, but it is a behaviour change and wants its own note")


# --- the tool/status filter, which nothing rejected data reached ------------
#
# `if rec.get("tool") != TOOL or rec.get("status") != "open": continue` had 18
# tests over it and `or -> and` survived every one, because each seeded exactly
# one finding of the right tool in the right status. Third instance in a single
# day of the same shape (see consumers/base.py::open_findings_for and its two
# filters): A COMPOUND FILTER IS ONLY TESTED BY DATA IT IS SUPPOSED TO REJECT.
#
# Not cosmetic. Under `and`, the skip fires only when the tool is wrong AND the
# status is not open -- so any OPEN finding of ANY tool is processed, and gets
# resolved when the push touches its file. A mutation resolver would clear
# gitleaks and semgrep findings on sight. The re-drain backstop this resolver
# leans on does not apply: it re-reports mutants, not secrets.

def test_does_not_resolve_another_tools_open_finding(tmp_path):
    """Kills `or -> and` on the tool half. The seeded gitleaks finding is on a
    file the push DID touch, so only the tool check stands between it and a
    resolve."""
    led = Ledger(tmp_path / "l.db")
    try:
        secret = Finding(
            id="s" * 64, tool="gitleaks", rule="generic-api-key",
            severity_raw="critical", severity=Severity.CRITICAL,
            verdict=Verdict.BLOCK, file="src/pkg/x.py", line=7,
            message="secret detected", evidence="", gate=Gate.ALL,
            source=Source.DETERMINISTIC)
        _seed(led, secret)
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"src/pkg/x.py"})
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == [], "the mutation resolver cleared a gitleaks finding"
    assert state["s" * 64]["status"] == "open"


def test_does_not_resolve_a_mutation_finding_that_is_not_open(tmp_path):
    """Kills `or -> and` on the status half, and pins that an operator's
    override is not quietly rewritten into a `fixed` by a later push."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        led.append(Event(EventType.FINDING_OVERRIDDEN, "r0", NOW,
                         finding_id="m" * 64,
                         payload={"reason": "equivalent mutant"}))
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"src/pkg/x.py"})
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["m" * 64]["status"] == "overridden"


# --- the skipped counter, which is user-visible output ----------------------
#
# `skipped = 0` -> 1 and `skipped += 1` -> 2 both survived every test here.
# They were deferred once as "diagnostics only"; that was the wrong reading.
# `diagnostics.note_skipped` is SILENT at zero and prints to stderr otherwise,
# so under the first mutant every clean run tells the operator their ledger
# holds a malformed record when it does not, and under the second the count is
# doubled. A security tool inventing a complaint about the user's own data is
# not a cosmetic defect -- it is the noise that trains people to stop reading
# the output.
#
# Asserted on the RENDERED stderr rather than on the counter, because the
# counter is not the contract; the message is the only part anyone sees.

def _raising_rec(led, fid):
    """A record that genuinely raises INSIDE the try -- `file` non-str and
    truthy, so `normalize_path` raises AttributeError. A `None` file does not
    do this: `if not path: continue` catches it first and counts no skip,
    which is why the pre-existing 'skips malformed rec' test could never have
    pinned this counter."""
    _seed_raw(led, fid, {"tool": "mutation", "file": 123, "rule": "flip",
                         "severity": "medium", "line": 1, "message": "m",
                         "evidence": "", "verdict": "warn"})


def test_resolve_says_nothing_when_no_record_is_malformed(tmp_path, capsys):
    """Kills `skipped = 0` -> 1: the clean path must stay quiet."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        mutation_gate.auto_resolve_mutation(led, "r1", NOW, {"src/pkg/x.py"})
    finally:
        led.close()
    err = capsys.readouterr().err
    assert "malformed" not in err, (
        f"a clean run reported a malformed record: {err!r}")


def test_resolve_reports_exactly_one_malformed_record(tmp_path, capsys):
    """Kills `skipped += 1` -> 2: the count must be the number of records that
    actually failed, not a multiple of it."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        _raising_rec(led, "d" * 64)
        mutation_gate.auto_resolve_mutation(led, "r1", NOW, {"src/pkg/x.py"})
    finally:
        led.close()
    err = capsys.readouterr().err
    assert "skipped 1 malformed record" in err, (
        f"expected exactly one skip to be reported, got: {err!r}")


# ------------------------- gap_addressed is a PENDING state, not a repair ---
# Measured on aramid's own ledger, 2026-08-30: 21 `gap_addressed` resolves in
# the repo's history, 20 never re-examined. The docstring's "re-drain
# backstop" is structurally void for them -- range-mode mutation regenerates
# only mutants on CHANGED lines and the id is content-keyed, so an old id can
# only return through the survivor re-test (b2), which reads OPEN rows. An
# optimistic resolve therefore made `fixed` permanent and vacuous. The
# resolve stays (a dev who added a test must not be blocked), but it now
# records a state the re-test can find and a reader can trust.

def test_gap_addressed_leaves_the_finding_pending_retest_not_fixed(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        resolved = mutation_gate.auto_resolve_mutation(led, "r1", NOW, {"tests/test_x.py"})
        rec = led.open_findings()["m" * 64]
        ev = [e for e in led.events() if e.type is EventType.FINDING_RESOLVED][-1]
    finally:
        led.close()
    assert resolved == ["m" * 64]
    assert rec["status"] == "pending_retest"
    assert "re-test" in rec["reason"]
    assert ev.payload["auto_resolved"] == "gap_addressed" and ev.payload["pending_retest"] is True


def test_a_pending_retest_finding_does_not_block_the_gate(tmp_path):
    """The unblock is the reason the optimistic resolve exists; the new
    state must keep it. Only `open` rows gate."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        mutation_gate.auto_resolve_mutation(led, "r1", NOW, {"src/pkg/x.py"})
        out = mutation_gate.mutation_gate_findings(_cfg(True), led, Gate.PRE_PUSH)
    finally:
        led.close()
    assert out == []


def test_gap_addressed_skips_a_suppressed_survivor(tmp_path):
    """An `equivalent mutant` entry in the tracked suppressions file says
    "unkillable, adjudicated" -- there is no gap to address, and writing any
    resolve for it is a false claim (c5326a9c, twice). The re-test already
    skips these; the gate now agrees."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        resolved = mutation_gate.auto_resolve_mutation(
            led, "r1", NOW, {"src/pkg/x.py"}, suppressed={"m" * 64})
        rec = led.open_findings()["m" * 64]
    finally:
        led.close()
    assert resolved == []
    assert rec["status"] == "open"


def test_a_legacy_gap_addressed_event_still_reads_fixed(tmp_path):
    """Migration: events written before the `pending_retest` key existed keep
    materializing as they always did. The ledger is append-only and those
    rows were never re-examined; rewriting their history is not this
    change's job."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _mut_finding())
        led.append(Event(EventType.FINDING_RESOLVED, "r1", NOW, finding_id="m" * 64,
                         payload={"auto_resolved": "gap_addressed"}))
        rec = led.open_findings()["m" * 64]
    finally:
        led.close()
    assert rec["status"] == "fixed"
