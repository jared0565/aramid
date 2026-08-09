"""Resolution for the `tests` runner's whole-suite findings.

THE BUG THESE PIN. `ledger.record_run` resolves an open finding only when
`rec["file"] in scope_files` (ledger.py:93-94). The tests runner reports every
whole-suite finding against the synthetic marker `<test-suite>`
(runners/tests.py:142), which is not a path and can therefore never appear in
any scope_files. Such a finding was IMMORTAL: once the suite failed or timed
out even once, it stayed open forever, through any number of green runs.

Observed in aramid's own ledger before this fix -- detected 2026-07-12 with
exactly one event, still open weeks later after the suite had passed
thousands of times. `tests` is BLOCK-tier, so a stuck finding is not cosmetic.

WHY THESE TARGET THE FILE MARKER AND NOT `tool == "tests"`. RunnerResult.tool
is `Path(argv[0]).name` (runners/base.py:165), so a real failure carries
"pytest", "npm", or -- under a configured `[tests].command` like aramid's own
`["python", "-m", "pytest", ...]` -- "python". The label "tests" appears only
because degraded results are relabelled to the registry name (1556a3f). The
marker is the one stable property shared by exactly the immortal set.
"""
from datetime import datetime, timezone

from aramid import tests_gate
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Verdict

NOW = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)
SUITE_MARKER = "<test-suite>"


def _suite_finding(fid="a" * 64, rule="tests-failed", tool="pytest"):
    return Finding(id=fid, tool=tool, rule=rule,
                   severity_raw="high", severity=Severity.HIGH,
                   verdict=Verdict.BLOCK, file=SUITE_MARKER, line=0,
                   message="pytest exited 1: test suite failed",
                   evidence="pytest exited 1: test suite failed",
                   gate=Gate.PRE_PUSH)


def _ruff_finding(fid="b" * 64):
    return Finding(id=fid, tool="ruff", rule="S102",
                   severity_raw="error", severity=Severity.HIGH,
                   verdict=Verdict.WARN, file="src/app.py", line=3,
                   message="exec used", evidence="exec(x)",
                   gate=Gate.PRE_PUSH)


def _seed(led, *findings):
    led.record_run("r0", NOW.isoformat(), "pre-push", set(), set(), list(findings))


def test_record_run_alone_cannot_resolve_a_suite_finding(tmp_path):
    """The mechanism, pinned. Even a run whose scope covers the tool AND every
    real file leaves the finding open, because `<test-suite>` is not a real
    file and can never be in scope_files.

    Without this, the resolver tests below could pass for the wrong reason --
    they would not prove the resolver is what does the work.

    `root=` IS THE WHOLE POINT AND WAS MISSING UNTIL 2026-08-09. This asserted
    the right thing about the wrong call: `run_gate` is the only production
    caller that passes `root`, and it ALWAYS passes it, so a version of this
    test that omits it exercises a configuration the gate never runs. It
    passed for a reason unrelated to its own docstring -- `_departed` short-
    circuits to False on `root is None` -- and hid a second, live route to
    resolution that scope_files has nothing to do with. Measured with `root`
    supplied and the shipped code: `fixed`. See
    `test_the_suite_marker_is_not_a_departed_file` for the route and the fix.
    """
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _suite_finding())
        led.record_run("r1", NOW.isoformat(), "pre-push",
                       {"pytest", "tests"},
                       {"src/app.py", "tests/unit/test_x.py"}, [],
                       root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


def test_the_suite_marker_is_not_a_departed_file(tmp_path):
    """`<test-suite>` is a synthetic label, not a path, so "does this file still
    exist?" is not a question that can be asked about it -- and `_departed`
    answering True is how a BLOCK-tier suite finding gets resolved by a run
    that never established the suite passed.

    `ledger._departed` used to claim in its own docstring that such a path is
    "reported as present, i.e. NOT departed", on the theory that the marker is
    an illegal Windows filename and the check would raise. MEASURED FALSE on
    Windows / CPython 3.14: non-strict `Path.resolve()` does not raise on an
    illegal name, and `.exists()` returns False rather than raising, so
    `_departed` returned True. On Linux the marker is a perfectly legal
    filename that simply does not exist -- also True. The documented safety
    property held on no platform at all.

    THIS WAS LIVE, not a hazard introduced by some other change. `scope_tools`
    holds `Path(argv[0]).name`; aramid's own `[tests].command` is
    `["python", "-m", "pytest", ...]`, so "python" is in scope_tools whenever
    that runner exits OK, the tool clause passes, and `record_run` reached the
    departed check and resolved the finding -- several steps before
    `tests_gate.auto_resolve_tests` was consulted. Measured in aramid's own
    ledger: of 4 historical resolutions of whole-suite findings, 3 carry an
    EMPTY payload (record_run's departed path) and only 1 carries
    `auto_resolved: suite_completed_clean`. The resolver written to be the only
    thing that can clear these was beaten to it three times out of four.

    Outcomes coincided with the correct ones only by accident of labelling --
    "tests ran OK" and "python in scope_tools" happen to be the same condition
    HERE. The module docstring above already warns those labels vary per repo;
    where they diverge, a suite finding cleared on a run whose suite never ran.
    """
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _suite_finding(tool="python"))
        # Exactly the shipped pre-push shape: the tests runner exited OK, so
        # its argv[0] label is in scope_tools and the tool clause does NOT
        # stop us. Only the synthetic-path guard does.
        led.record_run("r1", NOW.isoformat(), "pre-push",
                       {"gitleaks", "python", "semgrep"}, {"src/app.py"}, [],
                       root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


def test_resolves_stale_suite_failure_once_the_suite_completes(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _suite_finding())
        resolved = tests_gate.auto_resolve_tests(
            led, "r1", NOW.isoformat(), present_ids=set(), suite_completed=True)
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == ["a" * 64]
    assert state["a" * 64]["status"] == "fixed"


def test_does_not_resolve_when_the_suite_did_not_complete(tmp_path):
    """THE SAFETY PROPERTY. runners/tests.py deliberately emits `tests-failed`
    on TIMEOUT and CRASHED as well as on a non-zero exit, so "no suite finding
    this run" does NOT imply the suite passed -- it equally covers the runner
    never getting to say. Only a completed run (ToolState.OK on the `tests`
    slot) makes absence meaningful.

    Getting this wrong clears a BLOCK-tier finding on a run where the suite
    hung, which is strictly worse than leaving it open.
    """
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _suite_finding())
        resolved = tests_gate.auto_resolve_tests(
            led, "r1", NOW.isoformat(), present_ids=set(), suite_completed=False)
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["a" * 64]["status"] == "open"


def test_keeps_a_failure_that_re_fired_this_run(tmp_path):
    """A still-failing suite re-emits the SAME id (line_content is "" for the
    marker either way, so both hash identically -- runners/tests.py:165-175),
    so present_ids is what distinguishes "fixed" from "still broken"."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _suite_finding())
        resolved = tests_gate.auto_resolve_tests(
            led, "r1", NOW.isoformat(), present_ids={"a" * 64},
            suite_completed=True)
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["a" * 64]["status"] == "open"


def test_resolves_regardless_of_which_tool_label_the_finding_carries(tmp_path):
    """The label varies with argv[0] -- "pytest", "npm", "python" under a
    configured command, or "tests" after degraded-result relabelling. All of
    them are equally immortal, so all must clear."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led,
              _suite_finding(fid="a" * 64, tool="pytest"),
              _suite_finding(fid="c" * 64, tool="npm"),
              _suite_finding(fid="d" * 64, tool="tests",
                             rule="tests-tool-missing"))
        resolved = tests_gate.auto_resolve_tests(
            led, "r1", NOW.isoformat(), present_ids=set(), suite_completed=True)
    finally:
        led.close()
    assert sorted(resolved) == sorted(["a" * 64, "c" * 64, "d" * 64])


def test_leaves_findings_on_real_files_alone(tmp_path):
    """Scoped to the synthetic marker. A finding on a real path resolves
    through the normal scope_files route and must not be swept up here."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _suite_finding(), _ruff_finding())
        resolved = tests_gate.auto_resolve_tests(
            led, "r1", NOW.isoformat(), present_ids=set(), suite_completed=True)
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == ["a" * 64]
    assert state["b" * 64]["status"] == "open"
