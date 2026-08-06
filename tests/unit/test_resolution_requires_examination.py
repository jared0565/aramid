"""A runner may only resolve findings in files it actually examined.

THE BUG. `record_run` resolved an open finding when its tool was in
`scope_tools` and its file was in `scope_files`. But `scope_tools` is built
from `ToolState.OK`, and `scope_files` is the WHOLE run's file set — while
every selective runner examines a subset of it. So a runner was credited for
files it never looked at.

Measured before the fix, ruff 0.15.18:

    ruff check --force-exclude --extend-select S -- bad.py
      no exclude          -> exit 0, 2 findings (S110, S602)
      exclude=["bad.py"]  -> exit 0, 0 findings, stderr warning only

`--force-exclude` makes ruff honour the repo's own `exclude` config even for
explicitly-passed paths, and exit 0 maps to `ToolState.OK`. So adding a path
to `[tool.ruff] exclude` silently recorded every open finding in that file as
FIXED — in an append-only audit ledger, as genuinely repaired rather than
suppressed. The same shape applies to `.eslintignore` and clippy exclusions.

This is the aramid analogue of graphite's round-56 defect, and the same
sentence describes both: A HEALTH METRIC OVER DETECTED ITEMS CANNOT BOUND A
NON-DETECTION CLASS. Their ratio counted detected call sites, so an unmodelled
invocation could never lower it; aramid's resolution counted reported
findings, so an unexamined file could never keep one open.

THE FIX. A runner reports the files it can vouch for having analyzed
(`RunnerResult.examined`), and resolution intersects against that rather than
the gate-wide `scope_files`. `examined=None` means "cannot report" and falls
back to the old behaviour, so no runner is broken by not opting in — the gap
that leaves is real and deliberate, and named in the runner tests below.
"""
from datetime import datetime, timezone
from pathlib import Path

from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Verdict
from aramid.runners import ruff
from aramid.runners.base import RunContext, ToolState

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=timezone.utc)
FID = "a" * 64


def _finding(tool="ruff", file="bad.py"):
    return Finding(id=FID, tool=tool, rule="S110", severity_raw="error",
                   severity=Severity.HIGH, verdict=Verdict.WARN, file=file,
                   line=2, message="try-except-pass", evidence="pass",
                   gate=Gate.PRE_COMMIT)


def _seed(led):
    led.record_run("r0", NOW.isoformat(), "pre-commit", set(), set(), [_finding()])


# ------------------------------------------------- the resolution contract ---


def test_a_finding_resolves_when_its_tool_examined_the_file(tmp_path):
    """The behaviour that must survive: ruff looked at bad.py and reported
    nothing, so the finding really is fixed."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led)
        led.record_run("r1", NOW.isoformat(), "pre-commit", {"ruff"}, {"bad.py"}, [],
                       examined_by_tool={"ruff": {"bad.py"}})
        assert led.open_findings()[FID]["status"] == "fixed"
    finally:
        led.close()


def test_a_finding_is_NOT_resolved_when_its_tool_skipped_the_file(tmp_path):
    """THE BUG. bad.py is in the gate's file set and ruff exited 0, but ruff
    never examined it — the repo's ruff config excludes it. Crediting that as
    'fixed' writes a false repair into an append-only audit trail."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led)
        led.record_run("r1", NOW.isoformat(), "pre-commit", {"ruff"}, {"bad.py"}, [],
                       examined_by_tool={"ruff": set()})
        assert led.open_findings()[FID]["status"] == "open"
    finally:
        led.close()


def test_a_partial_exclusion_only_resolves_the_examined_file(tmp_path):
    """The realistic case is partial, not total: `exclude = ["legacy/"]` in a
    repo where legacy/ is full of findings. One file examined must not resolve
    the other."""
    led = Ledger(tmp_path / "l.db")
    other = "b" * 64
    try:
        led.record_run("r0", NOW.isoformat(), "pre-commit", set(), set(),
                       [_finding(), Finding(id=other, tool="ruff", rule="S110",
                                            severity_raw="error", severity=Severity.HIGH,
                                            verdict=Verdict.WARN, file="legacy/old.py",
                                            line=1, message="m", evidence="e",
                                            gate=Gate.PRE_COMMIT)])
        led.record_run("r1", NOW.isoformat(), "pre-commit", {"ruff"},
                       {"bad.py", "legacy/old.py"}, [],
                       examined_by_tool={"ruff": {"bad.py"}})
        state = led.open_findings()
        assert state[FID]["status"] == "fixed"
        assert state[other]["status"] == "open"
    finally:
        led.close()


def test_omitting_the_examined_map_preserves_the_old_behaviour(tmp_path):
    """`record_run` has three production callers; only the gate can report an
    examined set. init._scan_history and drain must keep working unchanged."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led)
        led.record_run("r1", NOW.isoformat(), "pre-commit", {"ruff"}, {"bad.py"}, [])
        assert led.open_findings()[FID]["status"] == "fixed"
    finally:
        led.close()


def test_a_tool_that_reports_no_examined_set_falls_back(tmp_path):
    """A runner absent from the map (it could not report) is not penalised —
    otherwise its findings would become immortal, which is the bug the
    departed-file fix existed to remove."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led)
        led.record_run("r1", NOW.isoformat(), "pre-commit", {"ruff"}, {"bad.py"}, [],
                       examined_by_tool={"gitleaks": {"other.py"}})
        assert led.open_findings()[FID]["status"] == "fixed"
    finally:
        led.close()


def test_a_departed_file_still_resolves_even_though_nothing_examined_it(tmp_path):
    """The `_departed` clause must survive: a file that has LEFT the repo can
    never be examined by anyone, so requiring examination would make its
    findings immortal — exactly the regression this guards against."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led)
        led.record_run("r1", NOW.isoformat(), "pre-commit", {"ruff"}, {"other.py"}, [],
                       examined_by_tool={"ruff": set()}, root=tmp_path)
        assert led.open_findings()[FID]["status"] == "fixed"
    finally:
        led.close()


# ---------------------------------------------- the runner side of the deal ---


def test_ruff_reports_the_files_it_examined(tmp_path):
    (tmp_path / "bad.py").write_text("import os\ntry:\n    os.getcwd()\n"
                                     "except Exception:\n    pass\n", encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["bad.py"])
    res = ruff.run(ctx)

    assert res.state is ToolState.OK
    assert res.examined is not None, "ruff must report what it examined"
    assert "bad.py" in res.examined


def test_ruff_excluded_files_are_absent_from_examined(tmp_path):
    """The measured bug, at the runner boundary. ruff still exits 0 here, so
    `state` alone cannot tell the difference — `examined` is what carries it."""
    (tmp_path / "bad.py").write_text("import os\ntry:\n    os.getcwd()\n"
                                     "except Exception:\n    pass\n", encoding="utf-8")
    (tmp_path / "ruff.toml").write_text('exclude = ["bad.py"]\n', encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["bad.py"])
    res = ruff.run(ctx)

    assert res.state is ToolState.OK, "ruff exits 0 for an excluded path"
    assert res.examined == frozenset(), \
        f"ruff examined nothing but reported {res.examined!r}"


def test_ruff_with_no_python_in_scope_reports_an_empty_examined_set(tmp_path):
    """The no-op path returns OK without invoking ruff at all. It must still
    say it examined nothing, or the no-op is indistinguishable from a scan."""
    ctx = RunContext(root=tmp_path, files=["README.md"])
    res = ruff.run(ctx)

    assert res.state is ToolState.OK
    assert res.examined == frozenset()


def test_examined_defaults_to_none_for_runners_that_do_not_report():
    """Explicit: `None` means 'cannot vouch', and is NOT the same as the empty
    set. Only the empty set blocks resolution; None falls back."""
    from aramid.runners.base import RunnerResult

    assert RunnerResult("x", ToolState.OK).examined is None
