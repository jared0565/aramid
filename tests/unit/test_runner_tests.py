import time
from pathlib import Path

import pytest

from aramid.runners import tests as tests_runner
from aramid.runners.base import RunContext, RunnerResult, ToolState


def test_parse_zero_exit_is_no_findings():
    result = RunnerResult(tool="pytest", state=ToolState.OK, raw="5 passed in 0.12s\n", returncode=0)
    assert tests_runner.parse(result, RunContext(root=Path("."))) == []


def test_parse_nonzero_exit_is_single_tests_failed_finding():
    result = RunnerResult(tool="pytest", state=ToolState.OK,
                           raw="=== 2 failed, 3 passed in 0.45s ===\n", returncode=1)
    findings = tests_runner.parse(result, RunContext(root=Path(".")))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "tests-failed"
    assert f.tool == "pytest"


def test_parse_npm_test_nonzero_is_single_finding():
    result = RunnerResult(tool="npm", state=ToolState.OK, raw="npm ERR! Test failed\n", returncode=1)
    findings = tests_runner.parse(result, RunContext(root=Path(".")))
    assert len(findings) == 1
    assert findings[0].rule == "tests-failed"


def test_parse_skips_non_ok_state():
    """A bare top-level MISSING (single-suite `run_pytest`/`run_npm_test`,
    or run_custom's empty-argv case) stays a silent skip, UNCHANGED --
    the tests-tool-missing finding (review B4, below) is deliberately
    scoped to a dual-suite aggregate's sub-result only (`parse()`'s
    private `_sub` flag), never a top-level call: the degraded-tool path
    a top-level MISSING already takes (pipeline.run_gate's
    degraded_block_tier / --accept-degraded) has its own correct escape
    hatch that a BLOCK finding here would short-circuit past."""
    result = RunnerResult(tool="pytest", state=ToolState.MISSING)
    assert tests_runner.parse(result, RunContext(root=Path("."))) == []


def test_parse_timeout_is_blocking_finding_not_silent_pass():
    """CRITICAL: a hung test suite must not read as a passing empty result
    just because there's no exit code to check. Tests is a BLOCK-tier
    check (design doc §3) -- TIMEOUT has to produce the same blocking
    tests-failed finding as a non-zero exit, never zero findings."""
    result = RunnerResult(tool="pytest", state=ToolState.TIMEOUT)
    findings = tests_runner.parse(result, RunContext(root=Path(".")))
    assert len(findings) == 1
    assert findings[0].rule == "tests-failed"
    assert findings[0].tool == "pytest"


def test_parse_crashed_is_blocking_finding_not_silent_pass():
    result = RunnerResult(tool="npm", state=ToolState.CRASHED)
    findings = tests_runner.parse(result, RunContext(root=Path(".")))
    assert len(findings) == 1
    assert findings[0].rule == "tests-failed"


def test_run_pytest_argv(tmp_path, monkeypatch):
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="pytest", state=ToolState.OK, raw="1 passed\n", returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", fake_run_subprocess)
    result = tests_runner.run_pytest(RunContext(root=tmp_path))
    assert captured["argv"] == ["pytest", "-q"]
    assert result.state is ToolState.OK
    assert result.returncode == 0


def test_run_npm_test_argv(tmp_path, monkeypatch):
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="npm", state=ToolState.OK, raw="", returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", fake_run_subprocess)
    tests_runner.run_npm_test(RunContext(root=tmp_path))
    assert captured["argv"] == ["npm", "test"]


def test_run_dispatches_pytest_when_detected(tmp_path, monkeypatch):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_x(): pass\n")
    monkeypatch.setattr(
        tests_runner, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="pytest", state=ToolState.OK, raw="", returncode=0),
    )
    result = tests_runner.run(RunContext(root=tmp_path))
    assert result.tool == "pytest"


def test_run_dispatches_npm_when_test_script_defined(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text('{"scripts": {"test": "jest"}}')
    monkeypatch.setattr(
        tests_runner, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="npm", state=ToolState.OK, raw="", returncode=0),
    )
    result = tests_runner.run(RunContext(root=tmp_path))
    assert result.tool == "npm"


def test_run_missing_when_no_tests_detected(tmp_path):
    result = tests_runner.run(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING


def test_end_to_end_nonzero_exit_produces_block_worthy_finding(tmp_path, monkeypatch):
    """The whole point of this adapter: a failing suite must yield exactly
    one actionable finding, not silence and not a pile of unparsed noise."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_x(): assert False\n")
    monkeypatch.setattr(
        tests_runner, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="pytest", state=ToolState.OK, raw="1 failed in 0.01s\n", returncode=1),
    )
    ctx = RunContext(root=tmp_path)
    result = tests_runner.run(ctx)
    findings = tests_runner.parse(result, ctx)
    assert [f.rule for f in findings] == ["tests-failed"]


# ------------------------------------------- [tests] config: custom command --

def _spy(monkeypatch, tool="pytest", **result_kw):
    """Capture the argv/timeout the runner hands to run_subprocess."""
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        captured["timeout_s"] = timeout_s
        return RunnerResult(tool=tool, state=ToolState.OK,
                             returncode=result_kw.get("returncode", 0))

    monkeypatch.setattr(tests_runner, "run_subprocess", fake_run_subprocess)
    return captured


def test_custom_command_string_is_split_into_argv(tmp_path, monkeypatch):
    captured = _spy(monkeypatch)
    tests_runner.run(RunContext(root=tmp_path, test_command="pytest -q tests/unit"))
    assert captured["argv"] == ["pytest", "-q", "tests/unit"]


def test_custom_command_list_is_taken_verbatim(tmp_path, monkeypatch):
    """The argv form sidesteps shell quoting entirely -- the reason it
    exists is that `shlex.split` eats backslashes, so a Windows path in a
    string command would silently lose its separators."""
    captured = _spy(monkeypatch)
    argv = ["pytest", "-q", r"tests\unit"]
    tests_runner.run(RunContext(root=tmp_path, test_command=list(argv)))
    assert captured["argv"] == argv


def test_custom_command_wins_over_detected_pytest(tmp_path, monkeypatch):
    """An explicitly configured command is the repo's answer -- detection
    must not override it."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_x(): pass\n")
    captured = _spy(monkeypatch)
    tests_runner.run(RunContext(root=tmp_path, test_command="make test"))
    assert captured["argv"] == ["make", "test"]


def test_blank_custom_command_is_missing_not_a_silent_pass(tmp_path, monkeypatch):
    """A command that parses to no argv at all is a misconfiguration. It
    must degrade (MISSING -> BLOCK-tier escalation at pre-push), never
    quietly resolve to "no findings"."""
    _spy(monkeypatch)
    result = tests_runner.run(RunContext(root=tmp_path, test_command="   "))
    assert result.state is ToolState.MISSING


def test_timeout_comes_from_the_context_when_configured(tmp_path, monkeypatch):
    # A real test file, not a bare dir (Task 1) -- run() only reaches
    # run_subprocess (and thus the spy) when detect_tests() finds a suite.
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_x(): pass\n")
    captured = _spy(monkeypatch)
    tests_runner.run(RunContext(root=tmp_path, test_timeout_s=42.0))
    assert captured["timeout_s"] == 42.0


def test_timeout_falls_back_to_the_module_default_when_unset(tmp_path, monkeypatch):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_x(): pass\n")
    captured = _spy(monkeypatch)
    tests_runner.run(RunContext(root=tmp_path))
    assert captured["timeout_s"] == tests_runner.TIMEOUT_S


def test_custom_command_also_honors_the_configured_timeout(tmp_path, monkeypatch):
    captured = _spy(monkeypatch)
    tests_runner.run(RunContext(root=tmp_path, test_command="make test",
                                 test_timeout_s=7.5))
    assert captured["timeout_s"] == 7.5


# --------------------------------------------- rc 5: no tests were collected -

def test_pytest_rc5_still_blocks_but_says_no_tests_collected(tmp_path):
    """A selector matching nothing is a vacuous gate, not a pass -- rc 5
    stays a blocking `tests-failed`. Only the wording differs, so a repo
    whose `[tests].command` selector went stale can tell that apart from a
    genuine failure."""
    result = RunnerResult(tool="pytest", state=ToolState.OK, returncode=5)
    findings = tests_runner.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "tests-failed"
    assert "no tests" in findings[0].message.lower()


def test_rc5_from_a_non_pytest_command_keeps_the_generic_wording(tmp_path):
    """rc 5 is pytest's "no tests collected"; from `npm test` or a custom
    `make test` it means whatever that tool says it means -- claiming "no
    tests collected" there would be an invented fact."""
    result = RunnerResult(tool="make", state=ToolState.OK, returncode=5)
    findings = tests_runner.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    assert "no tests" not in findings[0].message.lower()
    assert "exited 5" in findings[0].message


# ------------------------------------- dual-stack: run BOTH suites (Task 3) --

def _dual_repo(tmp_path, lockfile: str | None = "package-lock.json"):
    """A dual-stack repo: a real Python test file (Task 1's pytest signal)
    plus a package.json test script (its npm signal). `lockfile` names the
    JS lockfile to also create, or None to leave the repo without one --
    the C1/B1 boundary that decides whether npm is promoted to a real
    second suite (see runners/tests.py module docstring)."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_x.py").write_text("def test_x(): assert True\n")
    (tmp_path / "package.json").write_text('{"scripts": {"test": "vitest"}}')
    if lockfile:
        (tmp_path / lockfile).write_text("{}")
    return tmp_path


def _tracking_ok_fake(calls: list):
    """A fake run_subprocess that records (argv[0], timeout_s) and reports
    every suite as a clean pass."""
    def fake(argv, cwd, timeout_s, env=None):
        calls.append((argv[0], timeout_s))
        return RunnerResult(tool=argv[0], state=ToolState.OK, returncode=0)
    return fake


def test_dual_stack_both_ok_aggregates_with_two_sub_results(tmp_path, monkeypatch):
    _dual_repo(tmp_path)
    monkeypatch.setattr(tests_runner, "run_subprocess", _tracking_ok_fake([]))
    result = tests_runner.run(RunContext(root=tmp_path))
    assert result.tool == "tests"
    assert result.state is ToolState.OK
    assert [r.tool for r in result.sub_results] == ["pytest", "npm"]


def test_dual_stack_pytest_ok_npm_missing_is_not_ok_aggregate(tmp_path, monkeypatch):
    """[review C2] The inverted-rule regression test: pytest OK + npm
    MISSING -> aggregate NOT OK. ("pytest OK + npm FAILING" is
    unimplementable here: a failing suite is OK + rc!=0, so under a
    CORRECT worst-wins rule both subs are OK and the aggregate would be OK
    too -- MISSING is the only clean discriminator against
    deps._run_mixed's OR rule, which would call `py=OK, js=MISSING` -> OK.)
    Also pins [review B4]: the MISSING sub-result must still surface as an
    explicit tests-tool-missing finding, not silently vanish."""
    _dual_repo(tmp_path)

    def fake(argv, cwd, timeout_s, env=None):
        if argv[0] == "pytest":
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        return RunnerResult(tool="npm", state=ToolState.MISSING)

    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    ctx = RunContext(root=tmp_path)
    result = tests_runner.run(ctx)
    assert result.state is not ToolState.OK
    assert result.state is ToolState.MISSING

    findings = tests_runner.parse(result, ctx)
    assert len(findings) == 1
    assert findings[0].tool == "tests"
    assert findings[0].rule == tests_runner.TOOL_MISSING_RULE


def test_dual_stack_state_picks_first_sub_bad_state_when_both_bad(tmp_path, monkeypatch):
    """[review M2] When BOTH subs are non-OK, the aggregate takes the
    FIRST (pytest, per the fixed pytest-then-npm `.sub_results` order) bad
    state, never npm's -- ToolState has no "worst" ranking to fall back
    on, only OK-vs-not-OK is ever consulted downstream."""
    _dual_repo(tmp_path)

    def fake(argv, cwd, timeout_s, env=None):
        if argv[0] == "pytest":
            return RunnerResult(tool="pytest", state=ToolState.TIMEOUT)
        return RunnerResult(tool="npm", state=ToolState.MISSING)

    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    result = tests_runner.run(RunContext(root=tmp_path))
    assert result.state is ToolState.TIMEOUT   # pytest's (first) bad state, not npm's MISSING


def test_dual_stack_pytest_failing_npm_ok_aggregate_is_ok_with_tests_failed_finding(
        tmp_path, monkeypatch):
    """Pins Constraint 4 from the other side: a FAILING suite (rc != 0) is
    still ToolState.OK (the subprocess completed) -- the aggregate must
    read OK, and the failure must surface only via the tests-failed
    finding, never via the aggregate STATE (folding returncode into the
    state rule would yield degraded_block_tier=True with an empty
    degraded list -- a test failure misreported as tool degradation)."""
    _dual_repo(tmp_path)

    def fake(argv, cwd, timeout_s, env=None):
        if argv[0] == "pytest":
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=1,
                                 raw="1 failed\n")
        return RunnerResult(tool="npm", state=ToolState.OK, returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    ctx = RunContext(root=tmp_path)
    result = tests_runner.run(ctx)
    assert result.state is ToolState.OK

    findings = tests_runner.parse(result, ctx)
    assert len(findings) == 1
    assert findings[0].tool == "pytest"
    assert findings[0].rule == "tests-failed"


def test_dual_stack_both_fail_produces_findings_from_both_suites(tmp_path, monkeypatch):
    """Neither suite's failure may hide the other's."""
    _dual_repo(tmp_path)

    def fake(argv, cwd, timeout_s, env=None):
        return RunnerResult(tool=argv[0], state=ToolState.OK, returncode=1, raw="failed\n")

    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    ctx = RunContext(root=tmp_path)
    result = tests_runner.run(ctx)
    findings = tests_runner.parse(result, ctx)
    assert {f.tool for f in findings} == {"pytest", "npm"}
    assert all(f.rule == "tests-failed" for f in findings)


def test_dual_stack_one_missing_one_failing_still_returns_the_failing_subs_finding(
        tmp_path, monkeypatch):
    """[review I4] The recursion-order regression test. Under worst-wins
    the aggregate STATE here is MISSING (pytest, the first sub, is not
    OK) -- if `parse()`'s sub_results recursion were placed AFTER the
    `state is MISSING -> []` guard instead of before it, this would
    return [] and silently drop npm's real tests-failed finding too (the
    push would still exit 1 via degraded_block_tier, hiding the bug behind
    a correct exit code). Without this test I4 ships silently."""
    _dual_repo(tmp_path)

    def fake(argv, cwd, timeout_s, env=None):
        if argv[0] == "pytest":
            return RunnerResult(tool="pytest", state=ToolState.MISSING)
        return RunnerResult(tool="npm", state=ToolState.OK, returncode=1, raw="failed\n")

    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    ctx = RunContext(root=tmp_path)
    result = tests_runner.run(ctx)
    assert result.state is ToolState.MISSING

    findings = tests_runner.parse(result, ctx)
    # Two findings, neither hidden by the other: pytest's MISSING sub
    # reports tool="tests" (B4 -- never the sub-tool's own name), so this
    # dict is keyed by rule instead of assuming a "pytest" tool that the
    # missing-tool finding deliberately does not carry.
    assert len(findings) == 2
    rules = sorted(f.rule for f in findings)
    assert rules == sorted([tests_runner.TOOL_MISSING_RULE, "tests-failed"])
    npm_finding = next(f for f in findings if f.rule == "tests-failed")
    assert npm_finding.tool == "npm"   # npm's real failure, preserved


def test_single_suite_repo_produces_no_sub_results_attribute(tmp_path, monkeypatch):
    """No behaviour change when only ONE suite is detected: the existing
    single-result path is taken, and NO `sub_results` attribute is
    produced at all -- not even `None` -- matching every other
    single-kind repo."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_x(): pass\n")
    monkeypatch.setattr(tests_runner, "run_subprocess", _tracking_ok_fake([]))
    result = tests_runner.run(RunContext(root=tmp_path))
    assert result.tool == "pytest"
    assert not hasattr(result, "sub_results")


def test_explicit_command_wins_on_dual_stack_repo_neither_suite_auto_runs(tmp_path, monkeypatch):
    """An explicit `[tests].command` still wins and short-circuits before
    any detection -- even on a dual-stack repo with a real lockfile, where
    both suites are otherwise auto-detectable."""
    _dual_repo(tmp_path)
    calls: list = []
    monkeypatch.setattr(tests_runner, "run_subprocess", _tracking_ok_fake(calls))
    result = tests_runner.run(RunContext(root=tmp_path, test_command="make test"))
    assert result.tool == "make"
    assert [argv0 for argv0, _ in calls] == ["make"]   # neither pytest nor npm ran


def test_rc5_from_pytest_sub_result_keeps_the_no_tests_collected_wording(tmp_path):
    """The existing rc-5 special-casing must still apply correctly when
    `parse()` recurses into a sub-result, not only at the top level."""
    combined = RunnerResult("tests", ToolState.OK)
    combined.sub_results = [
        RunnerResult(tool="pytest", state=ToolState.OK, returncode=5),
        RunnerResult(tool="npm", state=ToolState.OK, returncode=0),
    ]
    findings = tests_runner.parse(combined, RunContext(root=tmp_path))
    assert len(findings) == 1
    assert findings[0].tool == "pytest"
    assert "no tests" in findings[0].message.lower()


def test_dual_stack_no_lockfile_runs_pytest_only_single_result_with_notice(
        tmp_path, monkeypatch, capsys):
    """[C1/B1 boundary] Both kinds detected but NO JS lockfile: pytest
    runs, npm does NOT, a single (non-aggregate) result is returned, and
    the skipped-suite notice fires. Without this test the lockfile gate is
    unpinned."""
    _dual_repo(tmp_path, lockfile=None)
    calls: list = []
    monkeypatch.setattr(tests_runner, "run_subprocess", _tracking_ok_fake(calls))
    result = tests_runner.run(RunContext(root=tmp_path))
    assert result.tool == "pytest"
    assert not hasattr(result, "sub_results")
    assert [argv0 for argv0, _ in calls] == ["pytest"]   # npm never ran
    assert "lockfile" in capsys.readouterr().err.lower()


def test_js_only_repo_with_no_lockfile_still_runs_npm_test(tmp_path, monkeypatch):
    """[B1 regression] A JS-ONLY repo (no Python side detected at all)
    with no lockfile still runs `npm test` via the single-suite path --
    the lockfile gate only guards PROMOTING a detected npm suite to a
    second concurrent suite alongside an already-detected pytest one,
    never the single-suite dispatch. Proves the gate wasn't deleted."""
    (tmp_path / "package.json").write_text('{"scripts": {"test": "vitest"}}')
    calls: list = []
    monkeypatch.setattr(tests_runner, "run_subprocess", _tracking_ok_fake(calls))
    result = tests_runner.run(RunContext(root=tmp_path))
    assert result.tool == "npm"
    assert [argv0 for argv0, _ in calls] == ["npm"]


# --------------------------------------- dual-stack: shared deadline (B2) ----

def test_shared_budget_caps_the_second_suites_timeout(tmp_path, monkeypatch):
    """[review B2] The two suites share ONE deadline: the SECOND suite's
    timeout is `remaining_budget`, not its own independent full timeout --
    proven by a real (small) sleep in the first suite eating into the
    budget the second suite is then handed."""
    _dual_repo(tmp_path)
    captured: list = []

    def fake(argv, cwd, timeout_s, env=None):
        captured.append((argv[0], timeout_s))
        if argv[0] == "pytest":
            time.sleep(0.2)
        return RunnerResult(tool=argv[0], state=ToolState.OK, returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    ctx = RunContext(root=tmp_path, gate_budget_s=0.5)
    tests_runner.run(ctx)

    assert captured[0][0] == "pytest"
    assert captured[0][1] == pytest.approx(0.5, abs=0.05)   # ~full shared budget
    assert captured[1][0] == "npm"
    # Budget minus ~0.2s pytest already spent -- a wide band (not a tight
    # pytest.approx) because real sleep() can overshoot under scheduler
    # jitter; still comfortably separates "capped by remaining" from
    # either the full 300s per-tool default or a fresh 0.5s budget.
    assert 0.05 < captured[1][1] < 0.45


def test_budget_exhausted_after_first_suite_skips_second_but_keeps_first_result(
        tmp_path, monkeypatch):
    """[review B2] Two suites whose combined runtime exceeds the budget
    still produce the completed suite's findings, and the second suite's
    timeout is attributed to THAT suite, not to the pipeline slot -- the
    aggregate reports what it learned instead of the whole slot being
    replaced by a bare TIMEOUT with the first suite's real result gone."""
    _dual_repo(tmp_path)

    def fake(argv, cwd, timeout_s, env=None):
        if argv[0] == "pytest":
            time.sleep(0.3)
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=1,
                                 raw="1 failed\n")
        pytest.fail("npm must not run at all once the shared budget is exhausted")

    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    ctx = RunContext(root=tmp_path, gate_budget_s=0.2)
    result = tests_runner.run(ctx)

    subs = {r.tool: r for r in result.sub_results}
    assert subs["pytest"].returncode == 1
    assert subs["npm"].state is ToolState.TIMEOUT

    findings = {f.tool: f.rule for f in tests_runner.parse(result, ctx)}
    assert findings["pytest"] == "tests-failed"   # first suite's real failure preserved
    assert findings["npm"] == "tests-failed"        # attributed to npm's OWN timeout, not the slot
