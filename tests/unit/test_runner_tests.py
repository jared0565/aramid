from pathlib import Path

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
