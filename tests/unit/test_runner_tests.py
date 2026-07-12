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
