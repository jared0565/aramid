from pathlib import Path

from aramid.runners import semgrep
from aramid.runners.base import RunContext, RunnerResult, ToolState

FIXTURE = Path(__file__).parent.parent / "fixtures" / "semgrep.json"


def test_parse_fixture_yields_finding():
    result = RunnerResult(tool="semgrep", state=ToolState.OK, raw=FIXTURE.read_text())
    ctx = RunContext(root=Path("."), files=["app.py"])

    findings = semgrep.parse(result, ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "semgrep"
    assert f.rule == "python.lang.security.audit.exec-detected.exec-detected"
    assert f.file == "app.py"
    assert f.line == 3
    assert f.severity_raw == "ERROR"
    assert "exec" in f.message


def test_parse_no_results_is_empty():
    result = RunnerResult(tool="semgrep", state=ToolState.OK, raw='{"results": [], "errors": []}')
    assert semgrep.parse(result, RunContext(root=Path("."))) == []


def test_parse_skips_non_ok_state():
    result = RunnerResult(tool="semgrep", state=ToolState.MISSING)
    assert semgrep.parse(result, RunContext(root=Path("."))) == []


def test_argv_uses_vendored_config_and_offline_flags(tmp_path):
    ctx = RunContext(root=tmp_path, files=["app.py"])
    argv = semgrep._build_argv(ctx)
    assert argv[0] == "semgrep"
    assert "--config" in argv
    assert argv[argv.index("--config") + 1] == str(semgrep.VENDORED_RULES_PATH)
    assert "--json" in argv
    assert "--metrics=off" in argv
    assert "--quiet" in argv
    sep = argv.index("--")
    assert argv[sep + 1:] == ["app.py"]


def test_run_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(
        semgrep, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="semgrep", state=ToolState.MISSING),
    )
    result = semgrep.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.MISSING


def test_run_ok_roundtrips_fixture(tmp_path, monkeypatch):
    fixture_text = FIXTURE.read_text()
    monkeypatch.setattr(
        semgrep, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="semgrep", state=ToolState.OK, raw=fixture_text),
    )
    ctx = RunContext(root=tmp_path, files=["app.py"])
    result = semgrep.run(ctx)
    assert result.state is ToolState.OK
    findings = semgrep.parse(result, ctx)
    assert findings[0].rule.endswith("exec-detected")


def test_run_unparseable_output_is_crashed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        semgrep, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="semgrep", state=ToolState.OK, raw="not json", stderr="boom"),
    )
    result = semgrep.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.CRASHED
