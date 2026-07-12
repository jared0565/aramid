import json
from pathlib import Path

import pytest

from aramid.runners import gitleaks
from aramid.runners.base import RunContext, RunnerResult, ToolState

FIXTURE = Path(__file__).parent.parent / "fixtures" / "gitleaks.json"


def test_parse_fixture_produces_finding_with_secret():
    result = RunnerResult(tool="gitleaks", state=ToolState.OK, raw=FIXTURE.read_text())
    ctx = RunContext(root=Path("."))

    findings = gitleaks.parse(result, ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "gitleaks"
    assert f.rule == "aws-access-token"
    assert f.file == "src/config.py"
    assert f.line == 3
    assert f.secret == "AKIAIOSFODNN7EXAMPLE"


def test_parse_empty_report_is_no_findings():
    result = RunnerResult(tool="gitleaks", state=ToolState.OK, raw="[]")
    assert gitleaks.parse(result, RunContext(root=Path("."))) == []


def test_parse_skips_non_ok_state():
    result = RunnerResult(tool="gitleaks", state=ToolState.MISSING)
    assert gitleaks.parse(result, RunContext(root=Path("."))) == []


def test_staged_argv_uses_protect_staged(tmp_path):
    ctx = RunContext(root=tmp_path)
    report_path = tmp_path / "report.json"
    argv = gitleaks._build_argv(ctx, report_path)
    assert argv[:3] == ["gitleaks", "protect", "--staged"]
    assert "--report-format" in argv and "json" in argv
    assert "--report-path" in argv and str(report_path) in argv
    assert "-" not in argv  # never pass "-" as a report-path sentinel


def test_range_argv_uses_git_log_opts(tmp_path):
    ctx = RunContext(root=tmp_path, rng="HEAD~5..HEAD")
    report_path = tmp_path / "report.json"
    argv = gitleaks._build_argv(ctx, report_path)
    assert argv[:2] == ["gitleaks", "git"]
    assert "--log-opts" in argv
    assert argv[argv.index("--log-opts") + 1] == "HEAD~5..HEAD"
    assert "--report-path" in argv and str(report_path) in argv


def test_run_reads_back_the_report_file_gitleaks_wrote(tmp_path, monkeypatch):
    """gitleaks writes its report to a FILE path, not stdout -- run() must
    write to a temp file and read it back, never pass "-" as a stdout
    sentinel (that would create a literal file named "-")."""
    fixture_text = FIXTURE.read_text()

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        report_path = Path(argv[argv.index("--report-path") + 1])
        report_path.write_text(fixture_text)
        return RunnerResult(tool="gitleaks", state=ToolState.OK, raw="", stderr="", duration_s=0.05)

    monkeypatch.setattr(gitleaks, "run_subprocess", fake_run_subprocess)

    ctx = RunContext(root=tmp_path)
    result = gitleaks.run(ctx)

    assert result.state is ToolState.OK
    findings = gitleaks.parse(result, ctx)
    assert len(findings) == 1
    assert findings[0].secret == "AKIAIOSFODNN7EXAMPLE"


def test_run_nonzero_exit_with_leaks_is_not_crashed(tmp_path, monkeypatch):
    """gitleaks exits non-zero when it finds leaks -- run_subprocess never
    surfaces the exit code, so this is really just re-confirming that a
    normally-populated report is treated as OK, not CRASHED."""
    fixture_text = FIXTURE.read_text()

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        report_path = Path(argv[argv.index("--report-path") + 1])
        report_path.write_text(fixture_text)
        return RunnerResult(tool="gitleaks", state=ToolState.OK, raw="", stderr="", duration_s=0.05)

    monkeypatch.setattr(gitleaks, "run_subprocess", fake_run_subprocess)
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.OK


def test_run_missing_binary_passes_through(tmp_path, monkeypatch):
    monkeypatch.setattr(
        gitleaks, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="gitleaks", state=ToolState.MISSING),
    )
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING


def test_run_unparseable_report_is_crashed(tmp_path, monkeypatch):
    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        report_path = Path(argv[argv.index("--report-path") + 1])
        report_path.write_text("not json{{{")
        return RunnerResult(tool="gitleaks", state=ToolState.OK, raw="", stderr="boom", duration_s=0.01)

    monkeypatch.setattr(gitleaks, "run_subprocess", fake_run_subprocess)
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.CRASHED


def test_run_missing_report_file_treated_as_no_leaks(tmp_path, monkeypatch):
    """If gitleaks exits clean and writes nothing (no leaks case for some
    versions), reading back an absent file must not crash -- treat as []."""
    monkeypatch.setattr(
        gitleaks, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="gitleaks", state=ToolState.OK, raw="", stderr="", duration_s=0.01),
    )
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.OK
    assert gitleaks.parse(result, RunContext(root=tmp_path)) == []
