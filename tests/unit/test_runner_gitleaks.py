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


def test_full_history_sentinel_argv_uses_git_log_not_staged_fallback(tmp_path):
    """MUST-FIX 1 (final-review.md): `pipeline.FULL_HISTORY_RNG` ("") is a
    deliberately falsy-but-not-None sentinel `pipeline._discover_files` now
    hands back for range mode when there is no @{u}/origin/HEAD yet (a
    brand-new repo's first push, spec §3: "scan every commit reachable from
    HEAD"). `_build_argv` must branch on `ctx.rng is not None`, NOT
    truthiness -- pre-fix, `if ctx.rng:` treated "" exactly like None and
    fell back to `protect --staged`, which only sees the currently-staged
    diff and silently scans nothing on a clean working tree. An empty
    `--log-opts` value is itself gitleaks/`git log`'s own "no revision
    given -> walk everything reachable from HEAD" default."""
    ctx = RunContext(root=tmp_path, rng="")
    report_path = tmp_path / "report.json"
    argv = gitleaks._build_argv(ctx, report_path)
    assert argv[:2] == ["gitleaks", "git"]
    assert "--log-opts" in argv
    assert argv[argv.index("--log-opts") + 1] == ""
    assert "protect" not in argv
    assert "--staged" not in argv


def test_run_reads_back_the_report_file_gitleaks_wrote(tmp_path, monkeypatch):
    """gitleaks writes its report to a FILE path, not stdout -- run() must
    write to a temp file and read it back, never pass "-" as a stdout
    sentinel (that would create a literal file named "-")."""
    fixture_text = FIXTURE.read_text()

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        report_path = Path(argv[argv.index("--report-path") + 1])
        report_path.write_text(fixture_text)
        return RunnerResult(tool="gitleaks", state=ToolState.OK, raw="", stderr="",
                             duration_s=0.05, returncode=1)

    monkeypatch.setattr(gitleaks, "run_subprocess", fake_run_subprocess)

    ctx = RunContext(root=tmp_path)
    result = gitleaks.run(ctx)

    assert result.state is ToolState.OK
    findings = gitleaks.parse(result, ctx)
    assert len(findings) == 1
    assert findings[0].secret == "AKIAIOSFODNN7EXAMPLE"


def test_run_nonzero_exit_with_leaks_is_not_crashed(tmp_path, monkeypatch):
    """gitleaks exits 1 (its documented "leaks found" code) when it finds
    leaks -- that must be treated as OK, not CRASHED."""
    fixture_text = FIXTURE.read_text()

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        report_path = Path(argv[argv.index("--report-path") + 1])
        report_path.write_text(fixture_text)
        return RunnerResult(tool="gitleaks", state=ToolState.OK, raw="", stderr="",
                             duration_s=0.05, returncode=1)

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


def test_run_errored_before_report_written_is_crashed_not_clean(tmp_path, monkeypatch):
    """CRITICAL: gitleaks can error before writing a report at all (bad
    --log-opts range, not-a-git-repo, permission error, ...) -- the report
    file never exists, so text is "" and json.loads("[]") succeeds. Without
    checking the returncode, that reads as ToolState.OK with zero findings
    -- a broken BLOCK-tier secrets scanner would silently "pass". The real
    exit code (anything outside gitleaks' documented {0, 1}) must surface
    as CRASHED, never as a clean empty scan."""
    monkeypatch.setattr(
        gitleaks, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="gitleaks", state=ToolState.OK, raw="", stderr="fatal: not a git repository",
            duration_s=0.01, returncode=2),
    )
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.CRASHED
    # Even though state is CRASHED, parse() itself still yields zero
    # findings for a non-OK state -- proving why a future pipeline (Task
    # 5.3) MUST inspect RunnerResult.state directly and cannot rely on
    # parse() output alone to detect this failure.
    assert gitleaks.parse(result, RunContext(root=tmp_path)) == []


def test_run_clean_exit_with_missing_report_file_is_ok(tmp_path, monkeypatch):
    """Distinct from the CRASHED case above: if gitleaks exits with its
    documented "no leaks" code (0) but happens to write nothing, that is
    still a clean run -- treat as []. The discriminator is the returncode,
    not merely "was there a report file"."""
    monkeypatch.setattr(
        gitleaks, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="gitleaks", state=ToolState.OK, raw="", stderr="", duration_s=0.01, returncode=0),
    )
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.OK
    assert gitleaks.parse(result, RunContext(root=tmp_path)) == []
