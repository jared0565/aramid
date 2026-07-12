from pathlib import Path

from aramid.runners import ruff
from aramid.runners.base import RunContext, RunnerResult, ToolState

FIXTURE = Path(__file__).parent.parent / "fixtures" / "ruff.json"


def test_parse_fixture_yields_s_rule_finding():
    """A no-ruff-config repo containing `exec(x)` must still produce an S102
    finding -- proves aramid enforces the security (S) family itself via
    --extend-select, independent of the target repo's own ruff config."""
    result = RunnerResult(tool="ruff", state=ToolState.OK, raw=FIXTURE.read_text())
    ctx = RunContext(root=Path("."), files=["app.py"])

    findings = ruff.parse(result, ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "ruff"
    assert f.rule == "S102"
    assert f.file == "app.py"
    assert f.line == 3
    assert f.severity_raw == "error"
    assert "exec" in f.message


def test_parse_empty_is_no_findings():
    result = RunnerResult(tool="ruff", state=ToolState.OK, raw="[]")
    assert ruff.parse(result, RunContext(root=Path("."))) == []


def test_parse_skips_non_ok_state():
    result = RunnerResult(tool="ruff", state=ToolState.CRASHED)
    assert ruff.parse(result, RunContext(root=Path("."))) == []


def test_argv_mandates_extend_select_s(tmp_path):
    """--extend-select S is mandatory: ruff's default rule set excludes the
    bandit-derived S family, so without this flag the security rules never
    fire regardless of the target repo's own config."""
    ctx = RunContext(root=tmp_path, files=["app.py", "b.py"])
    argv = ruff._build_argv(ctx)
    assert argv[0] == "ruff"
    assert argv[1] == "check"
    assert "--output-format" in argv and argv[argv.index("--output-format") + 1] == "json"
    assert "--force-exclude" in argv
    assert "--extend-select" in argv and argv[argv.index("--extend-select") + 1] == "S"
    assert argv[-2:] == ["app.py", "b.py"] or "--" in argv
    sep = argv.index("--")
    assert argv[sep + 1:] == ["app.py", "b.py"]


def test_argv_filters_to_python_files_only(tmp_path):
    """ctx.files is the gate's WHOLE file set; ruff parses whatever explicit
    paths it is handed as Python, so non-.py files (YAML, templates, ...)
    must never reach its argv -- live-CI bug: 958 invalid-syntax findings
    from owasp.yml / ARAMID.md.tmpl / the workflow YAML."""
    ctx = RunContext(root=tmp_path, files=[
        "app.py", "rules/owasp.yml", "data/ARAMID.md.tmpl",
        ".github/workflows/aramid.yml", "typed.pyi", "README.md",
    ])
    argv = ruff._build_argv(ctx)
    sep = argv.index("--")
    assert argv[sep + 1:] == ["app.py", "typed.pyi"]


def test_run_no_python_files_is_clean_noop(tmp_path, monkeypatch):
    """Zero paths after filtering must NOT invoke ruff at all -- ruff given
    no explicit paths falls back to scanning the whole cwd."""
    def _boom(*a, **k):
        raise AssertionError("run_subprocess must not be called")
    monkeypatch.setattr(ruff, "run_subprocess", _boom)
    result = ruff.run(RunContext(root=tmp_path, files=["rules/owasp.yml", "README.md"]))
    assert result.state is ToolState.OK
    assert ruff.parse(result, RunContext(root=tmp_path)) == []


def test_run_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(
        ruff, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="ruff", state=ToolState.MISSING),
    )
    result = ruff.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.MISSING


def test_run_ok_roundtrips_fixture(tmp_path, monkeypatch):
    fixture_text = FIXTURE.read_text()
    monkeypatch.setattr(
        ruff, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="ruff", state=ToolState.OK, raw=fixture_text),
    )
    ctx = RunContext(root=tmp_path, files=["app.py"])
    result = ruff.run(ctx)
    assert result.state is ToolState.OK
    findings = ruff.parse(result, ctx)
    assert findings[0].rule == "S102"


def test_run_unparseable_output_is_crashed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        ruff, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="ruff", state=ToolState.OK, raw="not json", stderr="boom"),
    )
    result = ruff.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.CRASHED


def test_run_empty_output_with_error_returncode_is_crashed(tmp_path, monkeypatch):
    """Empty stdout parses fine as '[]' -- without a returncode check this
    would silently read as a clean 'zero findings' run even though ruff
    errored (bad args, internal error, ...) with a returncode outside its
    documented {0, 1}."""
    monkeypatch.setattr(
        ruff, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="ruff", state=ToolState.OK, raw="", stderr="error: bad argument", returncode=2),
    )
    result = ruff.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.CRASHED
