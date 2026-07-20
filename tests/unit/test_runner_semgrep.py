import json
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


def test_parse_normalizes_live_prefixed_check_id_to_canonical_rule_id():
    """Task 81b regression test. Real semgrep (observed LIVE, v1.169.0
    against this repo's own vendored config at
    src/aramid/rules/owasp.yml) does not report the bare rule `id:` as
    `check_id` -- it prefixes it with the `--config` file's *directory*
    path, dot-joined (drive letter and every path separator become '.'):

        F.Projects.aramid.src.aramid.rules.owasp-top-ten.a03-injection.python-sqli-string-concat

    for the vendored rule whose `id:` in owasp.yml is
    `owasp-top-ten.a03-injection.python-sqli-string-concat`.
    block_rules.toml's `[semgrep] block` list matches rule ids with the
    fnmatch pattern "owasp-top-ten.*", which anchors at the START of the
    string -- against the raw, prefixed check_id above it NEVER matches,
    so `parse()` must normalize `check_id` back to the canonical form
    before it becomes RawFinding.rule."""
    raw_check_id = (
        "F.Projects.aramid.src.aramid.rules."
        "owasp-top-ten.a03-injection.python-sqli-string-concat"
    )
    raw_json = json.dumps({
        "errors": [],
        "results": [{
            "check_id": raw_check_id,
            "path": "vuln.py",
            "start": {"line": 2, "col": 1, "offset": 0},
            "end": {"line": 2, "col": 60, "offset": 60},
            "extra": {
                "message": "SQL injection via string concatenation.",
                "severity": "ERROR",
            },
        }],
    })
    result = RunnerResult(tool="semgrep", state=ToolState.OK, raw=raw_json)
    ctx = RunContext(root=Path("."), files=["vuln.py"])

    findings = semgrep.parse(result, ctx)

    assert len(findings) == 1
    assert findings[0].rule == "owasp-top-ten.a03-injection.python-sqli-string-concat"


def test_parse_leaves_non_vendored_check_id_unchanged():
    """Fallback path: a check_id with no 'owasp-top-ten.' substring at all
    (a future non-vendored/registry rule) has no vendored-config prefix to
    strip, so it passes through unchanged -- exactly today's fixture,
    which is a real (non-vendored) semgrep registry rule id."""
    findings = semgrep.parse(
        RunnerResult(tool="semgrep", state=ToolState.OK, raw=FIXTURE.read_text()),
        RunContext(root=Path("."), files=["app.py"]),
    )
    assert findings[0].rule == "python.lang.security.audit.exec-detected.exec-detected"


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


def test_argv_includes_extra_configs(tmp_path):
    ctx = RunContext(root=tmp_path, files=["a.py"],
                     extra_semgrep_configs=(str(tmp_path / "regression.yml"),))
    argv = semgrep._build_argv(ctx)
    assert argv.count("--config") == 2
    assert str(tmp_path / "regression.yml") in argv


def test_canonical_rule_id_strips_prefix_for_pack_rules():
    live = "repo.aramid-rules.regression.aramid-regression.block.deadbeef"
    assert semgrep._canonical_rule_id(live) == "aramid-regression.block.deadbeef"
    # owasp behavior unchanged
    assert semgrep._canonical_rule_id("x.y.owasp-top-ten.a01") == "owasp-top-ten.a01"


def test_run_empty_output_with_error_returncode_is_crashed(tmp_path, monkeypatch):
    """CRITICAL: empty stdout parses fine as '{}' -- without a returncode
    check this would silently read as a clean 'zero findings' run even
    though semgrep exited 2 (its documented fatal-error code, e.g. a bad
    --config) before producing a report. A broken BLOCK-tier SAST scanner
    must not silently 'pass'."""
    monkeypatch.setattr(
        semgrep, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="semgrep", state=ToolState.OK, raw="", stderr="invalid config", returncode=2),
    )
    result = semgrep.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.CRASHED


def test_canonical_rule_id_uses_rightmost_prefix_occurrence():
    from aramid.runners.semgrep import _CANONICAL_RULE_PREFIX, _canonical_rule_id
    # A checkout path that itself embeds the literal prefix must not truncate
    # the id early -- the REAL canonical id is the rightmost occurrence.
    cid = f"/src/{_CANONICAL_RULE_PREFIX}junk/config/{_CANONICAL_RULE_PREFIX}sqli"
    assert _canonical_rule_id(cid) == f"{_CANONICAL_RULE_PREFIX}sqli"
