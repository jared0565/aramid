import json
import os
import time
from pathlib import Path

from aramid.runners import deps
from aramid.runners.base import RunContext, RunnerResult, ToolState

FIXTURES = Path(__file__).parent.parent / "fixtures"
PIP_AUDIT = FIXTURES / "pip-audit.json"
NPM_AUDIT = FIXTURES / "npm-audit.json"
PNPM_AUDIT = FIXTURES / "pnpm-audit.json"
YARN_AUDIT = FIXTURES / "yarn-audit.json"


# ---------------- parse() ----------------

def test_parse_pip_audit_only_reports_packages_with_vulns(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==3.2.0\nrequests==2.25.0\n")
    result = RunnerResult(tool="pip-audit", state=ToolState.OK, raw=PIP_AUDIT.read_text())
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "pip-audit"
    assert f.rule == "PYSEC-2021-9"
    assert f.severity_raw == "low"  # pip-audit's own JSON carries no severity field
    assert "django" in f.message
    assert f.file == "requirements.txt"
    assert f.line == 1  # matched the "django==3.2.0" line


def test_parse_npm_audit(tmp_path):
    result = RunnerResult(tool="npm", state=ToolState.OK, raw=NPM_AUDIT.read_text())
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "npm"
    assert f.rule == "GHSA-p6mc-m468-83gw"
    assert f.severity_raw == "high"
    assert "lodash" in f.message or "Prototype" in f.message


def test_parse_pnpm_audit(tmp_path):
    result = RunnerResult(tool="pnpm", state=ToolState.OK, raw=PNPM_AUDIT.read_text())
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "pnpm"
    assert f.severity_raw == "critical"
    assert "minimatch" in f.message or "ReDoS" in f.message


def test_parse_yarn_audit_ndjson(tmp_path):
    result = RunnerResult(tool="yarn", state=ToolState.OK, raw=YARN_AUDIT.read_text())
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 2
    assert findings[0].tool == "yarn"
    assert findings[0].severity_raw == "low"
    assert findings[1].severity_raw == "critical"


def test_parse_skips_non_ok_state(tmp_path):
    for tool in ("pip-audit", "npm", "pnpm", "yarn"):
        result = RunnerResult(tool=tool, state=ToolState.MISSING)
        assert deps.parse(result, RunContext(root=tmp_path)) == []


# ---------------- python: discovery + skip ----------------

def test_run_python_missing_when_no_requirements_files(tmp_path):
    result = deps.run_python(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING


def test_find_requirements_matches_glob(tmp_path):
    (tmp_path / "requirements.txt").write_text("a==1\n")
    (tmp_path / "requirements-dev.txt").write_text("b==2\n")
    (tmp_path / "setup.py").write_text("")
    found = {p.name for p in deps._find_requirements(tmp_path)}
    assert found == {"requirements.txt", "requirements-dev.txt"}


def test_run_python_invokes_pip_audit_with_dash_r_per_file(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n")
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="pip-audit", state=ToolState.OK, raw=PIP_AUDIT.read_text())

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    result = deps.run_python(RunContext(root=tmp_path))
    assert result.state is ToolState.OK
    argv = captured["argv"]
    assert argv[0] == "pip-audit"
    assert "-r" in argv
    assert str(tmp_path / "requirements.txt") in argv
    assert "-f" in argv and "json" in argv


# ---------------- JS: dispatch by lockfile ----------------

def test_run_js_missing_when_no_lockfile(tmp_path):
    result = deps.run_js(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING


def test_run_js_dispatches_npm(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}")
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="npm", state=ToolState.OK, raw=NPM_AUDIT.read_text())

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    result = deps.run_js(RunContext(root=tmp_path, pkg_manager="npm"))
    assert result.state is ToolState.OK
    assert captured["argv"] == ["npm", "audit", "--json"]


def test_run_js_dispatches_pnpm(tmp_path, monkeypatch):
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="pnpm", state=ToolState.OK, raw=PNPM_AUDIT.read_text())

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    result = deps.run_js(RunContext(root=tmp_path, pkg_manager="pnpm"))
    assert result.state is ToolState.OK
    assert captured["argv"] == ["pnpm", "audit", "--json"]


def test_run_js_dispatches_yarn(tmp_path, monkeypatch):
    (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n")

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        return RunnerResult(tool="yarn", state=ToolState.OK, raw=YARN_AUDIT.read_text())

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    result = deps.run_js(RunContext(root=tmp_path, pkg_manager="yarn"))
    assert result.state is ToolState.OK
    assert result.tool == "yarn"


def test_run_mixed_stack_runs_both_python_and_js_audits(tmp_path, monkeypatch):
    """A repo with BOTH requirements*.txt AND a JS lockfile is a common
    full-stack layout -- run() must not silently skip the JS audit just
    because a Python one is also possible (the Important-severity bug)."""
    (tmp_path / "requirements.txt").write_text("a==1\n")
    (tmp_path / "package-lock.json").write_text("{}")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="pip-audit", state=ToolState.OK, raw="{}"),
    )
    result = deps.run(RunContext(root=tmp_path))
    assert result.state is ToolState.OK
    sub_tools = {sub.tool for sub in result.sub_results}
    assert sub_tools == {"pip-audit", "npm"}


def test_run_mixed_stack_merges_findings_from_both_audits(tmp_path, monkeypatch):
    """End-to-end: findings from the pip-audit AND npm audit fixtures both
    surface out of deps.parse() for a single deps.run() call."""
    (tmp_path / "requirements.txt").write_text("django==3.2.0\nrequests==2.25.0\n")
    (tmp_path / "package-lock.json").write_text("{}")

    monkeypatch.setattr(deps, "run_python",
                         lambda ctx: RunnerResult("pip-audit", ToolState.OK, raw=PIP_AUDIT.read_text()))
    monkeypatch.setattr(deps, "run_js",
                         lambda ctx: RunnerResult("npm", ToolState.OK, raw=NPM_AUDIT.read_text()))

    ctx = RunContext(root=tmp_path, pkg_manager="npm")
    result = deps.run(ctx)
    findings = deps.parse(result, ctx)

    assert {f.tool for f in findings} == {"pip-audit", "npm"}
    assert len(findings) == 2


def test_run_falls_back_to_js_when_no_python_deps(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="npm", state=ToolState.OK, raw="{}"),
    )
    result = deps.run(RunContext(root=tmp_path, pkg_manager="npm"))
    assert result.tool == "npm"


def test_run_missing_when_no_stack_detected(tmp_path):
    result = deps.run(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING


# ---------------- CRASHED detection ----------------

def test_run_python_unparseable_output_is_crashed(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("a==1\n")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="pip-audit", state=ToolState.OK, raw="not json", stderr="boom"),
    )
    result = deps.run_python(RunContext(root=tmp_path))
    assert result.state is ToolState.CRASHED


def test_run_js_unparseable_output_is_crashed(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="npm", state=ToolState.OK, raw="not json", stderr="boom"),
    )
    result = deps.run_js(RunContext(root=tmp_path, pkg_manager="npm"))
    assert result.state is ToolState.CRASHED


def test_run_python_empty_output_with_error_returncode_is_crashed(tmp_path, monkeypatch):
    """Empty stdout parses fine as '{}' -- without a returncode check this
    would silently read as a clean 'zero vulnerabilities' run even though
    pip-audit errored (bad requirements file, no network, ...) before
    producing a report."""
    (tmp_path / "requirements.txt").write_text("a==1\n")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="pip-audit", state=ToolState.OK, raw="", stderr="fatal error", returncode=2),
    )
    result = deps.run_python(RunContext(root=tmp_path))
    assert result.state is ToolState.CRASHED


def test_run_js_npm_empty_output_with_error_returncode_is_crashed(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="npm", state=ToolState.OK, raw="", stderr="ENOTFOUND", returncode=2),
    )
    result = deps.run_js(RunContext(root=tmp_path, pkg_manager="npm"))
    assert result.state is ToolState.CRASHED


def test_run_js_pnpm_empty_output_with_error_returncode_is_crashed(tmp_path, monkeypatch):
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="pnpm", state=ToolState.OK, raw="", stderr="fatal error", returncode=2),
    )
    result = deps.run_js(RunContext(root=tmp_path, pkg_manager="pnpm"))
    assert result.state is ToolState.CRASHED


def test_run_js_yarn_empty_output_with_error_returncode_is_crashed(tmp_path, monkeypatch):
    (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="yarn", state=ToolState.OK, raw="", stderr="fatal error", returncode=2),
    )
    result = deps.run_js(RunContext(root=tmp_path, pkg_manager="yarn"))
    assert result.state is ToolState.CRASHED


# ---------------- cache (lockfile-keyed, 24h TTL) ----------------

def test_js_result_is_cached_and_reused_within_ttl(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}')
    call_count = {"n": 0}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        call_count["n"] += 1
        return RunnerResult(tool="npm", state=ToolState.OK, raw=NPM_AUDIT.read_text())

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    ctx = RunContext(root=tmp_path, pkg_manager="npm")

    r1 = deps.run_js(ctx)
    r2 = deps.run_js(ctx)

    assert call_count["n"] == 1  # second call served from cache
    assert r1.raw == r2.raw
    assert deps.parse(r2, ctx)[0].rule == "GHSA-p6mc-m468-83gw"

    cache_files = list((tmp_path / ".aramid" / "cache").glob("deps-*.json"))
    assert len(cache_files) == 1


def test_cache_key_changes_with_lockfile_content(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}')
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="npm", state=ToolState.OK, raw="{}"),
    )
    ctx = RunContext(root=tmp_path, pkg_manager="npm")
    deps.run_js(ctx)
    first_cache = set((tmp_path / ".aramid" / "cache").glob("deps-*.json"))

    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3, "extra": true}')
    deps.run_js(ctx)
    second_cache = set((tmp_path / ".aramid" / "cache").glob("deps-*.json"))

    assert first_cache != second_cache
    assert len(first_cache | second_cache) == 2


def test_stale_cache_past_ttl_triggers_refresh(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}')
    call_count = {"n": 0}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        call_count["n"] += 1
        return RunnerResult(tool="npm", state=ToolState.OK, raw="{}")

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    ctx = RunContext(root=tmp_path, pkg_manager="npm")
    deps.run_js(ctx)
    assert call_count["n"] == 1

    cache_file = next((tmp_path / ".aramid" / "cache").glob("deps-*.json"))
    stale = time.time() - deps.CACHE_TTL_S - 60
    os.utime(cache_file, (stale, stale))

    deps.run_js(ctx)
    assert call_count["n"] == 2  # cache expired, tool re-invoked


def test_force_refresh_bypasses_cache(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}')
    call_count = {"n": 0}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        call_count["n"] += 1
        return RunnerResult(tool="npm", state=ToolState.OK, raw="{}")

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    ctx = RunContext(root=tmp_path, pkg_manager="npm")
    deps.run_js(ctx)
    ctx.force_refresh = True
    deps.run_js(ctx)
    assert call_count["n"] == 2


def test_python_result_is_also_cached(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n")
    call_count = {"n": 0}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        call_count["n"] += 1
        return RunnerResult(tool="pip-audit", state=ToolState.OK, raw=PIP_AUDIT.read_text())

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    ctx = RunContext(root=tmp_path)
    deps.run_python(ctx)
    deps.run_python(ctx)
    assert call_count["n"] == 1


# ---------------- force_refresh wiring (Task 3) ----------------

def _git(root, *a):
    import subprocess
    subprocess.run(["git", "-C", str(root), *a], check=True, capture_output=True, text=True)


def test_runcontext_has_force_refresh_default_false():
    assert RunContext(root=Path(".")).force_refresh is False


def test_run_gate_sets_force_refresh_for_all_mode(monkeypatch, tmp_path):
    # mode=="all" must build a RunContext with force_refresh=True so check --all
    # re-audits instead of serving a stale deps cache. Intercept at
    # _select_runners: capture the ctx and return NO runners (hermetic).
    import subprocess

    import aramid.pipeline as pipeline
    from aramid import config as config_mod
    from aramid.ledger import Ledger
    from aramid.models import Gate

    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True,
                   capture_output=True, text=True)
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "base")

    captured = {}

    def _capture(gate, ctx):
        captured["ctx"] = ctx
        return {}

    monkeypatch.setattr(pipeline, "_select_runners", _capture)
    cfg = config_mod.load_config(tmp_path)
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    try:
        pipeline.run_gate(tmp_path, Gate.ALL, "all", cfg, led)
    finally:
        led.close()
    assert captured["ctx"].force_refresh is True


def test_run_gate_no_force_refresh_for_non_all_mode(monkeypatch, tmp_path):
    # pre-commit/pre-push (mode != "all") keep force_refresh False so the deps
    # audit cache is still used in the interactive gates.
    import subprocess

    import aramid.pipeline as pipeline
    from aramid import config as config_mod
    from aramid.ledger import Ledger
    from aramid.models import Gate

    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True,
                   capture_output=True, text=True)
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "base")

    captured = {}

    def _capture(gate, ctx):
        captured["ctx"] = ctx
        return {}

    monkeypatch.setattr(pipeline, "_select_runners", _capture)
    cfg = config_mod.load_config(tmp_path)
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    try:
        pipeline.run_gate(tmp_path, Gate.PRE_COMMIT, "staged", cfg, led)
    finally:
        led.close()
    assert captured["ctx"].force_refresh is False
