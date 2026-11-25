import json
import os
import time
from pathlib import Path

import pytest

from aramid.runners import deps
from aramid.runners.base import RunContext, RunnerResult, ToolState

FIXTURES = Path(__file__).parent.parent / "fixtures"
PIP_AUDIT = FIXTURES / "pip-audit.json"
NPM_AUDIT = FIXTURES / "npm-audit.json"
PNPM_AUDIT = FIXTURES / "pnpm-audit.json"
YARN_AUDIT = FIXTURES / "yarn-audit.json"
CARGO_AUDIT = FIXTURES / "cargo-audit.json"
CARGO_AUDIT_CVSS = FIXTURES / "cargo-audit-cvss.json"


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


def test_parse_cargo_audit(tmp_path):
    result = RunnerResult(tool="cargo-audit", state=ToolState.OK, raw=CARGO_AUDIT.read_text())
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "cargo-audit"
    assert f.rule == "RUSTSEC-2020-0071"
    # cargo-audit advisories often carry no simple severity string (many
    # RUSTSEC entries have no CVSS score at all) -- same constant-severity
    # choice as pip-audit's own precedent, not a parsed value.
    assert f.severity_raw == deps._CARGO_AUDIT_SEVERITY_RAW
    assert "chrono" in f.message
    assert f.file == "Cargo.lock"


def test_parse_cargo_severity_banded_from_real_cvss_vectors(tmp_path):
    # Oracles, not guesses: this fixture is a verbatim `cargo audit --json`
    # capture (cargo-audit 0.22.2) from a crate pinned to two known-vulnerable
    # deps. Both advisories carry full CVSS v3.1 vectors, which is what
    # falsified the original "RUSTSEC has no usable severity" premise.
    #   RUSTSEC-2021-0003 smallvec  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    #   RUSTSEC-2020-0071 time      AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
    result = RunnerResult(tool="cargo-audit", state=ToolState.OK,
                          raw=CARGO_AUDIT_CVSS.read_text(), returncode=1)
    findings = {f.rule: f for f in deps.parse(result, RunContext(root=tmp_path))}
    assert set(findings) == {"RUSTSEC-2021-0003", "RUSTSEC-2020-0071"}
    # Remotely reachable, no privileges/interaction, total C+I+A loss. Must
    # reach "critical" or it never blocks: deps.block_severity defaults to
    # "critical", so anything lower is a WARN no matter how severe.
    assert findings["RUSTSEC-2021-0003"].severity_raw == "critical"
    # Local-only, availability-only -- genuinely not critical.
    assert findings["RUSTSEC-2020-0071"].severity_raw != "critical"


def test_parse_cargo_falls_back_to_constant_when_cvss_absent(tmp_path):
    # The hand-written fixture carries "cvss": null, which is normal RUSTSEC
    # data, not shape drift. Absent CVSS must degrade to the conservative
    # constant, never below it.
    result = RunnerResult(tool="cargo-audit", state=ToolState.OK, raw=CARGO_AUDIT.read_text())
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert findings[0].severity_raw == deps._CARGO_AUDIT_SEVERITY_RAW


def test_cvss_severity_rejects_junk_rather_than_guessing(tmp_path):
    for junk in (None, "", "not-a-vector", "CVSS:2.0/AV:N/AC:L/Au:N/C:P", 7.5, {}):
        assert deps._cvss_severity(junk) is None


def test_cargo_shape_check_does_not_require_cvss(tmp_path):
    # A missing CVSS is data, not drift -- it must not trip the advisory.
    raw = '{"vulnerabilities": {"found": true, "count": 1, "list": [{"advisory": {"id": "X"}}]}}'
    assert deps._cargo_shape_recognized(raw) is True


def test_parse_skips_non_ok_state(tmp_path):
    for tool in ("pip-audit", "npm", "pnpm", "yarn", "cargo-audit"):
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


# ---------------- cargo: dispatch by Cargo.lock ----------------

def test_run_cargo_missing_when_no_cargo_lock(tmp_path):
    result = deps.run_cargo(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING


def test_run_cargo_missing_when_cargo_audit_plugin_not_installed(tmp_path, monkeypatch):
    # `cargo` itself resolving is NOT evidence that `cargo audit` works:
    # cargo-audit is a separately-installed subcommand plugin. Without it
    # cargo exits 101 ("no such command: audit") with no JSON, which
    # json_or_crashed would read as CRASHED -- reporting "the tool broke"
    # for the ordinary "the tool isn't installed" case, on every Rust repo
    # that hasn't run `cargo install cargo-audit`. Probe for the plugin and
    # report MISSING, the same signal run_subprocess gives for any other
    # unresolvable binary.
    (tmp_path / "Cargo.lock").write_text("version = 3\n")
    monkeypatch.setattr(deps.toolpath, "resolve", lambda name: None)

    def explode(*a, **k):  # pragma: no cover - must never be reached
        raise AssertionError("cargo must not be invoked when the plugin is absent")

    monkeypatch.setattr(deps, "run_subprocess", explode)
    result = deps.run_cargo(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING
    assert result.tool == "cargo-audit"


def test_run_cargo_invokes_cargo_audit_json(tmp_path, monkeypatch):
    (tmp_path / "Cargo.lock").write_text("version = 3\n")
    monkeypatch.setattr(deps.toolpath, "resolve", lambda name: f"/fake/{name}")
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="cargo-audit", state=ToolState.OK, raw=CARGO_AUDIT.read_text())

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    result = deps.run_cargo(RunContext(root=tmp_path))
    assert result.state is ToolState.OK
    assert captured["argv"] == ["cargo", "audit", "--json"]


def test_run_cargo_unparseable_output_is_crashed(tmp_path, monkeypatch):
    (tmp_path / "Cargo.lock").write_text("version = 3\n")
    monkeypatch.setattr(deps.toolpath, "resolve", lambda name: f"/fake/{name}")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult(
            tool="cargo-audit", state=ToolState.OK, raw="not json", returncode=0))
    result = deps.run_cargo(RunContext(root=tmp_path))
    assert result.state is ToolState.CRASHED


def test_run_cargo_vulnerabilities_found_returncode_1_is_still_ok(tmp_path, monkeypatch):
    # cargo-audit exits 1 when it finds vulnerabilities -- a real report,
    # not a crash, same 0/1 convention as every other deps tool here.
    (tmp_path / "Cargo.lock").write_text("version = 3\n")
    monkeypatch.setattr(deps.toolpath, "resolve", lambda name: f"/fake/{name}")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult(
            tool="cargo-audit", state=ToolState.OK, raw=CARGO_AUDIT.read_text(), returncode=1))
    result = deps.run_cargo(RunContext(root=tmp_path))
    assert result.state is ToolState.OK


def test_parse_cargo_unrecognized_shape_emits_advisory_warn(tmp_path):
    result = RunnerResult("cargo-audit", ToolState.OK, raw='{"summary":"format changed"}')
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == deps.DEPS_SHAPE_DRIFT_RULE
    assert findings[0].tool == "cargo-audit"


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

    def clean_audits(argv, cwd, timeout_s, env=None):
        # Each tool's own clean report: a bare "{}" is not pip-audit's.
        if argv[0] == "pip-audit":
            return RunnerResult(tool="pip-audit", state=ToolState.OK, raw=_EMPTY_REPORT)
        return RunnerResult(tool="npm", state=ToolState.OK, raw="{}")
    monkeypatch.setattr(deps, "run_subprocess", clean_audits)
    result = deps.run(RunContext(root=tmp_path))
    assert result.state is ToolState.OK
    sub_tools = {sub.tool for sub in result.sub_results}
    assert sub_tools == {"pip-audit", "npm"}
    assert all(sub.state is ToolState.OK for sub in result.sub_results)


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


def test_run_falls_back_to_cargo_when_no_python_or_js_deps(tmp_path, monkeypatch):
    (tmp_path / "Cargo.lock").write_text("version = 3\n")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="cargo-audit", state=ToolState.OK, raw="{}"),
    )
    result = deps.run(RunContext(root=tmp_path))
    assert result.tool == "cargo-audit"


def test_run_mixed_python_and_cargo_runs_both_audits(tmp_path, monkeypatch):
    """The exact shape of a repo with real Python utility scripts alongside
    a Rust workspace (no requirements*.txt necessarily, but this covers the
    case where both a Python deps file AND Cargo.lock are present) -- both
    audits must run, mirroring the existing python+js guarantee."""
    (tmp_path / "requirements.txt").write_text("a==1\n")
    (tmp_path / "Cargo.lock").write_text("version = 3\n")
    monkeypatch.setattr(deps, "run_python",
                         lambda ctx: RunnerResult("pip-audit", ToolState.OK, raw=PIP_AUDIT.read_text()))
    monkeypatch.setattr(deps, "run_cargo",
                         lambda ctx: RunnerResult("cargo-audit", ToolState.OK, raw=CARGO_AUDIT.read_text()))

    ctx = RunContext(root=tmp_path)
    result = deps.run(ctx)
    findings = deps.parse(result, ctx)

    assert result.state is ToolState.OK
    sub_tools = {sub.tool for sub in result.sub_results}
    assert sub_tools == {"pip-audit", "cargo-audit"}
    assert {f.tool for f in findings} == {"pip-audit", "cargo-audit"}


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


# pip-audit's `_fatal` logs and exits 1 -- its "vulnerabilities found" code --
# with NOTHING on stdout. Seen 2026-11-24 in a gate run: it could not upgrade
# pip inside its temporary venv, `json_or_crashed` read the empty stdout as
# "{}", and the audit counted as clean: no findings, not degraded, and in the
# run's scope, so earlier pip-audit rows could close as gone. A real report
# always carries a `dependencies` list; pip-audit 2.10.1 audits an empty
# requirements file as `{"dependencies": [], "fixes": []}` (measured). Operator
# decision 2026-11-25: require that shape, retry once, then CRASHED with
# pip-audit's own line as the reason.
_FATAL = ("ERROR:pip_audit._cli:Failed to upgrade `pip`: ['/tmp/tmpx/bin/python', '-m', "
          "'pip', 'install', '--upgrade', 'pip', 'wheel', 'setuptools']\n")
_EMPTY_REPORT = '{"dependencies": [], "fixes": []}'


def _pip_audit_runs(monkeypatch, *outcomes):
    """Fake run_subprocess answering each pip-audit call with the next
    outcome; returns the list of argvs it was called with."""
    calls = []
    queue = list(outcomes)

    def fake(argv, cwd, timeout_s, env=None):
        calls.append(argv)
        return queue.pop(0)
    monkeypatch.setattr(deps, "run_subprocess", fake)
    return calls


def _cached(root):
    return sorted((root / ".aramid" / "cache").glob("deps-*.json")) \
        if (root / ".aramid" / "cache").is_dir() else []


def test_run_python_a_fatal_exit_with_no_report_is_retried_once_then_crashed(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.6.0\n")
    fatal = RunnerResult(tool="pip-audit", state=ToolState.OK, raw="", stderr=_FATAL,
                         duration_s=2.0, returncode=1)
    calls = _pip_audit_runs(monkeypatch, fatal, fatal)
    result = deps.run_python(RunContext(root=tmp_path))
    assert len(calls) == 2
    assert calls[0] == calls[1]
    assert result.state is ToolState.CRASHED
    assert result.tool == "pip-audit"
    assert result.returncode == 1
    assert result.duration_s == 4.0
    assert result.reason == ("crashed (exit 1): no report after a retry -- Failed to upgrade "
                             "`pip`: ['/tmp/tmpx/bin/python', '-m', 'pip', 'install', "
                             "'--upgrade', 'pip', 'wheel', 'setuptools']")
    assert _cached(tmp_path) == []


def test_run_python_a_retry_that_reports_is_the_result_and_is_cached(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n")
    fatal = RunnerResult(tool="pip-audit", state=ToolState.OK, raw="", stderr=_FATAL, returncode=1)
    report = RunnerResult(tool="pip-audit", state=ToolState.OK, raw=PIP_AUDIT.read_text(),
                          returncode=1)
    calls = _pip_audit_runs(monkeypatch, fatal, report)
    result = deps.run_python(RunContext(root=tmp_path))
    assert len(calls) == 2
    assert result.state is ToolState.OK
    assert result.reason is None
    assert json.loads(result.raw) == json.loads(PIP_AUDIT.read_text())
    assert len(_cached(tmp_path)) == 1


@pytest.mark.parametrize("raw",["{}", "[]", "null", '{"dependencies": {}}', '"x"'])
def test_run_python_json_that_is_not_a_report_is_crashed(tmp_path, monkeypatch, raw):
    (tmp_path / "requirements.txt").write_text("a==1\n")
    bare = RunnerResult(tool="pip-audit", state=ToolState.OK, raw=raw, returncode=0)
    calls = _pip_audit_runs(monkeypatch, bare, bare)
    result = deps.run_python(RunContext(root=tmp_path))
    assert len(calls) == 2
    assert result.state is ToolState.CRASHED
    assert result.reason == "crashed (exit 0): no report after a retry -- nothing on stderr"
    assert _cached(tmp_path) == []


def test_run_python_an_empty_requirements_report_stays_ok_without_a_retry(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("# nothing pinned\n")
    calls = _pip_audit_runs(monkeypatch, RunnerResult(
        tool="pip-audit", state=ToolState.OK, raw=_EMPTY_REPORT,
        stderr="No known vulnerabilities found\n", returncode=0))
    result = deps.run_python(RunContext(root=tmp_path))
    assert len(calls) == 1
    assert result.state is ToolState.OK
    assert deps.parse(result, RunContext(root=tmp_path)) == []


def test_run_python_a_crash_is_retried_and_keeps_its_line(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("a==1\n")
    crash = RunnerResult(tool="pip-audit", state=ToolState.OK, raw="",
                         stderr="usage: pip-audit [-h]\nERROR:pip_audit._cli:bad flag\n",
                         returncode=2)
    calls = _pip_audit_runs(monkeypatch, crash, crash)
    result = deps.run_python(RunContext(root=tmp_path))
    assert len(calls) == 2
    assert result.state is ToolState.CRASHED
    assert result.reason == "crashed (exit 2): no report after a retry -- bad flag"


@pytest.mark.parametrize("state", [ToolState.TIMEOUT, ToolState.MISSING])
def test_run_python_a_timeout_or_missing_tool_is_not_retried(tmp_path, monkeypatch, state):
    (tmp_path / "requirements.txt").write_text("a==1\n")
    calls = _pip_audit_runs(monkeypatch, RunnerResult(tool="pip-audit", state=state,
                                                      duration_s=180.0))
    result = deps.run_python(RunContext(root=tmp_path))
    assert len(calls) == 1
    assert result.state is state
    assert result.reason is None


def test_run_python_a_cached_entry_that_is_not_a_report_is_a_miss(tmp_path, monkeypatch):
    """A `{}` cached before this fix would read as a clean audit for 24 h."""
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n")
    sources = deps.python_sources(tmp_path)
    path = deps._cache_path(tmp_path, b"\x00".join(s.read_bytes() for s in sources))
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    calls = _pip_audit_runs(monkeypatch, RunnerResult(
        tool="pip-audit", state=ToolState.OK, raw=PIP_AUDIT.read_text(), returncode=1))
    result = deps.run_python(RunContext(root=tmp_path))
    assert len(calls) == 1
    assert result.state is ToolState.OK
    assert json.loads(path.read_text(encoding="utf-8")) == json.loads(PIP_AUDIT.read_text())


@pytest.mark.parametrize("stderr, said", [
    (_FATAL, "Failed to upgrade `pip`: ['/tmp/tmpx/bin/python', '-m', 'pip', 'install', "
             "'--upgrade', 'pip', 'wheel', 'setuptools']"),
    # `_fatal` after a connection error logs two lines; the first names it.
    ("ERROR:pip_audit._cli:HTTPSConnectionPool(host='pypi.org'): timed out\n"
     "ERROR:pip_audit._cli:Tip: your network may be blocking this service.\n",
     "HTTPSConnectionPool(host='pypi.org'): timed out"),
    ("Traceback (most recent call last):\n  ...\nKeyError: 'x'\n", "KeyError: 'x'"),
    ("", "nothing on stderr"),
    ("  \n\n", "nothing on stderr"),
    ("ERROR:" + "y" * 500, "y" * 300),
])
def test_what_pip_audit_said_is_its_first_error_line(stderr, said):
    assert deps._pip_audit_said(stderr) == said


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

# The same hole in the other dependency audits (operator decision 2026-11-25,
# "no-report rule, all four"). npm, pnpm, yarn and cargo-audit exit 1 for
# "vulnerabilities found", so exit 1 with NOTHING on stdout reported nothing
# while claiming findings; npm also fails with exit 1 and an error object on
# stdout -- measured, npm 11.13.0 with no lockfile:
_NPM_ENOLOCK = ('{\n  "error": {\n    "code": "ENOLOCK",\n    "summary": "This command requires '
                'an existing lockfile.",\n    "detail": "Try creating one first with: npm i '
                '--package-lock-only\\nOriginal error: loadVirtual requires existing shrinkwrap '
                'file"\n  }\n}\n')
_NPM_ENOLOCK_STDERR = ("npm error code ENOLOCK\nnpm error audit This command requires an "
                       "existing lockfile.\n")
# Exit 0 with nothing on stdout stays clean: yarn's clean audit prints
# nothing (see _yarn_shape_recognized). cargo-audit's own fatal error exits 2
# (measured, 0.22.2: "error: not found: Couldn't load Cargo.lock"), which was
# already CRASHED; exit 1 empty is the defensive half.
_LOCKFILE_OF = {"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "yarn": "yarn.lock"}


def _js_repo(tmp_path, pm):
    (tmp_path / _LOCKFILE_OF[pm]).write_text("{}")
    return RunContext(root=tmp_path, pkg_manager=pm)


@pytest.mark.parametrize("pm", ["npm", "pnpm", "yarn"])
def test_run_js_exit_1_with_nothing_on_stdout_is_retried_once_then_crashed(tmp_path, monkeypatch, pm):
    ctx = _js_repo(tmp_path, pm)
    silent = RunnerResult(tool=pm, state=ToolState.OK, raw="",
                          stderr=f"{pm} error code EAI_AGAIN\n{pm} error network failed\n",
                          duration_s=1.5, returncode=1)
    calls = _pip_audit_runs(monkeypatch, silent, silent)
    result = deps.run_js(ctx)
    assert len(calls) == 2
    assert result.tool == pm
    assert result.state is ToolState.CRASHED
    assert result.returncode == 1
    assert result.duration_s == 3.0
    assert result.raw == ""
    assert result.reason == f"crashed (exit 1): no report after a retry -- {pm} error code EAI_AGAIN"
    assert _cached(tmp_path) == []


def test_run_js_npm_s_error_reply_is_retried_once_then_crashed(tmp_path, monkeypatch):
    ctx = _js_repo(tmp_path, "npm")
    reply = RunnerResult(tool="npm", state=ToolState.OK, raw=_NPM_ENOLOCK,
                         stderr=_NPM_ENOLOCK_STDERR, returncode=1)
    calls = _pip_audit_runs(monkeypatch, reply, reply)
    result = deps.run_js(ctx)
    assert len(calls) == 2
    assert result.state is ToolState.CRASHED
    assert result.reason == ("crashed (exit 1): no report after a retry -- ENOLOCK: This "
                             "command requires an existing lockfile.")
    assert _cached(tmp_path) == []


def test_run_js_pnpm_s_error_reply_is_crashed(tmp_path, monkeypatch):
    """pnpm's reply shape is not captured here (pnpm is not installed); an
    object carrying `error` is never an audit report, whichever tool wrote it."""
    ctx = _js_repo(tmp_path, "pnpm")
    reply = RunnerResult(tool="pnpm", state=ToolState.OK, returncode=1, raw=json.dumps(
        {"error": {"code": "ERR_PNPM_AUDIT_BAD_RESPONSE", "message": "The audit endpoint "
                   "responded with 503"}}))
    calls = _pip_audit_runs(monkeypatch, reply, reply)
    result = deps.run_js(ctx)
    assert len(calls) == 2
    assert result.state is ToolState.CRASHED
    assert result.reason == ("crashed (exit 1): no report after a retry -- "
                             "ERR_PNPM_AUDIT_BAD_RESPONSE: The audit endpoint responded with 503")


@pytest.mark.parametrize("pm", ["npm", "pnpm", "yarn"])
def test_run_js_exit_0_with_nothing_on_stdout_is_still_clean(tmp_path, monkeypatch, pm):
    ctx = _js_repo(tmp_path, pm)
    calls = _pip_audit_runs(monkeypatch, RunnerResult(tool=pm, state=ToolState.OK, raw="",
                                                      returncode=0))
    result = deps.run_js(ctx)
    assert len(calls) == 1
    assert result.state is ToolState.OK
    assert result.reason is None
    assert deps.parse(result, ctx) == []


def test_run_js_a_retry_that_reports_is_the_result_and_is_cached(tmp_path, monkeypatch):
    ctx = _js_repo(tmp_path, "npm")
    calls = _pip_audit_runs(
        monkeypatch,
        RunnerResult(tool="npm", state=ToolState.OK, raw="", returncode=1),
        RunnerResult(tool="npm", state=ToolState.OK, raw=NPM_AUDIT.read_text(), returncode=1))
    result = deps.run_js(ctx)
    assert len(calls) == 2
    assert result.state is ToolState.OK
    assert deps.parse(result, ctx)[0].rule == "GHSA-p6mc-m468-83gw"
    assert len(_cached(tmp_path)) == 1


@pytest.mark.parametrize("state", [ToolState.TIMEOUT, ToolState.MISSING])
def test_run_js_a_timeout_or_missing_tool_is_not_retried(tmp_path, monkeypatch, state):
    ctx = _js_repo(tmp_path, "npm")
    calls = _pip_audit_runs(monkeypatch, RunnerResult(tool="npm", state=state))
    result = deps.run_js(ctx)
    assert len(calls) == 1
    assert result.state is state
    assert result.reason is None


def _seed_cache(root, key_bytes, content):
    path = deps._cache_path(root, key_bytes)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.mark.parametrize("cached", ["{}", " {} \n", _NPM_ENOLOCK])
def test_run_js_a_cached_placeholder_or_error_reply_is_a_miss(tmp_path, monkeypatch, cached):
    """A `{}` cached before this fix was aramid's stand-in for nothing on
    stdout, not npm's report: npm writes a report even when clean."""
    ctx = _js_repo(tmp_path, "npm")
    path = _seed_cache(tmp_path, (tmp_path / "package-lock.json").read_bytes(), cached)
    calls = _pip_audit_runs(monkeypatch, RunnerResult(
        tool="npm", state=ToolState.OK, raw=NPM_AUDIT.read_text(), returncode=1))
    result = deps.run_js(ctx)
    assert len(calls) == 1
    assert result.state is ToolState.OK
    assert path.read_text(encoding="utf-8") == NPM_AUDIT.read_text()


def test_run_js_yarn_s_cached_clean_audit_is_still_a_hit(tmp_path, monkeypatch):
    ctx = _js_repo(tmp_path, "yarn")
    _seed_cache(tmp_path, (tmp_path / "yarn.lock").read_bytes(), "")
    calls = _pip_audit_runs(monkeypatch)
    result = deps.run_js(ctx)
    assert calls == []
    assert result.state is ToolState.OK and result.raw == ""


def test_run_cargo_exit_1_with_nothing_on_stdout_is_retried_once_then_crashed(tmp_path, monkeypatch):
    (tmp_path / "Cargo.lock").write_text("version = 3\n")
    monkeypatch.setattr(deps.toolpath, "resolve", lambda name, *a, **k: "cargo-audit")
    silent = RunnerResult(tool="cargo", state=ToolState.OK, raw="", returncode=1,
                          stderr="error: couldn't fetch advisory database: timed out\n")
    calls = _pip_audit_runs(monkeypatch, silent, silent)
    result = deps.run_cargo(RunContext(root=tmp_path))
    assert len(calls) == 2
    assert result.tool == "cargo-audit"
    assert result.state is ToolState.CRASHED
    assert result.reason == ("crashed (exit 1): no report after a retry -- error: couldn't "
                             "fetch advisory database: timed out")
    assert _cached(tmp_path) == []


def test_run_cargo_a_cached_placeholder_is_a_miss(tmp_path, monkeypatch):
    (tmp_path / "Cargo.lock").write_text("version = 3\n")
    monkeypatch.setattr(deps.toolpath, "resolve", lambda name, *a, **k: "cargo-audit")
    _seed_cache(tmp_path, (tmp_path / "Cargo.lock").read_bytes(), "{}")
    clean = ('{"vulnerabilities": {"found": false, "count": 0, "list": []}, "warnings": {}}')
    calls = _pip_audit_runs(monkeypatch, RunnerResult(tool="cargo", state=ToolState.OK,
                                                      raw=clean, returncode=0))
    result = deps.run_cargo(RunContext(root=tmp_path))
    assert len(calls) == 1
    assert result.state is ToolState.OK


def test_run_js_an_unknown_package_manager_is_missing(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}")
    calls = _pip_audit_runs(monkeypatch)
    result = deps.run_js(RunContext(root=tmp_path, pkg_manager="bun"))
    assert calls == []
    assert (result.tool, result.state) == ("deps-js", ToolState.MISSING)


def test_run_cargo_a_cached_report_is_used(tmp_path, monkeypatch):
    (tmp_path / "Cargo.lock").write_text("version = 3\n")
    monkeypatch.setattr(deps.toolpath, "resolve", lambda name, *a, **k: "cargo-audit")
    clean = ('{"vulnerabilities": {"found": false, "count": 0, "list": []}, "warnings": {}}')
    _seed_cache(tmp_path, (tmp_path / "Cargo.lock").read_bytes(), clean)
    calls = _pip_audit_runs(monkeypatch)
    result = deps.run_cargo(RunContext(root=tmp_path))
    assert calls == []
    assert (result.state, result.raw) == (ToolState.OK, clean)


@pytest.mark.parametrize("raw, stderr, said", [
    (_NPM_ENOLOCK, _NPM_ENOLOCK_STDERR, "ENOLOCK: This command requires an existing lockfile."),
    # An `error` that is neither an object nor text says nothing itself.
    ('{"error": null}', "npm error code E1\n", "npm error code E1"),
    ('{"error": 7}', "", "nothing on stderr"),
    ('{"error": {"message": "boom\\nmore"}}', "", "boom"),
    ('{"error": "registry down"}', "", "registry down"),
    ('{"error": {}}', "npm error code E500\n", "npm error code E500"),
    ("", "warn: slow\nError: socket hang up\nat x\n", "Error: socket hang up"),
    ("", "something odd\nlast words\n", "last words"),
    ("", "", "nothing on stderr"),
    ("", "error: " + "z" * 500, ("error: " + "z" * 500)[:300]),
])
def test_what_an_audit_said_is_its_error_reply_else_its_error_line(raw, stderr, said):
    assert deps._audit_said(raw, stderr) == said


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


def test_an_audit_holding_characters_outside_the_code_page_is_cached_as_utf8(
        tmp_path, monkeypatch, cp1252_locale):
    """npm, pnpm, yarn and cargo-audit write JSON with raw non-ASCII, and
    run_subprocess hands it over decoded as UTF-8 (runners/base.py). The
    cache was written in the locale code page: on cp1252 a character it
    cannot hold raised UnicodeEncodeError, not an OSError, so the deps
    runner crashed and the push was refused under --strict."""
    (tmp_path / "package-lock.json").write_bytes(b'{"lockfileVersion": 3}')
    raw = json.dumps({"advisories": {"t": "漢字 aːramid"}}, ensure_ascii=False)
    calls = {"n": 0}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        calls["n"] += 1
        return RunnerResult(tool="npm", state=ToolState.OK, raw=raw)

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    ctx = RunContext(root=tmp_path, pkg_manager="npm")

    first, second = deps.run_js(ctx), deps.run_js(ctx)

    assert calls["n"] == 1, "the second run is served from the cache"
    assert first.raw == second.raw == raw


def test_a_cache_file_that_is_not_utf8_is_a_miss_not_a_crash(tmp_path, monkeypatch,
                                                             cp1252_locale):
    """A cache written before the cache became UTF-8, in cp1252, or a
    corrupt one: the read raised UnicodeDecodeError, a ValueError the
    OSError arm does not catch. It is now a cache miss, and the audit runs
    again. Such files live at most CACHE_TTL_S anyway."""
    (tmp_path / "package-lock.json").write_bytes(b'{"lockfileVersion": 3}')
    calls = {"n": 0}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        calls["n"] += 1
        return RunnerResult(tool="npm", state=ToolState.OK, raw="{}")

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    ctx = RunContext(root=tmp_path, pkg_manager="npm")
    deps.run_js(ctx)
    [cache] = (tmp_path / ".aramid" / "cache").glob("deps-*.json")
    cache.write_bytes('{"t": "café"}'.encode("cp1252"))   # 0xE9 alone is not UTF-8

    again = deps.run_js(ctx)

    assert calls["n"] == 2, "the undecodable cache was a miss, so the audit ran again"
    assert again.state is ToolState.OK and again.raw == "{}"


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


# ------------ pnpm/yarn shape-shift drift -> advisory WARN (Task 7) ----------
#
# Fixture provenance (spec section 8): tests/fixtures/pnpm-audit.json (pnpm
# {"report":{"advisories":...}} shape) and yarn-audit.json (Yarn Berry >=4.0.1
# NDJSON, one advisory object with a `children` dict per line) are HAND-AUTHORED
# from the documented shapes, NOT live captures. A live capture + reconcile is
# deferred until pnpm v8/9 and Yarn Berry are installable here. Because those
# shapes are unverified, an UNRECOGNIZED-but-present audit shape surfaces as a
# non-blocking advisory WARN finding (deps-audit-shape-unrecognized) -- visible
# in the report, never a silent [] and never a hard CI failure on a possible
# false positive (spec section 8 mitigation).

def test_pnpm_shape_recognized_good_and_drifted():
    from aramid.runners.deps import _pnpm_shape_recognized
    assert _pnpm_shape_recognized('{"report":{"advisories":{}}}') is True   # clean
    assert _pnpm_shape_recognized('{"advisories":{}}') is True              # clean alt
    assert _pnpm_shape_recognized("{}") is True                            # no output
    # degenerate present-but-empty shapes have no advisories container -> drift;
    # the isinstance guard makes report=null return False cleanly (not crash).
    assert _pnpm_shape_recognized('{"report":null}') is False
    assert _pnpm_shape_recognized('{"metadata":{"vulnerabilities":3}}') is False  # drift
    # present-but-NON-DICT advisories is also drift: _parse_advisories_dict would
    # call .items() on it and raise uncaught -> route to CRASHED-visibility instead.
    assert _pnpm_shape_recognized('{"advisories":"not-a-dict"}') is False
    assert _pnpm_shape_recognized('{"advisories":[1,2]}') is False


def test_yarn_shape_recognized_good_and_drifted():
    from aramid.runners.deps import _yarn_shape_recognized
    good = '{"value":"pkg@1","children":{"ID":"X","Severity":"high","Issue":"i"}}'
    assert _yarn_shape_recognized(good) is True
    assert _yarn_shape_recognized("") is True   # clean (no output)
    assert _yarn_shape_recognized("   \n\n") is True   # whitespace only = clean
    assert _yarn_shape_recognized('{"value":"pkg@1","summary":"changed"}') is False  # drift


def test_known_good_fixtures_are_shape_recognized():
    # Regression-lock: the real (hand-authored) fixtures must NOT be false-
    # flagged as drift -- the guard only fires on genuinely unrecognized shapes.
    from aramid.runners.deps import _pnpm_shape_recognized, _yarn_shape_recognized
    assert _pnpm_shape_recognized(PNPM_AUDIT.read_text()) is True
    assert _yarn_shape_recognized(YARN_AUDIT.read_text()) is True


def test_run_js_serves_drifted_pnpm_as_ok_not_crashed(monkeypatch, tmp_path):
    # run_js no longer downgrades an unrecognized shape to CRASHED (that forced
    # exit 2 / a hard CI failure on a possible false positive). It serves OK; the
    # drift is surfaced downstream by parse as a non-blocking advisory WARN.
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: 6.0\n", encoding="utf-8")
    monkeypatch.setattr(deps, "detect_package_manager", lambda root: "pnpm")
    monkeypatch.setattr(deps, "run_subprocess",
                        lambda argv, cwd, t, env=None: RunnerResult(
                            "pnpm", ToolState.OK,
                            raw='{"metadata":{"vulnerabilities":3}}', returncode=1))
    ctx = RunContext(root=tmp_path, pkg_manager="pnpm", force_refresh=True)
    result = deps.run_js(ctx)
    assert result.state is ToolState.OK   # NOT degraded -> no forced exit 2


def test_parse_pnpm_unrecognized_shape_emits_advisory_warn(tmp_path):
    # A drifted pnpm payload -> exactly one synthetic advisory finding
    # (deps-audit-shape-unrecognized), medium severity (WARN, below the deps
    # critical block threshold) -> visible but non-blocking.
    result = RunnerResult("pnpm", ToolState.OK, raw='{"metadata":{"vulnerabilities":3}}')
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == deps.DEPS_SHAPE_DRIFT_RULE
    assert findings[0].tool == "pnpm"
    assert findings[0].severity_raw == "medium"


def test_parse_pnpm_nondict_advisories_emits_warn_not_crash(tmp_path):
    # {"advisories":"str"} previously reached _parse_advisories_dict and raised
    # on .items(); now it is an unrecognized shape -> one advisory WARN, no crash.
    result = RunnerResult("pnpm", ToolState.OK, raw='{"advisories":"not-a-dict"}')
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == deps.DEPS_SHAPE_DRIFT_RULE


def test_parse_yarn_unrecognized_shape_emits_advisory_warn(tmp_path):
    result = RunnerResult("yarn", ToolState.OK,
                          raw='{"value":"pkg@1","summary":"format changed"}\n')
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == deps.DEPS_SHAPE_DRIFT_RULE
    assert findings[0].tool == "yarn"


def test_parse_known_good_fixtures_emit_no_drift_finding(tmp_path):
    # Regression-lock: the recognized fixtures parse to their real advisories
    # ONLY -- no spurious deps-audit-shape-unrecognized finding is added.
    for tool, fixture, n in (("pnpm", PNPM_AUDIT, 1), ("yarn", YARN_AUDIT, 2), ("cargo-audit", CARGO_AUDIT, 1)):
        result = RunnerResult(tool, ToolState.OK, raw=fixture.read_text())
        findings = deps.parse(result, RunContext(root=tmp_path))
        assert len(findings) == n
        assert all(f.rule != deps.DEPS_SHAPE_DRIFT_RULE for f in findings)


def test_cargo_audit_timeout_still_carries_the_runner_name(tmp_path, monkeypatch):
    """`json_or_crashed` passed MISSING/TIMEOUT straight through, keeping the
    name `run_subprocess` derived from argv[0] -- here "cargo", because the
    runner shells out to `cargo audit`.

    That is the same wrong name clippy's timeout produced, and the two
    collide: `pipeline.degraded_tools` is a set comprehension over `r.tool`,
    so two distinct degraded Rust gates report as one entry, and
    `_write_logs` keys its filename on `r.tool`, so the second overwrites
    the first. The run where both Rust gates failed is the run whose
    evidence is half missing.
    """
    (tmp_path / "Cargo.lock").write_text("[[package]]\nname = \"x\"\n")
    monkeypatch.setattr(deps.toolpath, "resolve", lambda name: f"/fake/{name}")
    monkeypatch.setattr(
        deps, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("cargo", ToolState.TIMEOUT))

    result = deps.run_cargo(RunContext(root=tmp_path, force_refresh=True))
    assert result.state is ToolState.TIMEOUT
    assert result.tool == deps.NAME_CARGO_AUDIT


# ---------------- cargo-audit informational warnings (interop round 20) ----

CARGO_AUDIT_WARNINGS = FIXTURES / "cargo-audit-warnings.json"


def _warn_result():
    return RunnerResult(tool=deps.NAME_CARGO_AUDIT, state=ToolState.OK,
                        raw=CARGO_AUDIT_WARNINGS.read_text())


def test_cargo_warnings_are_off_by_default(tmp_path):
    """Default-off is the whole reason this is opt-in: most informational
    advisories have no fix, so on by default they are a permanent finding on
    every Rust repo. A bare RunContext must therefore produce none."""
    assert deps.parse_cargo(_warn_result(), RunContext(root=tmp_path)) == []


def test_cargo_warnings_opt_in_yields_findings_under_a_distinct_tool(tmp_path):
    """Verbatim `cargo audit --json` capture (cargo-audit 0.22.2) against a
    crate depending on ansi_term 0.12.1, which carries RUSTSEC-2021-0139
    (unmaintained). `warnings` is an object keyed by KIND whose values are
    lists -- not a flat list -- so this pins the shape as well as the opt-in.
    """
    ctx = RunContext(root=tmp_path, cargo_audit_warnings=True)
    findings = deps.parse_cargo(_warn_result(), ctx)

    assert len(findings) == 1
    f = findings[0]
    # A DISTINCT tool, not a rule namespace under cargo-audit: this is what
    # keeps it out of policy._DEPS_TOOLS (guarantee 1 of three).
    assert f.tool == deps.NAME_CARGO_AUDIT_WARNINGS
    assert f.tool != deps.NAME_CARGO_AUDIT
    assert f.rule == "unmaintained/RUSTSEC-2021-0139"
    assert f.severity_raw == "info"
    assert "ansi_term" in f.message


def test_cargo_warnings_do_not_disturb_the_vulnerability_path(tmp_path):
    """The real advisory path must be byte-identical whether the opt-in is on
    or off -- the feature adds findings, it never reclassifies existing ones.
    """
    result = RunnerResult(tool=deps.NAME_CARGO_AUDIT, state=ToolState.OK,
                          raw=CARGO_AUDIT_CVSS.read_text())
    off = deps.parse_cargo(result, RunContext(root=tmp_path))
    on = deps.parse_cargo(result, RunContext(root=tmp_path, cargo_audit_warnings=True))
    assert off == on
    assert off and all(f.tool == deps.NAME_CARGO_AUDIT for f in off)


def test_cargo_warning_without_an_advisory_falls_back_to_its_kind(tmp_path):
    """`advisory` is nullable in this wire format: a YANKED crate has no
    RUSTSEC advisory behind it, so there is no id to name the rule with. The
    kind is then the only identifier available, and it must still fingerprint
    to something stable rather than crash or produce a `None` rule."""
    raw = json.dumps({"vulnerabilities": {"count": 0, "list": []},
                      "warnings": {"yanked": [
                          {"kind": "yanked", "advisory": None,
                           "package": {"name": "ghostcrate", "version": "1.2.3"}}]}})
    ctx = RunContext(root=tmp_path, cargo_audit_warnings=True)
    findings = deps.parse_cargo(RunnerResult(deps.NAME_CARGO_AUDIT, ToolState.OK, raw=raw), ctx)

    assert len(findings) == 1
    assert findings[0].rule == "yanked"
    assert findings[0].message == "ghostcrate 1.2.3: ghostcrate is yanked"


# ---------------- python: pyproject [project] as the dependency source ----------------

PYPROJECT_WITH_DEPS = (
    "[project]\n"
    "name = \"x\"\n"
    "version = \"0.0.1\"\n"
    "dependencies = [\n"
    "  \"requests==2.25.0\",\n"
    "  \"django==3.2.0\",\n"
    "]\n"
)
TOOL_ONLY_PYPROJECT = "[tool.ruff]\nline-length = 100\n"


def test_python_sources_prefers_requirements_then_pyproject_then_nothing(tmp_path):
    assert deps.python_sources(tmp_path) == []
    (tmp_path / "pyproject.toml").write_text(TOOL_ONLY_PYPROJECT, encoding="utf-8")
    assert deps.python_sources(tmp_path) == []  # a tool-only pyproject declares no dependencies
    (tmp_path / "pyproject.toml").write_text(PYPROJECT_WITH_DEPS, encoding="utf-8")
    assert deps.python_sources(tmp_path) == [tmp_path / "pyproject.toml"]
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n", encoding="utf-8")
    assert deps.python_sources(tmp_path) == [tmp_path / "requirements.txt"]


def test_run_python_audits_the_pyproject_when_no_requirements_file_exists(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT_WITH_DEPS, encoding="utf-8")
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="pip-audit", state=ToolState.OK, raw=PIP_AUDIT.read_text())

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    result = deps.run_python(RunContext(root=tmp_path))
    assert result.state is ToolState.OK
    assert captured["argv"] == ["pip-audit", str(tmp_path), "-f", "json"]


def test_run_python_prefers_requirements_files_over_the_pyproject(tmp_path, monkeypatch):
    # pip-audit refuses `-r` together with a project path, so one source wins;
    # requirements files keep precedence to leave existing repos unchanged.
    (tmp_path / "pyproject.toml").write_text(PYPROJECT_WITH_DEPS, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n", encoding="utf-8")
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="pip-audit", state=ToolState.OK, raw=PIP_AUDIT.read_text())

    monkeypatch.setattr(deps, "run_subprocess", fake_run_subprocess)
    deps.run_python(RunContext(root=tmp_path))
    assert captured["argv"][1] == "-r"
    assert str(tmp_path) not in captured["argv"]


def test_run_python_is_missing_for_a_pyproject_without_a_project_table(tmp_path, monkeypatch):
    # pip-audit exits 1 with empty stdout on such a file, and 1 is in the OK
    # set (it means "vulnerabilities found") -- so the runner must never ask.
    (tmp_path / "pyproject.toml").write_text(TOOL_ONLY_PYPROJECT, encoding="utf-8")

    def explode(*a, **k):
        raise AssertionError("pip-audit must not be invoked")

    monkeypatch.setattr(deps, "run_subprocess", explode)
    assert deps.run_python(RunContext(root=tmp_path)).state is ToolState.MISSING


def test_parse_pip_audit_locates_a_project_mode_finding_in_the_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT_WITH_DEPS, encoding="utf-8")
    result = RunnerResult(tool="pip-audit", state=ToolState.OK, raw=PIP_AUDIT.read_text())
    findings = deps.parse(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    assert findings[0].file == "pyproject.toml"
    assert findings[0].line == 6  # the `"django==3.2.0",` entry


def test_locate_dependency_falls_back_to_requirements_line_one(tmp_path):
    """The drain confirms a mutant against the unit suite alone, and the
    no-sources fallback `("requirements.txt", 1)` was reached only through
    tests/integration."""
    assert deps._locate_dependency(tmp_path, "requests") == ("requirements.txt", 1)
    (tmp_path / "requirements.txt").write_text("flask\nRequests==2.0\n", encoding="utf-8")
    assert deps._locate_dependency(tmp_path, "requests") == ("requirements.txt", 2)
    assert deps._locate_dependency(tmp_path, "urllib3") == ("requirements.txt", 1), \
        "named nowhere: line 1 of the first source"
