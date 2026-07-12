import json
import sys
from pathlib import Path

from aramid.runners import eslint
from aramid.runners.base import RunContext, RunnerResult, ToolState

FIXTURE = Path(__file__).parent.parent / "fixtures" / "eslint.json"


def test_parse_fixture_yields_finding():
    result = RunnerResult(tool="eslint", state=ToolState.OK, raw=FIXTURE.read_text())
    ctx = RunContext(root=Path("."), files=["src/app.js"])

    findings = eslint.parse(result, ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "eslint"
    assert f.rule == "no-eval"
    assert f.file.endswith("app.js")
    assert "\\" not in f.file  # forward-slash pathspec for git
    assert f.line == 4
    assert f.severity_raw == "2"
    assert "eval" in f.message


def test_parse_relativizes_absolute_path_against_root(tmp_path):
    """Real ESLint reports absolute filePath; the normalizer needs a
    root-relative, forward-slash path to hand to `git show <ref>:<path>`."""
    abs_file = tmp_path / "src" / "app.js"
    payload = [{
        "filePath": str(abs_file),
        "messages": [{"ruleId": "no-eval", "severity": 2, "message": "bad", "line": 1, "column": 1}],
    }]
    result = RunnerResult(tool="eslint", state=ToolState.OK, raw=json.dumps(payload))
    ctx = RunContext(root=tmp_path)

    findings = eslint.parse(result, ctx)

    assert findings[0].file == "src/app.js"


def test_parse_empty_is_no_findings():
    result = RunnerResult(tool="eslint", state=ToolState.OK, raw="[]")
    assert eslint.parse(result, RunContext(root=Path("."))) == []


def test_parse_skips_non_ok_state():
    result = RunnerResult(tool="eslint", state=ToolState.MISSING)
    assert eslint.parse(result, RunContext(root=Path("."))) == []


def test_resolves_repo_local_binary_windows_cmd(tmp_path):
    binp = eslint._eslint_bin(tmp_path)
    assert binp.parent == tmp_path / "node_modules" / ".bin"
    if sys.platform == "win32":
        assert binp.name == "eslint.cmd"
    else:
        assert binp.name == "eslint"


def test_run_is_missing_when_no_local_eslint_never_falls_back_to_global(tmp_path):
    # node_modules/.bin/eslint(.cmd) does not exist under tmp_path
    ctx = RunContext(root=tmp_path, files=["a.js"])
    result = eslint.run(ctx)
    assert result.state is ToolState.MISSING


def test_run_uses_resolved_local_binary_argv(tmp_path, monkeypatch):
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    binp = eslint._eslint_bin(tmp_path)
    binp.write_text("#!/bin/sh\n")

    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="eslint", state=ToolState.OK, raw="[]")

    monkeypatch.setattr(eslint, "run_subprocess", fake_run_subprocess)
    ctx = RunContext(root=tmp_path, files=["a.js", "b.js"])
    result = eslint.run(ctx)

    assert result.state is ToolState.OK
    assert captured["argv"][0] == str(binp)
    assert "-f" in captured["argv"] and "json" in captured["argv"]
    assert captured["argv"][-2:] == ["a.js", "b.js"]


def test_run_filters_to_js_family_files_only(tmp_path, monkeypatch):
    """ctx.files is the gate's WHOLE file set; eslint must only be handed
    JS/TS-family paths (same live-CI bug class as the ruff adapter feeding
    YAML to a Python parser)."""
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    binp = eslint._eslint_bin(tmp_path)
    binp.write_text("#!/bin/sh\n")

    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="eslint", state=ToolState.OK, raw="[]")

    monkeypatch.setattr(eslint, "run_subprocess", fake_run_subprocess)
    ctx = RunContext(root=tmp_path, files=[
        "a.js", "app.py", "conf.yml", "web.tsx", "README.md", "mod.mjs",
    ])
    eslint.run(ctx)

    assert captured["argv"][-3:] == ["a.js", "web.tsx", "mod.mjs"]


def test_run_no_js_files_is_clean_noop_even_without_binary(tmp_path):
    """A JS-stack repo whose current diff touches no JS/TS files must get a
    clean no-op, NOT a MISSING degradation -- checked before the binary
    lookup (no node_modules/.bin/eslint exists under tmp_path here)."""
    result = eslint.run(RunContext(root=tmp_path, files=["app.py", "conf.yml"]))
    assert result.state is ToolState.OK
    assert eslint.parse(result, RunContext(root=tmp_path)) == []


def test_run_unparseable_output_is_crashed(tmp_path, monkeypatch):
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    eslint._eslint_bin(tmp_path).write_text("#!/bin/sh\n")
    monkeypatch.setattr(
        eslint, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="eslint", state=ToolState.OK, raw="not json", stderr="boom"),
    )
    result = eslint.run(RunContext(root=tmp_path, files=["a.js"]))
    assert result.state is ToolState.CRASHED


def test_run_empty_output_with_error_returncode_is_crashed(tmp_path, monkeypatch):
    """Empty stdout parses fine as '[]' -- without a returncode check this
    would silently read as a clean 'zero findings' run even though eslint
    exited 2 (its documented fatal-error code) before producing a report."""
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    eslint._eslint_bin(tmp_path).write_text("#!/bin/sh\n")
    monkeypatch.setattr(
        eslint, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="eslint", state=ToolState.OK, raw="", stderr="fatal config error", returncode=2),
    )
    result = eslint.run(RunContext(root=tmp_path, files=["a.js"]))
    assert result.state is ToolState.CRASHED
