import json
import subprocess
import sys
from pathlib import Path

import pytest

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


# --- file-level notices vs findings ----------------------------------------
#
# Both payloads below are copied from a live `eslint -f json` capture (v9.39.5,
# 2026-08-06) rather than reconstructed from the docs, because the whole point
# is which keys are actually present.

# eslint reports an explicitly-passed ignored file as a WARNING with no rule id
# and no position -- it is talking about the file, not about anything in it.
_IGNORE_NOTICE = {
    "ruleId": None,
    "fatal": False,
    "severity": 1,
    "message": ('File ignored because of a matching ignore pattern. Use '
                '"--no-ignore" to disable file ignore settings or use '
                '"--no-warn-ignored" to suppress this warning.'),
    "nodeType": None,
}

# A real parse error ALSO has `ruleId: null`, which is why the discriminator
# cannot be the rule id alone: this one is fatal and carries a position.
_PARSE_ERROR = {
    "ruleId": None,
    "nodeType": None,
    "fatal": True,
    "severity": 2,
    "message": "Parsing error: Unexpected token ;",
    "line": 1,
    "column": 16,
}


def _payload(tmp_path, *entries) -> str:
    return json.dumps([
        {"filePath": str(tmp_path / rel), "messages": msgs,
         "fatalErrorCount": sum(1 for m in msgs if m.get("fatal"))}
        for rel, msgs in entries
    ])


def test_ignored_file_notice_is_not_a_finding(tmp_path):
    """An ignored file must not manufacture a finding.

    `parse` mapped `msg["ruleId"] or "eslint-parse-error"`, so eslint's
    "File ignored because of a matching ignore pattern" notice -- which has a
    null ruleId -- became a WARN finding named `eslint-parse-error` on a file
    eslint deliberately declined to lint. It fingerprints and lands in the
    ledger like any other, so on pre-push it is a NEW id, and new ids are what
    the ratchet escalates to BLOCK. Adding a path to `ignores` and touching a
    file under it could therefore block the push.
    """
    result = RunnerResult(tool="eslint", state=ToolState.OK,
                          raw=_payload(tmp_path, ("skipped/hidden.js", [_IGNORE_NOTICE])))

    assert eslint.parse(result, RunContext(root=tmp_path)) == []


def test_real_parse_error_is_still_a_finding(tmp_path):
    """The notice filter must not swallow genuine parse errors -- a file that
    does not compile is exactly the kind of thing the gate exists to report."""
    result = RunnerResult(tool="eslint", state=ToolState.OK,
                          raw=_payload(tmp_path, ("src/broken.js", [_PARSE_ERROR])))

    findings = eslint.parse(result, RunContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].rule == "eslint-parse-error"
    assert findings[0].file == "src/broken.js"
    assert findings[0].line == 1


# --- examined set -----------------------------------------------------------

def test_examined_excludes_a_file_eslint_declined_to_lint(tmp_path, monkeypatch):
    """`.eslintignore` / flat-config `ignores` is eslint's version of the ruff
    `--force-exclude` hole: eslint exits cleanly having never opened the file,
    and resolution would record every open finding in it as fixed."""
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    eslint._eslint_bin(tmp_path).write_text("#!/bin/sh\n")
    raw = _payload(
        tmp_path,
        ("src/clean.js", []),
        ("src/dirty.js", [{"ruleId": "no-unused-vars", "severity": 2,
                           "message": "unused", "line": 1, "column": 7}]),
        ("skipped/hidden.js", [_IGNORE_NOTICE]),
    )
    monkeypatch.setattr(
        eslint, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("eslint", ToolState.OK, raw=raw, returncode=1))

    result = eslint.run(RunContext(root=tmp_path, files=[
        "src/clean.js", "src/dirty.js", "skipped/hidden.js"]))

    assert result.examined == frozenset({"src/clean.js", "src/dirty.js"})


def test_examined_excludes_a_file_that_failed_to_parse(tmp_path, monkeypatch):
    """eslint that could not parse a file analysed nothing in it, so it must
    not vouch for that file -- otherwise introducing a syntax error silently
    resolves every other finding in the file."""
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    eslint._eslint_bin(tmp_path).write_text("#!/bin/sh\n")
    raw = _payload(tmp_path, ("src/ok.js", []), ("src/broken.js", [_PARSE_ERROR]))
    monkeypatch.setattr(
        eslint, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("eslint", ToolState.OK, raw=raw, returncode=1))

    result = eslint.run(RunContext(root=tmp_path, files=["src/ok.js", "src/broken.js"]))

    assert result.examined == frozenset({"src/ok.js"})


def test_no_js_files_vouches_for_nothing_rather_than_the_gate_scope(tmp_path):
    """The clean no-op returned `examined=None`, which falls back to the whole
    gate file set -- so a repo whose eslint config lints `.vue`/`.svelte`
    (extensions absent from `_JS_SUFFIXES`, so `files` is empty and eslint
    never runs) had every open finding on those paths silently resolved."""
    result = eslint.run(RunContext(root=tmp_path, files=["app.py", "ui.vue"]))

    assert result.state is ToolState.OK
    assert result.examined == frozenset()


def test_degraded_run_vouches_for_nothing(tmp_path, monkeypatch):
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    eslint._eslint_bin(tmp_path).write_text("#!/bin/sh\n")
    monkeypatch.setattr(
        eslint, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("eslint", ToolState.TIMEOUT))

    result = eslint.run(RunContext(root=tmp_path, files=["a.js"]))

    assert result.state is ToolState.TIMEOUT
    assert result.examined is not None and not result.examined


def test_timeout_still_carries_the_runner_name(tmp_path, monkeypatch):
    """On win32 the binary is `eslint.cmd`, so `run_subprocess` -- which
    names results `Path(argv[0]).name` -- labels a timeout "eslint.cmd".

    `json_or_crashed` returned MISSING/TIMEOUT unchanged, so that name
    survived into the pipeline, where nothing matches it: it is not in
    `toolset.RUNNER_TOOL_NAMES` and not the "eslint" every Finding carries.
    The result is asserted here rather than the platform, so the win32 shape
    is pinned wherever the suite runs.
    """
    binp = tmp_path / "node_modules" / ".bin"
    binp.mkdir(parents=True)
    (binp / ("eslint.cmd" if sys.platform == "win32" else "eslint")).write_text("")
    monkeypatch.setattr(
        eslint, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("eslint.cmd", ToolState.TIMEOUT))

    result = eslint.run(RunContext(root=tmp_path, files=["src/app.js"]))
    assert result.state is ToolState.TIMEOUT
    assert result.tool == eslint.NAME


# --- FN-34: a command line cmd.exe refuses must never read as a clean lint --
#
# Channel round 314 (aramid 0.20.3, Windows): a whole-tree file list went
# through node_modules/.bin/eslint.cmd, cmd.exe refused the line ("The command
# line is too long.") and exited 1 -- one of eslint's accepted codes -- with
# nothing on stdout, so the run read as OK with zero findings.

def _with_bin(tmp_path):
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    binp = eslint._eslint_bin(tmp_path)
    binp.write_text("")
    return binp


def _prefix_len(tmp_path) -> int:
    return len(subprocess.list2cmdline([str(eslint._eslint_bin(tmp_path)), "-f", "json"]))


def test_exit_1_with_no_report_is_crashed_not_a_clean_lint(tmp_path, monkeypatch):
    _with_bin(tmp_path)
    monkeypatch.setattr(
        eslint, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult(
            "eslint", ToolState.OK, raw="", stderr="The command line is too long.", returncode=1))

    result = eslint.run(RunContext(root=tmp_path, files=["a.js"]))

    assert result.state is ToolState.CRASHED
    assert "too long" in result.stderr
    assert result.examined == frozenset()


def test_exit_1_with_only_warnings_is_crashed(tmp_path, monkeypatch):
    """eslint exits 1 only when it reports an error (aramid never passes
    --max-warnings), so a warnings-only report under exit 1 is not one of
    its verdicts."""
    _with_bin(tmp_path)
    raw = _payload(tmp_path, ("a.js", [{"ruleId": "no-console", "severity": 1,
                                       "message": "console", "line": 1, "column": 1}]))
    monkeypatch.setattr(
        eslint, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("eslint", ToolState.OK, raw=raw, returncode=1))

    assert eslint.run(RunContext(root=tmp_path, files=["a.js"])).state is ToolState.CRASHED


def test_exit_1_with_json_that_is_not_a_report_is_crashed(tmp_path, monkeypatch):
    _with_bin(tmp_path)
    monkeypatch.setattr(
        eslint, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("eslint", ToolState.OK, raw='{"x": 1}',
                                                    returncode=1))

    assert eslint.run(RunContext(root=tmp_path, files=["a.js"])).state is ToolState.CRASHED


def _reports_each_file(calls):
    """A stand-in eslint: one entry per file it was handed, an error in every
    file whose name starts with `dirty`, and exit 1 exactly when it reported
    an error -- eslint's own contract."""
    def fake(argv, cwd, t, env=None):
        calls.append(list(argv))
        entries = [{"filePath": str(Path(cwd) / f),
                    "messages": ([{"ruleId": "no-eval", "severity": 2, "message": "eval",
                                   "line": 1, "column": 1}]
                                 if Path(f).name.startswith("dirty") else [])}
                   for f in argv[3:]]
        rc = 1 if any(e["messages"] for e in entries) else 0
        return RunnerResult("eslint", ToolState.OK, raw=json.dumps(entries), returncode=rc)
    return fake


def test_a_long_file_list_is_linted_in_batches_that_fit_the_budget(tmp_path, monkeypatch):
    _with_bin(tmp_path)
    files = [f"src/clean_{i:02d}.js" for i in range(12)] + ["src/dirty_a.js", "src/dirty_b.js"]
    budget = _prefix_len(tmp_path) + 60
    calls = []
    monkeypatch.setattr(eslint, "run_subprocess", _reports_each_file(calls))
    monkeypatch.setattr(eslint, "_line_budget", lambda binp: budget)

    result = eslint.run(RunContext(root=tmp_path, files=files))

    assert len(calls) >= 2
    assert all(len(subprocess.list2cmdline(argv)) <= budget for argv in calls)
    assert all(argv[:3] == calls[0][:3] for argv in calls)      # same binary and flags
    assert [f for argv in calls for f in argv[3:]] == files     # every file once, in order
    assert result.state is ToolState.OK
    assert result.examined == frozenset(files)
    findings = eslint.parse(result, RunContext(root=tmp_path))
    assert sorted(f.file for f in findings) == ["src/dirty_a.js", "src/dirty_b.js"]


def test_one_failing_batch_degrades_the_whole_run(tmp_path, monkeypatch):
    """A partial OK would vouch for the files of the batches that ran and
    say nothing of the rest -- the run is degraded, vouching for nothing."""
    _with_bin(tmp_path)
    files = [f"src/f_{i:02d}.js" for i in range(10)]
    calls = []
    good = _reports_each_file(calls)

    def later_batches_fail(argv, cwd, t, env=None):
        if calls:
            calls.append(list(argv))
            return RunnerResult("eslint", ToolState.OK, raw="", stderr="boom", returncode=2)
        return good(argv, cwd, t, env)

    monkeypatch.setattr(eslint, "run_subprocess", later_batches_fail)
    monkeypatch.setattr(eslint, "_line_budget", lambda binp: _prefix_len(tmp_path) + 40)

    result = eslint.run(RunContext(root=tmp_path, files=files))

    assert len(calls) >= 2
    assert result.state is ToolState.CRASHED
    assert result.examined == frozenset()


def test_batches_are_sized_in_the_units_cmd_exe_counts():
    """cmd.exe counts UTF-16 units, so a file name with a character outside
    the BMP costs one more than its code points. Sized in code points, a
    batch one unit over the budget went out whole -- and the launcher, which
    counts units, refused it."""
    prefix = ["eslint.cmd", "-f", "json"]
    files = ["src/\U0001F600.js", "src/b.js"]

    def units(argv):
        return len(subprocess.list2cmdline(argv).encode("utf-16-le")) // 2

    budget = units([*prefix, *files]) - 1
    assert len(subprocess.list2cmdline([*prefix, *files])) == budget  # fits in code points
    batches = eslint._batches(prefix, files, budget)
    assert batches == [["src/\U0001F600.js"], ["src/b.js"]]
    assert all(units([*prefix, *b]) <= budget for b in batches)


def test_only_a_batch_file_binary_is_held_to_cmd_exe_s_limit():
    assert eslint._line_budget(Path("node_modules/.bin/eslint")) is None
    budget = eslint._line_budget(Path("node_modules/.bin/eslint.cmd"))
    assert budget is not None and budget < 8191
    assert eslint._line_budget(Path("node_modules/.bin/ESLINT.CMD")) == budget


@pytest.mark.skipif(sys.platform != "win32", reason="cmd.exe's command-line limit is a Windows property")
def test_a_whole_tree_list_through_a_real_cmd_shim_is_linted_not_refused(tmp_path):
    """Round 314 end to end through the real launcher: a stand-in eslint.cmd
    that reports nothing, handed about 25,000 characters of paths. Before the
    fix cmd.exe refused the line, exited 1, and the run read as OK."""
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "eslint.cmd").write_text("@echo off\r\necho []\r\nexit /b 0\r\n", encoding="utf-8")
    files = [f"src/components/some-fairly-long-directory-name/module_{i:04d}.ts" for i in range(400)]
    assert len(" ".join(files)) > 8191

    result = eslint.run(RunContext(root=tmp_path, files=files))

    assert result.state is ToolState.OK
    assert result.returncode == 0
    assert "too long" not in result.stderr
