import sys
from pathlib import Path

from aramid.runners import typecheck
from aramid.runners.base import RunContext, RunnerResult, ToolState

TSC_FIXTURE = Path(__file__).parent.parent / "fixtures" / "tsc.txt"
MYPY_FIXTURE = Path(__file__).parent.parent / "fixtures" / "mypy.txt"


def _repo(tmp_path, *, tsconfig=False, mypy_ini=False, mypy_pyproject=False):
    if tsconfig:
        (tmp_path / "tsconfig.json").write_text("{}")
    if mypy_ini:
        (tmp_path / "mypy.ini").write_text("[mypy]\n")
    if mypy_pyproject:
        (tmp_path / "pyproject.toml").write_text("[tool.mypy]\nstrict = true\n")
    return tmp_path


# ---- tsc text parsing ----

def test_parse_tsc_fixture_yields_two_findings():
    result = RunnerResult(tool="tsc", state=ToolState.OK, raw=TSC_FIXTURE.read_text())
    ctx = RunContext(root=Path("."))
    findings = typecheck.parse_tsc(result, ctx)
    assert len(findings) == 2
    f0 = findings[0]
    assert f0.tool == "tsc"
    assert f0.rule == "TS2322"
    assert f0.file == "src/app.ts"
    assert f0.line == 10
    assert "not assignable" in f0.message
    assert findings[1].rule == "TS2554"


def test_parse_tsc_ignores_summary_lines():
    result = RunnerResult(tool="tsc", state=ToolState.OK, raw="Found 2 errors in 2 files.\n")
    assert typecheck.parse_tsc(result, RunContext(root=Path("."))) == []


# ---- mypy text parsing ----

def test_parse_mypy_fixture_skips_notes_keeps_errors():
    result = RunnerResult(tool="mypy", state=ToolState.OK, raw=MYPY_FIXTURE.read_text())
    ctx = RunContext(root=Path("."))
    findings = typecheck.parse_mypy(result, ctx)
    assert len(findings) == 2  # the "note:" line must not become a finding
    assert findings[0].rule == "arg-type"
    assert findings[0].file == "app.py"
    assert findings[0].line == 10
    assert findings[0].severity_raw == "error"
    assert findings[1].rule == "name-defined"
    assert findings[1].file == "utils.py"


def test_parse_generic_skips_non_ok_state():
    result = RunnerResult(tool="tsc", state=ToolState.MISSING)
    assert typecheck.parse(result, RunContext(root=Path("."))) == []
    result = RunnerResult(tool="mypy", state=ToolState.MISSING)
    assert typecheck.parse(result, RunContext(root=Path("."))) == []


# ---- config-presence dispatch ----

def test_has_tsconfig_true_when_present(tmp_path):
    _repo(tmp_path, tsconfig=True)
    assert typecheck.has_tsconfig(tmp_path) is True


def test_has_mypy_config_true_for_mypy_ini(tmp_path):
    _repo(tmp_path, mypy_ini=True)
    assert typecheck.has_mypy_config(tmp_path) is True


def test_has_mypy_config_true_for_pyproject_tool_mypy(tmp_path):
    _repo(tmp_path, mypy_pyproject=True)
    assert typecheck.has_mypy_config(tmp_path) is True


def test_has_mypy_config_false_when_pyproject_has_no_mypy_section(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 100\n")
    assert typecheck.has_mypy_config(tmp_path) is False


def test_has_mypy_config_false_when_nothing_present(tmp_path):
    assert typecheck.has_mypy_config(tmp_path) is False


def test_run_dispatches_to_tsc_when_tsconfig_present(tmp_path, monkeypatch):
    _repo(tmp_path, tsconfig=True)
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    typecheck._tsc_bin(tmp_path).write_text("#!/bin/sh\n")

    monkeypatch.setattr(
        typecheck, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="tsc", state=ToolState.OK, raw=""),
    )
    result = typecheck.run(RunContext(root=tmp_path))
    assert result.tool == "tsc"
    assert result.state is ToolState.OK


def test_run_tsc_relabels_windows_cmd_suffix_so_parse_still_finds_the_error(
        tmp_path, monkeypatch):
    """T-8 section 11 (corrects the spec's own section 11.1, which framed
    this as resolve-only). run_subprocess derives RunnerResult.tool from
    argv[0]'s basename ("tsc.cmd" on win32, via _tsc_bin). typecheck.parse()
    dispatches on `result.tool == NAME_TSC` ("tsc") -- so an UNRELABELED
    Windows-shaped result makes parse_tsc unreachable and a real TS error is
    silently dropped, not merely stranded in the ledger.

    Proven by mocking run_subprocess to return EXACTLY the shape it produces
    on win32 (tool="tsc.cmd") regardless of the host platform actually
    running this test -- so it fails on every CI leg pre-fix, not only a
    Windows one, and it exercises run_tsc's REAL relabeling logic rather
    than a hand-built RunnerResult that would trivially agree either way."""
    _repo(tmp_path, tsconfig=True)
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    typecheck._tsc_bin(tmp_path).write_text("#!/bin/sh\n")
    real_ts_error = ("src/app.ts(10,5): error TS2322: Type 'string' is not "
                      "assignable to type 'number'.\n")
    monkeypatch.setattr(
        typecheck, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="tsc.cmd", state=ToolState.OK, raw=real_ts_error, returncode=2),
    )

    result = typecheck.run_tsc(RunContext(root=tmp_path))
    findings = typecheck.parse(result, RunContext(root=tmp_path))

    assert result.tool == typecheck.NAME_TSC, (
        "run_tsc must relabel to NAME_TSC regardless of argv[0]'s basename")
    assert len(findings) == 1
    assert findings[0].rule == "TS2322"
    assert findings[0].file == "src/app.ts"


def test_run_tsc_relabels_even_on_timeout(tmp_path, monkeypatch):
    """The relabel must be unconditional -- run_subprocess's TIMEOUT path
    ALSO carries argv[0]'s basename, not just the OK path."""
    _repo(tmp_path, tsconfig=True)
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    typecheck._tsc_bin(tmp_path).write_text("#!/bin/sh\n")
    monkeypatch.setattr(
        typecheck, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="tsc.cmd", state=ToolState.TIMEOUT),
    )
    result = typecheck.run_tsc(RunContext(root=tmp_path))
    assert result.tool == typecheck.NAME_TSC
    assert result.state is ToolState.TIMEOUT


def test_run_dispatches_to_mypy_when_no_tsconfig_but_mypy_configured(tmp_path, monkeypatch):
    _repo(tmp_path, mypy_ini=True)
    monkeypatch.setattr(
        typecheck, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="mypy", state=ToolState.OK, raw=""),
    )
    result = typecheck.run(RunContext(root=tmp_path))
    assert result.tool == "mypy"
    assert result.state is ToolState.OK


def test_run_missing_when_neither_configured(tmp_path):
    result = typecheck.run(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING


def test_run_tsc_missing_when_no_local_binary_never_falls_back_to_global(tmp_path):
    _repo(tmp_path, tsconfig=True)
    result = typecheck.run_tsc(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING


def test_tsc_bin_name_is_platform_aware(tmp_path):
    binp = typecheck._tsc_bin(tmp_path)
    assert binp.parent == tmp_path / "node_modules" / ".bin"
    assert binp.name == ("tsc.cmd" if sys.platform == "win32" else "tsc")


def test_run_mypy_argv(tmp_path, monkeypatch):
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="mypy", state=ToolState.OK, raw="")

    monkeypatch.setattr(typecheck, "run_subprocess", fake_run_subprocess)
    typecheck.run_mypy(RunContext(root=tmp_path, files=["a.py"]))
    argv = captured["argv"]
    assert argv[0] == "mypy"
    assert "--no-error-summary" in argv
    assert "--show-column-numbers" in argv
    assert "a.py" in argv


# --- mypy is handed ONLY Python files (graphite, interop round 139 s1) --------

def test_run_mypy_hands_mypy_only_python_files(tmp_path, monkeypatch):
    """`ctx.files` is the gate's whole file set, and mypy tokenises whatever
    path it is given as Python. Measured by graphite on its own gate: a lone
    `ci.yml` in range became a BLOCK-tier `mypy:syntax` on its first
    tokenizer error ("Leading zeros in decimal integer literals"), while two
    non-Python files made mypy bail on a duplicate `__main__` before parsing
    and the push passed. Same edit, opposite verdicts, decided by what else
    was in the range. Mirror of the ruff runner's `_py_files` scoping."""
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="mypy", state=ToolState.OK, raw="")
    monkeypatch.setattr(typecheck, "run_subprocess", fake_run_subprocess)

    typecheck.run_mypy(RunContext(root=tmp_path, files=[
        "a.py", ".github/workflows/ci.yml", "CONTRIBUTING.md", "pkg/b.pyi", "Makefile"]))

    assert captured["argv"][-2:] == ["a.py", "pkg/b.pyi"], captured["argv"]
    assert not [p for p in captured["argv"] if p.endswith((".yml", ".md")) or p == "Makefile"]


def test_run_mypy_with_no_python_in_range_is_a_clean_no_op(tmp_path, monkeypatch):
    """No invocation at all: mypy given zero paths would fall back to its
    config's `files=` (or complain), and either way it would be a run that
    examined none of the range. OK, and vouching for nothing -- the empty
    set, not None, so nothing resolves off a run that never looked."""
    calls = []

    def fake_run_subprocess(*a, **k):
        calls.append(a)
        return RunnerResult("mypy", ToolState.OK, raw="")
    monkeypatch.setattr(typecheck, "run_subprocess", fake_run_subprocess)

    result = typecheck.run_mypy(RunContext(root=tmp_path, files=[".github/workflows/ci.yml"]))

    assert calls == [], "a no-op must not invoke mypy"
    assert result.tool == typecheck.NAME_MYPY and result.state is ToolState.OK
    assert result.examined == frozenset()
    assert typecheck.parse(result, RunContext(root=tmp_path, files=[])) == []


def test_run_mypy_vouches_only_for_the_files_it_was_handed(tmp_path, monkeypatch):
    """Interop round 149 s1: two `mypy:syntax` rows recorded against `ci.yml`
    and `README.md` were written `fixed` by pushes that carried `.py` files
    beside them. `_examined_by_tool` is keyed by the result's tool, and a
    real mypy run came back from `run_subprocess` with `examined=None` -- so
    resolution fell back to the gate's whole file scope and credited mypy
    for files it never opened. 8650958 stamped the empty set on the no-op
    branch only. The real run must vouch for exactly the paths in its argv,
    as ruff does: a non-Python row can then never resolve off a mypy run."""
    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        return RunnerResult(tool="mypy", state=ToolState.OK, raw="")
    monkeypatch.setattr(typecheck, "run_subprocess", fake_run_subprocess)

    result = typecheck.run_mypy(RunContext(root=tmp_path, files=[
        "a.py", ".github/workflows/ci.yml", "pkg/b.pyi", "README.md"]))

    assert result.examined == frozenset({"a.py", "pkg/b.pyi"})


# --- mypy's OWN scope: `[tool.mypy] files` / `exclude` -------------------------
# Interop round 149 (b): a consumer whose `[tool.mypy] files = ["src/graphite"]`
# deliberately leaves tests/, scripts/ and benchmarks/ untyped got 786
# block-tier `mypy` findings from a whole-tree gate run, because the runner
# handed mypy every .py in range regardless of the repo's own type gate.
# The slot now honours that scope, read from the same config it already
# keys applicability on, so what the gate types is what the repo types.

def test_mypy_scope_reads_files_and_exclude_from_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.mypy]\nfiles = ["src/pkg", "tools/run.py"]\nexclude = "src/pkg/vendored/"\n',
        encoding="utf-8")
    scope = typecheck.mypy_scope(tmp_path)
    assert scope is not None
    assert typecheck.in_mypy_scope("src/pkg/a.py", scope) is True
    assert typecheck.in_mypy_scope("tools/run.py", scope) is True
    assert typecheck.in_mypy_scope("tests/test_a.py", scope) is False
    assert typecheck.in_mypy_scope("src/pkg/vendored/x.py", scope) is False, "exclude is a regex, as mypy reads it"


def test_mypy_scope_accepts_the_comma_string_form_and_mypy_ini(tmp_path):
    (tmp_path / "mypy.ini").write_text("[mypy]\nfiles = src, scripts/one.py\n", encoding="utf-8")
    scope = typecheck.mypy_scope(tmp_path)
    assert typecheck.in_mypy_scope("src/deep/b.py", scope) is True
    assert typecheck.in_mypy_scope("scripts/one.py", scope) is True
    assert typecheck.in_mypy_scope("scripts/two.py", scope) is False


def test_mypy_scope_is_none_without_a_files_setting(tmp_path):
    """No `files` means mypy's own default -- whatever it is handed -- so the
    runner keeps handing it every Python file in range."""
    (tmp_path / "pyproject.toml").write_text("[tool.mypy]\nstrict = true\n", encoding="utf-8")
    assert typecheck.mypy_scope(tmp_path) is None


def test_run_mypy_hands_mypy_only_the_paths_inside_its_own_scope(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[tool.mypy]\nfiles = ["src"]\n', encoding="utf-8")
    captured = {}

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult(tool="mypy", state=ToolState.OK, raw="")
    monkeypatch.setattr(typecheck, "run_subprocess", fake_run_subprocess)

    result = typecheck.run_mypy(RunContext(root=tmp_path, files=[
        "src/a.py", "tests/test_a.py", "scripts/b.py"]))

    assert [p for p in captured["argv"] if not p.startswith("--")][1:] == ["src/a.py"]
    assert result.examined == frozenset({"src/a.py"}), "it vouches only for what its scope let it see"


def test_run_mypy_with_nothing_inside_its_scope_is_the_clean_no_op(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[tool.mypy]\nfiles = ["src"]\n', encoding="utf-8")
    calls = []
    monkeypatch.setattr(typecheck, "run_subprocess", lambda *a, **k: calls.append(a) or RunnerResult("mypy", ToolState.OK, raw=""))

    result = typecheck.run_mypy(RunContext(root=tmp_path, files=["tests/test_a.py"]))

    assert calls == []
    assert result.state is ToolState.OK and result.examined == frozenset()
