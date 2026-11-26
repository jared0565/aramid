"""`doctor.probe_stack_tools`: rows for eslint, tsc and mypy, in a repo
where the gate selects them (spec 2026-11-26-doctor-stack-tool-rows).

What a row may claim is narrow, and every test asserts the whole line:
  - found means the binary is where the gate looks, shown as that path;
  - not found names that path and what a gate then does. Never
    "non-blocking": a `--strict` pre-push gate refuses the push (measured
    2026-11-26);
  - mypy is reported on the runner's own answer (`typecheck.dispatched`):
    beside a root tsconfig.json it does not run, and the row says so.
The probe starts no process: these tools belong to the repo, and whether
they RUN is the gate's to find out."""
import sys
from types import SimpleNamespace

import pytest

from aramid import detectors, pipeline, toolpath
from aramid.commands import doctor
from aramid.runners import eslint as eslint_runner
from aramid.runners import typecheck
from aramid.runners.base import ToolState

TAIL = "At pre-push it shows as a degraded tool, and a --strict gate refuses the push"
# eslint and mypy are handed files, and with none of theirs in a push they
# never look for their binary (independent review, 2026-11-26): the cost is
# stated for the pushes that pay it. tsc and the Rust tools check the whole
# project on every push, so they keep TAIL.
TAIL_JS = ("A pre-push that holds JS/TS files shows it as a degraded tool, and a --strict "
           "gate refuses that push")
TAIL_PY = ("A pre-push that holds Python files in mypy's scope shows it as a degraded "
           "tool, and a --strict gate refuses that push")
_CMD = ".cmd" if sys.platform == "win32" else ""


def _rows(root):
    return [doctor._report_line(s) for s in doctor.probe_stack_tools(root)]


def _js_repo(tmp_path, lock="package-lock.json", tsconfig=True):
    (tmp_path / "package.json").write_text('{"name": "p"}', encoding="utf-8")
    (tmp_path / "index.js").write_text("export const a = 1;\n", encoding="utf-8")
    if lock:
        (tmp_path / lock).write_text("", encoding="utf-8")
    if tsconfig:
        (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    return tmp_path


def _bin(root, name):
    path = root / "node_modules" / ".bin" / f"{name}{_CMD}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    return path


def _eslint_missing(root, pm):
    return (f"  MISSING  eslint       not found at {eslint_runner._eslint_bin(root)} -- JS/TS "
            f"lint is NOT being checked on this repo; the gate looks nowhere else, so "
            f"install eslint in this repo with {pm}. {TAIL_JS}")


def _tsc_missing(root, pm):
    return (f"  MISSING  tsc          not found at {typecheck._tsc_bin(root)} -- TypeScript "
            f"is NOT being type-checked on this repo; the gate looks nowhere else, so "
            f"install typescript in this repo with {pm}. {TAIL}")


def test_a_js_repo_with_its_tools_installed_reads_ok_with_their_paths(tmp_path):
    root = _js_repo(tmp_path)
    eslint, tsc = _bin(root, "eslint"), _bin(root, "tsc")

    assert _rows(root) == [f"  OK       eslint        ({eslint})",
                           f"  OK       tsc           ({tsc})"]


def test_missing_js_tools_name_the_root_path_and_the_gate_consequence(tmp_path):
    root = _js_repo(tmp_path)
    # A workspace member has its own eslint. The gate never looks there, so
    # doctor must not count it.
    _bin(root / "packages" / "a", "eslint")

    assert _rows(root) == [_eslint_missing(root, "npm"), _tsc_missing(root, "npm")]


@pytest.mark.parametrize("lock, pm", [("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"),
                                      (None, "your package manager"),
                                      ("Cargo.lock", "your package manager")])
def test_the_hint_names_the_detected_package_manager_or_none(tmp_path, lock, pm):
    root = _js_repo(tmp_path, lock=lock, tsconfig=False)

    assert _rows(root) == [_eslint_missing(root, pm)]


def test_mypy_configured_beside_a_tsconfig_is_reported_as_not_running(tmp_path, monkeypatch):
    root = _js_repo(tmp_path)
    (root / "mypy.ini").write_text("[mypy]\n", encoding="utf-8")
    _bin(root, "eslint")
    _bin(root, "tsc")
    monkeypatch.setattr(toolpath, "resolve", lambda name: tmp_path / "found" / name)

    assert _rows(root)[2:] == [
        "  WARN     mypy         configured, but it does NOT run in any gate: tsconfig.json "
        "is at the repo root, and the typecheck runner runs tsc alone"]
    assert len(_rows(root)) == 3


def test_a_python_repo_gets_a_mypy_row_only_with_a_mypy_config(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "p"\nversion = "1"\n',
                                             encoding="utf-8")
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    found = tmp_path / "bin" / "mypy"
    monkeypatch.setattr(toolpath, "resolve", lambda name: found)
    assert _rows(tmp_path) == []

    (tmp_path / "mypy.ini").write_text("[mypy]\n", encoding="utf-8")
    assert _rows(tmp_path) == [f"  OK       mypy          ({found})"]

    monkeypatch.setattr(toolpath, "resolve", lambda name: None)
    assert _rows(tmp_path) == [
        "  MISSING  mypy         not found on PATH -- Python is NOT being type-checked on "
        "this repo although a mypy config is present; install mypy where aramid's hooks "
        f"can find it. {TAIL_PY}"]


def test_a_package_json_with_no_js_file_gets_no_eslint_row(tmp_path):
    """A Python repo with a package.json for its tooling is on the `js`
    stack, so the gate selects eslint, and the runner then returns OK
    without looking for a binary because it is handed no file. MISSING there
    told the reader to install a linter that would lint nothing."""
    (tmp_path / "package.json").write_text('{"name": "p"}', encoding="utf-8")
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    # A dependency's JS is not the repo's: no gate hands it to eslint.
    dep = tmp_path / "node_modules" / "dep"
    dep.mkdir(parents=True)
    (dep / "index.js").write_text("", encoding="utf-8")

    assert _rows(tmp_path) == []


def _tree(root, layout):
    for rel in layout:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    return [rel for rel in layout if not rel.startswith("node_modules/")]


@pytest.mark.parametrize("layout", [
    ["package.json", "index.js"],
    ["package.json", "src/deep/App.TSX"],
    ["package.json", "m.py"],
    ["package.json", "m.py", "node_modules/dep/index.js"],
    ["pyproject.toml", "m.py", "web/index.js"],
])
def test_doctor_reports_eslint_missing_exactly_where_the_runner_would(tmp_path, layout):
    """Doctor's answer and the gate's are two computations that must agree:
    the runner, handed every file of the repo with no eslint installed, is
    MISSING exactly when doctor prints a MISSING eslint row."""
    files = _tree(tmp_path, layout)
    stacks = detectors.detect_stacks(tmp_path, tmp_path)
    ctx = SimpleNamespace(root=tmp_path, files=files, stacks=stacks)
    gate_says = (pipeline._is_applicable("eslint", ctx)
                 and eslint_runner.run(ctx).state is ToolState.MISSING)

    doctor_says = any(r.startswith("  MISSING  eslint ") for r in _rows(tmp_path))

    assert doctor_says == gate_says


def test_a_stack_probe_that_raises_leaves_the_typecheck_rows(tmp_path, monkeypatch):
    root = _js_repo(tmp_path)
    tsc = _bin(root, "tsc")

    def boom(*_args):
        raise OSError("unreadable tree")
    monkeypatch.setattr(detectors, "detect_stacks", boom)

    assert _rows(root) == [f"  OK       tsc           ({tsc})"]


def test_a_typecheck_probe_that_raises_leaves_the_eslint_row(tmp_path, monkeypatch):
    root = _js_repo(tmp_path)
    eslint = _bin(root, "eslint")

    def boom(_root):
        raise OSError("unreadable config")
    monkeypatch.setattr(typecheck, "dispatched", boom)

    assert _rows(root) == [f"  OK       eslint        ({eslint})"]


def test_the_rust_rows_say_what_a_missing_tool_costs_at_a_strict_gate(tmp_path, monkeypatch):
    """They used to end "(non-blocking: ... is not a BLOCK-tier gate)".
    Measured 2026-11-26 on a scratch crate with ~/.cargo/bin off PATH:
    `check --gate pre-push --all` exits 2 with cargo-audit and clippy
    degraded ("not found"), and with `--strict` it exits 1."""
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "p"\nversion = "0.1.0"\n',
                                         encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    monkeypatch.setattr(toolpath, "resolve", lambda name: None)

    assert [doctor._report_line(s) for s in doctor.probe_deps(tmp_path)] == [
        "  MISSING  cargo-audit  not installed -- Rust dependency advisories are NOT being "
        f"checked on this repo; `cargo install cargo-audit` to enable. {TAIL}",
        "  MISSING  clippy       not installed -- Rust lint is NOT being checked on this "
        f"repo; `rustup component add clippy` to enable. {TAIL}"]


def test_a_pyproject_that_is_not_toml_does_not_break_the_probe(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.mypy\n", encoding="utf-8")
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")

    assert _rows(tmp_path) == []
