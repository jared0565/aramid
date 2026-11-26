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

import pytest

from aramid import detectors, toolpath
from aramid.commands import doctor
from aramid.runners import eslint as eslint_runner
from aramid.runners import typecheck

TAIL = "At pre-push it shows as a degraded tool, and a --strict gate refuses the push"
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
            f"install eslint in this repo with {pm}. {TAIL}")


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
        f"can find it. {TAIL}"]


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


def test_a_pyproject_that_is_not_toml_does_not_break_the_probe(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.mypy\n", encoding="utf-8")
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")

    assert _rows(tmp_path) == []
