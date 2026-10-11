"""`[tests].command` argv: a relative argv[0] with a path separator is
anchored to the repo root.

Interop round 174: graphite's `[tests].command` names its dev-venv
interpreter by a repo-relative path. The gate happens to run with the repo
root as its cwd, so the path resolved there by accident. The scheduled drain
runs from wherever the scheduler started it (no Start In) and launches into
a throwaway worktree, so the same path resolved against neither -- 43
`baseline failing` rows over three weeks, none of which started a process.
"""
import os
import sys
from pathlib import Path

import pytest

from aramid.runners import tests as tests_runner


def _launcher(root: Path) -> str:
    d = root / "tools"
    d.mkdir()
    if os.name == "nt":
        p = d / "py.cmd"
        p.write_text("@echo off\r\npython %*\r\n", encoding="utf-8")
    else:
        p = d / "py"
        p.write_text("#!/bin/sh\nexec python \"$@\"\n", encoding="utf-8")
        p.chmod(0o755)
    return "tools/" + p.name


def test_relative_argv0_with_a_separator_is_anchored_to_root(tmp_path, monkeypatch):
    rel = _launcher(tmp_path)
    # A cwd where the relative path does NOT resolve -- the drain's shape.
    monkeypatch.chdir(tmp_path / "tools")
    argv = tests_runner._argv([rel, "-m", "pytest"], tmp_path)
    assert argv[0] == str((tmp_path / rel).resolve())
    assert argv[1:] == ["-m", "pytest"]


def test_bare_names_and_absolute_paths_are_left_alone(tmp_path):
    assert tests_runner._argv(["python", "-m", "pytest"], tmp_path) == \
        ["python", "-m", "pytest"]
    absolute = str((tmp_path / "somewhere" / "python").resolve())
    assert tests_runner._argv([absolute, "-q"], tmp_path) == [absolute, "-q"]


def test_a_relative_path_that_does_not_exist_under_root_is_left_for_resolve(tmp_path):
    # MISSING is the runner's verdict to give; anchoring must not invent a file.
    assert tests_runner._argv("./nope/python -q", tmp_path) == ["./nope/python", "-q"]


def test_without_a_root_the_old_behaviour_holds(tmp_path):
    rel = _launcher(tmp_path)
    assert tests_runner._argv([rel, "-q"]) == [rel, "-q"]


# --- the extension a Windows command leaves out ---------------------------
#
# These run on every platform: the platform and PATHEXT are the test's own,
# and each file is written with its extension in the case PATHEXT has it, for
# a file system that tells case apart.

@pytest.fixture
def as_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("PATHEXT", ".exe;.cmd")


def _files(root: Path, *rels: str) -> None:
    for rel in rels:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("", encoding="utf-8")


def test_on_windows_a_name_without_its_extension_is_anchored_to_the_file_it_starts(
        tmp_path, monkeypatch, as_windows):
    """`.venv/Scripts/python` is python.exe there and `tools/run` is run.cmd.
    No file has the name the command uses, so nothing was anchored, and the
    name was looked up from the directory aramid's process was started in:
    the drain's `baseline failing` again, and through MCP the working tree's
    copy of a committed launcher (the review of 3697181)."""
    _files(tmp_path, "tools/run.cmd", "tools/go.v2.cmd")
    monkeypatch.chdir(tmp_path / "tools")     # a cwd where the path does not resolve

    assert tests_runner._argv(["tools/run", "-q"], tmp_path) == [
        str((tmp_path / "tools" / "run.cmd").resolve()), "-q"]
    # The extension is added to the whole name, as Windows adds it.
    assert tests_runner._argv(["tools/go.v2"], tmp_path) == [
        str((tmp_path / "tools" / "go.v2.cmd").resolve())]


def test_the_extensions_are_tried_in_the_order_pathext_has_them(tmp_path, as_windows):
    _files(tmp_path, "tools/run.cmd", "tools/run.exe")

    assert tests_runner._argv(["tools/run"], tmp_path) == [
        str((tmp_path / "tools" / "run.exe").resolve())]


def test_a_file_of_the_very_name_is_taken_before_any_extension(tmp_path, as_windows):
    _files(tmp_path, "tools/run", "tools/run.exe")

    assert tests_runner._argv(["tools/run"], tmp_path) == [
        str((tmp_path / "tools" / "run").resolve())]


def test_no_extension_is_added_on_another_platform(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("PATHEXT", ".exe;.cmd")
    _files(tmp_path, "tools/run.cmd")

    assert tests_runner._argv(["tools/run", "-q"], tmp_path) == ["tools/run", "-q"]


def test_pathext_is_read_as_windows_writes_it(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("PATHEXT", ".COM;.EXE;;.BAT")
    assert tests_runner._program_extensions() == [".COM", ".EXE", ".BAT"]
    monkeypatch.delenv("PATHEXT")
    assert tests_runner._program_extensions() == [".COM", ".EXE", ".BAT", ".CMD"]
