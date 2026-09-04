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
from pathlib import Path

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
