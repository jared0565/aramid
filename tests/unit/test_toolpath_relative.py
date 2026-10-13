"""A relative PATH entry names a directory of the repo aramid is judging
(FN-48). aramid's current directory is that repo, so `bin`, `./bin` or `.` on
PATH make its files programs. Measured 2026-10-12 on 0.20.9: a relative `bin`
FIRST on PATH answered every lookup with a file of the repo's, and LAST it
still answered `gitleaks`, which aramid keeps only in its own tools directory
and so finds after PATH.

The operator's decision: aramid's own tools -- whatever is in its tools
directory, and its declared dependencies (ruff, semgrep, pip-audit) where a
scripts directory holds them -- are never supplied by a relative entry, and
`aramid doctor` warns about every relative entry. Other programs, an absolute
entry (an activated venv inside the repo is one) and the order of PATH are
left as they are."""
import os
import shutil

import pytest

from aramid import toolpath
from aramid.commands import doctor

_OWN = "aramid-fn48-own"         # in the tools directory, as gitleaks is
_DEP = "ruff"                     # a declared dependency
_OTHER = "aramid-fn48-other"      # nobody's own


def _program(directory, name):
    """A file the platform's lookup takes for the program `name`: `name.cmd`
    on Windows, `name` with its x bit anywhere else."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (f"{name}.cmd" if os.name == "nt" else name)
    path.write_text("@echo off\r\n" if os.name == "nt" else "#!/bin/sh\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o755)
    return path


def _copy(directory, name):
    """A copy where aramid keeps its own: `name.exe` on Windows, as
    `resolve` looks for it there."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / toolpath.exe_name(name)
    path.write_text("not run", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o755)
    return path


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """The current directory is a repo with a `bin` of planted programs. The
    tools and scripts directories are scratch ones; PATH is set per test,
    with nothing on it but what the test names."""
    here = tmp_path / "repo"
    here.mkdir()
    monkeypatch.chdir(here)
    monkeypatch.setenv("NoDefaultCurrentDirectoryInExePath", "1")
    tools, scripts = tmp_path / "tools", tmp_path / "scripts"
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tools)
    monkeypatch.setattr(toolpath, "scripts_dirs", lambda: [scripts])
    return here, tools, scripts


def _path(monkeypatch, *entries):
    monkeypatch.setenv("PATH", os.pathsep.join(str(e) for e in entries))


def _planted_hit(name, planted):
    """The control: the platform's own lookup names the planted file. Without
    it the assertions below could pass where nothing reached the repo."""
    hit = shutil.which(name)
    assert hit is not None and os.path.samefile(hit, planted), hit


# --------------------------------------------- aramid's own tools are guarded --

@pytest.mark.parametrize("entry", ["bin", os.path.join(os.curdir, "bin")])
@pytest.mark.parametrize("where", ["first", "last"])
def test_a_relative_entry_never_supplies_a_program_of_the_tools_directory(
        repo, monkeypatch, tmp_path, entry, where):
    here, tools, _scripts = repo
    planted, own = _program(here / "bin", _OWN), _copy(tools, _OWN)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _path(monkeypatch, *([entry, elsewhere] if where == "first" else [elsewhere, entry]))
    _planted_hit(_OWN, planted)

    assert toolpath.which(_OWN) is None
    assert toolpath.resolve(_OWN) == own


def test_a_relative_entry_never_supplies_a_declared_dependency_a_scripts_directory_holds(
        repo, monkeypatch):
    here, _tools, scripts = repo
    planted, own = _program(here / "bin", _DEP), _copy(scripts, _DEP)
    _path(monkeypatch, "bin")
    _planted_hit(_DEP, planted)

    assert toolpath.which(_DEP) is None
    assert toolpath.resolve(_DEP) == own


def test_dot_on_path_never_supplies_one_of_aramids_own_tools(repo, monkeypatch):
    """FN-46 kept `.` on PATH as the operator's own choice. For aramid's own
    tools it no longer is: the file of the repo is not the tool."""
    here, tools, _scripts = repo
    planted, own = _program(here, _OWN), _copy(tools, _OWN)
    _path(monkeypatch, os.curdir)
    _planted_hit(_OWN, planted)

    assert toolpath.which(_OWN) is None
    assert toolpath.resolve(_OWN) == own


def test_an_absolute_entry_after_the_relative_one_still_wins(repo, monkeypatch, tmp_path):
    """PATH first, as ever, among the entries that may supply the tool: the
    relative entry is passed over, not PATH."""
    here, tools, _scripts = repo
    planted, _own = _program(here / "bin", _OWN), _copy(tools, _OWN)
    on_path = _program(tmp_path / "abs", _OWN)
    _path(monkeypatch, "bin", tmp_path / "abs")
    _planted_hit(_OWN, planted)

    assert os.path.samefile(toolpath.which(_OWN), on_path)
    assert os.path.samefile(toolpath.resolve(_OWN), on_path)


def test_the_walk_past_a_relative_entry_never_reaches_the_current_directory(
        repo, monkeypatch, tmp_path):
    """With the lookup's own reach into the current directory back on, a
    file there is still not the tool, and neither is the relative entry's."""
    here, tools, _scripts = repo
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    _program(here, _OWN)
    _program(here / "bin", _OWN)
    own = _copy(tools, _OWN)
    empty = tmp_path / "empty"
    empty.mkdir()
    _path(monkeypatch, "bin", empty)

    assert toolpath.which(_OWN) is None
    assert toolpath.resolve(_OWN) == own


# ------------------------------------------------------ everything else as was --

def test_a_relative_entry_still_supplies_a_program_that_is_not_aramids_own(
        repo, monkeypatch):
    here, _tools, _scripts = repo
    planted = _program(here / "bin", _OTHER)
    _path(monkeypatch, "bin")
    _planted_hit(_OTHER, planted)

    assert os.path.samefile(toolpath.which(_OTHER), planted)
    assert toolpath.resolve(_OTHER) == planted.resolve()


def test_a_program_in_a_scripts_directory_that_aramid_does_not_declare_is_not_guarded(
        repo, monkeypatch):
    """A scripts directory holds pytest, python and pip as well as aramid's
    dependencies. A relative entry may still supply those, as today."""
    here, _tools, scripts = repo
    planted = _program(here / "bin", _OTHER)
    _copy(scripts, _OTHER)
    _path(monkeypatch, "bin")
    _planted_hit(_OTHER, planted)

    assert os.path.samefile(toolpath.which(_OTHER), planted)


def test_an_absolute_entry_inside_the_repo_still_supplies_aramids_own_tool(
        repo, monkeypatch):
    """An activated venv inside the repo is an absolute entry: the user's own
    statement, and left alone."""
    here, tools, _scripts = repo
    venv = here / ".venv" / ("Scripts" if os.name == "nt" else "bin")
    planted = _program(venv, _OWN)
    _copy(tools, _OWN)
    _path(monkeypatch, venv)

    assert os.path.samefile(toolpath.which(_OWN), planted)
    assert os.path.samefile(toolpath.resolve(_OWN), planted)


def test_with_no_relative_entry_nothing_changes(repo, monkeypatch, tmp_path):
    _here, tools, _scripts = repo
    on_path = _program(tmp_path / "abs", _OWN)
    _copy(tools, _OWN)
    _path(monkeypatch, tmp_path / "abs")

    assert os.path.samefile(toolpath.which(_OWN), on_path)


# ------------------------------------------------------- doctor says it --

def test_the_relative_entries_are_named_in_order_once_each(monkeypatch, tmp_path):
    absolute = str(tmp_path / "abs")
    _path(monkeypatch, "bin", absolute, os.curdir, "", os.path.join(os.curdir, "x"), "bin")

    assert toolpath.relative_path_entries() == ["bin", os.curdir, os.path.join(os.curdir, "x")]


def test_doctor_warns_once_for_each_relative_entry(monkeypatch, tmp_path):
    _path(monkeypatch, "bin", str(tmp_path / "abs"), os.curdir)

    assert doctor.relative_path_lines() == [
        "  WARN     PATH         relative entry `bin`: it names a directory of the repo"
        " aramid is judging, which can supply any program but aramid's own tools --"
        " make it absolute or remove it",
        "  WARN     PATH         relative entry `.`: it names a directory of the repo"
        " aramid is judging, which can supply any program but aramid's own tools --"
        " make it absolute or remove it",
    ]


def test_doctor_is_quiet_for_an_activated_venv_and_an_empty_entry(monkeypatch, tmp_path):
    """An empty entry names no directory to aramid's lookups (FN-46)."""
    _path(monkeypatch, str(tmp_path / ".venv" / "Scripts"), "", str(tmp_path / "abs"))

    assert doctor.relative_path_lines() == []


def test_cmd_doctor_actually_prints_the_warning_and_keeps_its_exit_code(
        tmp_path, monkeypatch, capsys):
    """The helper being right is worth nothing if `cmd_doctor` never calls
    it; and a warning is advice, so the exit code is what it was without it."""
    line = "  WARN     PATH         relative entry `bin`: (stand-in)"
    monkeypatch.setattr(doctor, "relative_path_lines", lambda: [])
    without = doctor.cmd_doctor(tmp_path)
    capsys.readouterr()
    monkeypatch.setattr(doctor, "relative_path_lines", lambda: [line])

    with_it = doctor.cmd_doctor(tmp_path)

    assert line in capsys.readouterr().out.splitlines()
    assert with_it == without
