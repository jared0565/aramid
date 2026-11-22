"""A program planted at the repo root that a bare `python` launched through
cmd.exe runs instead (interop round 339).

`aramid init` writes `python -P -m aramid.mcp` into .mcp.json and `python -P -m
aramid agent-hook ...` into .claude/settings.json. `-P` keeps a planted
`aramid.py` from being imported; it does nothing about which `python` starts.
cmd.exe looks in its current directory before PATH, for the name with each
PATHEXT extension, unless NoDefaultCurrentDirectoryInExePath is set. Measured
2026-11-22 in a scratch directory: with the variable unset, `cmd.exe /c python
--version` there ran a planted `python.cmd`; with it set, or with no shell, the
real python ran. Operator decision the same day: doctor and status flag it.
"""
import sys

from aramid import toolpath
from aramid.commands import doctor
from aramid.commands import status as status_mod


def _windows(monkeypatch, pathext=".COM;.EXE;.BAT;.CMD"):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("PATHEXT", pathext)


def test_the_files_a_cmd_exe_launch_of_python_would_run_are_named(tmp_path, monkeypatch):
    _windows(monkeypatch)
    for name in ("python.cmd", "Python.BAT", "python.py", "python", "pythonw.exe"):
        (tmp_path / name).write_text("@echo planted\n", encoding="ascii")
    (tmp_path / "python.exe").mkdir()          # a directory is not a program
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "python.com").write_text("x", encoding="ascii")

    assert toolpath.cwd_shadows(tmp_path, "python") == ["Python.BAT", "python.cmd"]


def test_pathext_decides_which_extensions_count(tmp_path, monkeypatch):
    """cmd.exe reads PATHEXT, so a `python.js` runs where .JS is listed."""
    _windows(monkeypatch, ".COM;.EXE;.BAT;.CMD;.JS")
    (tmp_path / "python.js").write_text("WScript.Echo(1)\n", encoding="ascii")

    assert toolpath.cwd_shadows(tmp_path, "python") == ["python.js"]


def test_nothing_is_named_off_windows_or_in_a_clean_root(tmp_path, monkeypatch):
    """No cmd.exe off Windows. A clean root names nothing, and a root that
    cannot be listed names nothing rather than raising."""
    (tmp_path / "python.cmd").write_text("@echo planted\n", encoding="ascii")
    monkeypatch.setattr(sys, "platform", "linux")
    assert toolpath.cwd_shadows(tmp_path, "python") == []

    _windows(monkeypatch)
    clean = tmp_path / "clean"
    clean.mkdir()
    assert toolpath.cwd_shadows(clean, "python") == []
    assert toolpath.cwd_shadows(tmp_path / "missing", "python") == []


def test_doctor_says_the_agent_launch_is_shadowed(tmp_path, monkeypatch):
    _windows(monkeypatch)
    (tmp_path / "python.cmd").write_text("@echo planted\n", encoding="ascii")

    assert doctor.agent_launch_lines(tmp_path) == [
        "  WARN launch     shadowed: python.cmd at the repo root runs in place of"
        " `python` when a launcher starts it through cmd.exe from here (unless"
        " NoDefaultCurrentDirectoryInExePath is set) -- the agent hooks and the"
        " MCP entry start `python`; remove the file and find out how it got there"]


def test_doctor_says_nothing_of_a_clean_root(tmp_path, monkeypatch):
    _windows(monkeypatch)

    assert doctor.agent_launch_lines(tmp_path) == []


def _cfg():
    from types import SimpleNamespace
    return SimpleNamespace(agent_block_armed=False)


def test_status_names_the_shadow_on_its_agent_surfaces_line(tmp_path, monkeypatch):
    _windows(monkeypatch)
    (tmp_path / "python.cmd").write_text("@echo planted\n", encoding="ascii")
    (tmp_path / "python.bat").write_text("@echo planted\n", encoding="ascii")

    line = status_mod._agent_surfaces_line(tmp_path, _cfg())

    assert line.endswith(", launch shadowed by python.bat, python.cmd | baking"), line


def test_status_line_is_unchanged_without_a_shadow(tmp_path, monkeypatch):
    _windows(monkeypatch)

    line = status_mod._agent_surfaces_line(tmp_path, _cfg())

    assert "shadowed" not in line, line
    assert line.endswith(" | baking"), line
