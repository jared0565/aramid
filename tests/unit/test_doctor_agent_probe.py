"""agent_interpreter_lines' probe arms, exercised hermetically (the
autouse conftest stub is bypassed via the real_interpreter_probe marker;
inside these tests the subprocess itself is monkeypatched)."""
import subprocess

import pytest

from aramid.commands import doctor


pytestmark = pytest.mark.real_interpreter_probe


def test_no_python_on_path(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert doctor.agent_interpreter_lines() == [
        "  WARN interpreter no `python` on PATH -- the generated"
        " agent-hook command cannot run; install one or adjust PATH"]


def test_probe_failure_names_a_remedy(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/x/python")
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="python", timeout=15)
    monkeypatch.setattr(doctor.subprocess, "run", _boom)
    assert doctor.agent_interpreter_lines() == [
        "  WARN interpreter `python` on PATH (/x/python) could not be"
        " probed -- run `/x/python -P -c \"import aramid\"` yourself; if"
        " it fails, `pip install aramid` into that interpreter or fix"
        " PATH"]


def test_import_failure_line(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/x/python")
    class _P:
        returncode = 1
    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: _P())
    assert doctor.agent_interpreter_lines() == [
        "  WARN interpreter `python` on PATH (/x/python) cannot import"
        " aramid -- the agent-hook entry in .claude/settings.json will"
        " error at every session start; `pip install aramid` into that"
        " interpreter or fix PATH"]


def test_healthy_probe_is_silent(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/x/python")
    class _P:
        returncode = 0
    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: _P())
    assert doctor.agent_interpreter_lines() == []
