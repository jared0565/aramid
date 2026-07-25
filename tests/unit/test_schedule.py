import sys
from pathlib import Path

import pytest

from aramid.commands import schedule


def test_xml_contains_startwhenavailable_interval_and_interpreter():
    xml = schedule.render_task_xml(Path("C:/py/python.exe"), 4,
                                   "2026-07-13T00:00:00")
    assert "<StartWhenAvailable>true</StartWhenAvailable>" in xml
    assert "<Interval>PT4H</Interval>" in xml
    assert "C:\\py\\python.exe" in xml or "C:/py/python.exe" in xml
    assert "-m aramid drain --all" in xml
    assert "<StartBoundary>2026-07-13T00:00:00</StartBoundary>" in xml


def test_schtasks_argvs():
    assert schedule._create_argv(Path("t.xml")) == \
        ["schtasks", "/Create", "/TN", "aramid-drain", "/XML", "t.xml", "/F"]
    assert schedule._delete_argv() == \
        ["schtasks", "/Delete", "/TN", "aramid-drain", "/F"]
    assert schedule._query_argv() == \
        ["schtasks", "/Query", "/TN", "aramid-drain"]


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Task Scheduler install is Windows-only by design")
def test_install_invokes_schtasks(monkeypatch, tmp_path):
    calls = {}

    def fake_run(argv, **kw):
        calls["argv"] = argv
        class R: returncode = 0; stdout = ""; stderr = ""
        return R()

    monkeypatch.setattr(schedule.subprocess, "run", fake_run)
    assert schedule.cmd_schedule(tmp_path, "install") == 0
    assert calls["argv"][:4] == ["schtasks", "/Create", "/TN", "aramid-drain"]


@pytest.mark.skipif(sys.platform == "win32", reason="the off-Windows refusal path")
def test_install_refuses_cleanly_off_windows(monkeypatch, tmp_path):
    """The documented behaviour (`schedule.py:67-70`: exit 3, "only supported on
    Windows") had NO test -- the win32 path was asserted unconditionally, so on
    Linux/macOS the suite failed on intended behaviour rather than covering it.

    Refusing must also be SILENT toward the system: no schtasks attempt at all,
    since the binary does not exist there and a spawn error would surface as an
    engine fault rather than an honest "not supported"."""
    spawned = []
    monkeypatch.setattr(schedule.subprocess, "run",
                        lambda argv, **kw: spawned.append(argv))

    assert schedule.cmd_schedule(tmp_path, "install") == 3
    assert spawned == [], "attempted to run schtasks on a platform without it"
