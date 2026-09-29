"""FN-18: `schedule install` must not move the drain's cadence.

2026-09-28 12:10Z the post-promotion re-install that 0.19.1's CHANGELOG
asks every Windows user for moved this machine's next drain from 14:00Z
to 16:10Z: the task's StartBoundary was `datetime.now()`, so every install
re-anchored the interval to the moment it ran and the next run landed a
full interval later. A re-install now keeps the installed task's
boundary -- it changes the limit, not the cadence -- and a first install
starts on the hour grid cron's `0 */N` uses."""
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid.commands import schedule

_INSTALLED = ("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Task><Triggers><TimeTrigger>"
              "<StartBoundary>2026-09-28T15:00:00</StartBoundary>"
              "<Repetition><Interval>PT4H</Interval></Repetition>"
              "</TimeTrigger></Triggers></Task>")


def test_a_reinstall_keeps_the_installed_tasks_boundary():
    assert schedule.start_boundary(_INSTALLED, datetime(2026, 9, 29, 0, 10), 4) == \
        "2026-09-28T15:00:00"


@pytest.mark.parametrize("now, hours, expected", [
    (datetime(2026, 9, 28, 13, 10, 27), 4, "2026-09-28T16:00:00"),
    (datetime(2026, 9, 28, 16, 0, 0), 4, "2026-09-28T20:00:00"),
    (datetime(2026, 9, 28, 22, 30, 0), 4, "2026-09-29T00:00:00"),
    (datetime(2026, 9, 28, 13, 10, 27), 6, "2026-09-28T18:00:00"),
    (datetime(2026, 9, 28, 13, 10, 27), 24, "2026-09-29T00:00:00"),
    (datetime(2026, 9, 28, 13, 10, 27), 48, "2026-09-29T00:00:00"),
    (datetime(2026, 9, 28, 14, 10, 0), 1, "2026-09-28T15:00:00"),
    (datetime(2026, 9, 28, 14, 10, 0), 0, "2026-09-28T15:00:00"),
], ids=["next grid hour", "on the grid is the NEXT one", "over midnight",
        "a six-hour grid", "a day", "two days", "hourly", "zero floors at one"])
def test_a_first_install_starts_on_the_hour_grid_cron_uses(now, hours, expected):
    """Strictly after now: a boundary equal to the moment of registering
    was measured to run first a whole interval later."""
    assert schedule.start_boundary(None, now, hours) == expected


def test_an_installed_task_without_a_boundary_reads_as_a_first_install():
    assert schedule.start_boundary("<Task></Task>", datetime(2026, 9, 28, 13, 10), 4) == \
        "2026-09-28T16:00:00"


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Task Scheduler install is Windows-only by design")
def test_install_registers_the_installed_boundary(monkeypatch, tmp_path):
    created = {}

    def fake_run(argv, **kw):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        if argv[:2] == ["schtasks", "/Query"]:
            R.stdout = _INSTALLED
        elif argv[:2] == ["schtasks", "/Create"]:
            created["xml"] = Path(argv[5]).read_text(encoding="utf-16")
        return R()

    monkeypatch.setattr(schedule.subprocess, "run", fake_run)
    assert schedule.cmd_schedule(tmp_path, "install") == 0
    assert "<StartBoundary>2026-09-28T15:00:00</StartBoundary>" in created["xml"]


def test_the_installed_task_is_read_with_schtasks_query_xml(monkeypatch):
    """The boundary comes from the task that is installed. Faked here so the
    ubuntu leg, which skips the install itself, still runs every line."""
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"], seen["timeout"] = argv, kw.get("timeout")
        return SimpleNamespace(returncode=0, stdout=_INSTALLED, stderr="")
    monkeypatch.setattr(schedule.subprocess, "run", fake_run)

    assert schedule._installed_task_xml() == _INSTALLED
    assert seen == {"argv": ["schtasks", "/Query", "/TN", "aramid-drain", "/XML"], "timeout": 30}


@pytest.mark.parametrize("outcome", ["no task", "no schtasks", "hung"])
def test_no_readable_installed_task_reads_as_a_first_install(monkeypatch, outcome):
    def fake_run(argv, **kw):
        if outcome == "no schtasks":
            raise FileNotFoundError("schtasks")
        if outcome == "hung":
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        return SimpleNamespace(returncode=1, stdout=_INSTALLED,
                               stderr="ERROR: The system cannot find the file specified.")
    monkeypatch.setattr(schedule.subprocess, "run", fake_run)

    assert schedule._installed_task_xml() is None
