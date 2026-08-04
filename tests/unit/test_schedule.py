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
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()

    monkeypatch.setattr(schedule.subprocess, "run", fake_run)
    assert schedule.cmd_schedule(tmp_path, "install") == 0
    assert calls["argv"][:4] == ["schtasks", "/Create", "/TN", "aramid-drain"]


@pytest.mark.skipif(sys.platform == "win32", reason="the off-Windows install path")
def test_install_off_windows_uses_cron_and_never_schtasks(monkeypatch, tmp_path):
    """This test used to assert the OPPOSITE -- that off-Windows install exits 3
    with "only supported on Windows". That refusal was the blocker; the drain
    now installs via cron on Linux/macOS.

    The property worth keeping from the old test is preserved: schtasks must
    never be spawned on a platform that does not have it, since the spawn error
    would surface as an engine fault rather than honest behaviour.
    """
    spawned = []
    monkeypatch.setattr(schedule, "_read_crontab", lambda: "")
    monkeypatch.setattr(schedule, "_write_crontab", lambda text: None)
    monkeypatch.setattr(schedule.subprocess, "run",
                        lambda argv, **kw: spawned.append(argv))

    assert schedule.cmd_schedule(tmp_path, "install") == 0
    assert not any("schtasks" in str(a) for a in spawned), spawned


# --------------------------------------------------------- POSIX cron backend

# `aramid schedule` was Windows-only: cmd_schedule returned exit 3 with
# "only supported on Windows (Task Scheduler)" on every other platform, so the
# scheduled drain -- the whole red-team half of the product -- could not be
# installed on the platforms most servers and CI runners actually run. The gate
# was always cross-platform; only the scheduler was not.


def test_render_cron_line_uses_an_hourly_step_for_sub_day_intervals():
    line = schedule.render_cron_line(Path("/usr/bin/python3"), 4)
    assert line.startswith("0 */4 * * * ")
    assert "-m aramid drain --all" in line
    assert schedule.CRON_MARKER in line


def test_render_cron_line_converts_a_multi_day_interval():
    """`*/N` in the hour field is only meaningful for N <= 23; 48 hours must
    become a day step, not the silently-wrong `0 */48 * * *`."""
    line = schedule.render_cron_line(Path("/usr/bin/python3"), 48)
    assert line.startswith("0 0 */2 * * ")


def test_render_cron_line_never_emits_a_zero_step():
    """A zero step is a cron syntax error, and a misconfigured
    `[drain].interval_hours = 0` must not produce an uninstallable entry."""
    assert schedule.render_cron_line(Path("/usr/bin/python3"), 0).startswith("0 */1 * * * ")


def test_strip_preserves_every_line_that_is_not_ours():
    """THE SAFETY PROPERTY. install/remove rewrite the user's whole crontab, so
    a bug here silently destroys unrelated scheduled jobs -- backups, certbot,
    anything. Only aramid's own marked lines may be removed."""
    existing = "\n".join([
        "# m h  dom mon dow   command",
        "0 3 * * * /usr/local/bin/backup.sh",
        f"0 */4 * * * /usr/bin/python3 -m aramid drain --all  {schedule.CRON_MARKER}",
        "@reboot /opt/thing/start.sh",
    ])
    out = schedule.strip_aramid_lines(existing)
    assert "/usr/local/bin/backup.sh" in out
    assert "@reboot /opt/thing/start.sh" in out
    assert "# m h  dom mon dow   command" in out
    assert schedule.CRON_MARKER not in out


def test_install_is_idempotent_and_keeps_foreign_entries(monkeypatch, tmp_path):
    """Re-installing must replace aramid's entry rather than accumulate copies,
    and must hand crontab back everything it did not own."""
    written = {}
    monkeypatch.setattr(schedule, "_read_crontab",
                        lambda: "0 3 * * * /usr/local/bin/backup.sh\n")
    monkeypatch.setattr(schedule, "_write_crontab",
                        lambda text: written.__setitem__("text", text))
    monkeypatch.setattr(sys, "platform", "linux")

    assert schedule.cmd_schedule(tmp_path, "install") == 0
    first = written["text"]
    assert "/usr/local/bin/backup.sh" in first
    assert first.count(schedule.CRON_MARKER) == 1

    monkeypatch.setattr(schedule, "_read_crontab", lambda: first)
    assert schedule.cmd_schedule(tmp_path, "install") == 0
    assert written["text"].count(schedule.CRON_MARKER) == 1, written["text"]
    assert "/usr/local/bin/backup.sh" in written["text"]


def test_remove_takes_out_only_aramid_and_status_reports_both_ways(monkeypatch, tmp_path):
    written = {}
    installed = ("0 3 * * * /usr/local/bin/backup.sh\n"
                 f"0 */4 * * * /usr/bin/python3 -m aramid drain --all  {schedule.CRON_MARKER}\n")
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(schedule, "_read_crontab", lambda: installed)
    monkeypatch.setattr(schedule, "_write_crontab",
                        lambda text: written.__setitem__("text", text))

    assert schedule.cmd_schedule(tmp_path, "status") == 0
    assert schedule.cmd_schedule(tmp_path, "remove") == 0
    assert schedule.CRON_MARKER not in written["text"]
    assert "/usr/local/bin/backup.sh" in written["text"]

    monkeypatch.setattr(schedule, "_read_crontab", lambda: written["text"])
    assert schedule.cmd_schedule(tmp_path, "status") == 3   # not installed


def test_schedule_no_longer_refuses_outright_on_posix(monkeypatch, tmp_path):
    """Regression guard for the blocker itself: a non-Windows platform must not
    get 'only supported on Windows' back."""
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(schedule, "_read_crontab", lambda: "")
    monkeypatch.setattr(schedule, "_write_crontab", lambda text: None)
    assert schedule.cmd_schedule(tmp_path, "install") == 0
