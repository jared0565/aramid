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


# ------------------------------------------- reading a crontab that we cannot

# `_read_crontab` used to return "" for EVERY non-zero exit from `crontab -l`,
# on the reasoning that a missing crontab exits non-zero. install then wrote
# that "" straight back -- so any OTHER failure (a transient filesystem error,
# a permission problem, a corrupted spool file) silently REPLACED the user's
# entire crontab with aramid's single line. The only recoverable direction is
# to refuse: an aborted install is a message, a destroyed crontab is not.


class _FakeCP:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _fake_crontab_read(monkeypatch, cp):
    """Patch subprocess.run so `crontab -l` yields `cp`. Deliberately patches
    the SUBPROCESS rather than `_read_crontab`, so the return-code handling
    under test is the code actually exercised."""
    monkeypatch.setattr(schedule.subprocess, "run", lambda argv, **kw: cp)


def test_absent_crontab_reads_as_empty_not_as_an_error(monkeypatch):
    """The genuine first-install case. `crontab -l` exits non-zero with
    "no crontab for <user>" when none exists; that IS an empty crontab, and
    treating it as a failure would make the very first install impossible."""
    _fake_crontab_read(monkeypatch, _FakeCP(1, "", "no crontab for jared\n"))
    assert schedule._read_crontab() == ""


def test_an_unexpected_crontab_failure_raises_instead_of_reading_as_empty(monkeypatch):
    _fake_crontab_read(monkeypatch, _FakeCP(1, "", "crontab: cannot open spool: I/O error\n"))
    with pytest.raises(RuntimeError, match="crontab"):
        schedule._read_crontab()


def test_a_silent_crontab_failure_raises(monkeypatch):
    """rc != 0 with nothing on stderr is ambiguous. Refusing costs a failed
    install the user can see and retry; guessing "empty" costs their crontab."""
    _fake_crontab_read(monkeypatch, _FakeCP(2, "", ""))
    with pytest.raises(RuntimeError):
        schedule._read_crontab()


def test_install_never_writes_when_the_read_failed(monkeypatch, tmp_path, capsys):
    """THE SAFETY PROPERTY, at the command level: if we could not read the
    existing crontab, we must not write one. Anything else is data loss."""
    monkeypatch.setattr(sys, "platform", "linux")
    _fake_crontab_read(monkeypatch, _FakeCP(1, "", "crontab: cannot open spool: I/O error\n"))
    wrote = []
    monkeypatch.setattr(schedule, "_write_crontab", lambda text: wrote.append(text))

    assert schedule.cmd_schedule(tmp_path, "install") == 3
    assert wrote == [], f"install wrote despite an unreadable crontab: {wrote}"
    assert "spool" in capsys.readouterr().err


def test_remove_never_writes_when_the_read_failed(monkeypatch, tmp_path):
    """remove rewrites the whole crontab too, from the same unread base."""
    monkeypatch.setattr(sys, "platform", "linux")
    _fake_crontab_read(monkeypatch, _FakeCP(1, "", "crontab: cannot open spool: I/O error\n"))
    wrote = []
    monkeypatch.setattr(schedule, "_write_crontab", lambda text: wrote.append(text))

    assert schedule.cmd_schedule(tmp_path, "remove") == 3
    assert wrote == []


# ------------------------------------------------- quoting the interpreter ---


def test_cron_line_survives_an_interpreter_path_containing_spaces():
    """cron hands the command to a shell, which splits on whitespace. An
    unquoted `/opt/my venv/bin/python3` runs `/opt/my` -- the drain never
    fires, and cron reports it nowhere the user is looking."""
    import shlex
    from pathlib import PurePosixPath

    # PurePosixPath, not Path: cron is POSIX-only, and on Windows a plain Path
    # would render backslashes that POSIX shlex.split then eats as escapes --
    # the test would fail on the runner rather than on the behaviour.
    interp = "/opt/my venv/bin/python3"
    line = schedule.render_cron_line(PurePosixPath(interp), 4)
    command = line.split(" ", 5)[5]                     # past the 5 cron fields
    argv = shlex.split(command.split(schedule.CRON_MARKER)[0])
    assert argv[0] == interp, argv


def test_cron_line_leaves_an_ordinary_path_unquoted():
    """Quoting must not churn the common case -- an already-installed line
    should keep matching what a fresh render produces."""
    from pathlib import PurePosixPath

    assert "'" not in schedule.render_cron_line(PurePosixPath("/usr/bin/python3"), 4)


# --- crontab is not a shell -------------------------------------------------
#
# shlex.quote makes the path safe for the SHELL that cron hands the command
# to. It does nothing about the layer above it: crontab(5) says the command
# runs "up to a newline or a % character", that an unescaped `%` becomes a
# newline, and that everything after the first `%` is fed to the command as
# stdin. Single quotes do not protect either character, because cron parses
# the line before any shell sees it.

def _as_cron_would_run(line: str) -> str:
    r"""The command cron actually hands the shell.

    Models crontab(5) faithfully, because the weak version of these tests only
    collapsed `\%` to `%` -- which is a no-op when nothing is escaped, so they
    passed against the unfixed renderer. The damaging half is the TRUNCATION:
    cron stops the command at the first unescaped `%` and feeds everything
    after it to the command as stdin.
    """
    command = line.split(" ", 5)[5]                     # past the 5 cron fields
    out, i = [], 0
    while i < len(command):
        if command[i] == "\\" and command[i + 1:i + 2] == "%":
            out.append("%")                             # cron unescapes `\%`
            i += 2
        elif command[i] == "%":
            break                                       # rest becomes stdin
        else:
            out.append(command[i])
            i += 1
    return "".join(out)


def test_cron_line_escapes_a_percent_in_the_interpreter_path():
    r"""cron turns an unescaped `%` into a newline and sends the remainder to
    the command as stdin, so `/opt/py%3/bin/python` silently installs a
    truncated command plus a second, UNMARKED line -- which
    `strip_aramid_lines` can then never remove, because the marker went to the
    orphan half."""
    import re
    from pathlib import PurePosixPath

    line = schedule.render_cron_line(PurePosixPath("/opt/py%3/bin/python"), 4)

    assert "%" in line                      # the path really did contain one
    assert "\\%" in line
    # no BARE percent survives: every one is preceded by a backslash
    assert not re.search(r"(?<!\\)%", line), line


def test_cron_line_survives_cron_percent_processing_as_one_whole_command():
    """The command must reach the shell INTACT. Unfixed, cron truncated it at
    the `%` in the path, so the drain invocation never ran at all -- and the
    severed tail became stdin."""
    from pathlib import PurePosixPath

    line = schedule.render_cron_line(PurePosixPath("/opt/py%3/bin/python"), 4)

    assert "-m aramid drain --all" in _as_cron_would_run(line)


def test_cron_line_percent_escape_round_trips_to_the_original_path():
    """Put a path carrying BOTH hazards through cron's processing and then the
    shell's, and check the interpreter that comes out is the one that went in."""
    import shlex
    from pathlib import PurePosixPath

    interp = "/opt/py%3/my venv/bin/python"
    line = schedule.render_cron_line(PurePosixPath(interp), 4)

    argv = shlex.split(_as_cron_would_run(line).split(schedule.CRON_MARKER)[0])

    assert argv[0] == interp, argv


@pytest.mark.parametrize("hostile", ["\n", "\r"])
def test_cron_line_refuses_a_path_that_cannot_be_one_line(hostile):
    """A newline in the path ends the crontab entry outright -- no amount of
    quoting or escaping can carry it, since a crontab line IS the unit. The
    only correct answer is to refuse the install rather than write a mangled
    crontab, the same reasoning as `_read_crontab` refusing on an unreadable
    crontab instead of treating it as empty."""
    from pathlib import PurePosixPath

    with pytest.raises(ValueError):
        schedule.render_cron_line(PurePosixPath(f"/opt/py{hostile}evil/python"), 4)


def test_cron_line_is_always_exactly_one_line():
    from pathlib import PurePosixPath

    line = schedule.render_cron_line(PurePosixPath("/opt/py%3/my venv/bin/python"), 4)

    assert len(line.splitlines()) == 1, line
