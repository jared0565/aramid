"""aramid schedule install|remove|status -- a recurring `aramid drain --all`
every [drain].interval_hours (spec section 2), via Windows Task Scheduler on
Windows and cron everywhere else.

Windows: XML registration is used (not bare /SC flags) because
StartWhenAvailable -- "run as soon as possible after a missed start", spec
section 6 -- is only expressible in the XML schema.

POSIX: a single marked crontab line (see CRON_MARKER). cron has no
StartWhenAvailable equivalent, which is tolerable because the sweep already
self-heals a fully missed window. cron rather than launchd on macOS so one
implementation covers both platforms; launchd is the natural follow-up if
per-user agent semantics are ever wanted."""
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from aramid import config as config_mod

TASK_NAME = "aramid-drain"

# <Arguments> below carries `-P`. The rationale -- and the MEASURED cwd this
# task actually runs from -- is at render_cron_line, next to the cron line
# that carries the same flag for a different severity of the same reason.
_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>aramid: scheduled queue drain (zero-token triage consumers)</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>{start}</StartBoundary>
      <Repetition>
        <Interval>PT{hours}H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Settings>
    <StartWhenAvailable>true</StartWhenAvailable>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{interpreter}</Command>
      <Arguments>-P -m aramid drain --all</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def render_task_xml(interpreter: Path, interval_hours: int, start_boundary: str) -> str:
    return _XML_TEMPLATE.format(start=start_boundary, hours=interval_hours,
                                interpreter=str(interpreter))


def _create_argv(xml_path: Path) -> list[str]:
    return ["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(xml_path), "/F"]


def _delete_argv() -> list[str]:
    return ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]


def _query_argv() -> list[str]:
    return ["schtasks", "/Query", "/TN", TASK_NAME]


# ------------------------------------------------------------ POSIX (cron) ---
# The drain used to be installable on Windows only, which meant the scheduled
# red-team half of the product could not run on the platforms most servers and
# CI runners use. The gate was always cross-platform; only the scheduler was
# not.
#
# cron rather than launchd on macOS: one implementation covers both Linux and
# macOS, and `crontab` is present on both. launchd would be more native on
# macOS, and is the natural follow-up if per-user agent semantics are ever
# wanted.
#
# cron has no equivalent of Task Scheduler's StartWhenAvailable ("run as soon
# as possible after a missed start"). That is acceptable here because the drain
# sweep already self-heals a fully missed window -- see the module docstring.
CRON_MARKER = "# aramid-drain"


def render_cron_line(interpreter: Path, interval_hours: int) -> str:
    """One crontab line, tagged with CRON_MARKER so it can be found and
    replaced without touching anything else in the user's crontab.

    `*/N` in the HOUR field only means what you want for N <= 23; `0 */48 * * *`
    does not mean "every two days", it means "every hour divisible by 48",
    which never matches. Intervals of a day or more are therefore converted to
    a day-of-month step. A zero or negative interval would emit `*/0`, a cron
    syntax error, so it floors at 1.
    """
    hours = max(1, int(interval_hours))
    if hours >= 24:
        when = f"0 0 */{max(1, hours // 24)} * *"
    else:
        when = f"0 */{hours} * * *"
    # Two layers parse this, and shlex.quote only addresses the lower one.
    #
    # SHELL: cron hands the command to a shell, which splits on whitespace, so
    # an unquoted `/opt/my venv/bin/python3` runs `/opt/my` and the drain never
    # fires, reported nowhere the user is looking. shlex.quote leaves an
    # ordinary path completely untouched, so already-installed lines still
    # match what a fresh render produces.
    #
    # CRON: crontab(5) says the command runs "up to a newline or a % character".
    # An unescaped `%` is converted to a newline, and everything after the first
    # one is fed to the command as STDIN; `\%` is the escape. Quotes give no
    # protection at all here -- cron parses the line before any shell sees it --
    # so `/opt/py%3/bin/python` silently installed a TRUNCATED command whose
    # severed tail became stdin. Escaping after quoting is the right order:
    # cron unescapes first, then the shell parses what is left.
    text = str(interpreter)
    # A newline cannot be escaped at any layer -- a crontab line IS the unit of
    # the file. Rendering one anyway would append a second, UNMARKED line that
    # `strip_aramid_lines` could never remove, because CRON_MARKER goes with
    # whichever half it lands on. Refuse instead, the same call `_read_crontab`
    # makes: an aborted install is a message the user can act on.
    if "\n" in text or "\r" in text:
        raise ValueError(
            "aramid: schedule: refusing to install -- the interpreter path "
            f"contains a line break, which no crontab line can carry: {text!r}")
    command = shlex.quote(text).replace("%", "\\%")
    # `-P` for the same reason every hook shim carries it: `-m` puts the
    # CWD at sys.path[0], so an aramid.py wherever this happens to run
    # would be imported instead of the installed package. A scheduled
    # launch is the worst case of that -- it fires on a TIMER, with no
    # human present to notice. WHERE it fires from differs by scheduler,
    # and so does what `-P` is closing:
    #   cron     cwd is $HOME. Documented behaviour of Vixie-derived crons
    #            (the daemon chdirs to the owner's home before exec); NOT
    #            measured here, there is no cron on the development machine.
    #            $HOME is user-writable, so a hijack needs no privilege the
    #            account does not already have -- a live hole without `-P`.
    #   Windows  an empty <WorkingDirectory> in _XML_TEMPLATE resolves to
    #            C:/WINDOWS/system32. MEASURED 2026-08-26 by registering a
    #            task from that very template, running it, and reading
    #            os.getcwd(). Writing there needs admin, so on Windows `-P`
    #            is defence-in-depth, not the close of a live exposure.
    # Same flag on both; the comment splits because one sentence for two
    # platforms was wrong about one of them (interop rounds 126 and 127).
    return f"{when} {command} -P -m aramid drain --all  {CRON_MARKER}"


def strip_aramid_lines(text: str) -> str:
    """Drop only aramid's own marked lines. install/remove rewrite the user's
    ENTIRE crontab, so everything unmarked -- backups, certbot, @reboot jobs --
    must survive verbatim."""
    return "\n".join(ln for ln in text.splitlines() if CRON_MARKER not in ln)


# `crontab -l` exits non-zero for a user who simply has no crontab yet. Vixie
# cron, cronie, busybox and macOS all say so on stderr in these words.
_NO_CRONTAB = "no crontab for"


def _read_crontab() -> str:
    """The existing crontab, or "" when the user genuinely has none.

    Raises RuntimeError on any OTHER failure. That distinction is the whole
    point of this function: install and remove rewrite the user's ENTIRE
    crontab from whatever this returns, so treating a transient error as ""
    replaces every unrelated job -- backups, certbot, monitoring -- with
    aramid's single line. An aborted install is a message the user can act on;
    a destroyed crontab is not recoverable. When in doubt, refuse.
    """
    # S607 justification: `crontab` is resolved from PATH deliberately. Its
    # location differs across distributions and macOS (/usr/bin vs /bin), so an
    # absolute path would be wrong more often than it was right. argv is fixed
    # here -- no external input reaches it.
    cp = subprocess.run(["crontab", "-l"], capture_output=True, text=True,  # noqa: S607
                        errors="replace")
    if cp.returncode == 0:
        return cp.stdout
    err = (cp.stderr or "").strip()
    if _NO_CRONTAB in err.lower():
        return ""                       # genuinely empty: the first-install case
    # Includes rc != 0 with NOTHING on stderr. That is ambiguous, and the two
    # readings cost very different things, so it resolves to the recoverable
    # one.
    raise RuntimeError(f"`crontab -l` failed (exit {cp.returncode}): "
                       f"{err or 'no error output'}")


def _write_crontab(text: str) -> None:
    body = text.strip("\n")
    # S607 justification: as in _read_crontab -- fixed argv, PATH-resolved by
    # design. The crontab BODY arrives on stdin, never as an argument.
    cp = subprocess.run(["crontab", "-"], input=(body + "\n") if body else "",  # noqa: S607
                        capture_output=True, text=True, errors="replace")
    if cp.returncode != 0:
        raise RuntimeError(f"crontab write failed: {cp.stderr.strip()}")


def _cron_schedule(root, action: str) -> int:
    if action == "status":
        if CRON_MARKER in _read_crontab():
            print(f"aramid schedule: installed ({TASK_NAME}, cron)")
            return 0
        print("aramid-drain: not installed")
        return 3

    remaining = strip_aramid_lines(_read_crontab())
    if action == "remove":
        _write_crontab(remaining)
        print(f"aramid schedule: remove ok ({TASK_NAME})")
        return 0

    cfg = config_mod.load_config(Path(root))
    hours = int(cfg.drain.get("interval_hours", 4))
    line = render_cron_line(Path(sys.executable), hours)
    # Strip-then-append, so re-installing REPLACES aramid's entry instead of
    # accumulating a duplicate on every run.
    _write_crontab(f"{remaining}\n{line}" if remaining.strip() else line)
    print(f"aramid schedule: install ok ({TASK_NAME}, cron)")
    return 0


def cmd_schedule(root, action: str) -> int:
    if action not in ("install", "remove", "status"):
        print(f"aramid: schedule: unknown action {action!r}", file=sys.stderr)
        return 3
    if sys.platform != "win32":
        try:
            return _cron_schedule(root, action)
        except FileNotFoundError:
            print("aramid: schedule: `crontab` not found on PATH", file=sys.stderr)
            return 3
        except Exception as exc:
            print(f"aramid: schedule: engine error: {exc}", file=sys.stderr)
            return 3
    try:
        if action == "install":
            cfg = config_mod.load_config(Path(root))
            hours = int(cfg.drain.get("interval_hours", 4))
            start = datetime.now().replace(microsecond=0).isoformat()
            xml = render_task_xml(Path(sys.executable), hours, start)
            with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False,
                                             encoding="utf-16") as f:
                f.write(xml)
                xml_path = Path(f.name)
            try:
                # errors="replace" on all schtasks reads -- schtasks emits the
                # console/ANSI codepage, not UTF-8 (see drain._pid_alive).
                # S603 justification (all three schtasks calls in this block):
                # each argv comes from a module-local `_*_argv()` builder made
                # of fixed flags plus TASK_NAME (a constant) and a
                # tempfile-generated path aramid created itself. No shell, and
                # nothing external reaches argv.
                cp = subprocess.run(_create_argv(xml_path), capture_output=True, text=True,  # noqa: S603
                                    errors="replace")
            finally:
                xml_path.unlink(missing_ok=True)
        elif action == "remove":
            cp = subprocess.run(_delete_argv(), capture_output=True, text=True,  # noqa: S603
                                errors="replace")
        elif action == "status":
            cp = subprocess.run(_query_argv(), capture_output=True, text=True,  # noqa: S603
                                errors="replace")
            print(cp.stdout.strip() or "aramid-drain: not installed")
            return 0 if cp.returncode == 0 else 3
        else:
            print(f"aramid: schedule: unknown action {action!r}", file=sys.stderr)
            return 3
        if cp.returncode != 0:
            print(f"aramid: schedule {action} failed: {cp.stderr.strip()}", file=sys.stderr)
            return 3
        print(f"aramid schedule: {action} ok ({TASK_NAME})")
        return 0
    except Exception as exc:
        print(f"aramid: schedule: engine error: {exc}", file=sys.stderr)
        return 3
