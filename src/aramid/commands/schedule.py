"""aramid schedule install|remove|status -- Windows Task Scheduler entry
running `aramid drain --all` every [drain].interval_hours (spec section 2).
XML registration is used (not bare /SC flags) because StartWhenAvailable
-- "run as soon as possible after a missed start", spec section 6 -- is
only expressible in the XML schema. The sweep additionally self-heals any
fully missed window."""
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from aramid import config as config_mod

TASK_NAME = "aramid-drain"

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
      <Arguments>-m aramid drain --all</Arguments>
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


def cmd_schedule(root, action: str) -> int:
    if sys.platform != "win32":
        print("aramid: schedule: only supported on Windows (Task Scheduler)",
              file=sys.stderr)
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
                cp = subprocess.run(_create_argv(xml_path), capture_output=True, text=True,
                                    errors="replace")
            finally:
                xml_path.unlink(missing_ok=True)
        elif action == "remove":
            cp = subprocess.run(_delete_argv(), capture_output=True, text=True,
                                errors="replace")
        elif action == "status":
            cp = subprocess.run(_query_argv(), capture_output=True, text=True,
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
