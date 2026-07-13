"""Real schtasks round-trip with a DISPOSABLE task name -- never touches the
real aramid-drain task. Skips where schtasks is unavailable (non-Windows).

If this host's Task Scheduler is locked down (some CI/sandboxed and locked-
down corporate machines run schtasks under a restricted token), the /Create
call fails with stderr containing "Access is denied" rather than a clean
returncode. That's a host policy fact, not a bug in this module, so the
first assertion below is relaxed to skip that specific case instead of
failing the whole suite -- see the xfail-via-skip block.
"""
import shutil
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path

import pytest

from aramid.commands import schedule

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("schtasks") is None,
    reason="Windows Task Scheduler required")


def test_real_register_query_delete_roundtrip(monkeypatch, tmp_path):
    disposable = f"aramid-test-{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(schedule, "TASK_NAME", disposable)
    try:
        xml = schedule.render_task_xml(Path(sys.executable), 4,
                                       datetime.now().replace(microsecond=0).isoformat())
        xml_file = tmp_path / "t.xml"
        xml_file.write_text(xml, encoding="utf-16")
        cp = subprocess.run(schedule._create_argv(xml_file), capture_output=True, text=True)
        if cp.returncode != 0 and "access is denied" in cp.stderr.lower():
            pytest.skip(f"schtasks blocked by host policy: {cp.stderr.strip()}")
        assert cp.returncode == 0, cp.stderr
        q = subprocess.run(schedule._query_argv(), capture_output=True, text=True)
        assert q.returncode == 0 and disposable in q.stdout
    finally:
        subprocess.run(schedule._delete_argv(), capture_output=True, text=True)
    q2 = subprocess.run(schedule._query_argv(), capture_output=True, text=True)
    assert q2.returncode != 0, "disposable task must be cleaned up"
