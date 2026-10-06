"""The stall watchdog in run_subprocess: a child TREE with no CPU and no
output for the stall window is killed early and reported as stalled (still
ToolState.TIMEOUT, carrying stalled_s). Windows are shrunk through the
module seams so each test runs in seconds."""
import re
import sys
import time

import pytest

from aramid.runners import base
from aramid.runners.base import ToolState, run_subprocess


@pytest.fixture
def fast_watch(monkeypatch):
    monkeypatch.setattr(base, "_SAMPLE_S", 0.25)
    old = base.stall_window()
    base.set_stall_window(1.5)
    yield
    base.set_stall_window(old)


def test_an_idle_child_is_stalled_long_before_its_budget(tmp_path, fast_watch):
    start = time.monotonic()
    r = run_subprocess([sys.executable, "-c", "import time; time.sleep(60)"], tmp_path, 60)
    elapsed = time.monotonic() - start
    assert r.state is ToolState.TIMEOUT
    assert r.stalled_s is not None and r.stalled_s >= 1.5
    assert elapsed < 15, f"stall not detected early: {elapsed:.1f}s"
    # The process count is not asserted as 1: on Windows a venv's python.exe
    # can be a redirector that spawns the real interpreter, a tree of 2.
    assert re.fullmatch(
        rf"aramid: {re.escape(r.tool)} stalled: no CPU in any of its [12] processes and no"
        r" output for \d+ s; killed after \d+ s\. A child blocked on a full pipe or on a"
        r" read with no timeout looks like this; a slow one does not\.", r.stderr), r.stderr


def test_a_busy_child_is_never_stalled(tmp_path, fast_watch):
    r = run_subprocess([sys.executable, "-c", "x = 0\nwhile True: x += 1"], tmp_path, 4)
    assert r.state is ToolState.TIMEOUT
    assert r.stalled_s is None
    assert "timed out after 4 s" in r.stderr


def test_a_quiet_child_that_prints_is_never_stalled(tmp_path, fast_watch):
    code = "import time\nfor i in range(8):\n    print(i, flush=True); time.sleep(0.5)"
    r = run_subprocess([sys.executable, "-c", code], tmp_path, 30)
    assert r.state is ToolState.OK and r.returncode == 0
    assert r.raw.split() == [str(i) for i in range(8)]
    assert r.stalled_s is None


def test_a_busy_grandchild_keeps_an_idle_child_alive(tmp_path, fast_watch):
    code = ("import subprocess, sys\n"
            "subprocess.run([sys.executable, '-c', 'x = 0\\nwhile True: x += 1'])")
    r = run_subprocess([sys.executable, "-c", code], tmp_path, 4)
    assert r.state is ToolState.TIMEOUT
    assert r.stalled_s is None, "descendant CPU must count as activity"


def test_a_child_flooding_stderr_completes_and_is_not_stalled(tmp_path, fast_watch):
    code = "import sys; sys.stderr.write('x' * 1_000_000); print('done')"
    r = run_subprocess([sys.executable, "-c", code], tmp_path, 30)
    assert r.state is ToolState.OK and r.raw.strip() == "done"
    assert len(r.stderr) == 1_000_000


def test_window_zero_disables_the_watchdog(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "_SAMPLE_S", 0.25)
    old = base.stall_window()
    base.set_stall_window(0)
    try:
        r = run_subprocess([sys.executable, "-c", "import time; time.sleep(60)"], tmp_path, 3)
    finally:
        base.set_stall_window(old)
    assert r.state is ToolState.TIMEOUT and r.stalled_s is None
    assert "timed out after 3 s" in r.stderr


def test_an_unmeasurable_tree_is_active_not_stalled(tmp_path, fast_watch, monkeypatch):
    monkeypatch.setattr(base.proctree, "sample", lambda pid: None)
    r = run_subprocess([sys.executable, "-c", "import time; time.sleep(60)"], tmp_path, 4)
    assert r.state is ToolState.TIMEOUT and r.stalled_s is None


def test_a_raising_sampler_is_active_not_a_crash(tmp_path, fast_watch, monkeypatch):
    def boom(pid):
        raise RuntimeError("sampler broke")

    monkeypatch.setattr(base.proctree, "sample", boom)
    r = run_subprocess([sys.executable, "-c", "import time; time.sleep(60)"], tmp_path, 4)
    assert r.state is ToolState.TIMEOUT
    assert r.stalled_s is None
    assert "timed out after 4 s" in r.stderr


def test_set_stall_window_clamps_negative_to_zero():
    old = base.stall_window()
    try:
        base.set_stall_window(-5)
        assert base.stall_window() == 0.0
    finally:
        base.set_stall_window(old)


def test_the_default_window_is_three_hundred_seconds():
    assert base.DEFAULT_STALL_S == 300.0
    assert base._SAMPLE_S == 15.0
