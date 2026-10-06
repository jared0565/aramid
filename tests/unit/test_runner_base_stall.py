"""The stall watchdog in run_subprocess: a child TREE with no CPU and no
output for the stall window is killed early and reported as stalled (still
ToolState.TIMEOUT, carrying stalled_s). Windows are shrunk through the
module seams so each test runs in seconds."""
import io
import os
import re
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

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


def test_a_busy_grandchild_keeps_an_idle_child_alive(tmp_path, fast_watch, monkeypatch):
    real, samples = base.proctree.sample, []

    def spy(pid):
        s = real(pid)
        samples.append(s)
        return s

    monkeypatch.setattr(base.proctree, "sample", spy)
    code = ("import subprocess, sys\n"
            "subprocess.run([sys.executable, '-c', 'x = 0\\nwhile True: x += 1'])")
    r = run_subprocess([sys.executable, "-c", code], tmp_path, 4)
    assert r.state is ToolState.TIMEOUT
    assert r.stalled_s is None, "descendant CPU must count as activity"
    # Without this the test passes when every sample is None (unmeasurable
    # reads as active too): it must have SEEN the grandchild at least once.
    assert any(s is not None and len(s) >= 2 for s in samples), samples


def test_output_with_no_newline_is_activity_and_is_kept(tmp_path, fast_watch):
    # The reader counts BYTES as they arrive. A line reader saw nothing until
    # a newline, so a child printing progress dots read as silent and was
    # killed as stalled (a 2 s window killed exactly this child).
    code = ("import sys, time\n"
            "for _ in range(12):\n"
            "    sys.stdout.write('.'); sys.stdout.flush(); time.sleep(0.25)\n")
    r = run_subprocess([sys.executable, "-c", code], tmp_path, 30)
    assert r.state is ToolState.OK and r.returncode == 0, r.stderr
    assert r.stalled_s is None
    assert r.raw == "." * 12


def test_a_grandchild_holding_stdout_neither_hides_the_childs_last_line_nor_blocks(
        tmp_path, monkeypatch, capfd):
    # The child writes its JSON with no trailing newline and exits; the
    # grandchild it started still holds stdout. A line reader left that last
    # line inside a blocked readline and the run came back OK with raw ''.
    monkeypatch.setattr(base, "_POST_KILL_DRAIN_S", 1.0)
    pidfile = tmp_path / "grandchild.pid"
    code = ("import pathlib, subprocess, sys\n"
            "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],\n"
            "                     stdin=subprocess.DEVNULL, stdout=sys.stdout,\n"
            "                     stderr=subprocess.DEVNULL)\n"
            "pathlib.Path(sys.argv[1]).write_text(str(g.pid))\n"
            "sys.stdout.write('{\"a\": 1}'); sys.stdout.flush()\n")
    start = time.monotonic()
    try:
        r = run_subprocess([sys.executable, "-c", code, str(pidfile)], tmp_path, 60)
        elapsed = time.monotonic() - start
    finally:
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGTERM)
            except OSError:
                pass
    assert pidfile.exists(), "control: the grandchild was started"
    assert r.state is ToolState.OK and r.returncode == 0, r.stderr
    assert r.raw == '{"a": 1}'
    assert elapsed < 1.0 + 5, f"the held pipe was waited on: {elapsed:.1f}s"
    assert capfd.readouterr().err == (
        f"aramid: {r.tool}: a process it started still holds its output pipe after it"
        f" exited; using the output read so far\n")


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
    # Off means off: not even the idle figure at the wall clock.
    assert r.idle_s is None
    assert r.stderr.endswith("whatever it had written is discarded")


def test_an_unmeasurable_tree_is_active_not_stalled(tmp_path, fast_watch, monkeypatch):
    monkeypatch.setattr(base.proctree, "sample", lambda pid: None)
    r = run_subprocess([sys.executable, "-c", "import time; time.sleep(60)"], tmp_path, 4)
    assert r.state is ToolState.TIMEOUT and r.stalled_s is None
    assert r.idle_s is None, "a tree it could not see is never reported as idle"


# --- idle time at a WALL-CLOCK timeout (reporting only) ----------------------
# At the defaults the watchdog (300 s) cannot decide before any gate runner's
# budget (30-300 s), so a deadlocked pip-audit still dies at the wall clock.
# The result then says how long the tree had been idle; the kill is unchanged.

@pytest.fixture
def long_window(monkeypatch):
    monkeypatch.setattr(base, "_SAMPLE_S", 0.25)
    old = base.stall_window()
    base.set_stall_window(100)
    yield
    base.set_stall_window(old)


def test_an_idle_child_at_the_wall_clock_reports_its_idle_time(tmp_path, long_window):
    r = run_subprocess([sys.executable, "-c", "import time; time.sleep(60)"], tmp_path, 2)
    assert r.state is ToolState.TIMEOUT
    assert r.stalled_s is None, "the wall clock killed it, not the watchdog"
    assert r.idle_s is not None and 0.25 <= r.idle_s <= 2.0, r.idle_s
    assert re.fullmatch(
        rf"aramid: {re.escape(r.tool)} timed out after 2 s and was killed; whatever it had"
        r" written is discarded -- no CPU or output for the last \d+ s, which looks hung,"
        r" not slow", r.stderr), r.stderr


def test_a_busy_child_at_the_wall_clock_reports_no_idle_time(tmp_path, long_window):
    r = run_subprocess([sys.executable, "-c", "x = 0\nwhile True: x += 1"], tmp_path, 2)
    assert r.state is ToolState.TIMEOUT
    assert r.stalled_s is None and r.idle_s is None
    assert r.stderr.endswith("whatever it had written is discarded"), r.stderr


class _Clock:
    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t


class _Proc:
    """A child that never exits, on a fake clock: each `wait` sleeps the
    slice it is given (or its timeout) and times out. Empty pipes, so the
    readers finish at once."""
    args = ["fake"]
    pid = 4242

    def __init__(self, clock, slices=()):
        self.clock, self.slices = clock, list(slices)
        self.stdout, self.stderr = io.BytesIO(), io.BytesIO()

    def wait(self, timeout=None):
        self.clock.t += self.slices.pop(0) if self.slices else timeout
        raise subprocess.TimeoutExpired(self.args, timeout)


@pytest.fixture
def fake_clock(monkeypatch):
    """`_watched_communicate` on a fake clock with an idle tree: one sample
    per second, a 3 s window, nothing moving."""
    clock = _Clock()
    monkeypatch.setattr(base, "time", SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(base, "_SAMPLE_S", 1.0)
    monkeypatch.setattr(base.proctree, "sample", lambda pid: {pid: (1, 7)})
    old = base.stall_window()
    base.set_stall_window(3)
    yield clock
    base.set_stall_window(old)


def test_the_idle_figure_runs_to_the_deadline_not_to_the_previous_wake(fake_clock):
    base.set_stall_window(100)
    with pytest.raises(subprocess.TimeoutExpired) as exc:
        base._watched_communicate(_Proc(fake_clock), 5.5, None)
    # Wakes at 1..5 s, then the last slice ends at the 5.5 s deadline. Quiet
    # since the first sample (1 s): 4.5 s at the deadline, 4.0 at the wake before.
    assert fake_clock.t == 5.5
    assert exc.value.idle_s == 4.5


def test_an_idle_tree_on_the_fake_clock_stalls_at_the_window(fake_clock):
    # Control for the gap test below: same harness, no gap.
    with pytest.raises(base._Stalled) as exc:
        base._watched_communicate(_Proc(fake_clock), 1000, None)
    # Quiet from the first sample (1 s); 3 s of it at the 4 s wake.
    assert (fake_clock.t, exc.value.idle_s) == (4.0, 3.0)


def test_a_gap_longer_than_two_samples_restarts_the_quiet_clock(fake_clock):
    # A suspended machine or a starved aramid: the wake after 1 s, 1 s comes
    # 50 s late. Nothing was observed in between, so those 50 s are not
    # evidence of a stall; the window starts again from that wake (52 s).
    with pytest.raises(base._Stalled) as exc:
        base._watched_communicate(_Proc(fake_clock, [1, 1, 50]), 1000, None)
    assert (fake_clock.t, exc.value.idle_s) == (55.0, 3.0)


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
