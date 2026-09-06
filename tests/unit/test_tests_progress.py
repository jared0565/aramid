"""The gate's test suite reports progress while it runs.

Every push on this repo waits ~19 min on `python -m pytest -q` with nothing
on screen (2026-09-05, operator watching a rehearsal tag push). The tests
runner now taps the child's stdout, reads pytest's progress marker from
each line, and hands a one-line summary to a `progress` sink the gate puts
on the RunContext. No sink -> no tap -> byte-identical to before.
"""

import threading
import time

from aramid.runners import tests as tests_runner
from aramid.runners.base import RunContext, RunnerResult, ToolState


# ---------------------------------------------------------- the marker ----

def test_count_style_marker_parses_to_done_total_percent():
    assert tests_runner.parse_pytest_progress("......... [ 69/151]") == (69, 151, 45)


def test_count_style_marker_at_full_width_is_still_read():
    assert tests_runner.parse_pytest_progress("............s   [151/151]") == (151, 151, 100)


def test_percent_style_marker_has_no_count():
    # A repo whose command already sets console_output_style=progress.
    assert tests_runner.parse_pytest_progress(".................. [ 43%]") == (None, None, 43)


def test_a_line_without_a_marker_is_not_progress():
    assert tests_runner.parse_pytest_progress("1824 passed, 3 skipped in 316.84s") is None
    assert tests_runner.parse_pytest_progress("") is None
    # A marker anywhere but the line end is test output, not pytest's progress.
    assert tests_runner.parse_pytest_progress("[ 3/4] is what the fixture printed") is None


# ------------------------------------------------------------ the line ----

def test_progress_line_with_a_count_reads_done_of_total():
    assert tests_runner.format_tests_progress(1234, 2394, 52, 552.0) == \
        "aramid: tests 1234/2394 (52%) 9m12s elapsed"


def test_progress_line_without_a_count_reads_the_percent_only():
    assert tests_runner.format_tests_progress(None, None, 43, 61.0) == \
        "aramid: tests 43% 1m01s elapsed"


def test_progress_line_under_a_minute_has_no_minutes():
    assert tests_runner.format_tests_progress(69, 151, 45, 7.4) == \
        "aramid: tests 69/151 (45%) 7s elapsed"


def test_a_non_finite_or_negative_elapsed_reads_as_zero_not_a_crash():
    # The 15:00Z drain's fuzz pass (2026-09-05) reached `int(inf)`:
    # OverflowError out of a progress line. A monotonic clock never gives
    # inf, but a progress line must never raise into the gate either way.
    for bad in (float("inf"), float("-inf"), float("nan"), -3.0):
        assert tests_runner.format_tests_progress(1, 2, 50, bad) == \
            "aramid: tests 1/2 (50%) 0s elapsed", bad


def test_progress_line_at_exactly_one_minute_switches_to_minutes():
    assert tests_runner.format_tests_progress(69, 151, 45, 60.0) == \
        "aramid: tests 69/151 (45%) 1m00s elapsed"
    assert tests_runner.format_tests_progress(69, 151, 45, 59.9) == \
        "aramid: tests 69/151 (45%) 59s elapsed"


# ------------------------------------------------------- the pytest argv ----

def test_pytest_shaped_argv_gets_the_count_style():
    assert tests_runner.with_count_style(["python", "-m", "pytest", "-q"]) == \
        ["python", "-m", "pytest", "-q", "-o", "console_output_style=count"]
    assert tests_runner.with_count_style(["pytest", "-q"]) == \
        ["pytest", "-q", "-o", "console_output_style=count"]
    assert tests_runner.with_count_style([r"C:\py\Scripts\pytest.exe", "-q"]) == \
        [r"C:\py\Scripts\pytest.exe", "-q", "-o", "console_output_style=count"]


def test_a_command_that_already_sets_the_style_is_left_alone():
    argv = ["pytest", "-q", "-o", "console_output_style=progress"]
    assert tests_runner.with_count_style(argv) == argv
    joined = ["pytest", "-oconsole_output_style=classic"]
    assert tests_runner.with_count_style(joined) == joined


def test_a_non_pytest_command_is_left_alone():
    assert tests_runner.with_count_style(["npm", "test"]) == ["npm", "test"]
    assert tests_runner.with_count_style(["cargo", "test"]) == ["cargo", "test"]


def test_a_trailing_bare_dash_o_does_not_trip_the_style_scan():
    # `-o` with nothing after it is pytest's problem, not an IndexError here.
    assert tests_runner.with_count_style(["pytest", "-o"]) == \
        ["pytest", "-o", "-o", "console_output_style=count"]


# ------------------------------------------------------------ the runner ----

def _pytest_output(argv, cwd, timeout_s, env=None, on_stdout_line=None):
    for line in ("...... [ 69/151]", "...... [138/151]", "..s [151/151]",
                 "150 passed, 1 skipped in 0.21s"):
        on_stdout_line(line)
    return RunnerResult(tool="pytest", state=ToolState.OK, raw="", returncode=0)


def test_without_a_sink_the_launcher_is_called_exactly_as_before(tmp_path, monkeypatch):
    captured = {}

    def strict_fake(argv, cwd, timeout_s, env=None):   # no on_stdout_line accepted
        captured["argv"] = argv
        return RunnerResult(tool="pytest", state=ToolState.OK, raw="", returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", strict_fake)
    tests_runner.run_pytest(RunContext(root=tmp_path))
    assert captured["argv"] == ["pytest", "-q"]
    tests_runner.run_custom(RunContext(root=tmp_path), ["python", "-m", "pytest", "-q"])
    assert captured["argv"] == ["python", "-m", "pytest", "-q"]


def test_with_a_sink_every_marker_becomes_a_progress_line(tmp_path, monkeypatch):
    monkeypatch.setattr(tests_runner, "run_subprocess", _pytest_output)
    clock = iter([0.0, 7.4, 13.0, 19.6])
    monkeypatch.setattr(tests_runner.time, "monotonic", lambda: next(clock, 99.0))
    lines = []
    ctx = RunContext(root=tmp_path, progress=lines.append)
    tests_runner.run_custom(ctx, ["python", "-m", "pytest", "-q"])
    assert lines == [
        "aramid: tests collecting 0s",
        "aramid: tests 69/151 (45%) 7s elapsed",
        "aramid: tests 138/151 (91%) 13s elapsed",
        "aramid: tests 151/151 (100%) 19s elapsed",
    ]


# --------------------------------------------------------- the heartbeat ----

# pytest prints a marker only at the end of a 72-dot line, so on this repo the
# line sat unchanged for up to six minutes through the slow integration tests
# and read as a hang. A timer re-emits the current line with a fresh elapsed
# every HEARTBEAT_S seconds, from "collecting" onwards.

def test_collecting_line_carries_the_elapsed_time():
    assert tests_runner.format_collecting(0.0) == "aramid: tests collecting 0s"
    assert tests_runner.format_collecting(45.2) == "aramid: tests collecting 45s"
    assert tests_runner.format_collecting(65.0) == "aramid: tests collecting 1m05s"
    assert tests_runner.format_collecting(float("inf")) == "aramid: tests collecting 0s"


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


_REAL_MONOTONIC = time.monotonic     # the tests below patch time.monotonic itself


def _wait_for(pred, timeout_s=5.0):
    deadline = _REAL_MONOTONIC() + timeout_s
    while not pred():
        assert _REAL_MONOTONIC() < deadline, "timed out waiting on the heartbeat"
        time.sleep(0.005)


def test_the_heartbeat_re_emits_the_current_line_with_a_fresh_elapsed(tmp_path, monkeypatch):
    monkeypatch.setattr(tests_runner, "HEARTBEAT_S", 0.01)
    clock = _Clock()
    monkeypatch.setattr(tests_runner.time, "monotonic", clock)
    lines = []
    lock = threading.Lock()

    def sink(text):
        with lock:
            lines.append(text)

    def snapshot():
        with lock:
            return list(lines)

    def slow_suite(argv, cwd, timeout_s, env=None, on_stdout_line=None):
        clock.now = 45.0
        _wait_for(lambda: "aramid: tests collecting 45s" in snapshot())
        on_stdout_line("...... [ 69/151]")
        clock.now = 100.0
        _wait_for(lambda: "aramid: tests 69/151 (45%) 1m40s elapsed" in snapshot())
        return RunnerResult(tool="pytest", state=ToolState.OK, raw="", returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", slow_suite)
    tests_runner.run_custom(RunContext(root=tmp_path, progress=sink), ["pytest", "-q"])
    seen = snapshot()
    assert seen[0] == "aramid: tests collecting 0s"
    # The marker itself landed at 45 s; every later heartbeat carried 1m40s.
    assert "aramid: tests 69/151 (45%) 45s elapsed" in seen
    assert seen.index("aramid: tests collecting 45s") < seen.index("aramid: tests 69/151 (45%) 45s elapsed")
    assert not any(t.startswith("aramid: tests collecting") for t in
                   seen[seen.index("aramid: tests 69/151 (45%) 45s elapsed"):])


def test_the_heartbeat_stops_when_the_suite_returns(tmp_path, monkeypatch):
    monkeypatch.setattr(tests_runner, "HEARTBEAT_S", 0.01)
    lines = []
    lock = threading.Lock()

    def sink(text):
        with lock:
            lines.append(text)

    def suite(argv, cwd, timeout_s, env=None, on_stdout_line=None):
        _wait_for(lambda: len(lines) >= 3)
        return RunnerResult(tool="pytest", state=ToolState.OK, raw="", returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", suite)
    tests_runner.run_custom(RunContext(root=tmp_path, progress=sink), ["pytest", "-q"])
    with lock:
        settled = len(lines)
    time.sleep(0.1)     # ten heartbeat intervals
    with lock:
        assert len(lines) == settled
    assert not [t for t in threading.enumerate() if t.name.startswith("aramid-progress")]


def test_the_heartbeat_stops_when_the_suite_times_out(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setattr(tests_runner, "HEARTBEAT_S", 0.01)

    def hung(argv, cwd, timeout_s, env=None, on_stdout_line=None):
        raise subprocess.TimeoutExpired(argv, timeout_s)

    monkeypatch.setattr(tests_runner, "run_subprocess", hung)
    import pytest
    with pytest.raises(subprocess.TimeoutExpired):
        tests_runner.run_custom(RunContext(root=tmp_path, progress=lambda s: None), ["pytest"])
    time.sleep(0.05)
    assert not [t for t in threading.enumerate() if t.name.startswith("aramid-progress")]


def test_a_raising_sink_is_silenced_once_and_the_suite_still_runs(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(tests_runner, "HEARTBEAT_S", 0.01)
    calls = []

    def bad_sink(text):
        calls.append(text)
        raise RuntimeError("terminal gone")

    def suite(argv, cwd, timeout_s, env=None, on_stdout_line=None):
        time.sleep(0.05)
        on_stdout_line("...... [ 69/151]")
        return RunnerResult(tool="pytest", state=ToolState.OK, raw="", returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", suite)
    result = tests_runner.run_custom(RunContext(root=tmp_path, progress=bad_sink), ["pytest"])
    assert result.state is ToolState.OK
    assert calls == ["aramid: tests collecting 0s"]
    err = capsys.readouterr().err
    assert err.count("aramid: progress reporting stopped: RuntimeError('terminal gone')") == 1
    assert "Traceback" not in err


def test_with_a_sink_the_pytest_argv_carries_the_count_style(tmp_path, monkeypatch):
    captured = {}

    def fake(argv, cwd, timeout_s, env=None, on_stdout_line=None):
        captured["argv"] = argv
        return RunnerResult(tool="pytest", state=ToolState.OK, raw="", returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    tests_runner.run_pytest(RunContext(root=tmp_path, progress=lambda s: None))
    assert captured["argv"] == ["pytest", "-q", "-o", "console_output_style=count"]


def test_a_non_pytest_suite_with_a_sink_prints_nothing_but_still_runs(tmp_path, monkeypatch):
    calls = {}

    def fake(argv, cwd, timeout_s, env=None, on_stdout_line=None):
        calls["argv"] = argv
        calls["tap"] = on_stdout_line
        if on_stdout_line:
            on_stdout_line("> jest --ci")
        return RunnerResult(tool="npm", state=ToolState.OK, raw="", returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    lines = []
    tests_runner.run_npm_test(RunContext(root=tmp_path, progress=lines.append))
    assert calls["argv"] == ["npm", "test"]
    assert lines == []


def test_a_configured_non_pytest_command_with_a_sink_is_run_plain(tmp_path, monkeypatch):
    # `[tests].command = ["npm", "test"]` goes through run_custom, the one
    # path that can tap: no pytest, no tap, no "collecting" line.
    calls = {}

    def fake(argv, cwd, timeout_s, env=None, **kw):
        calls["argv"] = argv
        calls["kw"] = kw
        return RunnerResult(tool="npm", state=ToolState.OK, raw="", returncode=0)

    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    lines = []
    tests_runner.run_custom(RunContext(root=tmp_path, progress=lines.append), ["npm", "test"])
    assert calls["argv"] == ["npm", "test"] and calls["kw"] == {}
    assert lines == []
