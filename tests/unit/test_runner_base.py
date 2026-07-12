import sys
import time
from pathlib import Path
from aramid.runners.base import run_subprocess, ToolState

def test_missing_binary_is_missing(tmp_path):
    r = run_subprocess(["definitely-not-a-real-binary-xyz"], tmp_path, 5)
    assert r.state is ToolState.MISSING

def test_ok_captures_stdout(tmp_path):
    r = run_subprocess([sys.executable, "-c", "print('hi')"], tmp_path, 10)
    assert r.state is ToolState.OK and "hi" in r.raw

def test_ok_captures_zero_returncode(tmp_path):
    r = run_subprocess([sys.executable, "-c", "pass"], tmp_path, 10)
    assert r.state is ToolState.OK and r.returncode == 0

def test_ok_captures_nonzero_returncode(tmp_path):
    # A checker that "finds issues" exits non-zero without crashing --
    # run_subprocess must surface that exit code (needed by the tests
    # adapter, which has no JSON/text signal other than the exit code
    # itself to know pytest/npm-test failed).
    r = run_subprocess([sys.executable, "-c", "import sys;sys.exit(3)"], tmp_path, 10)
    assert r.state is ToolState.OK and r.returncode == 3

def test_timeout_kills(tmp_path):
    r = run_subprocess([sys.executable, "-c", "import time;time.sleep(30)"], tmp_path, 1)
    assert r.state is ToolState.TIMEOUT

def test_timeout_returns_promptly_and_bounded(tmp_path):
    # Confirms the happy path still returns TIMEOUT promptly after the
    # bounded post-kill drain was added (no regression from the fix).
    # Note: this does not exercise the "taskkill silently fails" branch
    # that motivated the fix -- on this path _kill_tree succeeds, so the
    # post-kill communicate() returns immediately regardless of its 5s
    # cap. The guarantee that a *failed* kill can no longer hang forever
    # rests on the bounded-timeout code itself (see base.py) plus
    # inspection, not on this test reproducing the failure.
    start = time.monotonic()
    r = run_subprocess([sys.executable, "-c", "import time;time.sleep(5)"], tmp_path, 0.5)
    elapsed = time.monotonic() - start
    assert r.state is ToolState.TIMEOUT
    assert elapsed < 10  # well under the 5s sleep + old unbounded-wait failure mode
