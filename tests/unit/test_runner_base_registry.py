"""FN-14: the drain's hard deadline has to stop what the consumer started.

The drain exits with `os._exit` at its deadline, which runs no `finally`, so
nothing a consumer launched would be killed by the consumer's own cleanup.
`runners.base` therefore keeps a registry of the children its two long-running
launchers have alive -- `run_subprocess` (every tool, test suite and mutant
run) and `providers.base.run_provider_subprocess` (the LLM CLIs) -- and
`kill_live()` tree-kills whatever is in it. Real child processes here: a
registry that only ever held fakes would say nothing about the launchers."""
import sys
import threading
import time

from aramid.providers import base as providers_base
from aramid.runners import base

_SLEEPER = [sys.executable, "-c", "import time; time.sleep(60)"]


def _wait_for(pred, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def _in_thread(fn):
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", fn()), daemon=True)
    t.start()
    return t, out


def test_a_finished_child_leaves_nothing_registered(tmp_path):
    before = len(base._LIVE)
    r = base.run_subprocess([sys.executable, "-c", "pass"], tmp_path, 60)
    assert r.state is base.ToolState.OK and r.returncode == 0
    assert len(base._LIVE) == before


def test_kill_live_stops_a_running_run_subprocess_child(tmp_path):
    started = time.monotonic()
    t, out = _in_thread(lambda: base.run_subprocess(_SLEEPER, tmp_path, 120))
    assert _wait_for(lambda: len(base._LIVE) == 1), "the child was never registered"
    assert base.kill_live() == 1
    t.join(30)
    assert not t.is_alive(), "run_subprocess still waiting: the child survived kill_live"
    assert time.monotonic() - started < 60, "the child ran its full sleep"
    assert out["r"].returncode != 0
    assert len(base._LIVE) == 0, "a killed child stays registered"


def test_kill_live_stops_a_running_provider_child():
    t, out = _in_thread(lambda: providers_base.run_provider_subprocess(_SLEEPER, "", 120))
    assert _wait_for(lambda: len(base._LIVE) == 1), "the provider child was never registered"
    assert base.kill_live() == 1
    t.join(30)
    assert not t.is_alive(), "the provider child survived kill_live"
    assert out["r"] is not None and out["r"][0] != 0
    assert len(base._LIVE) == 0


def test_a_kill_that_raises_does_not_spare_the_rest():
    """At the deadline the process is about to `os._exit`; one child whose
    kill fails (already gone, access denied) must not leave the next one
    running."""
    hit = []

    def boom():
        raise OSError("gone")
    with base.live_process(boom), base.live_process(lambda: hit.append(1)):
        assert base.kill_live() == 1
    assert hit == [1]
    assert len(base._LIVE) == 0


def test_kill_live_with_nothing_registered_is_a_no_op():
    assert base.kill_live() == 0


# --- close: the deadline's kill sticks ----------------------------------------
# `kill_live(close=True)` is the deadline's call. Every test that closes
# resets `_CLOSED` through monkeypatch, so the rest of the session is not
# left with launchers that refuse to start anything.

def test_after_close_run_subprocess_starts_nothing(tmp_path, monkeypatch):
    """A looping consumer's next child, asked for after the deadline, is
    never started -- it would outlive the drain's `os._exit`."""
    monkeypatch.setattr(base, "_CLOSED", False)
    assert base.kill_live(close=True) == 0
    marker = tmp_path / "started"
    r = base.run_subprocess([sys.executable, "-c",
                             f"open({str(marker)!r}, 'w').write('x')"], tmp_path, 60)
    assert r.state is base.ToolState.TIMEOUT
    assert "hard deadline" in r.stderr
    time.sleep(1.0)
    assert not marker.exists(), "a child was started after the close"


def test_after_close_the_provider_launcher_starts_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "_CLOSED", False)
    base.kill_live(close=True)
    marker = tmp_path / "started"
    assert providers_base.run_provider_subprocess(
        [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')"], "", 60) is None
    time.sleep(1.0)
    assert not marker.exists()


def test_a_child_registered_after_the_close_is_killed_at_once(monkeypatch):
    """The window between `Popen` and registering: a child that slips
    through it meets a closed registry and is killed on the spot."""
    monkeypatch.setattr(base, "_CLOSED", False)
    base.kill_live(close=True)
    hit = []
    with base.live_process(lambda: hit.append(1)):
        assert hit == [1]
    assert len(base._LIVE) == 0


def test_a_child_the_close_killed_reads_as_timeout_not_as_its_exit_code(tmp_path, monkeypatch):
    """A test run killed by the deadline exits non-zero, which the mutation
    consumer would read as "the tests failed", i.e. the mutant was killed:
    a false clean. It reads as TIMEOUT instead: the state a consumer
    already gets from a child that ran out of its own time."""
    monkeypatch.setattr(base, "_CLOSED", False)
    t, out = _in_thread(lambda: base.run_subprocess(_SLEEPER, tmp_path, 120))
    assert _wait_for(lambda: len(base._LIVE) == 1)
    assert base.kill_live(close=True) == 1
    t.join(30)
    assert not t.is_alive()
    assert out["r"].state is base.ToolState.TIMEOUT
    assert "hard deadline" in out["r"].stderr


def test_a_plain_kill_live_does_not_close(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "_CLOSED", False)
    base.kill_live()
    assert base.closed() is False
    r = base.run_subprocess([sys.executable, "-c", "pass"], tmp_path, 60)
    assert r.state is base.ToolState.OK
