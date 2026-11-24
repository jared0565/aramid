"""FN-14, end to end in a real process: the drain's hard deadline stops a
consumer that would otherwise run past the schedule, and leaves the record
the outside kills of 2026-09-25 and 09-27 did not -- a `degraded`
CONSUMER_RUN_FINISHED row, every process the consumer started dead, the
lock gone, the item still queued, exit 2.

A real `python` child runs `cmd_drain`, because the watchdog ends its
process with `os._exit`: in-process it would take the test runner with it.
The child patches its own seams (the suite's autouse fixtures are
monkeypatches this process cannot hand down) and sets the deadline
in-process -- there is no environment variable for it, and adding one to
make a test possible would be surface for a test's sake. The control arm
is the same child with a deadline that does not fall due: it drains
cleanly, so the kill arm's exit, row and dead processes are the deadline's
doing and nothing else's.

The consumer LOOPS, starting a new child each time the last one returns,
the way the mutation consumer runs one pytest per mutant. Killing the
running child hands control straight back to that loop, which would start
the next one before the process exits; the kill is slowed here to model
taskkill's latency, so that window is exercised, not left to luck."""
import json
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timedelta, timezone

from aramid import queue
from aramid.commands import drain as drain_mod
from aramid.ledger import Ledger
from aramid.models import EventType

_CHILD = textwrap.dedent('''
    import json, sys, time
    from pathlib import Path

    cfg = json.loads(sys.argv[1])
    tmp = Path(cfg["tmp"])

    from aramid import autolearn, config, drain_limits, leftovers, registry
    from aramid.commands import drain as drain_mod
    from aramid.commands import schedule
    from aramid.consumers.base import ConsumerResult
    from aramid.runners import base as runners_base

    drain_mod._lock_path = lambda: tmp / "drain.lock"
    autolearn.state_path = lambda: tmp / "autolearn_state.json"
    registry.registry_path = lambda: tmp / "repos.toml"
    config._user_config_path = lambda: tmp / "no-such-user-config.toml"
    leftovers.temp_root = lambda: tmp / "shells"
    schedule.installed_task_limit_minutes = lambda: None
    drain_limits.drain_deadline_s = lambda cfgs, **kw: cfg["deadline_s"]

    real_kill_live = runners_base.kill_live

    def slow_kill_live(**kw):
        done = real_kill_live(**kw)
        time.sleep(3)                   # taskkill returning late
        return done
    runners_base.kill_live = slow_kill_live

    # Each child starts a grandchild, records both pids, and sleeps: a kill
    # that stops only the direct child leaves the grandchild running, which
    # is what a mutant's pytest would do.
    GRANDPARENT = cfg.get("grandparent") or (
        "import subprocess, sys, time; "
        "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(%d)']); "
        "open(sys.argv[1], 'w').write('%%d %%d' %% (__import__('os').getpid(), g.pid)); "
        "time.sleep(%d)" % (cfg["sleep_s"], cfg["sleep_s"]))

    class Looping:
        @staticmethod
        def consume(item, ctx):
            states = []
            for i in range(cfg["loops"]):
                r = runners_base.run_subprocess(
                    [sys.executable, "-c", GRANDPARENT, str(tmp / f"pids-{i}")], tmp, 600)
                states.append(f"{r.state.value}:{r.returncode}")
            return ConsumerResult(consumer="looping", state="ok", note=",".join(states))

    drain_mod.CONSUMERS.clear()
    drain_mod.CONSUMERS["looping"] = Looping
    sys.exit(drain_mod.cmd_drain([cfg["repo"]]))
''')


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo_with_item(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty",
         "-m", "benign HEAD")
    (r / ".aramid").mkdir()
    at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, check=True,
                              capture_output=True, text=True).stdout.strip()
        queue.record_triage(led, at, head, head, 45, True, [])
        item = queue.enqueue(led, at, head, head, 45, ["t"])
    finally:
        led.close()
    return r, item


def _run_child(tmp_path, env, repo, *, deadline_s, sleep_s, loops, grandparent=None):
    (tmp_path / "shells").mkdir(exist_ok=True)
    arg = json.dumps({"tmp": str(tmp_path), "repo": str(repo), "deadline_s": deadline_s,
                      "sleep_s": sleep_s, "loops": loops, "grandparent": grandparent})
    started = time.monotonic()
    cp = subprocess.run([sys.executable, "-c", _CHILD, arg], env=env, capture_output=True,
                        text=True, errors="replace", timeout=240)
    return cp, time.monotonic() - started


def _finished_rows(repo):
    led = Ledger(repo / ".aramid" / "ledger.db")
    try:
        return ([e.payload for e in led.events()
                 if e.type == EventType.CONSUMER_RUN_FINISHED],
                queue.queued_item(queue.materialize_queue(led.events())))
    finally:
        led.close()


def _started(tmp_path):
    """{pid-file name: [child pid, grandchild pid]} for every child that got
    far enough to say so. Read after a pause, so a child started in the
    last moment before the exit has had time to write its file."""
    time.sleep(3)
    return {p.name: [int(x) for x in p.read_text(encoding="utf-8").split()]
            for p in sorted(tmp_path.glob("pids-*"))}


def test_the_deadline_kills_everything_the_consumer_started_and_leaves_the_record(
        tmp_path, checkout_env):
    repo, item = _repo_with_item(tmp_path)
    # Ten seconds from the lock: the drain's own start-up (config, sweep,
    # ledger) must be over and the consumer's first child up before it
    # falls due.
    cp, took = _run_child(tmp_path, checkout_env, repo, deadline_s=10.0, sleep_s=120, loops=20)
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert took < 90, f"the drain ran {took:.0f} s: the deadline did not stop it"
    assert "hard deadline" in cp.stderr
    started = _started(tmp_path)
    assert list(started) == ["pids-0"], \
        f"the consumer's loop started more children after the deadline: {sorted(started)}"
    pids = [pid for pair in started.values() for pid in pair]
    deadline = time.monotonic() + 15      # taskkill /T returns before the tree is reaped
    while time.monotonic() < deadline and any(drain_mod._pid_alive(p) for p in pids):
        time.sleep(0.2)
    alive = [p for p in pids if drain_mod._pid_alive(p)]
    assert alive == [], f"outlived the drain: {alive} of {started}"
    assert not (tmp_path / "drain.lock").exists(), "the lock leaked"
    rows, queued = _finished_rows(repo)
    assert [(r["consumer"], r["state"], r["item_id"]) for r in rows] == \
        [("looping", "degraded", item.id)]
    assert "[drain].hard_deadline_s" in rows[0]["note"]
    assert queued is not None and queued.id == item.id, "the killed item was dropped"


def test_control_a_deadline_that_does_not_fall_due_drains_cleanly(tmp_path, checkout_env):
    repo, item = _repo_with_item(tmp_path)
    cp, _took = _run_child(tmp_path, checkout_env, repo, deadline_s=600.0, sleep_s=1, loops=2)
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    assert "hard deadline" not in cp.stderr
    assert sorted(_started(tmp_path)) == ["pids-0", "pids-1"]
    rows, queued = _finished_rows(repo)
    assert [(r["consumer"], r["state"]) for r in rows] == [("looping", "ok")]
    assert rows[0]["note"] == "ok:0,ok:0"
    assert queued is None, "a clean drain left the item queued"
    assert not (tmp_path / "drain.lock").exists()


# The consumer's child starts a burst of grandchildren around the deadline, so
# the kill lands while it is still starting them. On Windows `taskkill /T` lists
# the tree and THEN kills it: a grandchild started in between was never listed,
# and it outlived the drain in 16 of 20 measured trials while taskkill exited 0
# (2026-11-24). Each grandchild touches its own heartbeat file until a stop file
# appears, so "still running after the drain" is read from writes, not from a
# PID -- a reused PID cannot pass for a survivor, and none can hide behind one.
_BURST_LEAD_S = 1.0     # the burst starts this long before the deadline...
_BURST_GAP_S = 0.02     # ...one grandchild every 20 ms...
_BURST_MAX = 150        # ...and stops by itself, so a missed deadline cannot run away
_SPAWNER = textwrap.dedent('''
    import json, os, subprocess, sys, time
    from pathlib import Path
    tmp = Path(sys.argv[1]).parent
    HEART = (
        "import sys, time\\n"
        "from pathlib import Path\\n"
        "hb, stop = Path(sys.argv[1]), Path(sys.argv[2])\\n"
        "end = time.monotonic() + 120\\n"
        "while time.monotonic() < end and not stop.exists():\\n"
        "    hb.touch()\\n"
        "    time.sleep(0.1)\\n")
    lock = json.loads((tmp / "drain.lock").read_text(encoding="utf-8"))
    start = float(lock["started_at"]) + float(lock["deadline_s"]) - LEAD
    Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")
    while time.time() < start:
        time.sleep(0.02)
    for n in range(MAX):
        subprocess.Popen([sys.executable, "-c", HEART, str(tmp / f"hb-{n}"), str(tmp / "stop")])
        time.sleep(GAP)
    time.sleep(600)
''').replace("LEAD", repr(_BURST_LEAD_S)).replace("MAX", repr(_BURST_MAX)) \
    .replace("GAP", repr(_BURST_GAP_S))


def test_nothing_the_consumer_starts_as_the_deadline_kills_it_outlives_the_drain(
        tmp_path, checkout_env):
    repo, _item = _repo_with_item(tmp_path)
    try:
        cp, took = _run_child(tmp_path, checkout_env, repo, deadline_s=10.0, sleep_s=0,
                              loops=1, grandparent=_SPAWNER)
        exited = time.time()
        assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
        assert took < 90, f"the drain ran {took:.0f} s: the deadline did not stop it"
        beats = sorted(tmp_path.glob("hb-*"))
        # Teeth: the burst ran, so the kill met children being started.
        assert len(beats) >= 5, f"only {len(beats)} grandchildren started before the kill"
        time.sleep(1.5)
        alive = [hb.name for hb in beats if hb.stat().st_mtime > exited + 0.5]
        assert alive == [], (f"{len(alive)} of {len(beats)} grandchildren still running "
                             f"after the drain exited: {alive[:10]}")
    finally:
        (tmp_path / "stop").touch()     # ends every survivor within 0.1 s
        time.sleep(0.5)
