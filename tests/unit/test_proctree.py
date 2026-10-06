"""proctree.sample: the process-tree measurement the stall watchdog compares
between two wakes. Pure parts (walk, parsers) are tested with literals; the
live part runs on every CI OS against real children."""
import os
import subprocess
import sys
import time

from aramid import proctree


def test_walk_returns_root_and_every_descendant():
    parent_of = {10: 1, 11: 10, 12: 11, 13: 10, 99: 1}
    times = {10: (100, 5), 11: (101, 6), 12: (102, 7), 13: (103, 8), 99: (1, 9)}.get
    assert proctree.walk(10, parent_of, times) == {
        10: (100, 5), 11: (101, 6), 12: (102, 7), 13: (103, 8)}


def test_walk_skips_a_reused_pid_created_before_its_parent():
    # 11's ppid says 10, but 11 was created before 10: a reused pid, not a child.
    parent_of = {10: 1, 11: 10}
    times = {10: (200, 5), 11: (150, 6)}.get
    assert proctree.walk(10, parent_of, times) == {10: (200, 5)}


def test_walk_keeps_a_child_when_creation_time_is_unknown():
    parent_of = {10: 1, 11: 10}
    times = {10: (0, 5), 11: (0, 6)}.get
    assert proctree.walk(10, parent_of, times) == {10: (0, 5), 11: (0, 6)}


def test_a_pid_that_vanishes_mid_walk_is_skipped():
    parent_of = {10: 1, 11: 10, 12: 10}
    times = {10: (100, 5), 12: (102, 7)}.get        # 11 exited after the listing
    assert proctree.walk(10, parent_of, times) == {10: (100, 5), 12: (102, 7)}


def test_walk_of_a_missing_root_is_none():
    assert proctree.walk(10, {}, {}.get) is None
    # Timeable but no longer listed (a Windows zombie whose handle is open):
    assert proctree.walk(10, {11: 1}, {10: (1, 1), 11: (2, 2)}.get) is None


def test_walk_survives_a_self_parented_pid():
    parent_of = {0: 0, 10: 0}
    times = {0: (1, 1), 10: (2, 2)}.get
    assert proctree.walk(0, parent_of, times) == {0: (1, 1), 10: (2, 2)}


def test_parse_proc_stat_reads_ppid_start_and_cpu_past_a_hostile_comm():
    # comm may contain spaces and ')' -- parse after the LAST ')'.
    text = "4242 (evil ) name) S 4000 4242 4000 0 -1 4194560 100 0 0 0 7 3 0 0 20 0 1 0 555 0 0"
    assert proctree.parse_proc_stat(text) == (4000, 555, 10)


def test_parse_proc_stat_of_garbage_is_none():
    assert proctree.parse_proc_stat("4242 (x) S") is None
    assert proctree.parse_proc_stat("") is None


def test_parse_ps_reads_minutes_hours_and_days():
    text = ("  1     0   0:01.50\n"
            " 20     1  12:00.00\n"
            " 21    20 1:02:03.04\n"
            " 22    20 2-01:00:00.00\n"
            "bad line\n")
    assert proctree.parse_ps(text) == {
        1: (0, 0, 150),
        20: (1, 0, 72000),
        21: (20, 0, 372304),
        22: (20, 0, 17640000),
    }


def test_sample_of_this_process_contains_this_process():
    snap = proctree.sample(os.getpid())
    assert snap is not None
    assert os.getpid() in snap


def test_sample_sees_a_live_child_and_its_cpu_advance():
    burn = "import time\nt=time.time()\nwhile time.time()-t<3: pass\ntime.sleep(30)"
    child = subprocess.Popen([sys.executable, "-c", burn])
    try:
        time.sleep(0.5)
        me = os.getpid()
        first = proctree.sample(me)
        assert first is not None and child.pid in first
        time.sleep(1.5)
        second = proctree.sample(me)
        assert second[child.pid][1] > first[child.pid][1], "a busy child's CPU must advance"
    finally:
        child.kill()
        child.wait()
