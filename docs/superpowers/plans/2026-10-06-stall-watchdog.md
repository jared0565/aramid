# Stall Watchdog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The resumable state stays in the gitignored `.superpowers/sdd/progress.md`.

**Goal:** `run_subprocess` recognises a child process tree that has stopped working (no CPU in any member, no output on either pipe, for `[timeouts].stall_s` seconds), kills it early, and reports it as *stalled* instead of letting it burn its whole wall-clock budget and reporting a bare `timeout`.

**Architecture:** A new stdlib-only module `aramid/proctree.py` samples `{pid: (created, cpu)}` for a root pid and its descendants (Windows: ctypes Toolhelp32 + GetProcessTimes; Linux: `/proc`; elsewhere: `ps`). `runners/base.py` always drains both pipes with reader threads that count characters, waits in 15 s slices, and compares samples. A stall is still `ToolState.TIMEOUT`, so every existing TIMEOUT branch keeps its control flow, but it carries `RunnerResult.stalled_s`. Reports read that field: `_degraded_reasons`, `GateResult.stalled`, the run row, `status`, health and fleet.

**Tech Stack:** Python 3.11+ stdlib (`ctypes`, `subprocess`, `threading`), pytest.

**Spec:** `docs/superpowers/specs/2026-10-06-aramid-stall-watchdog-and-handover-design.md` (Part A).

## Global Constraints

1. `src/aramid/runners/base.py` and `src/aramid/proctree.py` import nothing outside the standard library. The release's sdist smoke installs with `--no-deps` and imports the runners (0.17.10 failed its first tag run on exactly this).
2. **Every measurement failure means "active", never "stalled".** If `proctree.sample` returns `None`, raises, or cannot see, the watchdog behaves exactly like today's wall-clock timeout.
3. A stall is `ToolState.TIMEOUT` plus `stalled_s`. Never add a `ToolState` member. About a dozen sites branch on `is ToolState.TIMEOUT`; in mutation, a default branch means "mutant killed".
4. Defaults: `SAMPLE_S = 15.0`, `[timeouts] stall_s = 300`, and `0` disables the watchdog.
5. Stall reason text, verbatim: `aramid: <tool> stalled: no CPU in any of its <n> processes and no output for <idle:.0f> s; killed after <elapsed:.0f> s. A child blocked on a full pipe or on a read with no timeout looks like this; a slow one does not.`
6. Degraded reason text, verbatim: `stalled: no CPU or output for <idle:.0f> s (killed after <elapsed:.0f> s)`.
7. Every commit: CHANGELOG `[Unreleased]` entry; `python -P -m aramid check --staged`; `python -P -m aramid ledger filter --status open` (six suppressed rows and nothing else unless the new row is understood); `git commit -F <file>` written with the Write tool; trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; never `--no-verify`. Never `pip install -e .`.
8. New test files: run `pytest --co -q tests` before staging. Twins need unique basenames, since one module namespace covers all tests.
9. Push in the background with its own log and rc file, `timeout: 5400000` (the gate takes about 34 min), no tree edits while it runs, sampled rather than waited on blind; then CI 7/7 by full sha, attempt 1.

## Review Focus

1. **A child that exits while a sample is being taken.** `sample()` must return a smaller tree or `None`, never raise into the launcher. Test: Task 1 `test_a_pid_that_vanishes_mid_walk_is_skipped`.
2. **A busy grandchild under an idle child.** That is activity, never a stall. Test: Task 2 `test_a_busy_grandchild_keeps_an_idle_child_alive`.
3. **Large stderr with no stdout.** It must not deadlock aramid's own launcher (the pip-audit shape, turned on ourselves). Test: Task 2 `test_a_child_flooding_stderr_completes_and_is_not_stalled`.
4. **`stall_s = 0`.** Exactly today's behaviour; a sleeping child runs to the wall clock. Test: Task 2 `test_window_zero_disables_the_watchdog`.
5. **Invalid UTF-8 and the existing timeout/kill tests in `tests/unit/test_runner_base.py`.** They must pass unchanged on the unified reader path. Covered by running that whole file in Task 2 Step 4.

---

### Task 1: `proctree.sample` -- measure a process tree

**Files:**
- Create: `src/aramid/proctree.py`
- Test: `tests/unit/test_proctree.py`

**Interfaces:**
- Produces: `proctree.sample(root_pid: int) -> dict[int, tuple[int, int]] | None`, mapping pid to (creation ticks, CPU ticks), for the root and every descendant. `None` means not measurable. Also `proctree.walk(root_pid, parent_of, times)`, the pure tree walk, plus the parsers `proctree.parse_proc_stat(text) -> tuple[int, int, int] | None` (ppid, start, cpu) and `proctree.parse_ps(text) -> dict[int, tuple[int, int, int]]` (pid to (ppid, 0, cpu centiseconds)).

- [ ] **Step 1: Write the failing tests**

```python
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

```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -P -m pytest tests/unit/test_proctree.py -q`
Expected: collection error, `cannot import name 'proctree'`.

- [ ] **Step 3: Implement `src/aramid/proctree.py`**

```python
"""Measure a child process TREE: each member's creation time and CPU time.

`sample(pid)` returns {pid: (created, cpu)} for `pid` and every live
descendant, or None when the tree cannot be measured. Units are platform
ticks; callers only ever compare two samples for equality. Standard library
only -- runners/base imports this, and the release's sdist smoke installs
with --no-deps.

None is "not measured", NEVER "idle": the stall watchdog treats it as
activity, so a sampler that cannot see degrades to the wall-clock timeout
instead of inventing a stall. Every error inside this module leans the same
way: a pid that vanishes mid-walk is skipped (the tree changed = activity),
a reused pid created before its "parent" is not a descendant, and a
platform with no creation time records 0 and keeps the child.
"""
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable

Sample = dict[int, tuple[int, int]]
_PROC = Path("/proc")          # test seam
_PS_TIMEOUT_S = 5.0


def walk(root_pid: int, parent_of: dict[int, int],
         times: Callable[[int], tuple[int, int] | None]) -> Sample | None:
    """The root and every descendant reachable through `parent_of`, each
    with `times(pid)`. None when the root is not in the listing or cannot be
    timed (on Windows an exited child whose handle is still open can be
    timed, so the LISTING is what says it is gone)."""
    if root_pid not in parent_of:
        return None
    root = times(root_pid)
    if root is None:
        return None
    kids: dict[int, list[int]] = {}
    for pid, ppid in parent_of.items():
        if pid != ppid:
            kids.setdefault(ppid, []).append(pid)
    out: Sample = {root_pid: root}
    stack = [root_pid]
    while stack:
        parent = stack.pop()
        born = out[parent][0]
        for kid in kids.get(parent, ()):
            if kid in out:
                continue
            t = times(kid)
            if t is None:                       # exited after the listing
                continue
            if t[0] and born and t[0] < born:   # a reused pid, not our child
                continue
            out[kid] = t
            stack.append(kid)
    return out


def parse_proc_stat(text: str) -> tuple[int, int, int] | None:
    """(ppid, starttime, utime + stime) from one /proc/<pid>/stat line.
    comm (field 2) may hold spaces and ')', so fields are counted from the
    LAST ')'. After it, rest[0] is field 3, so field n is rest[n - 3]."""
    close = text.rfind(")")
    if close < 0:
        return None
    rest = text[close + 2:].split()
    try:
        return int(rest[1]), int(rest[19]), int(rest[11]) + int(rest[12])
    except (IndexError, ValueError):
        return None


def _cpu_centis(field: str) -> int | None:
    """`ps -o time` -> centiseconds: [[dd-]hh:]mm:ss[.cc]."""
    days = 0
    if "-" in field:
        d, field = field.split("-", 1)
        days = int(d)
    parts = field.split(":")
    secs = float(parts[-1])
    mins = int(parts[-2]) if len(parts) >= 2 else 0
    hours = int(parts[-3]) if len(parts) >= 3 else 0
    return round(((days * 24 + hours) * 60 + mins) * 6000 + secs * 100)


def parse_ps(text: str) -> dict[int, tuple[int, int, int]]:
    """`ps -A -o pid=,ppid=,time=` -> {pid: (ppid, 0, cpu centiseconds)};
    unparseable lines are skipped. ps gives no creation time, so 0."""
    table: dict[int, tuple[int, int, int]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        try:
            cpu = _cpu_centis(parts[2])
            table[int(parts[0])] = (int(parts[1]), 0, cpu)
        except (ValueError, IndexError):
            continue
    return table


def _from_table(root_pid: int, table: dict[int, tuple[int, int, int]]) -> Sample | None:
    parent_of = {pid: row[0] for pid, row in table.items()}
    return walk(root_pid, parent_of, lambda pid: table[pid][1:] if pid in table else None)


def _sample_proc(root_pid: int) -> Sample | None:
    table = {}
    for entry in _PROC.iterdir():
        if entry.name.isdigit():
            try:
                row = parse_proc_stat((entry / "stat").read_text())
            except OSError:
                continue
            if row is not None:
                table[int(entry.name)] = row
    return _from_table(root_pid, table)


def _sample_ps(root_pid: int) -> Sample | None:
    done = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,time="],  # noqa: S603,S607
                          capture_output=True, text=True, timeout=_PS_TIMEOUT_S)
    if done.returncode != 0:
        return None
    return _from_table(root_pid, parse_ps(done.stdout))


def _sample_windows(root_pid: int) -> Sample | None:
    import ctypes
    import ctypes.wintypes as wt

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                    ("th32ProcessID", wt.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                    ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.OpenProcess.restype = wt.HANDLE
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k32.GetProcessTimes.argtypes = [wt.HANDLE] + [ctypes.POINTER(wt.FILETIME)] * 4
    k32.CloseHandle.argtypes = [wt.HANDLE]

    snap = k32.CreateToolhelp32Snapshot(0x2, 0)          # TH32CS_SNAPPROCESS
    if not snap or snap == ctypes.c_void_p(-1).value:
        return None
    parent_of: dict[int, int] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            parent_of[entry.th32ProcessID] = entry.th32ParentProcessID
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)

    def ticks(ft) -> int:
        return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

    def times(pid: int) -> tuple[int, int] | None:
        h = k32.OpenProcess(0x1000, False, pid)          # QUERY_LIMITED_INFORMATION
        if not h:
            return None
        try:
            c, e, kt, ut = wt.FILETIME(), wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
            if not k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e),
                                       ctypes.byref(kt), ctypes.byref(ut)):
                return None
            return ticks(c), ticks(kt) + ticks(ut)
        finally:
            k32.CloseHandle(h)

    return walk(root_pid, parent_of, times)


def sample(root_pid: int) -> Sample | None:
    """See the module docstring. Never raises."""
    try:
        if sys.platform == "win32":
            return _sample_windows(root_pid)
        if _PROC.is_dir():
            return _sample_proc(root_pid)
        return _sample_ps(root_pid)
    except Exception:  # noqa: BLE001 -- unmeasurable is "active", never a crash
        return None
```

Delete `import os` from the module if ruff reports it unused. The tests import `os` themselves.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -P -m pytest tests/unit/test_proctree.py -q`
Expected: all pass. On Windows the live tests exercise ctypes; CI's ubuntu legs exercise `/proc` and the macOS leg exercises `ps`.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/proctree.py tests/unit/test_proctree.py CHANGELOG.md
git commit -F <msg file>   # feat(proctree): measure a child process tree's CPU, stdlib only
```

---

### Task 2: The watched wait in `run_subprocess`

**Files:**
- Modify: `src/aramid/runners/base.py`: `RunnerResult` (around line 90), `_tapped_communicate` (around line 407; replaced), `run_subprocess` (around line 443).
- Test: `tests/unit/test_runner_base_stall.py`

**Interfaces:**
- Consumes: `proctree.sample` (Task 1).
- Produces: `RunnerResult.stalled_s: float | None = None`; `base.set_stall_window(seconds: float) -> None`; `base.stall_window() -> float`; module seams `base._SAMPLE_S` (15.0) and `base.DEFAULT_STALL_S` (300.0).

- [ ] **Step 1: Write the failing tests**

```python
"""The stall watchdog in run_subprocess: a child TREE with no CPU and no
output for the stall window is killed early and reported as stalled (still
ToolState.TIMEOUT, carrying stalled_s). Windows are shrunk through the
module seams so each test runs in seconds."""
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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -P -m pytest tests/unit/test_runner_base_stall.py -q`
Expected: FAIL. `base.stall_window` does not exist (AttributeError in the fixture).

- [ ] **Step 3: Implement in `src/aramid/runners/base.py`**

Add `from aramid import proctree` beside `from aramid import toolpath`.

In `RunnerResult`, after `examined`:

```python
    # Seconds of NO CPU in the child's whole process tree and NO output on
    # either pipe when the stall watchdog killed it; None when it was not
    # stalled. A stall is still ToolState.TIMEOUT -- a dozen sites branch on
    # TIMEOUT (a killed mutation run must never read as a killed mutant), so
    # only the REPORT differs, never the control flow.
    stalled_s: float | None = None
```

Replace `_tapped_communicate` with `_watched_communicate`, and add the watchdog state above it:

```python
# Stall watchdog (0.20.4). A wall-clock timeout alone cannot tell a slow
# child from one that stopped working: a pip-audit whose inner pip blocked on
# a full stderr pipe (Windows pipes hold 4096 bytes; pip-audit reads stdout
# to EOF before touching stderr) sat at zero CPU for 97 minutes on
# 2026-10-06. Every SAMPLE_S the launcher compares the child TREE's
# {pid: (created, cpu)} and the characters read so far; no change in any of
# them for the stall window = stalled. Module state, like the drain's
# `closed()`: the launchers are reached from inside consumers that hold no
# config. `cmd_check` and the drain set it from `[timeouts].stall_s`.
_SAMPLE_S = 15.0
DEFAULT_STALL_S = 300.0
_STALL_S = DEFAULT_STALL_S


def set_stall_window(seconds: float) -> None:
    """0 disables the watchdog (wall clock only); negatives clamp to 0."""
    global _STALL_S
    _STALL_S = max(0.0, float(seconds))


def stall_window() -> float:
    return _STALL_S


class _Stalled(Exception):
    def __init__(self, idle_s: float, procs: int):
        super().__init__(f"stalled for {idle_s:.0f} s")
        self.idle_s = idle_s
        self.procs = procs


def _watched_communicate(proc: subprocess.Popen, timeout_s: float, on_stdout_line):
    """Drain both pipes on daemon threads (a single-threaded read of one pipe
    lets the other fill its OS buffer and wedge the child -- exactly the bug
    that hung pip-audit), tap stdout lines to `on_stdout_line` when given, and
    wait in SAMPLE_S slices. Raises `subprocess.TimeoutExpired` at the wall
    clock and `_Stalled` when neither the tree's CPU/membership nor the
    output moved for the stall window. An unmeasurable tree (sample() ->
    None) counts as activity, so a watchdog that cannot see is today's
    timeout, never a false stall. Returns (stdout, stderr) whole."""
    chunks: dict[str, list[str]] = {"out": [], "err": []}
    seen = [0]

    def pump(name, stream, tap):
        for line in iter(stream.readline, ""):
            chunks[name].append(line)
            seen[0] += len(line)
            if tap is not None:
                try:
                    tap(line.rstrip("\r\n"))
                except Exception as exc:  # noqa: BLE001 -- decoration never fails the run
                    print(f"aramid: progress reporting stopped: {exc!r}", file=sys.stderr)
                    tap = None
        stream.close()

    readers = [threading.Thread(target=pump, args=("out", proc.stdout, on_stdout_line), daemon=True),
               threading.Thread(target=pump, args=("err", proc.stderr, None), daemon=True)]
    for t in readers:
        t.start()
    deadline = time.monotonic() + timeout_s
    window = _STALL_S
    last_tree, last_seen = None, -1
    quiet_since = time.monotonic()
    while True:
        try:
            proc.wait(timeout=max(0.0, min(_SAMPLE_S, deadline - time.monotonic())))
            break
        except subprocess.TimeoutExpired:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(proc.args, timeout_s) from None
        if not window:
            continue
        now = time.monotonic()
        tree = proctree.sample(proc.pid)
        if tree is None or last_tree is None or tree != last_tree or seen[0] != last_seen:
            quiet_since = now
        last_tree, last_seen = tree, seen[0]
        if now - quiet_since >= window:
            raise _Stalled(now - quiet_since, len(tree))
    for t in readers:
        t.join(timeout=_POST_KILL_DRAIN_S)
    return "".join(chunks["out"]), "".join(chunks["err"])
```

In `run_subprocess`, replace the `try:` block from `with live_process(...)` through the TIMEOUT return with:

```python
    try:
        with live_process(lambda: _kill_tree(proc)):
            out, err = _watched_communicate(proc, timeout_s, on_stdout_line)
    except (subprocess.TimeoutExpired, _Stalled) as stop:
        _kill_tree(proc)
        try:
            # The reader threads own the pipes; `communicate` here would race
            # them for a stream one of them may already have closed.
            proc.wait(timeout=_POST_KILL_DRAIN_S)
        except subprocess.TimeoutExpired:
            proc.kill()
        elapsed = time.monotonic() - start
        if isinstance(stop, _Stalled):
            return RunnerResult(tool, ToolState.TIMEOUT,
                                stderr=(f"aramid: {tool} stalled: no CPU in any of its "
                                        f"{stop.procs} processes and no output for "
                                        f"{stop.idle_s:.0f} s; killed after {elapsed:.0f} s. "
                                        f"A child blocked on a full pipe or on a read with "
                                        f"no timeout looks like this; a slow one does not."),
                                duration_s=elapsed, stalled_s=stop.idle_s)
        # The result says what happened, because nothing else can: a killed
        # child leaves no report and no exit code, so a bare TIMEOUT wrote a
        # 0-byte log and the gate named the tool with no reason (2026-09-04,
        # gitleaks on a pre-push gate, two pushes refused with blocking 0).
        return RunnerResult(tool, ToolState.TIMEOUT,
                            stderr=(f"aramid: {tool} timed out after {timeout_s:g} s and was "
                                    f"killed; whatever it had written is discarded"),
                            duration_s=elapsed)
```

Update the `run_subprocess` docstring. It no longer has a "plain `communicate` path": both pipes are always drained on threads, and `on_stdout_line` only adds the tap.

- [ ] **Step 4: Run the new tests and the whole existing launcher file**

Run: `python -P -m pytest tests/unit/test_runner_base_stall.py tests/unit/test_runner_base.py tests/unit/test_runner_base_registry.py -q`
Expected: all pass. That includes `test_invalid_utf8_output_never_raises`, `test_failed_kill_tree_bounds_the_post_kill_wait` and `test_on_stdout_line_still_captures_a_large_stderr_without_deadlock`, unchanged.

- [ ] **Step 5: Run every test that drives `run_subprocess` through a gate**

Run: `python -P -m graphite query "callers run_gate"`, then run the integration and unit files it lists (memory: a new gate behaviour runs against every gate fixture). At minimum: `python -P -m pytest tests/integration/test_check.py tests/integration/test_pipeline_tests_gate.py tests/unit/test_tests_progress.py -q`.
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/aramid/runners/base.py tests/unit/test_runner_base_stall.py CHANGELOG.md
git commit -F <msg file>   # feat(runners): recognise a stalled child tree and kill it early
```

---

### Task 3: `[timeouts].stall_s` reaches the launcher

**Files:**
- Modify: `src/aramid/data/defaults.toml` (`[timeouts]`, around line 23); `src/aramid/commands/check.py` (`cmd_check`, after `load_config`, around line 172); `src/aramid/commands/drain.py` (per-repo `load_config`, around line 676)
- Test: `tests/unit/test_stall_window_config.py`

**Interfaces:**
- Consumes: `base.set_stall_window` (Task 2).
- Produces: `config.stall_window_s(cfg) -> float`, i.e. `float(cfg.timeouts.get("stall_s", base.DEFAULT_STALL_S))`, with a non-number reading as the default.

- [ ] **Step 1: Write the failing tests**

```python
"""[timeouts].stall_s is read once per command and handed to the launcher."""
from types import SimpleNamespace

from aramid import config as config_mod
from aramid.runners import base


def _cfg(**timeouts):
    return SimpleNamespace(timeouts=timeouts)


def test_default_is_three_hundred():
    assert config_mod.stall_window_s(_cfg()) == 300.0


def test_an_explicit_value_is_used():
    assert config_mod.stall_window_s(_cfg(stall_s=45)) == 45.0


def test_zero_is_kept_and_means_off():
    assert config_mod.stall_window_s(_cfg(stall_s=0)) == 0.0


def test_a_non_number_falls_back_to_the_default():
    assert config_mod.stall_window_s(_cfg(stall_s="soon")) == 300.0
    assert config_mod.stall_window_s(_cfg(stall_s=True)) == 300.0


def test_defaults_toml_declares_stall_s(tmp_path):
    cfg = config_mod.load_config(tmp_path)
    assert cfg.timeouts["stall_s"] == 300


def test_cmd_check_sets_the_window_from_config(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(base, "set_stall_window", seen.append)
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n[timeouts]\nstall_s = 42\n",
                                          encoding="utf-8")
    from aramid.commands import check
    check.apply_stall_window(config_mod.load_config(tmp_path))
    assert seen == [42.0]
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -P -m pytest tests/unit/test_stall_window_config.py -q`
Expected: FAIL. `config` has no attribute `stall_window_s`.

- [ ] **Step 3: Implement**

`defaults.toml`, in `[timeouts]` after `pre_push = 300`:

```toml
# Seconds a child process TREE may show no CPU and write no output before
# aramid kills it as STALLED rather than waiting out the budget above
# (0.20.4). 0 = off (wall clock only). Set it above the longest quiet wait
# your test suite legitimately has (a container or service starting).
stall_s = 300
```

`config.py`, below `arming_state`:

```python
def stall_window_s(cfg: "Config") -> float:
    """[timeouts].stall_s as seconds; a missing or non-numeric value is the
    launcher's default (bool is not a number here, though it is an int)."""
    from aramid.runners.base import DEFAULT_STALL_S
    value = cfg.timeouts.get("stall_s", DEFAULT_STALL_S)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return DEFAULT_STALL_S
    return float(value)
```

`commands/check.py`, a module-level helper and its call right after `cfg = config_mod.load_config(root)` in `cmd_check`:

```python
def apply_stall_window(cfg) -> None:
    from aramid.runners import base
    base.set_stall_window(config_mod.stall_window_s(cfg))
```

`commands/drain.py`, right after the per-repo `cfg = config_mod.load_config(root)`:

```python
                from aramid.commands.check import apply_stall_window
                apply_stall_window(cfg)
```

- [ ] **Step 4: Run the tests and the config-keys tests**

Run: `python -P -m pytest tests/unit/test_stall_window_config.py tests/unit/test_config_keys.py -q`
Expected: all pass, and `stall_s` is a known key with no `aramid: config:` warning.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/data/defaults.toml src/aramid/config.py src/aramid/commands/check.py src/aramid/commands/drain.py tests/unit/test_stall_window_config.py CHANGELOG.md
git commit -F <msg file>   # feat(config): [timeouts].stall_s sets the stall window (default 300, 0 = off)
```

---

### Task 4: Report a stall everywhere a timeout is reported

**Files:**
- Modify: `src/aramid/pipeline.py` (`_degraded_reasons` around line 767; `GateResult` around line 87; the `record_run` call around line 1117; the `GateResult(...)` return around line 1440); `src/aramid/ledger.py` (`record_run`, around lines 653 and 821); `src/aramid/commands/status.py` (`_last_run_line`, line 32); `src/aramid/health.py` (`Health` line 50, `snapshot` around line 362); `src/aramid/fleet.py` (evidence around line 149, red description around line 308)
- Test: `tests/unit/test_stall_reporting.py`

**Interfaces:**
- Consumes: `RunnerResult.stalled_s` (Task 2).
- Produces: `GateResult.stalled: tuple[str, ...] = ()`; `Ledger.record_run(..., stalled: list[str] | None = None)` writing `RUN_FINISHED.payload["stalled"]`; `Health.stalled_tools: tuple = ()`; fleet `evidence["stalled_tools"]`.

- [ ] **Step 1: Write the failing tests**

```python
"""A stalled tool reads as stalled on every surface that reports a timeout."""
from aramid import fleet, health, pipeline
from aramid.runners.base import RunnerResult, ToolState


def test_degraded_reason_names_a_stall_not_a_timeout():
    rs = [RunnerResult("pip-audit", ToolState.TIMEOUT, duration_s=312.4, stalled_s=301.0),
          RunnerResult("gitleaks", ToolState.TIMEOUT, duration_s=120.0)]
    assert pipeline._degraded_reasons(rs) == {
        "pip-audit": "stalled: no CPU or output for 301 s (killed after 312 s)",
        "gitleaks": "timeout after 120 s",
    }


def test_stalled_tools_come_from_the_field_not_the_text():
    rs = [RunnerResult("pip-audit", ToolState.TIMEOUT, duration_s=312.4, stalled_s=301.0),
          RunnerResult("ruff", ToolState.TIMEOUT, stderr="stalled: (just a message)",
                       duration_s=9.0),
          RunnerResult("semgrep", ToolState.OK)]
    assert pipeline._stalled_tools(rs) == ("pip-audit",)


def test_run_row_records_stalled(tmp_path):
    from aramid.ledger import EventType, Ledger
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        ledger.record_run("r1", "2026-10-06T00:00:00+00:00", "pre-push", set(), set(), [],
                          degraded={"pip-audit": "stalled: ..."}, stalled=["pip-audit"])
        fin = [e for e in ledger.events() if e.type is EventType.RUN_FINISHED][-1]
        assert fin.payload["stalled"] == ["pip-audit"]
    finally:
        ledger.close()


def test_status_last_run_line_names_the_stalled_tool(tmp_path):
    from aramid.commands import status
    from aramid.ledger import Ledger
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        ledger.record_run("r1", "2026-10-06T00:00:00+00:00", "pre-push", set(), set(), [],
                          finished_at="2026-10-06T00:05:00+00:00",
                          degraded={"pip-audit": "stalled: ..."}, stalled=["pip-audit"])
        assert status._last_run_line(ledger) == (
            "last run: 2026-10-06T00:00:00+00:00 (pre-push run r1, 0 blocking, took 300s,"
            " stalled: pip-audit)")
    finally:
        ledger.close()


def test_fleet_red_description_marks_the_stalled_tool():
    # Every other criterion green: _red_detail reports each one not True.
    row = {"criteria": {**{k: True for k in health.CRITERIA}, "no_self_inflicted_block": False},
           "evidence": {"bad_tools": ["gitleaks", "pip-audit"], "stalled_tools": ["pip-audit"]}}
    assert fleet._red_detail(row) == "no_self_inflicted_block: gitleaks, pip-audit (stalled)"
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -P -m pytest tests/unit/test_stall_reporting.py -q`
Expected: FAIL. The reason reads `timeout after 312 s`, and `_stalled_tools` does not exist.

- [ ] **Step 3: Implement**

`pipeline._degraded_reasons`, the TIMEOUT branch:

```python
        if r.state is ToolState.TIMEOUT:
            if r.stalled_s is not None:
                reasons[r.tool] = (f"stalled: no CPU or output for {r.stalled_s:.0f} s "
                                   f"(killed after {r.duration_s:.0f} s)")
            else:
                reasons[r.tool] = (f"timeout after {r.duration_s:.0f} s" if r.duration_s
                                   else "timeout (gate budget expired)")
```

Below it:

```python
def _stalled_tools(flat_results: list[RunnerResult]) -> tuple[str, ...]:
    """The tools the stall watchdog killed this run, from the FIELD -- never
    from reason text, which a tool's own stderr could imitate."""
    return tuple(sorted({r.tool for r in flat_results
                         if r.state is ToolState.TIMEOUT and r.stalled_s is not None}))
```

`GateResult`: `stalled: tuple = ()` after `degraded_reasons`. Where `degraded_reasons` is built (around line 1082): `stalled = _stalled_tools(flat_results)`. Pass `stalled=list(stalled)` to `ledger.record_run(...)` and `stalled=stalled` to `GateResult(...)`.

`ledger.record_run`: add the keyword `stalled: list[str] | None = None`. After the `degraded` block:

```python
        if stalled is not None:
            # The degraded tools the stall watchdog killed (0.20.4): no CPU
            # and no output for [timeouts].stall_s. Empty = none stalled;
            # absent = an aramid too old to know.
            finished["stalled"] = sorted(stalled)
```

`status._last_run_line`, before `return line + ")"`:

```python
    stalled = last.payload.get("stalled")
    if stalled:
        line += ", stalled: " + ", ".join(stalled)
```

`health.Health`: `stalled_tools: tuple = ()` after `bad_tools`. In `snapshot`: `stalled_tools=tuple(getattr(result, "stalled", ()) or ())`.
`fleet` evidence: `"stalled_tools": list(h.stalled_tools),`. In the red description's `no_self_inflicted_block` branch:

```python
            stalled = set(ev.get("stalled_tools") or [])
            what = ("engine error" if row.get("engine_error") else
                    ", ".join(f"{t} (stalled)" if t in stalled else t
                              for t in (ev.get("bad_tools") or [])))
```

- [ ] **Step 4: Run the tests and every file pinning these surfaces**

Run: `python -P -m pytest tests/unit/test_stall_reporting.py tests/unit/test_status_lines.py tests/unit/test_fleet*.py tests/unit/test_health*.py tests/integration/test_check.py -q`
Expected: all pass. A pinned full-dict assertion of a fleet `evidence` map gains `stalled_tools: []`; update those pins and name each one in the commit message.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/pipeline.py src/aramid/ledger.py src/aramid/commands/status.py src/aramid/health.py src/aramid/fleet.py tests/unit/test_stall_reporting.py CHANGELOG.md
git commit -F <msg file>   # feat(report): a stalled tool reads as stalled in the gate, run row, status and fleet
```

---

### Task 5: Docs and the release record

**Files:** `src/aramid/data/ARAMID.md.tmpl` (configuration section; check where `[timeouts]` is documented), `ARAMID.md` (regenerate with the `REGEN_CMD` quoted in `tests/unit/test_aramid_md_template_sync.py`, run with `PYTHONPATH=src`), `CHANGELOG.md`, `docs/superpowers/plans/2026-09-21-aramid-1.0-blockers.md` (file a dated note).

- [ ] **Step 1:** Add `stall_s` to the template wherever `[timeouts]` keys are described, in the same register as its neighbours, and regenerate `ARAMID.md`. Run `python -P -m pytest tests/unit/test_aramid_md_template_sync.py tests/unit/test_tool_only_rule.py -q`; expected: pass.
- [ ] **Step 2:** CHANGELOG `[Unreleased]` `### Added`: the watchdog, `[timeouts].stall_s` (default 300, 0 = off), the stall reason text, and the pip-audit mechanism (`_subprocess.run` reads stdout to EOF before stderr; 4096-byte threshold measured).
- [ ] **Step 3:** Run the full unit suite: `python -P -m pytest tests/unit -q -p no:cacheprovider > <scratch>/unit.log 2>&1; echo $? > <scratch>/unit.rc`. Read the rc file directly, not through a pipe. Expected 0.
- [ ] **Step 4:** Commit, then push per Global Constraint 9.
