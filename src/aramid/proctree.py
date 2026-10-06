"""Measure a child process TREE: each member's creation time and CPU time.

`sample(pid)` returns {pid: (created, cpu)} for `pid` and every live
descendant, or None when the tree cannot be measured. Units are platform
ticks; callers only ever compare two samples for equality. Standard library
only -- runners/base imports this, and the release's sdist smoke installs
with --no-deps.

None is "not measured", NEVER "idle": the stall watchdog treats it as
activity, so a sampler that cannot see degrades to the wall-clock timeout
instead of inventing a stall. Every error inside this module leans the same
way: a reused pid created before its "parent" is not a descendant, and a
platform with no creation time records 0 and keeps the child.

A LISTED descendant that cannot be timed (exited after the listing, or access
denied) makes the whole sample None rather than a smaller tree: a child we
cannot read could be the one doing the work, and one unmeasurable sample
costs only that sample's stall evidence.
"""
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
    timed, so the LISTING is what says it is gone). A listed descendant that
    cannot be timed makes the whole sample None: a child we cannot read could
    be the one doing the work, and one unmeasurable sample costs only that
    sample's stall evidence."""
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
            if t is None:                       # unreadable: cannot call it idle
                return None
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


def _cpu_centis(field: str) -> int:
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
