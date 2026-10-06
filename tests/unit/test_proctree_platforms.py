"""proctree's three platform samplers, pinned on EVERY OS.

`sample` dispatches by platform, so on any one machine two of the three
samplers never run natively: the ubuntu leg never ran the Windows or `ps`
paths, and the Windows drain (which grades mutants against tests/unit) never
ran `/proc` or `ps`. Each sampler is therefore driven here through fakes of
exactly what it touches -- `subprocess.run`, the `/proc` seam, and a fake
kernel32 behind `ctypes.WinDLL` -- and nothing in this file is skipped on
any platform: a skipped test executes nothing and the latent-mutant ratchet
(scripts/latent_mutants.py) would still count every line it was meant to
reach.

The kernel32 fake behaves as ctypes presents a real export: `argtypes`
convert and COUNT the arguments (a short call is the TypeError ctypes
raises), and `restype` converts the raw result, so a NULL handle arrives as
None and INVALID_HANDLE_VALUE as `c_void_p(-1).value`, exactly what
`_sample_windows` compares against.
"""
import ctypes
import ctypes.wintypes as wt   # importable off Windows since CPython 3.9 (bpo-16396)
from types import SimpleNamespace

import pytest

from aramid import proctree

# ---------------------------------------------------------------- ps (macOS)

_PS_ARGV = ["ps", "-A", "-o", "pid=,ppid=,time="]
_PS_OUT = ("    1     0   0:00.10\n"
           "   10     1   0:01.50\n"
           "   11    10   0:00.25\n"
           "   12    11   1:00.00\n"
           "   13     1   0:09.00\n")


def _fake_run(monkeypatch, returncode):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=returncode, stdout=_PS_OUT, stderr="")
    monkeypatch.setattr(proctree.subprocess, "run", run)
    return calls


def test_ps_sampler_reads_the_tree_from_one_ps_listing(monkeypatch):
    calls = _fake_run(monkeypatch, 0)
    assert proctree._sample_ps(10) == {10: (0, 150), 11: (0, 25), 12: (0, 6000)}
    assert calls == [(_PS_ARGV, {"capture_output": True, "text": True,
                                 "timeout": proctree._PS_TIMEOUT_S})]


@pytest.mark.parametrize("returncode", [1, 2, -9])
def test_a_failed_ps_is_unmeasured_even_when_it_printed_a_listing(monkeypatch, returncode):
    # The listing would parse into a tree containing the root: None here is
    # the returncode gate, not an empty parse.
    _fake_run(monkeypatch, returncode)
    assert proctree._sample_ps(10) is None


# ------------------------------------------------------------- /proc (Linux)

def _stat_line(pid, ppid, start, utime, stime, comm="x"):
    # fields 3..22: state ppid pgrp session tty tpgid flags minflt cminflt
    # majflt cmajflt utime stime cutime cstime priority nice threads itreal
    # starttime -- then a tail the parser ignores
    rest = ["S", ppid, pid, pid, 0, -1, 0, 0, 0, 0, 0, utime, stime, 0, 0, 20, 0, 1, 0,
            start, 0, 0]
    return f"{pid} ({comm}) " + " ".join(map(str, rest))


def test_proc_sampler_reads_each_numeric_entry_and_skips_the_unreadable(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    for pid, ppid, start, ut, st in [(1, 0, 1, 0, 0), (10, 1, 500, 7, 3),
                                     (11, 10, 501, 1, 1), (12, 11, 502, 0, 4)]:
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / "stat").write_text(_stat_line(pid, ppid, start, ut, st, "a ) b"))
    # Not a pid: `self` is a symlink on a real /proc; parsed, it would be a child.
    (proc / "self").mkdir()
    (proc / "self" / "stat").write_text(_stat_line(99, 10, 600, 1, 1))
    (proc / "uptime").write_text("1.0 1.0")
    (proc / "13").mkdir()                       # exited between listing and read
    (proc / "14").mkdir()
    (proc / "14" / "stat").write_text("garbage")
    monkeypatch.setattr(proctree, "_PROC", proc)
    assert proctree._sample_proc(10) == {10: (500, 10), 11: (501, 2), 12: (502, 4)}


# ------------------------------------------------------------- Windows

_SNAP = 0x5A5A                  # the snapshot handle the fake kernel32 issues
_H = 1 << 32                    # one high-dword unit of a FILETIME
_BYREF = type(ctypes.byref(ctypes.c_int()))     # CArgObject: logged as "&"


class _ENTRY(ctypes.Structure):
    """PROCESSENTRY32W as tlhelp32.h declares it: szExeFile is MAX_PATH (260)
    wide chars. Built from the same wintypes, so it matches on every OS."""
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


class _Export:
    """One kernel32 export as ctypes presents it. The code under test sets
    `argtypes`/`restype` on one attribute access and calls on another, so
    each export is a persistent object."""

    def __init__(self, name, impl, calls):
        self.name, self._impl, self._calls = name, impl, calls
        self.argtypes = None
        self.restype = ctypes.c_int             # ctypes' default

    def __call__(self, *args):
        if self.argtypes is not None:
            if len(args) != len(self.argtypes):
                raise TypeError(f"{self.name}: {len(self.argtypes)} argtypes, "
                                f"{len(args)} arguments")
            for kind, arg in zip(self.argtypes, args):
                kind.from_param(arg)            # raises as ctypes would on a mismatch
        self._calls.append((self.name, tuple("&" if isinstance(a, _BYREF) else a
                                             for a in args)))
        raw = self._impl(*args)
        return None if self.restype is None else self.restype(raw).value


class _Kernel32:
    """procs: [(pid, ppid)] in snapshot order. times: pid -> (created,
    exited, kernel, user) as 64-bit FILETIME ticks; a pid absent from it has
    exited (OpenProcess fails). deny: OpenProcess refused. untimeable:
    GetProcessTimes fails. snapshot: the raw CreateToolhelp32Snapshot result."""

    def __init__(self, procs, times, *, snapshot=_SNAP, deny=(), untimeable=()):
        self.procs, self.times, self.snapshot = procs, times, snapshot
        self.deny, self.untimeable = set(deny), set(untimeable)
        self.calls, self.entry_types, self.bad_close = [], [], []
        self.open: set = set()                 # issued and not yet closed
        self._pid_of: dict = {}
        self._cursor = 0
        for name in ("CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW",
                     "OpenProcess", "GetProcessTimes", "CloseHandle"):
            setattr(self, name, _Export(name, getattr(self, "_" + name), self.calls))

    def _CreateToolhelp32Snapshot(self, flags, pid):
        if self.snapshot == _SNAP:
            self.open.add(_SNAP)
        return self.snapshot

    def _Process32FirstW(self, snap, pentry):
        self._cursor = 0
        return self._Process32NextW(snap, pentry)

    def _Process32NextW(self, snap, pentry):
        entry = pentry._obj
        self.entry_types.append(type(entry))
        if snap != _SNAP or snap not in self.open:
            return 0                            # ERROR_INVALID_HANDLE
        if entry.dwSize != ctypes.sizeof(_ENTRY):
            return 0                            # ERROR_BAD_LENGTH
        if self._cursor >= len(self.procs):
            return 0                            # ERROR_NO_MORE_FILES
        entry.th32ProcessID, entry.th32ParentProcessID = self.procs[self._cursor]
        entry.szExeFile = "x.exe"
        self._cursor += 1
        return 1

    def _OpenProcess(self, access, inherit, pid):
        if pid in self.deny or pid not in self.times:
            return 0                            # NULL
        handle = 0x7000 + pid
        self.open.add(handle)
        self._pid_of[handle] = pid
        return handle

    def _GetProcessTimes(self, handle, created, exited, kernel, user):
        pid = self._pid_of.get(handle)
        if handle not in self.open or pid in self.untimeable:
            return 0
        for ref, ticks in zip((created, exited, kernel, user), self.times[pid]):
            ref._obj.dwLowDateTime = ticks & 0xFFFFFFFF
            ref._obj.dwHighDateTime = ticks >> 32
        return 1

    def _CloseHandle(self, handle):
        if handle not in self.open:
            self.bad_close.append(handle)
            return 0
        self.open.discard(handle)
        return 1


def _install(monkeypatch, kernel):
    def windll(name, use_last_error=False):
        assert (name, use_last_error) == ("kernel32", True)
        return kernel
    # ctypes.WinDLL does not exist off Windows: hence raising=False.
    monkeypatch.setattr(ctypes, "WinDLL", windll, raising=False)
    return kernel


# pid 0 is self-parented, as the System Idle Process is; 999 is not ours.
_PROCS = [(0, 0), (4, 0), (100, 4), (200, 100), (201, 100), (300, 200), (999, 4)]
# Every high dword is nonzero somewhere, so the `<< 32` in ticks is observable
# in both the creation time and the CPU sum; exited is distinct from created.
_TIMES = {4: (_H, 0, 1, 1),
          100: (7 * _H + 10, 9 * _H, 2 * _H + 30, 3 * _H + 40),
          200: (7 * _H + 20, 9 * _H, _H + 1, 5),
          201: (7 * _H + 21, 9 * _H, 0, _H),
          300: (8 * _H + 1, 9 * _H, 4, 4),
          999: (_H, 0, 1, 1)}
_TREE = {100: (7 * _H + 10, 5 * _H + 70), 200: (7 * _H + 20, _H + 6),
         201: (7 * _H + 21, _H), 300: (8 * _H + 1, 8)}


def _opened(kernel):
    return sorted(args for name, args in kernel.calls if name == "OpenProcess")


def test_windows_sampler_walks_the_snapshot_and_times_each_member(monkeypatch):
    kernel = _install(monkeypatch, _Kernel32(_PROCS, _TIMES))
    assert proctree._sample_windows(100) == _TREE
    # TH32CS_SNAPPROCESS, every process (the pid is ignored for that flag).
    assert [c for c in kernel.calls if c[0] == "CreateToolhelp32Snapshot"] == \
        [("CreateToolhelp32Snapshot", (0x2, 0))]
    # PROCESS_QUERY_LIMITED_INFORMATION, no inheritance, once per member.
    assert _opened(kernel) == [(0x1000, False, pid) for pid in (100, 200, 201, 300)]
    assert kernel.open == set() and kernel.bad_close == [], \
        "the snapshot and every process handle are closed, each once"


def test_the_snapshot_entry_is_the_win32_layout(monkeypatch):
    """dwSize must be sizeof(PROCESSENTRY32W) or Process32FirstW fails, and
    szExeFile is MAX_PATH wide chars. On Windows x64 a 261-char field pads
    to the same struct size, so the field itself is compared."""
    kernel = _install(monkeypatch, _Kernel32(_PROCS, _TIMES))
    proctree._sample_windows(100)
    layout = kernel.entry_types[0]
    assert [n for n, _ in layout._fields_] == [n for n, _ in _ENTRY._fields_]
    for name, _ in _ENTRY._fields_:
        got, want = getattr(layout, name), getattr(_ENTRY, name)
        assert (name, got.offset, got.size) == (name, want.offset, want.size)
    assert layout.szExeFile.size == 260 * ctypes.sizeof(ctypes.c_wchar)
    assert ctypes.sizeof(layout) == ctypes.sizeof(_ENTRY)


@pytest.mark.parametrize("raw", [0, -1], ids=["NULL", "INVALID_HANDLE_VALUE"])
def test_an_unusable_snapshot_is_unmeasured_and_never_walked_or_closed(monkeypatch, raw):
    kernel = _install(monkeypatch, _Kernel32(_PROCS, _TIMES, snapshot=raw))
    assert proctree._sample_windows(100) is None
    assert kernel.calls == [("CreateToolhelp32Snapshot", (0x2, 0))]


@pytest.mark.parametrize("pid", [100, 300], ids=["root", "descendant"])
def test_a_process_that_cannot_be_opened_makes_the_sample_unmeasured(monkeypatch, pid):
    kernel = _install(monkeypatch, _Kernel32(_PROCS, _TIMES, deny={pid}))
    assert proctree._sample_windows(100) is None
    assert (0x1000, False, pid) in _opened(kernel)
    # A NULL handle is neither timed nor closed.
    assert not [c for c in kernel.calls
                if c[0] in ("GetProcessTimes", "CloseHandle") and c[1][0] is None]
    assert kernel.open == set() and kernel.bad_close == []


@pytest.mark.parametrize("pid", [100, 300], ids=["root", "descendant"])
def test_a_process_that_cannot_be_timed_makes_the_sample_unmeasured(monkeypatch, pid):
    kernel = _install(monkeypatch, _Kernel32(_PROCS, _TIMES, untimeable={pid}))
    assert proctree._sample_windows(100) is None
    timed = [c[1][0] for c in kernel.calls if c[0] == "GetProcessTimes"]
    assert 0x7000 + pid in timed
    assert kernel.open == set() and kernel.bad_close == [], \
        "the handle of a process that could not be timed is still closed"


# ------------------------------------------------------------- dispatch

def test_sample_dispatches_by_platform_and_never_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(proctree, "_sample_windows", lambda pid: ("windows", pid))
    monkeypatch.setattr(proctree, "_sample_proc", lambda pid: ("proc", pid))
    monkeypatch.setattr(proctree, "_sample_ps", lambda pid: ("ps", pid))
    monkeypatch.setattr(proctree, "_PROC", tmp_path)            # a /proc exists...
    monkeypatch.setattr(proctree, "sys", SimpleNamespace(platform="win32"))
    assert proctree.sample(7) == ("windows", 7)                 # ...but Windows wins
    monkeypatch.setattr(proctree, "sys", SimpleNamespace(platform="linux"))
    assert proctree.sample(7) == ("proc", 7)
    monkeypatch.setattr(proctree, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(proctree, "_PROC", tmp_path / "absent")
    assert proctree.sample(7) == ("ps", 7)

    def no_ps(pid):
        raise FileNotFoundError("ps")
    monkeypatch.setattr(proctree, "_sample_ps", no_ps)
    assert proctree.sample(7) is None, "unmeasurable is None, never a crash"
