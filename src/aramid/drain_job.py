"""On Windows, the drain holds itself and everything it starts in one
kill-on-close Job object (operator decision 2026-11-24, "the drain only").

The drain's hard deadline (FN-14) promises that nothing a consumer started
outlives the drain. On Windows its kill is `taskkill /T`, which lists a tree
and THEN kills it: a process the consumer starts in between was never listed,
and it ran on after the drain -- 16 of 20 measured trials, with taskkill
exiting 0 each time, so nothing could tell. A process joins its parent's job
when it is created, so a job the drain joins before it starts anything holds
every descendant at any depth, and Windows ends them all when the last
handle to the job closes: this process's, at the deadline's `os._exit`, a
crash, or an outside kill. Measured: 0 of 48 trials left a survivor, nested
inside another job included (Task Scheduler and CI runners start one).

`taskkill` stays where it is: it ends a timed-out tool while the drain runs.
The job is the floor under it at exit. POSIX needs neither: a consumer's
child leads its own process group, and one signal reaches the whole group.

Gates, hooks and every other command run as before (the operator's scope)."""
from __future__ import annotations

import ctypes
import sys
from typing import NamedTuple


class Outcome(NamedTuple):
    line: str | None   # what the drain prints on stderr; None prints nothing
    joined: bool


_KILL_ON_JOB_CLOSE = 0x2000          # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
_EXTENDED_LIMIT_INFORMATION = 9      # JobObjectExtendedLimitInformation

# The job's handle, open for the life of the process. Nothing closes it:
# its closing, when this process ends, is what ends the job's processes.
_HELD: list[int] = []


class _BasicLimits(ctypes.Structure):    # JOBOBJECT_BASIC_LIMIT_INFORMATION
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32)]


class _IoCounters(ctypes.Structure):     # IO_COUNTERS
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                 "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimits(ctypes.Structure):  # JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    _fields_ = [("Basic", _BasicLimits),
                ("Io", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


def _platform() -> str:
    return sys.platform


def _kernel32():
    import ctypes.wintypes as wt
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentProcess.argtypes = []
    k32.GetCurrentProcess.restype = wt.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wt.LPCWSTR]
    k32.CreateJobObjectW.restype = wt.HANDLE
    k32.SetInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
    k32.SetInformationJobObject.restype = wt.BOOL
    k32.AssignProcessToJobObject.argtypes = [wt.HANDLE, wt.HANDLE]
    k32.AssignProcessToJobObject.restype = wt.BOOL
    return k32


def _refused(call: str) -> Outcome:
    return Outcome(f"aramid: drain: not held in a kill-on-close job ({call} failed, Windows"
                   f" error {ctypes.get_last_error()}) -- a process started as the hard"
                   " deadline kills a consumer can outlive this drain", False)


def join() -> Outcome:
    """Hold this process in a new kill-on-close job. Call it before the drain
    starts anything: only processes created after it are in the job. A call
    Windows refuses is named and the drain runs unheld, as before."""
    if _platform() != "win32":
        return Outcome(None, False)
    k32 = _kernel32()
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return _refused("CreateJobObjectW")
    limits = _ExtendedLimits()
    limits.Basic.LimitFlags = _KILL_ON_JOB_CLOSE
    if not k32.SetInformationJobObject(job, _EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits),
                                       ctypes.sizeof(limits)):
        return _refused("SetInformationJobObject")
    if not k32.AssignProcessToJobObject(job, k32.GetCurrentProcess()):
        return _refused("AssignProcessToJobObject")
    _HELD.append(job)
    return Outcome(None, True)
