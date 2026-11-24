"""On Windows the drain holds itself in a kill-on-close Job object (operator
decision 2026-11-24, "the drain only"). `taskkill /T` lists a tree and THEN
kills it, so a process a consumer starts as the drain's hard deadline kills it
was never listed and outlived the drain: 16 of 20 measured trials, taskkill
exiting 0 each time. Membership of a job is inherited when a process is
created, so a job the drain joins before it starts anything holds every
descendant, and the OS ends them all when the drain's handle closes -- at the
deadline's `os._exit`, a crash, or an outside kill. Measured 0 of 48, nested
inside another job included (as under Task Scheduler and CI runners).

Every line of drain_job runs here on every OS, through a fake kernel32 behind
`ctypes.WinDLL` (as tests/unit/test_drain_cpu_cap.py does), because the
latent-mutant ratchet counts the lines the unit suite never executes. The
real job is proven end to end in a child process by
tests/integration/test_drain_deadline.py: a pytest worker that joined one
would carry it for the rest of the session, so tests/conftest.py stubs `join`
suite-wide and only this file's `real_drain_job` tests see the module."""
import ctypes
import ctypes.wintypes as wt   # importable off Windows since CPython 3.9 (bpo-16396)

import pytest

from aramid import drain_job
from aramid.commands import drain as drain_mod

pytestmark = pytest.mark.real_drain_job

_SELF = ctypes.c_void_p(-1).value   # GetCurrentProcess's pseudo handle, as HANDLE returns it
_JOB = 0x1234                       # the handle the fake CreateJobObjectW hands out


class _Export:
    """One kernel32 export as ctypes presents it: argtypes convert and COUNT
    the arguments, restype converts the result."""

    def __init__(self, name, impl, calls):
        self.name, self._impl, self._calls = name, impl, calls
        self.argtypes = None
        self.restype = ctypes.c_int

    def __call__(self, *args):
        if self.argtypes is not None:
            if len(args) != len(self.argtypes):
                raise TypeError(f"{self.name}: {len(self.argtypes)} argtypes, "
                                f"{len(args)} arguments")
            for kind, arg in zip(self.argtypes, args):
                kind.from_param(arg)
        self._calls.append(self.name)
        raw = self._impl(*args)
        return None if self.restype is None else self.restype(raw).value


class _Kernel32:
    NAMES = ("GetCurrentProcess", "CreateJobObjectW", "SetInformationJobObject",
             "AssignProcessToJobObject")

    def __init__(self, *, refuse=None):
        self.refuse = refuse
        self.calls, self.limits, self.assigned = [], [], []
        for name in self.NAMES:
            setattr(self, name, _Export(name, getattr(self, "_" + name), self.calls))

    def _GetCurrentProcess(self):
        return _SELF

    def _CreateJobObjectW(self, attributes, name):
        assert (attributes, name) == (None, None)
        return 0 if self.refuse == "CreateJobObjectW" else _JOB

    def _SetInformationJobObject(self, job, info_class, info, size):
        # What the OS would read: the struct behind the pointer, by the size given.
        self.limits.append((job, info_class, info._obj.Basic.LimitFlags, size))
        return 0 if self.refuse == "SetInformationJobObject" else 1

    def _AssignProcessToJobObject(self, job, process):
        self.assigned.append((job, process))
        return 0 if self.refuse == "AssignProcessToJobObject" else 1


@pytest.fixture
def windows(monkeypatch):
    def install(kernel):
        def windll(name, use_last_error=False):
            assert (name, use_last_error) == ("kernel32", True)
            return kernel
        # ctypes.WinDLL and get_last_error do not exist off Windows: raising=False.
        monkeypatch.setattr(ctypes, "WinDLL", windll, raising=False)
        monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
        monkeypatch.setattr(drain_job, "_platform", lambda: "win32")
        monkeypatch.setattr(drain_job, "_HELD", [])
        return kernel
    return install


# ------------------------------------------------------------------ Windows --

def test_windows_declares_each_export_as_kernel32_does(windows):
    k = windows(_Kernel32())

    assert drain_job._kernel32() is k
    assert k.GetCurrentProcess.argtypes == [] and k.GetCurrentProcess.restype is wt.HANDLE
    assert k.CreateJobObjectW.argtypes == [ctypes.c_void_p, wt.LPCWSTR]
    assert k.CreateJobObjectW.restype is wt.HANDLE
    assert k.SetInformationJobObject.argtypes == [wt.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                  wt.DWORD]
    assert k.SetInformationJobObject.restype is wt.BOOL
    assert k.AssignProcessToJobObject.argtypes == [wt.HANDLE, wt.HANDLE]
    assert k.AssignProcessToJobObject.restype is wt.BOOL


def test_windows_holds_this_process_in_a_job_that_kills_everything_when_it_closes(windows):
    k = windows(_Kernel32())

    assert drain_job.join() == drain_job.Outcome(None, True)
    assert k.calls == ["CreateJobObjectW", "SetInformationJobObject", "GetCurrentProcess",
                       "AssignProcessToJobObject"]
    # JobObjectExtendedLimitInformation (9), JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, whole struct.
    assert k.limits == [(_JOB, 9, 0x2000, ctypes.sizeof(drain_job._ExtendedLimits))]
    assert k.assigned == [(_JOB, _SELF)]
    # The handle stays open for the life of the process: closing it is the kill.
    assert drain_job._HELD == [_JOB]


@pytest.mark.parametrize("call", _Kernel32.NAMES[1:])
def test_windows_a_refused_call_is_named_and_the_drain_runs_unheld(windows, call):
    k = windows(_Kernel32(refuse=call))

    assert drain_job.join() == drain_job.Outcome(
        f"aramid: drain: not held in a kill-on-close job ({call} failed, Windows error 5)"
        " -- a process started as the hard deadline kills a consumer can outlive this"
        " drain", False)
    assert drain_job._HELD == []
    assert k.calls[-1] == call, "nothing is tried after the call that failed"


def test_the_limits_struct_is_the_size_and_shape_windows_reads():
    # JOBOBJECT_EXTENDED_LIMIT_INFORMATION: 144 bytes on 64-bit, 112 on 32-bit.
    # A wrong size is ERROR_BAD_LENGTH; a wrong offset sets some other limit.
    wide = ctypes.sizeof(ctypes.c_void_p) == 8
    assert ctypes.sizeof(drain_job._ExtendedLimits) == (144 if wide else 112)
    assert drain_job._BasicLimits.LimitFlags.offset == 16
    assert drain_job._ExtendedLimits.Io.offset == (64 if wide else 48)


# --------------------------------------------------------------- elsewhere --

def test_off_windows_joins_nothing_and_says_nothing(monkeypatch):
    monkeypatch.setattr(drain_job, "_platform", lambda: "linux")
    monkeypatch.setattr(drain_job, "_kernel32", lambda: pytest.fail("kernel32 reached off Windows"))

    assert drain_job.join() == drain_job.Outcome(None, False)


def test_the_platform_is_this_interpreters(monkeypatch):
    monkeypatch.setattr(drain_job.sys, "platform", "sunos5")
    assert drain_job._platform() == "sunos5"


# ------------------------------------------------------------- the drain --

@pytest.fixture
def joins(monkeypatch):
    seen = []

    def join(result):
        def fake():
            seen.append("join")
            return result
        monkeypatch.setattr(drain_job, "join", fake)
        return seen
    return join


# The registry is isolated and empty (tests/conftest.py), so each drain below
# ends at "no repos registered" -- after the job, before any lock.

def test_a_drain_joins_the_job_and_names_a_refusal_on_stderr(joins, capsys):
    line = "aramid: drain: not held in a kill-on-close job (X failed, Windows error 5) -- ..."
    seen = joins(drain_job.Outcome(line, False))

    rc = drain_mod.cmd_drain([])

    assert seen == ["join"]
    out, err = capsys.readouterr()
    assert err.splitlines() == [line, "aramid drain: no repos registered and none given"]
    assert out == ""
    assert rc == 0, "a refused job does not stop the drain"


def test_a_held_drain_says_nothing_about_it(joins, capsys):
    seen = joins(drain_job.Outcome(None, True))

    drain_mod.cmd_drain([])

    assert seen == ["join"]
    out, err = capsys.readouterr()
    assert (out, err) == ("", "aramid drain: no repos registered and none given\n")


def test_the_job_comes_after_the_cpu_cap_and_before_the_registry(joins, monkeypatch):
    seen = joins(drain_job.Outcome(None, True))
    monkeypatch.setattr(drain_mod.cpu_cap, "apply_configured",
                        lambda: seen.append("cap") or drain_mod.cpu_cap.Outcome(None, False))
    real = drain_mod.registry.load_registry
    monkeypatch.setattr(drain_mod.registry, "load_registry",
                        lambda **kw: seen.append("registry") or real(**kw))

    drain_mod.cmd_drain([])

    assert seen == ["cap", "join", "registry"]


def test_a_stopped_cap_joins_no_job(joins, monkeypatch):
    seen = joins(drain_job.Outcome(None, True))
    monkeypatch.setattr(drain_mod.cpu_cap, "apply_configured",
                        lambda: drain_mod.cpu_cap.Outcome("STOP", True))

    assert drain_mod.cmd_drain([]) == 3
    assert seen == []


def test_a_dry_run_starts_nothing_and_joins_nothing(joins):
    seen = joins(drain_job.Outcome(None, True))

    drain_mod.cmd_drain([], dry_run=True)

    assert seen == []
