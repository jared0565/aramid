"""The drain can be held to fewer cores (interop round 351; operator decision
2026-11-24, "a drain core cap"). bytesTTS's host hard-resets under sustained
all-core load (13 Kernel-Power 41 events): the scheduled drain ran at
whatever parallelism its consumers chose, and below-normal priority does not
limit load on an idle machine. `[drain].cpu_cores` in ~/.aramid/config.toml
pins `aramid drain` as its first act, and every process it starts inherits
the mask.

Every line of cpu_cap runs here on every OS, through fakes of exactly what
it touches -- `cpu_cap.os` for Linux, a kernel32 behind `ctypes.WinDLL` for
Windows (as tests/unit/test_proctree_platforms.py does) -- because the
latent-mutant ratchet counts the lines the unit suite never executes. Only
the inheritance proof runs the real call, and only in a child process: a
test that pinned the pytest worker would leave it on one core, so the
autouse fixture below fails any test that changes the worker's affinity,
and puts it back."""
import ctypes
import ctypes.wintypes as wt   # importable off Windows since CPython 3.9 (bpo-16396)
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import config, cpu_cap
from aramid.commands import drain as drain_mod
from aramid.commands import status as status_mod

SRC = str(Path(cpu_cap.__file__).resolve().parents[1])
WHOLE = "should be a whole number above 0, got"

# ------------------------------------------- the pytest worker is never pinned

_REAL_GET = getattr(os, "sched_getaffinity", None)
_REAL_SET = getattr(os, "sched_setaffinity", None)
_REAL_K32 = cpu_cap._kernel32() if sys.platform == "win32" else None


def _real_mask():
    if _REAL_K32 is not None:
        proc, system = ctypes.c_size_t(), ctypes.c_size_t()
        _REAL_K32.GetProcessAffinityMask(_REAL_K32.GetCurrentProcess(), ctypes.byref(proc),
                                         ctypes.byref(system))
        return proc.value
    return frozenset(_REAL_GET(0)) if _REAL_GET is not None else None


def _real_restore(mask):
    if _REAL_K32 is not None:
        _REAL_K32.SetProcessAffinityMask(_REAL_K32.GetCurrentProcess(), mask)
    elif _REAL_SET is not None:
        _REAL_SET(0, mask)


@pytest.fixture(autouse=True)
def _the_pytest_worker_is_never_pinned():
    before = _real_mask()
    yield
    after = _real_mask()
    if after != before:
        _real_restore(before)
        pytest.fail(f"a test changed this pytest worker's CPU affinity ({before!r} -> "
                    f"{after!r}); put back -- fake cpu_cap.os or ctypes.WinDLL instead")


# ------------------------------------------------------------- the setting --

def _user(tmp_path, monkeypatch, text):
    p = tmp_path / "user-config.toml"
    p.write_text(text, encoding="utf-8")
    monkeypatch.setattr(config, "_user_config_path", lambda: p)
    return p


def test_no_machine_config_is_no_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "absent.toml")

    assert cpu_cap.setting() == cpu_cap.Setting(None, None)


@pytest.mark.parametrize("text", ["", "[drain]\ninterval_hours = 4\n", "drain = 3\n"])
def test_a_machine_config_without_the_key_is_no_cap(tmp_path, monkeypatch, text):
    _user(tmp_path, monkeypatch, text)

    assert cpu_cap.setting() == cpu_cap.Setting(None, None)


def test_a_whole_number_above_zero_is_the_cap(tmp_path, monkeypatch):
    _user(tmp_path, monkeypatch, "[drain]\ncpu_cores = 2\n")

    assert cpu_cap.setting() == cpu_cap.Setting(2, None)


@pytest.mark.parametrize("value, shown", [("0", "0"), ("-1", "-1"), ('"1"', "'1'"),
                                          ("1.5", "1.5"), ("true", "True")])
def test_anything_else_is_named_as_doctor_names_it_and_is_not_a_cap(tmp_path, monkeypatch,
                                                                    value, shown):
    p = _user(tmp_path, monkeypatch, f"[drain]\ncpu_cores = {value}\n")
    repo = tmp_path / "repo"
    repo.mkdir()

    s = cpu_cap.setting()

    assert s == cpu_cap.Setting(None, f"{p}: [drain].cpu_cores {WHOLE} {shown}")
    # Two computations that must agree: doctor's row for the same layer.
    assert config.layer_problems(repo) == [(p, f"[drain].cpu_cores {WHOLE} {shown}")]


def test_an_unreadable_machine_config_is_named_and_is_not_a_cap(tmp_path, monkeypatch):
    p = _user(tmp_path, monkeypatch, "[drain\n")

    assert cpu_cap.setting() == cpu_cap.Setting(None, f"{p} could not be read (TOMLDecodeError)")


def test_a_valid_cap_is_no_doctor_row(tmp_path, monkeypatch):
    _user(tmp_path, monkeypatch, "[drain]\ncpu_cores = 2\n")
    repo = tmp_path / "repo"
    repo.mkdir()

    assert config.layer_problems(repo) == []


def test_a_repo_cannot_cap_the_machine(tmp_path, monkeypatch, capsys):
    """Read from the merged config, a committed aramid.toml could cap -- or
    uncap -- every drain on the machine. It is named as ignored instead."""
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "absent.toml")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "aramid.toml").write_text("[drain]\ncpu_cores = 1\n", encoding="utf-8")
    said = ("[drain].cpu_cores is read only from ~/.aramid/config.toml (it caps every drain"
            " on this machine) -- ignored here")

    assert cpu_cap.setting() == cpu_cap.Setting(None, None)
    assert config.layer_problems(repo) == [(repo / "aramid.toml", said)]
    config.load_config(repo)
    assert f"aramid: config: {repo / 'aramid.toml'}: {said}" in capsys.readouterr().err


def test_the_machine_layer_may_set_it_without_that_warning(tmp_path, monkeypatch, capsys):
    _user(tmp_path, monkeypatch, "[drain]\ncpu_cores = 1\n")
    repo = tmp_path / "repo"
    repo.mkdir()

    config.load_config(repo)

    assert "cpu_cores" not in capsys.readouterr().err


# ---------------------------------------------------------- choosing cores --

def test_the_lowest_allowed_cores_are_kept():
    assert cpu_cap.lowest([5, 1, 3, 7], 2) == [1, 3]
    assert cpu_cap.lowest([0, 1], 8) == [0, 1]


def test_masks_and_core_lists_round_trip():
    assert cpu_cap.mask_of([0, 2, 3]) == 0b1101
    assert cpu_cap.mask_of([]) == 0
    assert cpu_cap.bits(0b1101) == [0, 2, 3]
    assert cpu_cap.bits(0) == []


def test_a_mask_holds_one_processor_group_of_64():
    assert cpu_cap.mask_of([0, 63]) == 1 | 1 << 63


@pytest.mark.parametrize("core", [-1, 64, 2 ** 63])
def test_a_core_outside_a_processor_group_is_refused_not_shifted(core):
    """The 07:00Z drain's fuzz run (finding d27acf9f): 2**63 raised
    OverflowError out of `1 << core`, and -1 is a negative shift. The OS
    never reports such a core; a caller that passes one gets a ValueError."""
    with pytest.raises(ValueError, match=rf"core {core} is outside a processor group \(0-63\)"):
        cpu_cap.mask_of([1, core])


# ----------------------------------------------------- Linux, through a fake --

def _posix(monkeypatch, cores=(0, 1, 2, 3), *, refuse=None, keep=True):
    """A fake `os` with the two affinity calls. refuse: the OSError the set
    call raises. keep=False: the set call returns and changes nothing."""
    state = {"cores": set(cores), "gets": [], "sets": []}

    def get(pid):
        state["gets"].append(pid)
        return set(state["cores"])

    def set_(pid, cores):
        state["sets"].append((pid, list(cores)))
        if refuse is not None:
            raise refuse
        if keep:
            state["cores"] = set(cores)
    monkeypatch.setattr(cpu_cap, "os", SimpleNamespace(sched_getaffinity=get,
                                                       sched_setaffinity=set_))
    monkeypatch.setattr(cpu_cap, "_platform", lambda: "linux")
    return state


def test_the_platform_is_this_one():
    assert cpu_cap._platform() == sys.platform


def test_linux_reads_and_pins_the_calling_thread_which_later_threads_inherit(monkeypatch):
    state = _posix(monkeypatch)

    assert cpu_cap.supported() is True
    assert cpu_cap.allowed_cores() == [0, 1, 2, 3]
    assert cpu_cap.apply(2) == ("aramid: drain: held to 2 of 4 cores ([drain].cpu_cores = 2);"
                                " every process it starts inherits that")
    assert state["sets"] == [(0, [0, 1])]
    assert set(state["gets"]) == {0}


def test_the_line_reports_what_the_os_kept_not_what_was_asked(monkeypatch):
    _posix(monkeypatch, keep=False)

    assert cpu_cap.apply(1).startswith("aramid: drain: held to 4 of 4 cores "
                                       "([drain].cpu_cores = 1)")


def test_a_cap_larger_than_the_machine_keeps_every_core(monkeypatch):
    state = _posix(monkeypatch, cores=(0, 1))

    assert cpu_cap.apply(8).startswith("aramid: drain: held to 2 of 2 cores")
    assert state["sets"] == [(0, [0, 1])]


def test_a_refused_cap_leaves_the_drain_running_and_says_so(monkeypatch):
    _posix(monkeypatch, refuse=OSError(22, "Invalid argument"))

    assert cpu_cap.apply(1) == (
        "aramid: drain: [drain].cpu_cores = 1 was not applied (OSError: [Errno 22] Invalid"
        " argument) -- the drain runs on every core it started with")


def test_no_allowed_cores_is_not_a_cap_of_zero(monkeypatch):
    state = _posix(monkeypatch, cores=())

    assert cpu_cap.apply(1) == (
        "aramid: drain: [drain].cpu_cores = 1 was not applied (OSError: the OS reported no"
        " cores this process may use) -- the drain runs on every core it started with")
    assert state["sets"] == []


def test_an_os_without_an_affinity_call_applies_nothing(monkeypatch):
    monkeypatch.setattr(cpu_cap, "os", SimpleNamespace())
    monkeypatch.setattr(cpu_cap, "_platform", lambda: "darwin")

    assert cpu_cap.supported() is False
    assert cpu_cap.apply(1) == ("aramid: drain: [drain].cpu_cores = 1 is set, but this OS has"
                                " no CPU affinity call -- the drain runs on every core")


# --------------------------------------------------- Windows, through a fake --

_SELF = ctypes.c_void_p(-1).value   # GetCurrentProcess's pseudo handle, as HANDLE returns it


class _Export:
    """One kernel32 export as ctypes presents it: argtypes convert and COUNT
    the arguments, restype converts the result (test_proctree_platforms)."""

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
    def __init__(self, mask, *, refuse_get=False, refuse_set=False):
        self.mask, self.refuse_get, self.refuse_set = mask, refuse_get, refuse_set
        self.calls, self.set_masks = [], []
        for name in ("GetCurrentProcess", "GetProcessAffinityMask", "SetProcessAffinityMask"):
            setattr(self, name, _Export(name, getattr(self, "_" + name), self.calls))

    def _GetCurrentProcess(self):
        return _SELF

    def _GetProcessAffinityMask(self, handle, proc, system):
        if handle != _SELF or self.refuse_get:
            return 0
        proc._obj.value = self.mask
        system._obj.value = 0xFF
        return 1

    def _SetProcessAffinityMask(self, handle, mask):
        self.set_masks.append(mask)
        if handle != _SELF or self.refuse_set:
            return 0
        self.mask = mask
        return 1


def _windows(monkeypatch, kernel):
    def windll(name, use_last_error=False):
        assert (name, use_last_error) == ("kernel32", True)
        return kernel
    # ctypes.WinDLL and get_last_error do not exist off Windows: raising=False.
    monkeypatch.setattr(ctypes, "WinDLL", windll, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 87, raising=False)
    monkeypatch.setattr(cpu_cap, "_platform", lambda: "win32")
    return kernel


def test_windows_declares_each_export_as_kernel32_does(monkeypatch):
    k = _windows(monkeypatch, _Kernel32(0b1111))

    assert cpu_cap._kernel32() is k
    assert k.GetCurrentProcess.restype is wt.HANDLE and k.GetCurrentProcess.argtypes == []
    assert k.GetProcessAffinityMask.argtypes == [wt.HANDLE, ctypes.POINTER(ctypes.c_size_t),
                                                 ctypes.POINTER(ctypes.c_size_t)]
    assert k.GetProcessAffinityMask.restype is wt.BOOL
    assert k.SetProcessAffinityMask.argtypes == [wt.HANDLE, ctypes.c_size_t]
    assert k.SetProcessAffinityMask.restype is wt.BOOL


def test_windows_reads_and_pins_the_process_mask_which_children_inherit(monkeypatch):
    k = _windows(monkeypatch, _Kernel32(0b11110))

    assert cpu_cap.supported() is True
    assert cpu_cap.allowed_cores() == [1, 2, 3, 4]
    assert cpu_cap.apply(2) == ("aramid: drain: held to 2 of 4 cores ([drain].cpu_cores = 2);"
                                " every process it starts inherits that")
    assert k.set_masks == [0b110]


def test_windows_names_a_refused_read(monkeypatch):
    _windows(monkeypatch, _Kernel32(0b1111, refuse_get=True))

    assert cpu_cap.apply(1) == (
        "aramid: drain: [drain].cpu_cores = 1 was not applied (OSError: [Errno 87]"
        " GetProcessAffinityMask failed (Windows error 87)) -- the drain runs on every core"
        " it started with")


def test_windows_names_a_refused_pin(monkeypatch):
    k = _windows(monkeypatch, _Kernel32(0b1111, refuse_set=True))

    assert cpu_cap.apply(1) == (
        "aramid: drain: [drain].cpu_cores = 1 was not applied (OSError: [Errno 87]"
        " SetProcessAffinityMask failed (Windows error 87)) -- the drain runs on every core"
        " it started with")
    assert k.set_masks == [0b1]


# ------------------------------------------------------- where it is used --

def test_the_configured_cap_is_applied(tmp_path, monkeypatch):
    _user(tmp_path, monkeypatch, "[drain]\ncpu_cores = 3\n")
    asked = []
    monkeypatch.setattr(cpu_cap, "apply", lambda n: asked.append(n) or "LINE")

    assert cpu_cap.apply_configured() == "LINE"
    assert asked == [3]


def test_with_no_cap_nothing_is_applied_or_said(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "absent.toml")
    monkeypatch.setattr(cpu_cap, "apply", lambda n: pytest.fail("applied with no cap"))

    assert cpu_cap.apply_configured() is None


def test_a_bad_value_is_said_and_nothing_is_pinned(tmp_path, monkeypatch):
    p = _user(tmp_path, monkeypatch, "[drain]\ncpu_cores = -2\n")
    monkeypatch.setattr(cpu_cap, "apply", lambda n: pytest.fail("pinned on a bad value"))

    assert cpu_cap.apply_configured() == (
        f"aramid: drain: no cpu cap applied -- {p}: [drain].cpu_cores {WHOLE} -2")


def test_the_drain_pins_before_it_reads_the_registry_and_says_so(monkeypatch, capsys):
    order = []
    monkeypatch.setattr(cpu_cap, "apply_configured", lambda: order.append("cap") or "CAP LINE")
    real = drain_mod.registry.load_registry
    monkeypatch.setattr(drain_mod.registry, "load_registry",
                        lambda **kw: order.append("registry") or real(**kw))

    drain_mod.cmd_drain([], dry_run=True)

    assert order == ["cap", "registry"]
    assert capsys.readouterr().out.splitlines()[0] == "CAP LINE"


def test_a_drain_with_no_cap_prints_nothing_about_it(monkeypatch, capsys):
    monkeypatch.setattr(cpu_cap, "apply_configured", lambda: None)

    drain_mod.cmd_drain([], dry_run=True)

    assert capsys.readouterr().out == ""


def test_status_names_the_cap(tmp_path, monkeypatch):
    _user(tmp_path, monkeypatch, "[drain]\ncpu_cores = 1\n")
    _posix(monkeypatch)

    assert cpu_cap.status_suffix() == "; drain cpu cap: 1 ([drain].cpu_cores in ~/.aramid/config.toml)"


def test_status_says_when_this_os_cannot_apply_it(tmp_path, monkeypatch):
    _user(tmp_path, monkeypatch, "[drain]\ncpu_cores = 2\n")
    monkeypatch.setattr(cpu_cap, "os", SimpleNamespace())
    monkeypatch.setattr(cpu_cap, "_platform", lambda: "darwin")

    assert cpu_cap.status_suffix() == (
        "; drain cpu cap: 2 ([drain].cpu_cores in ~/.aramid/config.toml), but this OS has no"
        " CPU affinity call -- not applied")


def test_status_names_a_bad_value(tmp_path, monkeypatch):
    p = _user(tmp_path, monkeypatch, "[drain]\ncpu_cores = 0\n")

    assert cpu_cap.status_suffix() == (
        f"; drain cpu cap NOT applied -- {p}: [drain].cpu_cores {WHOLE} 0")


def test_status_says_nothing_without_a_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "absent.toml")

    assert cpu_cap.status_suffix() == ""


def test_aramid_status_puts_it_on_the_scheduled_drain_line(tmp_path, monkeypatch, capsys):
    r = tmp_path / "r"
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    monkeypatch.setattr(status_mod, "_scheduled_drain_line", lambda: "scheduled drain: installed")
    monkeypatch.setattr(cpu_cap, "status_suffix", lambda: "; SUFFIX")

    status_mod.cmd_status(r)

    assert "scheduled drain: installed; SUFFIX" in capsys.readouterr().out.splitlines()


# ------------------------------------- the real call, in a child process --

_GRANDCHILD = "import sys; sys.path.insert(0, {src!r}); from aramid import cpu_cap; " \
              "print(len(cpu_cap.allowed_cores()))"
_CHILD = textwrap.dedent("""
    import subprocess, sys
    sys.path.insert(0, {src!r})
    from aramid import cpu_cap
    {apply}
    print(subprocess.run([sys.executable, "-P", "-c", {grandchild!r}],
                         capture_output=True, text=True, check=True).stdout.strip())
""")

real = pytest.mark.skipif(not cpu_cap.supported() or len(cpu_cap.allowed_cores()) < 2,
                          reason="needs a CPU affinity call and two allowed cores")


def _child(apply_line):
    code = _CHILD.format(src=SRC, apply=apply_line,
                         grandchild=_GRANDCHILD.format(src=SRC))
    out = subprocess.run([sys.executable, "-P", "-c", code], capture_output=True, text=True,
                         timeout=120)
    assert out.returncode == 0, out.stderr
    return out.stdout.splitlines()


@real
def test_a_process_the_capped_drain_starts_runs_on_the_cap():
    lines = _child("print(cpu_cap.apply(1))")

    assert lines[0].startswith("aramid: drain: held to 1 of ")
    assert lines[-1] == "1"


@real
def test_control_an_uncapped_child_starts_processes_on_every_core():
    assert int(_child("pass")[-1]) == len(cpu_cap.allowed_cores()) >= 2
