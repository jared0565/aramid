"""cpu_cap -- hold `aramid drain` to fewer CPU cores (interop round 351).

bytesTTS's host hard-resets under sustained all-core load (13 Kernel-Power 41
events). The scheduled drain ran at whatever parallelism its consumers chose
-- a repo's test command, semgrep, mutation runs -- and the task's
below-normal priority does not limit load on an idle machine. Adding an
affinity to the installed task by hand is undone by the next `aramid
schedule install`.

`[drain].cpu_cores` in ~/.aramid/config.toml -- the machine's file, never a
repo's aramid.toml, because it caps every drain on the machine -- makes
`aramid drain` pin itself to that many of its allowed cores, lowest first,
as the first thing it does. Everything it starts afterwards inherits the
mask. On Windows the mask is the process's. On Linux it is the calling
thread's, and every thread and child created after the call inherits it;
cmd_drain starts its threads (the deadline watchdog, consumer runs) later.
macOS has no affinity call: there the cap is reported and not applied.
"""
from __future__ import annotations

import os
import sys
from typing import NamedTuple

KEY = "[drain].cpu_cores"
_WHERE = f"{KEY} in ~/.aramid/config.toml"
_NOT_CAPPED = "the drain runs on every core it started with"


class Setting(NamedTuple):
    cores: int | None       # None: no cap
    problem: str | None     # why a value that is set is not used


def setting() -> Setting:
    """The cap, from the machine's config alone. Never from the merged
    config: a committed aramid.toml must not cap -- or uncap -- the machine
    (config_keys.MACHINE_ONLY names it as ignored there)."""
    from aramid import config, config_keys
    path = config._user_config_path()
    if not path.exists():
        return Setting(None, None)
    try:
        raw = config._read_toml_file(path)
    except (OSError, ValueError) as exc:        # tomllib.TOMLDecodeError is a ValueError
        return Setting(None, f"{path} could not be read ({type(exc).__name__})")
    drain = raw.get("drain")
    if not isinstance(drain, dict) or "cpu_cores" not in drain:
        return Setting(None, None)
    value = drain["cpu_cores"]
    # The sentence `aramid doctor` prints for this key in this layer.
    said = config_keys.problems({"drain": {"cpu_cores": value}})
    if said:
        return Setting(None, f"{path}: {said[0]}")
    return Setting(value, None)


def lowest(allowed: list[int], n: int) -> list[int]:
    return sorted(allowed)[:n]


# A Windows affinity mask covers one processor group: 64 processors at most.
_GROUP = 64


def mask_of(cores: list[int]) -> int:
    """The Windows affinity mask for `cores`. A core outside one processor
    group is a ValueError, never a shift: the OS reports none, and `1 << -1`
    or `1 << 2**63` fails with something else (finding d27acf9f, fuzz)."""
    mask = 0
    for core in cores:
        if not 0 <= core < _GROUP:
            raise ValueError(f"core {core} is outside a processor group (0-{_GROUP - 1})")
        mask |= 1 << core
    return mask


def bits(mask: int) -> list[int]:
    return [i for i in range(mask.bit_length()) if mask >> i & 1]


def _platform() -> str:
    return sys.platform


def supported() -> bool:
    return _platform() == "win32" or hasattr(os, "sched_setaffinity")


def _kernel32():
    import ctypes
    import ctypes.wintypes as wt
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentProcess.argtypes = []
    k32.GetCurrentProcess.restype = wt.HANDLE
    k32.GetProcessAffinityMask.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_size_t),
                                           ctypes.POINTER(ctypes.c_size_t)]
    k32.GetProcessAffinityMask.restype = wt.BOOL
    k32.SetProcessAffinityMask.argtypes = [wt.HANDLE, ctypes.c_size_t]
    k32.SetProcessAffinityMask.restype = wt.BOOL
    return k32


def _windows_error(call: str) -> OSError:
    import ctypes
    code = ctypes.get_last_error()
    return OSError(code, f"{call} failed (Windows error {code})")


def allowed_cores() -> list[int]:
    """The cores this process may run on, lowest first. OSError when the OS
    will not say. On Windows that is the process's processor group; a
    process spread over several groups reads as no cores (the mask is 0)."""
    if _platform() == "win32":
        import ctypes
        k32 = _kernel32()
        proc, system = ctypes.c_size_t(), ctypes.c_size_t()
        if not k32.GetProcessAffinityMask(k32.GetCurrentProcess(), ctypes.byref(proc),
                                          ctypes.byref(system)):
            raise _windows_error("GetProcessAffinityMask")
        return bits(proc.value)
    return sorted(os.sched_getaffinity(0))


def _pin(cores: list[int]) -> None:
    if _platform() == "win32":
        k32 = _kernel32()
        if not k32.SetProcessAffinityMask(k32.GetCurrentProcess(), mask_of(cores)):
            raise _windows_error("SetProcessAffinityMask")
        return
    os.sched_setaffinity(0, cores)


def apply(n: int) -> str:
    """Pin this process to its `n` lowest allowed cores; the line to print.

    Fails OPEN, the direction the operator chose for an OS with no affinity
    call (round 351, 2026-11-24): a cap the OS refuses leaves the drain on
    every core it started with, and this line says so on the drain's own
    output. The drain is not stopped. That is the load the cap exists to
    prevent, on a host that set it, so the line names it rather than hiding
    it."""
    if not supported():
        return (f"aramid: drain: {KEY} = {n} is set, but this OS has no CPU affinity call"
                " -- the drain runs on every core")
    try:
        before = allowed_cores()
        if not before:
            raise OSError("the OS reported no cores this process may use")
        _pin(lowest(before, n))
        now = allowed_cores()               # what the OS kept, not what was asked
    except OSError as exc:
        return (f"aramid: drain: {KEY} = {n} was not applied ({type(exc).__name__}: {exc})"
                f" -- {_NOT_CAPPED}")
    return (f"aramid: drain: held to {len(now)} of {len(before)} cores ({KEY} = {n});"
            " every process it starts inherits that")


def apply_configured() -> str | None:
    """cmd_drain's first act: the line to print, or None with no cap set."""
    s = setting()
    if s.problem:
        return f"aramid: drain: no cpu cap applied -- {s.problem}"
    if s.cores is None:
        return None
    return apply(s.cores)


def status_suffix() -> str:
    """What `aramid status` adds to its scheduled-drain line. Reads the
    config and nothing of the OS but whether it has the call."""
    s = setting()
    if s.problem:
        return f"; drain cpu cap NOT applied -- {s.problem}"
    if s.cores is None:
        return ""
    if not supported():
        return (f"; drain cpu cap: {s.cores} ({_WHERE}), but this OS has no CPU affinity call"
                " -- not applied")
    return f"; drain cpu cap: {s.cores} ({_WHERE})"
