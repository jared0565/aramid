"""Every shim aramid writes must invoke Python with `-P`.

`python -m aramid` puts the CURRENT WORKING DIRECTORY at `sys.path[0]`, and git
runs hooks from the top of the working tree. So an `aramid.py` file — or an
`aramid/` directory — sitting at a repo root beats the installed package and
the gate runs attacker-controlled code instead.

Measured on this machine, 2026-08-06, in a scratch repo carrying `aramid.toml`:

    shadow                    `python -m aramid check --gate pre-commit`
    ------------------------  ------------------------------------------
    none                      real gate runs, exit 0
    aramid.py                 SHADOW EXECUTES, then ModuleNotFoundError, exit 1
    aramid/__main__.py        FULL HIJACK, exit 0, real gate never runs
    any of the above, -P      shadow not executed, real gate runs

The package-shaped row is the dangerous one and it is worse here than the
usual case, because these are BLOCKING SECURITY hooks. The shim maps a status
of 0 straight to `exit 0`, so a hijacked pre-commit is indistinguishable from
a clean gate: the commit proceeds with nothing scanned. The module-shaped row
still executes arbitrary code, but exits non-zero, so it at least fails loudly.

`-P` rather than `PYTHONSAFEPATH=1` for the reason graphite gave when it fixed
the same class in its own hooks: it is visible in the command string an
operator audits by reading, and it cannot be lost by an environment that
resets on the way to the hook.

`py -3` is a launcher, not an interpreter path, but it forwards `-P` to the
interpreter it selects, so both arms are covered the same way.
"""
import re
from pathlib import Path

import pytest

from aramid import hooks
from aramid.models import Gate

INTERP = Path("C:/Python314/python.exe")

# Any `-m` invocation not preceded by -P. Matches both the `"$INTERP" -m ...`
# and `py -3 -m ...` arms.
_UNSAFE = re.compile(r'(?<!-P )(?<!-P)\s-m\s+aramid\b')


def _shims() -> list[tuple[str, str]]:
    out = [(f"render_shim({g.value})", hooks.render_shim(g, INTERP).decode())
           for g in hooks.GATES]
    out += [(f"render_template_shim({g.value})",
             hooks.render_template_shim(g, INTERP).decode())
            for g in hooks.GATES]
    out.append(("render_triage_shim", hooks.render_triage_shim(INTERP).decode()))
    return out


def test_the_guard_sees_every_generator():
    """Non-vacuity. hooks.py has THREE renderers and it is the one that gets
    forgotten that matters -- the triage shim was missed in the first pass of
    exactly this fix upstream. If a fourth is added and not listed here, this
    count assertion is the thing that says so."""
    shims = _shims()
    assert len(shims) == 2 * len(hooks.GATES) + 1, [n for n, _ in shims]
    assert all("-m aramid" in body for _, body in shims), \
        "a rendered shim stopped invoking aramid at all -- the checks below " \
        "would then pass vacuously"


@pytest.mark.parametrize("name,body", _shims(), ids=[n for n, _ in _shims()])
def test_every_python_m_invocation_passes_dash_P(name, body):
    offenders = [ln.strip() for ln in body.splitlines() if _UNSAFE.search(ln)]
    assert not offenders, (
        f"{name} invokes `-m aramid` without `-P`; a repo-root aramid.py or "
        f"aramid/ directory would hijack it:\n  " + "\n  ".join(offenders))


@pytest.mark.parametrize("name,body", _shims(), ids=[n for n, _ in _shims()])
def test_both_interpreter_arms_are_covered(name, body):
    """The fallback arm is the one that rots. A fix applied only to the
    `$INTERP` branch leaves every machine without that exact interpreter
    running the vulnerable form."""
    for arm in ('"$INTERP"', "py -3"):
        line = next((ln for ln in body.splitlines()
                     if arm in ln and "-m aramid" in ln), None)
        assert line is not None, f"{name}: no `-m aramid` line for arm {arm}"
        assert "-P" in line, f"{name}: arm {arm} missing -P: {line.strip()}"


def test_dash_P_sits_before_dash_m():
    """Order is load-bearing: `-P` is an interpreter option and must precede
    `-m`, or Python treats it as an argument to the module."""
    for name, body in _shims():
        for ln in body.splitlines():
            if "-m aramid" not in ln:
                continue
            assert ln.index("-P") < ln.index("-m"), f"{name}: {ln.strip()}"
