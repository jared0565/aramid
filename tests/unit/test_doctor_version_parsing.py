"""`--version` output parsing in `doctor`, pinned against the two mutants
that survived a real mutation run.

PROVENANCE. These are not speculative. `aramid drain` ran the mutation
consumer against `doctor.py` and three mutants survived, all in
`_version_of`:

    or  -> and   at `(cp.stdout or cp.stderr)`      line 179
    [0] -> [1]   at `out.splitlines()[0]`           line 180
    15  -> 16    at `timeout=15`                    line 176   (equivalent)

The first two are genuine test gaps; the third is an equivalent mutant (a
one-second change to a timeout has no observable behaviour, and a test
asserting `timeout == 15` would pin a literal, not a behaviour). What IS
worth pinning about the timeout is the docstring's load-bearing promise that
`_version_of` never raises, so a hanging tool cannot fail a doctor run --
tested below, and deliberately not as a mutant kill.

WHY 1598 TESTS MISSED THEM. Every existing caller-level test in
`test_toolpath_divergence.py` monkeypatches `_version_of` itself, so the
function's own body had no coverage at all -- measured, not assumed: with
either mutant applied, all four of those tests stay green.

`probe_tool` duplicates the same two lines (161-162) and is a DIFFERENT
case, narrower than it first looks. Its real-binary integration tests kill
both mutants there on their own (measured separately, each mutant alone), so
its parsing is not an untested gap. What those tests never reach is the
stderr branch or a multi-line answer -- real binaries on this machine
happen to answer on stdout in one line. The two `probe_tool` tests below buy
branch coverage that no mutant asked for, so that the branch stops depending
on which tools are installed on the host.

The `or cp.stderr` fallback is grounded in the production code, not in a
claim about any particular tool: the branch exists by design, so a tool that
answers on stderr must be read correctly or the fallback is decoration.
"""
import subprocess
import sys
from pathlib import Path

import pytest

from aramid import toolpath
from aramid.commands import doctor


def _answers(stdout: str = "", stderr: str = "", returncode: int = 0):
    """A fake `subprocess.run` returning a REAL CompletedProcess. Only the
    child process is faked -- every assertion below is on what aramid's own
    parsing does with it."""
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)
    return run


# --------------------------------------------------- _version_of, stderr ---

def test_version_of_reads_a_tool_that_answers_on_stderr(monkeypatch):
    """Kills `or` -> `and`. Under the mutant, `"" and "ruff 0.15.18"` is `""`
    and the version reads as unknown for a tool that answered perfectly
    well."""
    monkeypatch.setattr(doctor.subprocess, "run", _answers(stderr="ruff 0.15.18"))

    assert doctor._version_of(Path("/fake/bin/ruff")) == "ruff 0.15.18"


def test_stdout_wins_when_a_tool_writes_to_both_streams(monkeypatch):
    """The counterfactual for the test above: the fallback must stay a
    FALLBACK. A tool that warns on stderr while answering on stdout is the
    common case, and reading the warning as the version would be worse than
    reading nothing."""
    monkeypatch.setattr(doctor.subprocess, "run",
                        _answers(stdout="ruff 0.16.2", stderr="warning: deprecated flag"))

    assert doctor._version_of(Path("/fake/bin/ruff")) == "ruff 0.16.2"


# ------------------------------------------------ _version_of, first line ---

def test_version_of_takes_the_first_line_not_a_later_one(monkeypatch):
    """Kills `[0]` -> `[1]`. Under the mutant this returns the notice rather
    than the version -- and `divergence_lines` would then compare two
    notices, calling two genuinely different versions equal (or two equal
    ones different) depending on what each copy happened to warn about."""
    monkeypatch.setattr(doctor.subprocess, "run",
                        _answers(stdout="pip-audit 2.10.1\n"
                                        "notice: a new release is available\n"))

    assert doctor._version_of(Path("/fake/bin/pip-audit")) == "pip-audit 2.10.1"


def test_version_of_is_empty_when_the_tool_prints_nothing(monkeypatch):
    """`out.splitlines()[0]` on empty output would raise IndexError, and this
    function is not allowed to raise."""
    monkeypatch.setattr(doctor.subprocess, "run", _answers())

    assert doctor._version_of(Path("/fake/bin/quiet")) == ""


# ------------------------------------------- _version_of never raises ------
# Not mutant-driven. The docstring promises it "never raises: this feeds an
# advisory notice, and a notice must not be able to fail a doctor run", and
# nothing checked that promise.

@pytest.mark.parametrize("exc", [
    subprocess.TimeoutExpired(cmd=["x", "--version"], timeout=15),
    OSError("exec format error"),
])
def test_version_of_returns_empty_rather_than_raising(monkeypatch, exc):
    def boom(argv, **kwargs):
        raise exc

    monkeypatch.setattr(doctor.subprocess, "run", boom)

    assert doctor._version_of(Path("/fake/bin/hangs")) == ""


# ------------------------------------------------- the same two, upstream ---
# Branch coverage, NOT mutant kills -- see the module docstring. probe_tool's
# real-binary tests already kill both mutants; what they cannot do is
# exercise a branch no installed tool takes.

def test_probe_tool_reads_a_version_a_tool_answered_on_stderr(monkeypatch):
    monkeypatch.setattr(doctor.toolpath, "resolve", lambda name: Path("/fake/bin/tool"))
    monkeypatch.setattr(doctor.subprocess, "run", _answers(stderr="tool 3.2.1"))

    status = doctor.probe_tool("ruff")

    assert status.present
    assert status.version == "tool 3.2.1"


def test_probe_tool_takes_the_first_line_of_a_multi_line_version(monkeypatch):
    monkeypatch.setattr(doctor.toolpath, "resolve", lambda name: Path("/fake/bin/tool"))
    monkeypatch.setattr(doctor.subprocess, "run",
                        _answers(stdout="tool 3.2.1\nbuilt with love\n"))

    assert doctor.probe_tool("ruff").version == "tool 3.2.1"


# ----------------------------------------- what the mutant does to a USER ---

def test_two_stderr_only_copies_of_the_same_version_are_not_reported_as_drift(
        tmp_path, monkeypatch):
    """The user-visible consequence of `or` -> `and`, at the level a person
    actually sees.

    `test_doctor_does_not_cry_drift_when_both_copies_are_the_same_version`
    exists to prevent exactly this notice, and is VACUOUS against this
    failure mode because it monkeypatches `_version_of` -- the mutant lives
    inside the thing that test replaces. With the real function in place and
    a tool that answers on stderr, the mutant makes both versions read as
    unknown, `raw_rv and raw_dv` is false, and doctor cries DRIFT over two
    copies of the same version -- the precise noise that teaches a reader to
    skip the block.
    """
    on_path = tmp_path / "path-bin" / toolpath.exe_name("ruff")
    in_venv = tmp_path / "venv-scripts" / toolpath.exe_name("ruff")
    for p, body in ((on_path, "#path copy"), (in_venv, "#venv copy")):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    import shutil
    monkeypatch.setattr(shutil, "which",
                        lambda name, *a, **k: str(on_path) if name == "ruff" else None)
    monkeypatch.setattr(toolpath, "scripts_dirs", lambda: [in_venv.parent])
    monkeypatch.setattr(doctor.subprocess, "run", _answers(stderr="ruff 0.16.2"))

    assert doctor.divergence_lines() == [], (
        "two copies of the same version were reported as drift")


# ------------------------------------------------- against a real binary ---

def test_version_of_works_end_to_end_against_a_real_executable():
    """Everything above fakes the child process. This one does not: it runs
    the interpreter that is running these tests, which is the only assertion
    here that would notice `capture_output`, `text=True` or the encoding
    arguments going wrong."""
    version = doctor._version_of(Path(sys.executable))

    assert version, "a real executable answered --version with nothing"
    assert "\n" not in version
    assert "Python" in version


# --- two further survivors, found 2026-08-11 by re-probing the same function --
#
# The header above records the three mutants a real drain surfaced. Re-probing
# `_version_of` by hand -- applying candidate mutants and running this file --
# turned up two MORE that nothing killed. Worth stating why the drain had not:
# mutation only mutates files inside a queue item's diff range, so a function
# stops being re-probed as soon as the pushes stop touching it. Absence of a
# finding is not evidence of coverage.

def test_version_of_strips_before_taking_the_first_line(monkeypatch):
    """Kills `.strip()` dropped.

    Order matters and is not interchangeable: strip-then-splitlines is not
    splitlines-then-strip. A tool whose `--version` opens with a BLANK LINE
    (banner, deprecation notice, an empty first line from a shell wrapper)
    makes `splitlines()[0]` the empty string, so aramid reports NO VERSION for
    a tool that answered perfectly well -- and the notice this feeds then says
    nothing rather than saying something wrong, which is harder to notice."""
    monkeypatch.setattr(subprocess, "run",
                        _answers(stdout="\n\nruff 0.16.2\n"))
    assert doctor._version_of(Path("ruff")) == "ruff 0.16.2"


def test_version_of_treats_whitespace_only_output_as_no_answer(monkeypatch):
    """The other half of the same mutant. Without the strip, `out` is `"   "`
    -- truthy -- so the `if out else ""` guard passes and the function returns
    a string of spaces as the tool's version."""
    monkeypatch.setattr(subprocess, "run", _answers(stdout="   \n  \n"))
    assert doctor._version_of(Path("ruff")) == ""


def test_version_of_puts_the_exes_own_directory_first_on_path(monkeypatch):
    """Kills PATH prepend -> append.

    The docstring calls this prepend load-bearing and names the reason:
    semgrep's launcher shells out to a SIBLING BY BARE NAME, so if the
    inherited PATH is searched first, some other install answers instead --
    the same failure the packaged-wheel test found, where a PATH-first ruff
    0.15.18 ran while 0.16.2 sat beside it and reported one finding instead of
    three.

    HONEST SCOPE: this pins the environment aramid CONSTRUCTS, not the OS's
    resolution of it -- proving the latter needs a real wrapper that shells out
    by bare name, which is what test_toolpath_divergence.py exists for. Order
    is asserted positionally rather than with `in`, because `in` is true for
    both the prepend and the append."""
    import os as _os

    seen = {}

    def run(argv, **kwargs):
        seen["PATH"] = kwargs["env"]["PATH"]
        return subprocess.CompletedProcess(argv, 0, "x 1.0\n", "")

    monkeypatch.setenv("PATH", _os.pathsep.join(["/usr/bin", "/bin"]))
    monkeypatch.setattr(subprocess, "run", run)

    exe = Path("/opt/tools/bin/semgrep")
    doctor._version_of(exe)

    first = seen["PATH"].split(_os.pathsep)[0]
    assert first == str(exe.parent), (
        f"the exe's own directory must be searched first, got {first!r} "
        f"from {seen['PATH']!r}")


def test_probe_tool_puts_the_exes_own_directory_first_on_path(monkeypatch):
    """The SAME contract, in the other function that spells it.

    `doctor.py` writes this env line twice -- `probe_tool` at 147 and
    `_version_of` at 173 -- and only the second was covered. Mutating each line
    separately is what showed it: the `_version_of` mutant dies against the
    test above, the `probe_tool` mutant passed all 31 tests in both doctor
    files.

    Worth recording HOW that hid, because it nearly hid twice: probing by
    string match with `replace(old, new, 1)` silently rewrites the FIRST
    occurrence, so a mutant reported against `_version_of` was really applied
    to `probe_tool`. A duplicated line makes a by-text probe report the wrong
    subject -- mutate by LINE NUMBER when a codebase spells the same contract
    more than once. Same family as the earlier scoping miss, where a
    call-graph query could not see a duplicated implementation.

    Same honest scope as its sibling: this pins the environment aramid
    CONSTRUCTS, not the OS's resolution of it."""
    import os as _os

    seen = {}

    def run(argv, **kwargs):
        seen["PATH"] = kwargs["env"]["PATH"]
        return subprocess.CompletedProcess(argv, 0, "gitleaks 8.18.0\n", "")

    exe = Path("/opt/managed/bin/gitleaks")
    monkeypatch.setattr(doctor, "_locate_gitleaks", lambda: exe)
    monkeypatch.setenv("PATH", _os.pathsep.join(["/usr/bin", "/bin"]))
    monkeypatch.setattr(subprocess, "run", run)

    status = doctor.probe_tool("gitleaks")

    assert status.present is True, "fixture must reach the subprocess call"
    first = seen["PATH"].split(_os.pathsep)[0]
    assert first == str(exe.parent), (
        f"the exe's own directory must be searched first, got {first!r} "
        f"from {seen['PATH']!r}")
