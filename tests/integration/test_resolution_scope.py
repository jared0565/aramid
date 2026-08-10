"""Resolution scope is not scan scope: `--all` must not disable resolvers.

`[hooks].pre_push_match_ci = true` makes the pre-push shim run
`check --gate pre-push --all --strict`, so a finding in a file this push did
not touch is caught locally instead of on the seven-leg matrix. `--all`
resolves to `mode == "all"`, and every range-scoped resolver sat behind
`if mode == "range"` -- so turning on CI parity silently turned OFF mutation,
tdd and red-proof auto-resolution. Nothing said so; the opt-in's docstring
warned about the ratchet and not about this.

Measured on aramid's own ledger before the fix: `gap_addressed` and
`test_added` had fired ZERO times in the repo's entire history, across 182
`FINDING_RESOLVED` events, while the three resolvers that do not depend on
range scope had all fired. Four findings whose fixes were committed hours
earlier could never clear.

THE GUARD IS NOT REMOVED, IT IS MOVED. It exists because `scope_files` under
`all`/`staged` is the whole tracked tree, and resolving on that durably clears
every open finding -- `FINDING_RESOLVED` is appended and cannot be un-appended.
The fix computes the push's GENUINE delta independently of the scan mode, so
the hazard is answered by construction rather than by refusing to run. The
no-upstream case is what keeps it safe, and is the third test here.
"""
import subprocess

from aramid import pipeline
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Source, Verdict

NOW = "2026-08-10T12:00:00+00:00"
MUTANT_ID = "w" * 64


def _no_runners(monkeypatch):
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})


def _run(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


def _repo(tmp_path, *, with_upstream: bool):
    r = tmp_path / "repo"
    r.mkdir()
    _run(r, "init", "-q", "-b", "main")
    _run(r, "config", "user.email", "t@t")
    _run(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "src" / "widget.py").write_text("def add(a, b):\n    return a + b\n",
                                         encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "c1")
    if with_upstream:
        remote = tmp_path / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
        _run(r, "remote", "add", "origin", str(remote))
        _run(r, "push", "-q", "-u", "origin", "main")
    return r


def _seed_survivor(r):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("r0", NOW, "drain", set(), set(), [Finding(
            id=MUTANT_ID, tool="mutation", rule="flip_arith",
            severity_raw="medium", severity=Severity.MEDIUM,
            verdict=Verdict.WARN, file="src/widget.py", line=2,
            message="mutant survived: a - b", evidence="",
            gate=Gate.ALL, source=Source.DETERMINISTIC)])
    finally:
        led.close()


def _commit(r, rel, body):
    p = r / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", f"add {rel}")


def _status(r):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        return led.open_findings()[MUTANT_ID]["status"]
    finally:
        led.close()


def test_all_mode_resolves_when_the_mapped_test_is_in_the_pushes_delta(
        tmp_path, monkeypatch):
    """The regression this exists to prevent: CI parity must not cost
    resolution."""
    _no_runners(monkeypatch)
    r = _repo(tmp_path, with_upstream=True)
    _seed_survivor(r)
    _commit(r, "tests/test_widget.py",
            "from src.widget import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n")

    cmd_check(r, Gate.PRE_PUSH, "all")

    assert _status(r) == "fixed", (
        "the mapped test is in @{u}..HEAD, but --all skipped resolution")


def test_all_mode_does_not_resolve_when_the_mapped_test_is_outside_the_delta(
        tmp_path, monkeypatch):
    """THE DISCRIMINATING CASE. Under `--all` the mapped test is in the SCAN
    scope (it is a tracked file) while being absent from the push's delta. An
    implementation that hands `scope_files` to the resolver passes the test
    above and fails this one -- and in a real repo would clear every open
    finding on the first `--all` push, durably."""
    _no_runners(monkeypatch)
    r = _repo(tmp_path, with_upstream=True)
    # Mapped test committed and PUSHED, so it is tracked-but-not-in-the-delta.
    _commit(r, "tests/test_widget.py",
            "from src.widget import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n")
    _run(r, "push", "-q", "origin", "main")
    _seed_survivor(r)
    # The delta contains only an unrelated file.
    _commit(r, "src/other.py", "y = 2\n")

    cmd_check(r, Gate.PRE_PUSH, "all")

    assert _status(r) == "open", (
        "a finding was resolved by a test the push never touched -- the "
        "resolver was handed the scan scope, not the push delta")


def test_all_mode_with_no_upstream_resolves_nothing(tmp_path, monkeypatch):
    """The hazard the original `if rng:` guard existed for, re-checked at its
    new home. With no upstream and no origin/HEAD there is no delta to speak
    of, and the safe answer is to resolve nothing rather than to fall back to
    the whole tree -- which here holds the mapped test and would clear the
    finding on a repo that never pushed anything."""
    _no_runners(monkeypatch)
    r = _repo(tmp_path, with_upstream=False)
    _seed_survivor(r)
    _commit(r, "tests/test_widget.py",
            "from src.widget import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n")

    cmd_check(r, Gate.PRE_PUSH, "all")

    assert _status(r) == "open", (
        "with no upstream the resolver still cleared a finding -- the scope "
        "fell back to something, and the only somethings available are the "
        "whole tree or HEAD")
