"""scripts/promote_live.py -- promoting aramid must not silently move the
analyzers every other repo's verdict comes from (FN-26).

2026-10-02, promoting 0.19.4: `pip install --force-reinstall <wheel>`
re-resolved aramid's whole dependency tree to the newest allowed versions.
semgrep 1.179.0 had been published hours earlier with no Windows wheel, so pip
built it from the sdist without semgrep-core.exe; every semgrep run on the
machine exited 2 from 04:50Z to 06:46Z, and the script printed "OK. Consumers
now run 0.19.4." The release rehearsal push caught it, not the script.

Three guards, each pinned here: aramid itself is reinstalled with --no-deps;
any dependency version pip WOULD change is shown first and refused unless the
operator names it; and an analyzer that ran before promotion and does not
after fails it, as does a new `pip check` conflict.

The new seams are stubbed with `raising=False` so that, on the code before the
fix, these tests FAIL on behaviour rather than error on a missing attribute.
"""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "promote_live.py"
WHEEL_BYTES = b"not really a wheel"
DIGEST = hashlib.sha256(WHEEL_BYTES).hexdigest()
OK_TOOLS = {"semgrep": (True, "1.178.0"), "ruff": (True, "ruff 0.16.10"),
            "pip-audit": (True, "pip-audit 2.10.1")}


@pytest.fixture(scope="module")
def pl():
    spec = importlib.util.spec_from_file_location("promote_live", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _cp(rc: int, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr="")


def _promote(pl, monkeypatch, tmp_path, argv, *, changes=(), tools=(OK_TOOLS, OK_TOOLS),
             conflicts=(set(), set()), drain_lock=None):
    """Run main() with the release, the download and every new seam faked.
    Returns (rc, the argv of every `pip install` that was not a dry run)."""
    site = str(tmp_path / "site-packages" / "aramid" / "__init__.py")
    lives = iter([("0.5.0", site, False), ("0.5.1", site, False)])
    monkeypatch.setattr(sys, "argv", ["promote_live.py", "0.5.1", *argv])
    monkeypatch.setattr(pl, "_live", lambda: next(lives))
    monkeypatch.setattr(pl, "_release_digest", lambda tag, asset: DIGEST)
    installs = []

    def _run(argv, **kw):
        if "download" in argv:
            out = Path(argv[argv.index("--dir") + 1])
            (out / pl.WHEEL_ASSET.format(version="0.5.1")).write_bytes(WHEEL_BYTES)
        elif "pip" in argv and "install" in argv and "--dry-run" not in argv:
            installs.append(list(argv))
        return _cp(0)
    monkeypatch.setattr(pl, "_run", _run)
    monkeypatch.setattr(pl, "_dep_changes",
                        lambda wheel: None if changes is None else list(changes),
                        raising=False)
    tool_reads = iter(tools)
    monkeypatch.setattr(pl, "_probe_tools", lambda: next(tool_reads), raising=False)
    conflict_reads = iter(conflicts)
    monkeypatch.setattr(pl, "_pip_check", lambda: next(conflict_reads), raising=False)
    monkeypatch.setattr(pl, "_drain_lock", lambda: drain_lock or tmp_path / "no-drain.lock",
                        raising=False)
    return pl.main(), installs


# --- the install itself --------------------------------------------------------

def test_aramid_is_reinstalled_without_touching_its_dependencies(
        pl, monkeypatch, tmp_path, capsys):
    rc, installs = _promote(pl, monkeypatch, tmp_path, ["--confirm"])
    assert rc == 0, capsys.readouterr()
    assert installs, "nothing was installed"
    assert any("--force-reinstall" in a and "--no-deps" in a for a in installs), installs
    for argv in installs:
        assert "--force-reinstall" not in argv or "--no-deps" in argv, (
            f"a force-reinstall that re-resolves dependencies: {argv}")
        assert "--upgrade" not in argv and "-U" not in argv, argv
        assert argv[1:4] == ["-P", "-m", "pip"], f"-m pip from the repo root without -P: {argv}"


# --- what pip would change ------------------------------------------------------

def test_a_dependency_change_is_refused_before_anything_is_installed(
        pl, monkeypatch, tmp_path, capsys):
    rc, installs = _promote(pl, monkeypatch, tmp_path, ["--confirm"],
                            changes=[("semgrep", "1.178.0", "1.179.0")])
    out = capsys.readouterr()
    assert rc == 3
    assert "semgrep 1.178.0 -> 1.179.0" in out.out
    assert "--allow-dep-change semgrep" in out.err, out.err
    assert installs == [], "refused, so nothing may be installed"
    assert "Consumers now run" not in out.out


def test_a_named_dependency_change_is_allowed(pl, monkeypatch, tmp_path, capsys):
    """Named the way PyPI spells it; matched the way pip normalizes it."""
    rc, installs = _promote(pl, monkeypatch, tmp_path,
                            ["--confirm", "--allow-dep-change", "PyJWT"],
                            changes=[("pyjwt", "2.13.0", "2.15.1")])
    out = capsys.readouterr().out
    assert rc == 0
    assert installs
    assert "pyjwt 2.13.0 -> 2.15.1" in out and "[allowed]" in out


def test_a_dependency_that_is_new_rather_than_changed_is_named_as_new(
        pl, monkeypatch, tmp_path, capsys):
    rc, _ = _promote(pl, monkeypatch, tmp_path, [],
                     changes=[("tomli-w", None, "1.2.0")])
    assert "tomli-w (not installed) -> 1.2.0" in capsys.readouterr().out


def test_the_dry_run_shows_what_would_change_and_installs_nothing(
        pl, monkeypatch, tmp_path, capsys):
    rc, installs = _promote(pl, monkeypatch, tmp_path, [],
                            changes=[("semgrep", "1.178.0", "1.179.0")])
    out = capsys.readouterr().out
    assert rc == 0
    assert installs == []
    assert "semgrep 1.178.0 -> 1.179.0" in out
    assert "--confirm would refuse" in out


def test_an_uncomputable_change_set_is_refused_not_guessed(
        pl, monkeypatch, tmp_path, capsys):
    rc, installs = _promote(pl, monkeypatch, tmp_path, ["--confirm"], changes=None)
    assert rc == 3
    assert installs == []
    assert "could not work out" in capsys.readouterr().err


# --- do the analyzers still run? ------------------------------------------------

def test_an_analyzer_that_ran_before_and_not_after_fails_promotion(
        pl, monkeypatch, tmp_path, capsys):
    broken = {**OK_TOOLS, "semgrep": (False, "Failed to find semgrep-core.exe in PATH")}
    rc, _ = _promote(pl, monkeypatch, tmp_path, ["--confirm"], tools=(OK_TOOLS, broken))
    out = capsys.readouterr()
    assert rc == 3
    assert "FAILED" in out.err and "semgrep" in out.err and "semgrep-core" in out.err, out.err
    assert "Consumers now run" not in out.out


def test_an_analyzer_already_broken_before_is_reported_not_blamed(
        pl, monkeypatch, tmp_path, capsys):
    broken = {**OK_TOOLS, "semgrep": (False, "exited 2")}
    rc, _ = _promote(pl, monkeypatch, tmp_path, ["--confirm"], tools=(broken, broken))
    out = capsys.readouterr()
    assert rc == 0
    assert "WARNING: semgrep did not run before promotion either" in out.out, out.out


def test_an_analyzer_missing_after_install_fails_when_it_was_found_before(
        pl, monkeypatch, tmp_path, capsys):
    gone = {**OK_TOOLS, "ruff": (None, "not found")}
    rc, _ = _promote(pl, monkeypatch, tmp_path, ["--confirm"], tools=(OK_TOOLS, gone))
    assert rc == 3
    assert "ruff" in capsys.readouterr().err


def test_a_probe_that_cannot_run_after_install_fails_promotion(
        pl, monkeypatch, tmp_path, capsys):
    """An empty answer is not "every tool is fine"; it is "nothing was checked"."""
    rc, _ = _promote(pl, monkeypatch, tmp_path, ["--confirm"], tools=(OK_TOOLS, {}))
    assert rc == 3
    assert "could not check" in capsys.readouterr().err


def test_a_new_pip_check_conflict_fails_promotion(pl, monkeypatch, tmp_path, capsys):
    new = "semgrep 1.179.0 has requirement pyjwt>=2.15.0, but you have pyjwt 2.13.0."
    rc, _ = _promote(pl, monkeypatch, tmp_path, ["--confirm"], conflicts=(set(), {new}))
    out = capsys.readouterr()
    assert rc == 3
    assert new in out.err


def test_a_conflict_that_was_already_there_is_not_blamed(pl, monkeypatch, tmp_path, capsys):
    old = "fastapi 0.128.8 has requirement starlette<1.0.0, but you have starlette 1.7.0."
    rc, _ = _promote(pl, monkeypatch, tmp_path, ["--confirm"], conflicts=({old}, {old}))
    assert rc == 0, capsys.readouterr()


def test_a_pip_check_that_cannot_run_after_install_fails_promotion(
        pl, monkeypatch, tmp_path, capsys):
    rc, _ = _promote(pl, monkeypatch, tmp_path, ["--confirm"], conflicts=(set(), None))
    assert rc == 3
    assert "pip check: could not run" in capsys.readouterr().err


# --- a running drain ---------------------------------------------------------------

def test_a_running_drain_refuses_promotion(pl, monkeypatch, tmp_path, capsys):
    """The drain runs the live tool; promotion would swap packages under it."""
    lock = tmp_path / "drain.lock"
    lock.write_text('{"pid": 1}', encoding="utf-8")
    rc, installs = _promote(pl, monkeypatch, tmp_path, ["--confirm"], drain_lock=lock)
    assert rc == 3
    assert installs == []
    assert "a drain is running" in capsys.readouterr().err


def test_the_drain_lock_is_the_one_the_drain_writes(pl):
    """The script cannot import the live drain (it may be an older aramid),
    so it spells the path itself; this keeps the two spellings agreeing."""
    from aramid.commands import drain
    assert pl._drain_lock() == drain._lock_path()


# --- the seams, against faked subprocesses ----------------------------------------

def _report_run(report: dict, installed: dict, calls: list, rc: int = 0):
    def _run(argv, **kw):
        calls.append(list(argv))
        if "--dry-run" in argv:
            if rc == 0:
                Path(argv[argv.index("--report") + 1]).write_text(json.dumps(report),
                                                                  encoding="utf-8")
            return _cp(rc)
        return _cp(0, json.dumps(installed) + "\n")
    return _run


def test_dep_changes_reads_pips_dry_run_report(pl, monkeypatch, tmp_path):
    report = {"install": [{"metadata": {"name": "aramid", "version": "0.5.1"}},
                          {"metadata": {"name": "semgrep", "version": "1.179.0"}},
                          {"metadata": {"name": "PyJWT", "version": "2.15.1"}}]}
    calls = []
    monkeypatch.setattr(pl, "_run", _report_run(
        report, {"semgrep": "1.178.0", "PyJWT": "2.13.0"}, calls))
    assert pl._dep_changes(tmp_path / "w.whl") == [
        ("semgrep", "1.178.0", "1.179.0"), ("PyJWT", "2.13.0", "2.15.1")]
    dry = [c for c in calls if "--dry-run" in c]
    assert len(dry) == 1
    assert "--force-reinstall" not in dry[0] and "--upgrade" not in dry[0], dry[0]
    assert dry[0][1:4] == ["-P", "-m", "pip"], dry[0]


def test_dep_changes_with_only_aramid_planned_is_empty(pl, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(pl, "_run", _report_run(
        {"install": [{"metadata": {"name": "aramid", "version": "0.5.1"}}]}, {}, calls))
    assert pl._dep_changes(tmp_path / "w.whl") == []
    assert all("--dry-run" in c for c in calls), "no version probe for an empty plan"


def test_dep_changes_refuses_to_guess_when_pip_fails(pl, monkeypatch, tmp_path):
    monkeypatch.setattr(pl, "_run", _report_run({}, {}, [], rc=1))
    assert pl._dep_changes(tmp_path / "w.whl") is None


def test_probe_tools_reads_the_live_probe(pl, monkeypatch):
    monkeypatch.setattr(pl, "_run", lambda argv, **kw: _cp(
        0, '{"semgrep": [false, "exited 2"], "ruff": [null, "not found"]}\n'))
    assert pl._probe_tools() == {"semgrep": (False, "exited 2"), "ruff": (None, "not found")}


def test_probe_tools_distrusts_a_failed_probe(pl, monkeypatch):
    monkeypatch.setattr(pl, "_run", lambda argv, **kw: _cp(1, '{"semgrep": [true, "x"]}'))
    assert pl._probe_tools() == {}


def test_the_real_tool_probe_answers_in_shape(pl):
    """Unmocked: the probe source is a string run in a clean interpreter, so
    nothing else here would notice it failing to import or to parse."""
    tools = pl._probe_tools()
    assert set(tools) == {"semgrep", "ruff", "pip-audit"}, tools
    for name, (ok, detail) in tools.items():
        assert ok in (True, False, None) and isinstance(detail, str), (name, ok, detail)


def test_pip_check_reports_conflict_lines(pl, monkeypatch):
    monkeypatch.setattr(pl, "_run", lambda argv, **kw: _cp(
        1, "a 1.0 has requirement b<2, but you have b 2.0.\n"))
    assert pl._pip_check() == {"a 1.0 has requirement b<2, but you have b 2.0."}


def test_pip_check_clean_is_empty(pl, monkeypatch):
    monkeypatch.setattr(pl, "_run", lambda argv, **kw: _cp(0, "No broken requirements found.\n"))
    assert pl._pip_check() == set()
