"""PLAT-1's CI smoke must not be able to pass without checking.

`.github/scripts/installed_smoke.py` is the only proof that an INSTALLED
aramid -- not the editable checkout -- runs a real gate. Its whole value is
in `check_gate`'s assertions: that semgrep ran, from the venv, undegraded,
with the fixture's `[tests]` slot off as chosen, and that the installed
ruleset flagged the fixture's line. An assertion loosened by a later edit
would leave the CI step green over exactly the editable-install run it
exists to rule out, so each one is held here to a report that breaks it
alone. The end-to-end run (a real venv, a real semgrep) is CI's step
itself, on one leg per OS.
"""
import ast
import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
import venv
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "installed_smoke.py"
_spec = importlib.util.spec_from_file_location("installed_smoke", SCRIPT)
smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smoke)


def _report(venv: Path) -> dict:
    return {
        "tools_ran": ["gitleaks", "semgrep", "shadow"],
        "degraded": [],
        "degraded_reasons": {},
        "tools": {"semgrep": {"path": str(smoke.bin_dir(venv) / "semgrep")}},
        "findings": [{"tool": "semgrep", "file": smoke.FIXTURE_FILE, "line": 5,
                      "rule": "owasp-top-ten.a02-crypto-failures."
                              + smoke.WEAK_HASH_RULE}],
    }


def test_a_report_from_the_venvs_own_semgrep_passes(tmp_path):
    smoke.check_gate(_report(tmp_path / "venv"), tmp_path / "venv")


def _outside(r, tmp):
    r["tools"]["semgrep"]["path"] = str(tmp / "elsewhere" / "semgrep")


def _not_run(r, tmp):
    r["tools_ran"].remove("semgrep")


def _degraded(r, tmp):
    r["degraded"].append("semgrep")
    r["degraded_reasons"]["semgrep"] = "crashed"


def _tests_ran(r, tmp):
    r["tools_ran"].append("tests")


def _tests_degraded(r, tmp):
    r["degraded"].append("tests")


def _no_finding(r, tmp):
    r["findings"] = []


def _other_rule(r, tmp):
    r["findings"][0]["rule"] = "owasp-top-ten.a03-injection.python-dangerous-eval-exec"


def _other_file(r, tmp):
    r["findings"][0]["file"] = "other.py"


def _other_tool(r, tmp):
    r["findings"][0]["tool"] = "ruff"


@pytest.mark.parametrize("breaker", [
    _outside, _not_run, _degraded, _tests_ran, _tests_degraded,
    _no_finding, _other_rule, _other_file, _other_tool,
], ids=lambda f: f.__name__.strip("_"))
def test_each_assertion_fires_on_the_report_that_breaks_it_alone(tmp_path, breaker):
    venv = tmp_path / "venv"
    report = copy.deepcopy(_report(venv))
    breaker(report, tmp_path)
    with pytest.raises(smoke.SmokeFailed):
        smoke.check_gate(report, venv)


def test_a_broken_report_still_fails_under_python_O(tmp_path):
    """`python -O` strips `assert`: a smoke whose checks were asserts would
    pass a report that breaks every one of them. Run the real script under
    -O against a report with semgrep missing entirely."""
    venv = tmp_path / "venv"
    report = copy.deepcopy(_report(venv))
    _not_run(report, tmp_path)
    (tmp_path / "report.json").write_text(json.dumps(report), encoding="utf-8")
    code = ("import importlib.util, json, pathlib, sys\n"
            "spec = importlib.util.spec_from_file_location('s', sys.argv[1])\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "m.check_gate(json.loads(pathlib.Path(sys.argv[2]).read_text()), "
            "pathlib.Path(sys.argv[3]))\n")
    cp = subprocess.run([sys.executable, "-O", "-c", code, str(SCRIPT),
                         str(tmp_path / "report.json"), str(venv)],
                        capture_output=True, text=True, timeout=60)
    assert cp.returncode != 0, f"passed under -O: {cp.stdout}"
    assert "semgrep did not run" in cp.stderr


def test_no_check_in_the_script_is_an_assert():
    """Every check, not only check_gate's: probe's and gate_env's too."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    lines = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Assert)]
    assert lines == [], f"assert statements at lines {lines} vanish under -O"


@pytest.mark.parametrize("path, expected", [
    ("venv/Scripts/semgrep.exe", True),
    ("venv", True),
    ("venv-other/bin/semgrep", False),
    ("elsewhere/semgrep", False),
])
def test_inside_is_containment_not_a_string_prefix(tmp_path, path, expected):
    """`venv-other` shares the prefix `venv` and is not inside it."""
    assert smoke.inside(tmp_path / path, tmp_path / "venv") is expected


def test_bin_dir_and_python_in_match_a_real_venv(tmp_path):
    """Both are chosen per platform, and a report built with the same
    `bin_dir` agrees with a wrong one -- so hold them to the layout `venv`
    really creates on the platform running this (the 14Z drain's
    `== -> !=` survivors, 2100bf85 and c7437a78)."""
    where = tmp_path / "v"
    venv.EnvBuilder(with_pip=False).create(where)
    assert smoke.bin_dir(where).is_dir()
    assert smoke.python_in(where).is_file()


def _probe(monkeypatch, tmp_path, *, package: Path, rules: Path, make_rules: bool = True):
    """probe() with the interpreter's two printed lines faked: the real run
    needs an installed aramid, which is CI's end-to-end step."""
    if make_rules:
        rules.parent.mkdir(parents=True, exist_ok=True)
        rules.write_text("rules: []\n", encoding="utf-8")
    out = f"{package}\n{rules}\n"
    monkeypatch.setattr(smoke, "run", lambda argv, **kw: subprocess.CompletedProcess(
        argv, 0, stdout=out, stderr=""))
    where = tmp_path / "venv"
    smoke.probe(where, smoke.python_in(where), cwd=tmp_path)


def _in_venv(tmp_path, *parts) -> Path:
    return tmp_path.joinpath("venv", "site-packages", "aramid", *parts)


def test_probe_passes_a_package_and_ruleset_inside_the_venv(tmp_path, monkeypatch):
    _probe(monkeypatch, tmp_path, package=_in_venv(tmp_path, "__init__.py"),
           rules=_in_venv(tmp_path, "rules", "owasp.yml"))


@pytest.mark.parametrize("case, message", [
    ("package_outside", "aramid was imported from outside the venv"),
    ("rules_outside", "the ruleset resolved outside the venv"),
    ("rules_missing", "the ruleset is missing from the install"),
])
def test_each_probe_check_fires_on_the_output_that_breaks_it_alone(tmp_path, monkeypatch,
                                                                   case, message):
    """The probe is what rules out the source tree standing in for the
    install; its first check had no test (the `out[0] -> out[1]` survivor,
    2203d5ed, read the package line from the ruleset's)."""
    package = _in_venv(tmp_path, "__init__.py")
    rules = _in_venv(tmp_path, "rules", "owasp.yml")
    make_rules = True
    if case == "package_outside":
        package = tmp_path / "checkout" / "src" / "aramid" / "__init__.py"
    elif case == "rules_outside":
        rules = tmp_path / "checkout" / "src" / "aramid" / "rules" / "owasp.yml"
    else:
        make_rules = False
    with pytest.raises(smoke.SmokeFailed, match=message):
        _probe(monkeypatch, tmp_path, package=package, rules=rules, make_rules=make_rules)


def _never(*a, **kw):
    raise AssertionError("main did work before refusing its arguments")


@pytest.mark.parametrize("argv", [[], ["\U0001f642"], ["wheel"], ["wheel", "a.whl", "extra"]],
                         ids=["none", "one-odd", "mode-only", "three"])
def test_main_refuses_a_malformed_argv_before_doing_anything(monkeypatch, argv):
    """The 14Z drain's fuzz called main(['\U0001f642']) and got an IndexError
    (76559f50). A refusal is a SmokeFailed naming the usage, raised before
    any temp directory or venv exists."""
    monkeypatch.setattr(smoke.tempfile, "mkdtemp", _never)
    monkeypatch.setattr(smoke, "make_venv", _never)
    with pytest.raises(smoke.SmokeFailed, match=re.escape("usage: installed_smoke.py wheel|sdist <artifact>")):
        smoke.main(argv)


def test_main_refuses_an_unknown_mode(tmp_path, monkeypatch):
    artifact = tmp_path / "aramid.whl"
    artifact.write_bytes(b"")
    monkeypatch.setattr(smoke.tempfile, "mkdtemp", _never)
    monkeypatch.setattr(smoke, "make_venv", _never)
    with pytest.raises(smoke.SmokeFailed, match="mode must be wheel or sdist, not 'egg'"):
        smoke.main(["egg", str(artifact)])


def test_main_refuses_a_missing_artifact_before_making_a_venv(tmp_path, monkeypatch):
    """An unmatched `dist/*.whl` reaches here as the literal pattern: say so
    before building a venv to install nothing into."""
    monkeypatch.setattr(smoke.tempfile, "mkdtemp", _never)
    monkeypatch.setattr(smoke, "make_venv", _never)
    with pytest.raises(smoke.SmokeFailed, match="no such artifact"):
        smoke.main(["wheel", str(tmp_path / "dist" / "*.whl")])


def _no_gitleaks_on_path(monkeypatch, tmp_path) -> Path:
    """A user home of our own and a PATH with no gitleaks: gate_env must
    fall back to the copy aramid downloads into ~/.aramid/tools."""
    home = tmp_path / "userhome"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(smoke.shutil, "which", lambda name: None)
    return home / ".aramid" / "tools"


def _downloaded_gitleaks(tools: Path) -> None:
    tools.mkdir(parents=True)
    (tools / ("gitleaks.exe" if os.name == "nt" else "gitleaks")).write_bytes(b"")


@pytest.mark.parametrize("venv_first", [True, False])
def test_gate_env_puts_the_venv_first_then_the_downloaded_gitleaks(tmp_path, monkeypatch,
                                                                   venv_first):
    """PATH order IS the proof: `toolpath.resolve` asks `shutil.which` first,
    so the venv's semgrep runs only if its directory leads. The fallback
    names the platform's own executable (the `== -> !=` survivor at the
    `.exe` choice named the other platform's, and found nothing)."""
    tools = _no_gitleaks_on_path(monkeypatch, tmp_path)
    _downloaded_gitleaks(tools)
    venv_dir, scratch = tmp_path / "venv", tmp_path / "scratch"
    env = smoke.gate_env(venv_dir, scratch, venv_first=venv_first)
    lead = [str(smoke.bin_dir(venv_dir)), str(tools)] if venv_first else [str(tools)]
    assert env["PATH"].split(os.pathsep)[:len(lead)] == lead
    assert env["HOME"] == env["USERPROFILE"] == str(scratch)


def test_gate_env_refuses_without_any_gitleaks(tmp_path, monkeypatch):
    _no_gitleaks_on_path(monkeypatch, tmp_path)
    with pytest.raises(smoke.SmokeFailed, match="gitleaks is not on PATH"):
        smoke.gate_env(tmp_path / "venv", tmp_path / "scratch")


def _main_flow(monkeypatch, tmp_path, mode: str):
    """main() with every side effect recorded instead of performed: the
    real flow pip-installs semgrep into a fresh venv, which is CI's step."""
    artifact = tmp_path / ("aramid.whl" if mode == "wheel" else "aramid.tar.gz")
    artifact.write_bytes(b"")
    work = tmp_path / "work"
    calls = []

    def mkdtemp(prefix):
        work.mkdir()
        return str(work)

    monkeypatch.setattr(smoke.tempfile, "mkdtemp", mkdtemp)
    monkeypatch.setattr(smoke, "make_venv", lambda where: where)
    monkeypatch.setattr(smoke, "run", lambda argv, **kw: calls.append(
        ("run", [str(a) for a in argv])))
    monkeypatch.setattr(smoke, "probe", lambda venv, python, cwd: calls.append(("probe",)))
    monkeypatch.setattr(smoke, "fixture", lambda where: where)
    monkeypatch.setattr(smoke, "gate_env", lambda venv, home: {})
    monkeypatch.setattr(smoke, "gate", lambda venv, repo, env: calls.append(("gate",)) or {})
    monkeypatch.setattr(smoke, "check_gate", lambda report, venv: calls.append(("check_gate",)))
    return smoke.main([mode, str(artifact)]), calls, artifact


def test_main_installs_the_wheel_with_its_dependencies_then_gates_it(tmp_path, monkeypatch):
    rc, calls, artifact = _main_flow(monkeypatch, tmp_path, "wheel")
    assert rc == 0
    (kind, install), *rest = calls
    assert kind == "run" and install[-1] == str(artifact) and "--no-deps" not in install
    assert rest == [("probe",), ("gate",), ("check_gate",)]


def test_main_installs_the_sdist_without_dependencies_and_only_probes_it(tmp_path, monkeypatch):
    """`--no-deps` is the release job's arm: the only one that reproduces an
    sdist whose runner chain imports a dependency (0.17.10)."""
    rc, calls, artifact = _main_flow(monkeypatch, tmp_path, "sdist")
    assert rc == 0
    (kind, install), *rest = calls
    assert kind == "run" and install[-1] == str(artifact) and "--no-deps" in install
    assert rest == [("probe",)]
