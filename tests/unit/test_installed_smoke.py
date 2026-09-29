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
import subprocess
import sys
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
