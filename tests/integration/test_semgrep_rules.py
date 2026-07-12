"""integration: the vendored, offline OWASP semgrep ruleset actually loads
and fires. This is the regression test for the bug described in Task 8a:
real semgrep runs used to crash because
`aramid.runners.semgrep.VENDORED_RULES_PATH` (`src/aramid/rules/owasp.yml`)
did not exist on disk.

Semgrep ships as a `semgrep`/`semgrep.exe` console-script entry point that is
not necessarily on PATH -- on this dev machine it installs into the
interpreter's *user-site* Scripts dir (`site-packages/../Scripts`), not
`sys.executable`'s own Scripts dir, and `python -m semgrep` is deprecated as
of 1.38 and exits 2 without running anything. `_find_semgrep()` below
searches `shutil.which`, the dir next to `sys.executable`, and every
`site-packages` sibling on `sys.path` for the real console script -- the
same places `aramid.runners.base.run_subprocess`'s own `shutil.which("semgrep")`
check would find it once that directory is on PATH.

If no working semgrep binary is found, the live-scan tests below skip with a
clear reason (portability for CI environments without semgrep installed).
`test_owasp_yaml_parses` never skips -- it is the brief's documented minimum
bar (valid YAML) and runs regardless of whether semgrep itself is runnable.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from aramid.runners import semgrep as semgrep_runner
from aramid.runners.base import RunContext, ToolState


def _find_semgrep() -> Path | None:
    candidates: list[Path] = []
    which = shutil.which("semgrep")
    if which:
        candidates.append(Path(which))
    exe_dir = Path(sys.executable).parent
    candidates.append(exe_dir / "Scripts" / "semgrep.exe")
    candidates.append(exe_dir / "semgrep")
    for entry in sys.path:
        p = Path(entry)
        if p.name == "site-packages":
            candidates.append(p.parent / "Scripts" / "semgrep.exe")
            candidates.append(p.parent / "bin" / "semgrep")
    for c in candidates:
        if c.exists():
            return c
    return None


_SEMGREP_BIN = _find_semgrep()
_SKIP_REASON = (
    "semgrep console-script not found via shutil.which, next to sys.executable, "
    "or next to any sys.path site-packages dir -- cannot exercise a live scan "
    "in this environment."
)


@pytest.fixture
def semgrep_path_env(monkeypatch):
    """Prepend the discovered semgrep's directory to PATH.

    Needed for two independent reasons: (1) `aramid.runners.base.run_subprocess`
    gates on `shutil.which(argv[0])` before it will even attempt to run
    "semgrep", and (2) the semgrep.exe console script itself shells out to a
    sibling `pysemgrep` process by bare name -- if that directory isn't on
    PATH, semgrep.exe fails with "executing pysemgrep failed" even when
    invoked by its own full path.
    """
    assert _SEMGREP_BIN is not None
    monkeypatch.setenv("PATH", str(_SEMGREP_BIN.parent) + os.pathsep + os.environ.get("PATH", ""))


# --- minimum bar: valid YAML, runs even with no semgrep installed at all ----

def test_owasp_yaml_parses():
    data = yaml.safe_load(semgrep_runner.VENDORED_RULES_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert len(data["rules"]) >= 10


# --- (a): the vendored ruleset loads OFFLINE (no registry fetch), for real --

@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_semgrep_validate_loads_ruleset_offline(semgrep_path_env):
    result = subprocess.run(
        [str(_SEMGREP_BIN), "--validate", "--config", str(semgrep_runner.VENDORED_RULES_PATH),
         "--metrics=off"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "configuration is valid" in result.stderr.lower(), result.stderr


# --- (b)/(c): the real aramid.runners.semgrep.run()/parse() path, live ------

_SQLI_SRC = (
    'def get_user(cursor, user):\n'
    '    return cursor.execute("SELECT * FROM t WHERE x=" + user)\n'
)
_PICKLE_SRC = (
    'import pickle\n\n\n'
    'def load(data):\n'
    '    return pickle.loads(data)\n'
)
_CLEAN_SRC = (
    'import hashlib\n\n\n'
    'def get_user(cursor, user):\n'
    '    return cursor.execute("SELECT * FROM t WHERE x=%s", (user,))\n\n\n'
    'def strong_hash(x):\n'
    '    return hashlib.sha256(x).hexdigest()\n'
)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_reports_sqli_and_pickle_as_error(tmp_path, semgrep_path_env):
    """Drives the exact path aramid.pipeline uses at scan time: run() builds
    the argv and shells out to real semgrep against the vendored ruleset,
    parse() turns the JSON report into RawFindings. Proves the crash
    described in the brief is fixed, not just that some semgrep somewhere
    can read this YAML."""
    (tmp_path / "vuln.py").write_text(_SQLI_SRC + "\n" + _PICKLE_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["vuln.py"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    findings = semgrep_runner.parse(result, ctx)
    sqli = [f for f in findings if "sqli" in f.rule]
    pickled = [f for f in findings if "pickle" in f.rule]

    assert sqli, findings
    assert pickled, findings
    assert all(f.severity_raw == "ERROR" for f in sqli)
    assert all(f.severity_raw == "ERROR" for f in pickled)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_clean_code_yields_zero_findings(tmp_path, semgrep_path_env):
    (tmp_path / "clean.py").write_text(_CLEAN_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["clean.py"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    findings = semgrep_runner.parse(result, ctx)
    assert findings == []
