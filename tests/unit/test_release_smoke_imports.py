"""The release workflow's sdist smoke test, at unit scope.

`release.yml` installs the built sdist into a clean venv with `--no-deps`
and imports `aramid.runners.semgrep` from it (the vendored ruleset must
resolve from a SOURCE install). `--no-deps` was chosen because the wheel
smoke had already proven the dependency set -- and it quietly makes a
second guarantee: nothing on the import path from `aramid` down to the
runners needs a third-party module. 0.17.10's first tag run (35416406548,
2026-09-19 02:42Z) failed exactly there: `runners/base.py` had started
importing `aramid.registry` for one constant, and `registry` imports
`tomli_w` at module top, so `from aramid.runners import semgrep` raised
ModuleNotFoundError in the clean venv. Nothing was published, but the tag
had to be undone and cut again.

This pins the guarantee where it can fail BEFORE a tag: a fresh
interpreter on the tree under test imports the runner the smoke test
imports and must not have loaded any of the declared dependencies.
"""
import os
import subprocess
import sys
from pathlib import Path

import aramid

# The module names of `[project] dependencies` in pyproject.toml.
DECLARED = ("tomli_w", "pip_audit", "ruff", "semgrep")


def test_the_runner_import_chain_needs_no_declared_dependency():
    """The environment is inherited (the dependencies ARE installed here,
    as in the wheel smoke); what is asserted is that the runner import
    never reaches for one. In the release's clean venv the same reach is
    a ModuleNotFoundError."""
    tree = Path(aramid.__file__).resolve().parent.parent   # src/ or site-packages/
    code = ("import sys\n"
            "from aramid.runners import semgrep\n"
            f"print(sorted(m for m in {DECLARED!r} if m in sys.modules))\n")
    res = subprocess.run([sys.executable, "-P", "-c", code], capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": str(tree)}, timeout=120)
    assert res.returncode == 0, f"import failed:\n{res.stderr}"
    assert res.stdout.strip() == "[]", (
        f"importing aramid.runners.semgrep loaded a third-party dependency: "
        f"{res.stdout.strip()} -- the release's --no-deps sdist smoke test will fail")
