"""Live, skip-if-absent coverage for the gitleaks BLOCK-tier secrets gate.
Every other gitleaks test is fixture/monkeypatch-only; this one drives the
REAL binary end-to-end so argv/exit-contract drift (e.g. the deprecated
`protect` subcommand) is actually caught. Skips cleanly where gitleaks is
absent (local dev); runs in CI, which provisions gitleaks on PATH."""
import shutil
import subprocess

import pytest

from aramid.runners import gitleaks
from aramid.runners.base import RunContext, ToolState

_GITLEAKS = shutil.which("gitleaks")
_SKIP = "gitleaks binary not on PATH (installed in CI, skipped in local dev)"

# A syntactically valid AWS access-key id (AKIA + 16 upper-alnum) that is NOT
# the canonical ...EXAMPLE key, to dodge any example-key allowlisting.
_SECRET = "AKIAZ7PB4XQK9WORNC2D"


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "readme.txt").write_text("clean\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "clean base")
    return r


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_live_staged_secret_is_found(tmp_path):
    r = _repo(tmp_path)
    (r / "config.py").write_text(f'AWS_KEY = "{_SECRET}"\n', encoding="utf-8")
    _git(r, "add", "config.py")               # staged, not committed
    ctx = RunContext(root=r)                    # rng is None -> staged mode
    result = gitleaks.run(ctx)
    assert result.state is ToolState.OK, result.stderr
    findings = gitleaks.parse(result, ctx)
    assert any(_SECRET in (f.secret or "") for f in findings), \
        "real gitleaks git --staged must flag the staged AWS key"


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_live_history_secret_is_found(tmp_path):
    r = _repo(tmp_path)
    (r / "config.py").write_text(f'AWS_KEY = "{_SECRET}"\n', encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "leak")
    ctx = RunContext(root=r, rng="")            # "" -> full-history scan
    result = gitleaks.run(ctx)
    assert result.state is ToolState.OK, result.stderr
    findings = gitleaks.parse(result, ctx)
    assert any(_SECRET in (f.secret or "") for f in findings)


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_live_clean_tree_no_findings_and_exit_ok(tmp_path):
    r = _repo(tmp_path)
    (r / "notes.txt").write_text("nothing secret here\n", encoding="utf-8")
    _git(r, "add", "notes.txt")
    ctx = RunContext(root=r)
    result = gitleaks.run(ctx)
    # exit 0 (clean) stays OK; the {0,1} contract is honored by the real binary
    assert result.state is ToolState.OK, result.stderr
    assert gitleaks.parse(result, ctx) == []
