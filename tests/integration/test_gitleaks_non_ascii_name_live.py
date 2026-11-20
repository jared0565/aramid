"""Live: a secret in a tracked file whose NAME is not ASCII is found by every
scan mode. Skips where gitleaks is absent (local dev); runs in CI, which
provisions gitleaks on PATH.

`--all` scans a copy of the files git lists. git escapes a name with a byte
above 0x7F in a listing that is not `-z` ("pronounced-a\\313\\220ramid.py",
quotes included), so before the fix the copy held no such file: measured on
the published 0.20.14, `check --all` and init's baseline missed the secret
and reported nothing about it. The commit and push scans read git
themselves and found it, so they are the controls here, and so is a second
secret in an ASCII-named file of the same repo.

The secret-shaped values are built at run time, so this file holds none."""
import secrets
import shutil
import string
import subprocess

import pytest

from aramid import config, pipeline
from aramid.ledger import Ledger
from aramid.models import Gate

_GITLEAKS = shutil.which("gitleaks")
_SKIP = "gitleaks binary not on PATH (installed in CI, skipped in local dev)"
_ODD = "pronounced-a" + chr(0x2D0) + "ramid.py"


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout.strip()


def _token():
    alnum = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alnum) for _ in range(36))


def _repo(tmp_path, commit: bool):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    _git(r, "config", "core.quotePath", "true")   # git's default, whatever the machine says
    (r / "readme.txt").write_text("clean\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    for name in ("plain.py", _ODD):
        (r / name).write_text(f'TOKEN = "{_token()}"\n', encoding="utf-8")
        _git(r, "add", "--", name)
    if commit:
        _git(r, "commit", "-q", "-m", "leak")
    return r


@pytest.fixture(autouse=True)
def _no_config_variables(monkeypatch):
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
@pytest.mark.parametrize("mode", ["all", "staged", "range"])
def test_a_secret_in_a_non_ascii_named_file_blocks_in_every_scan_mode(tmp_path, monkeypatch, mode):
    r = _repo(tmp_path, commit=(mode != "staged"))
    gate = Gate.PRE_PUSH if mode == "range" else Gate.PRE_COMMIT
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, gate, ["gitleaks"])
    res = pipeline.run_gate(r, gate, mode, config.load_config(r),
                            Ledger(tmp_path / "l.db"), run_id=f"odd-{mode}")
    found = sorted((f.rule, f.file, f.line, str(f.verdict)) for f in res.findings
                   if f.tool == "gitleaks")
    assert found == sorted([("github-pat", "plain.py", 1, "block"),
                            ("github-pat", _ODD, 1, "block")])
    assert res.exit_code != 0
