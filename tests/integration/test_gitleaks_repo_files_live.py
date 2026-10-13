"""FN-40, live: a secret the repo's `.gitleaksignore` or `.gitleaks.toml`
hides from gitleaks is reported as a WARN under the inline label, in each scan
mode it hides it from, and the gate still exits 0 for it. Skips where gitleaks
is absent (local dev); runs in CI, which provisions gitleaks on PATH.

Every arm's own scan is asserted first: the file really does hide the secret
from the tool's own run (or, for `.gitleaksignore` under `--all`, really does
not), so a reported hit is never one the tool found anyway.

The secret-shaped value is built at run time, so this file holds none."""
import json
import os
import secrets
import shutil
import string
import subprocess

import pytest

from aramid import config, pipeline
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.runners import gitleaks, inline
from aramid.runners.base import RunContext

_GITLEAKS = shutil.which("gitleaks")
_SKIP = "gitleaks binary not on PATH (installed in CI, skipped in local dev)"

_ALLOW = "[extend]\nuseDefault = true\n\n[allowlist]\ndescription = \"t\"\npaths = ['''cfg\\.py''']\n"
_REPLACE = "title = \"t\"\n\n[[rules]]\nid = \"nothing\"\nregex = '''q{9}-never'''\n"
_ENTRY = "a `.gitleaksignore` entry"
_CONFIG = "the repo's `.gitleaks.toml`"


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout.strip()


def _token():
    alnum = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alnum) for _ in range(36))


def _repo(tmp_path, channel, mode):
    """The repo file is committed first; the secret is staged, or committed."""
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "readme.txt").write_text("clean\n", encoding="utf-8")
    if channel == "ignore":
        (r / ".gitleaksignore").write_text("cfg.py:github-pat:1\n", encoding="utf-8")
    else:
        (r / ".gitleaks.toml").write_text(_ALLOW if channel == "allow" else _REPLACE,
                                          encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    (r / "cfg.py").write_text(f'TOKEN = "{_token()}"\n', encoding="utf-8")
    _git(r, "add", "cfg.py")
    if mode != "staged":
        _git(r, "commit", "-q", "-m", "leak")
    return r


def _ctx(r, mode):
    if mode == "staged":
        return RunContext(root=r, inline_pass=True)
    if mode == "range":
        return RunContext(root=r, rng="", inline_pass=True)
    files = _git(r, "ls-files").split()
    return RunContext(root=r, files=files, full_tree=True, inline_pass=True)


def _scan(r, mode):
    ctx = _ctx(r, mode)
    found = gitleaks.parse(gitleaks.run(ctx), ctx)
    own = [(f.rule, f.file, f.line) for f in found if f.tool == "gitleaks"]
    hidden = [(f.rule, f.file, f.line, f.message.split(" hides ")[0]) for f in found
              if f.tool == inline.GITLEAKS]
    return own, hidden


@pytest.fixture(autouse=True)
def _no_config_variables(monkeypatch):
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
@pytest.mark.parametrize("mode", ["staged", "range", "all"])
@pytest.mark.parametrize("channel", ["ignore", "allow", "replace"])
def test_a_secret_a_repo_file_hides_is_reported(tmp_path, channel, mode):
    own, hidden = _scan(_repo(tmp_path, channel, mode), mode)
    if channel == "ignore" and mode == "all":
        # The copy `--all` scans puts a temp path in every fingerprint, so no
        # entry matches: the tool's own run blocks, and nothing is hidden.
        assert own == [("github-pat", "cfg.py", 1)] and hidden == []
        return
    assert own == []
    assert hidden == [(inline.RULE, "cfg.py", 1, _ENTRY if channel == "ignore" else _CONFIG)]


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_a_relative_index_file_from_a_hook_still_finds_it(tmp_path, monkeypatch):
    r = _repo(tmp_path, "allow", "staged")
    monkeypatch.setenv("GIT_INDEX_FILE", ".git/index")   # what a pre-commit hook gets
    # The control: run from an empty directory with the value as inherited,
    # gitleaks finds nothing at all, so the runner must not pass it on as is.
    empty, report = tmp_path / "empty", tmp_path / "raw.json"
    empty.mkdir()
    defaults = tmp_path / "defaults.toml"
    defaults.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    cp = subprocess.run([_GITLEAKS, "git", "--staged", "--report-format", "json",
                         "--report-path", str(report), "--config", str(defaults), str(empty)],
                        cwd=empty, capture_output=True, text=True,
                        env={**os.environ, "GIT_DIR": str(r / ".git"), "GIT_WORK_TREE": str(r)})
    assert cp.returncode == 0 and json.loads(report.read_text() or "[]") == []
    assert _scan(r, "staged") == ([], [(inline.RULE, "cfg.py", 1, _CONFIG)])


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_the_push_gate_reports_it_as_a_warning_and_passes(tmp_path, monkeypatch):
    r = _repo(tmp_path, "allow", "range")
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["gitleaks"])
    res = pipeline.run_gate(r, Gate.PRE_PUSH, "range", config.load_config(r),
                            Ledger(tmp_path / "l.db"), run_id="fn40")
    assert res.exit_code == 0
    assert [(f.tool, f.rule, f.file, f.line, str(f.verdict)) for f in res.findings
            if f.tool.startswith("gitleaks")] == [
        (inline.GITLEAKS, inline.RULE, "cfg.py", 1, "warn")]
