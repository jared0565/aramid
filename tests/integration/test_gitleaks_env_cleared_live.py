"""FN-53, live: GITLEAKS_CONFIG or GITLEAKS_CONFIG_TOML naming a config that
replaces every rule hides a secret from a raw gitleaks run -- the control,
which proves the variable takes effect on this gitleaks -- and the runner,
which clears both, still reports it, in each scan mode. Skips where gitleaks
is absent (local dev); runs in CI, which provisions gitleaks on PATH.

The secret-shaped value is built at run time, so this file holds none."""
import json
import os
import secrets
import shutil
import string
import subprocess

import pytest

from aramid.runners import gitleaks
from aramid.runners.base import RunContext

_GITLEAKS = shutil.which("gitleaks")
_SKIP = "gitleaks binary not on PATH (installed in CI, skipped in local dev)"

# One rule of its own and no `[extend] useDefault`, so it replaces every
# default rule; its regex matches nothing in the repos below.
_REPLACING = "title = \"t\"\n\n[[rules]]\nid = \"nothing\"\nregex = '''q{9}-never'''\n"


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _token():
    alnum = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alnum) for _ in range(36))


def _repo(tmp_path, mode):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "readme.txt").write_text("clean\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "clean base")
    (r / "cfg.py").write_text(f'TOKEN = "{_token()}"\n', encoding="utf-8")
    _git(r, "add", "cfg.py")
    if mode != "staged":
        _git(r, "commit", "-q", "-m", "leak")
    return r


def _ctx(r, mode):
    if mode == "staged":
        return RunContext(root=r)
    if mode == "range":
        return RunContext(root=r, rng="")
    return RunContext(root=r, files=["cfg.py", "readme.txt"], full_tree=True)


def _raw_rules(r, mode, report, extra_env):
    """A raw gitleaks run, as the runner would start it, with `extra_env` on
    top of this process' environment. Returns the rule ids it reported."""
    scan = {"staged": ["git", "--staged"], "range": ["git", "--log-opts", ""],
            "all": ["dir", str(r)]}[mode]
    cp = subprocess.run([_GITLEAKS, *scan, "--report-format", "json", "--report-path",
                         str(report)], cwd=r, capture_output=True, text=True,
                        env={**os.environ, **extra_env})
    assert cp.returncode in (0, 1), cp.stderr
    return sorted(item["RuleID"] for item in json.loads(report.read_text() or "[]"))


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
@pytest.mark.parametrize("mode", ["staged", "range", "all"])
@pytest.mark.parametrize("var", ["GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"])
def test_a_config_variable_cannot_hide_a_secret_from_the_runner(tmp_path, monkeypatch, var, mode):
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    r = _repo(tmp_path, mode)
    replacing = tmp_path / "replacing.toml"
    replacing.write_text(_REPLACING, encoding="utf-8")
    value = str(replacing) if var == "GITLEAKS_CONFIG" else _REPLACING

    # The controls: the secret is found with no variable, and the variable
    # really does hide it from a gitleaks that is handed it.
    assert _raw_rules(r, mode, tmp_path / "plain.json", {}) == ["github-pat"]
    assert _raw_rules(r, mode, tmp_path / "hidden.json", {var: value}) == []

    monkeypatch.setenv(var, value)
    ctx = _ctx(r, mode)
    result = gitleaks.run(ctx)
    assert [f.rule for f in gitleaks.parse(result, ctx)] == ["github-pat"], result.stderr
