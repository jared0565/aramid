"""Unit-scope twins of the pre-push hook-stdin contract in `cmd_check`
(tests/integration/test_check_push_drift.py has the full drift story).

They exist because the drain's mutation consumer confirms against
`pytest -q tests/unit` (this repo's `[mutation].test_command`), and the
18:00Z drain of 2026-09-04 reported three survivors on this code that the
integration suite kills and the unit suite did not:

- `return 3` -> `return 4` on the engine-error exit before the gate;
- `hook_text or ""` -> `hook_text and ""`, which turns every real push
  into "nothing to push" and skips the gate;
- `return 0` -> `return 1` on the empty-ref-list exit.

Same harness as the integration file: a scratch repo whose only pre-push
runner is a fake, so the whole pipeline runs in about a second.
"""
import io
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import config as config_mod
from aramid import pipeline, pushrefs
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import EventType, Gate
from aramid.runners.base import RunnerResult, ToolState

ZERO = "0" * 40


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout.strip()


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    (r / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "initial")
    return r


def _arm(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    calls = []

    def run(ctx):
        calls.append("ran")
        return RunnerResult(tool="fake", state=ToolState.OK, returncode=0)

    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                        SimpleNamespace(run=run, parse=lambda result, ctx: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["fake"])
    return root, _git(root, "rev-parse", "HEAD"), calls


def _hook_stdin(monkeypatch, sha, text=None):
    monkeypatch.setenv(pushrefs.HOOK_ENV, "pre-push")
    line = f"refs/heads/main {sha} refs/heads/main {ZERO}\n" if text is None else text
    monkeypatch.setattr("sys.stdin", io.StringIO(line))


def _events(root, kind):
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        return [e for e in led.events() if e.type is kind]
    finally:
        led.close()


def test_an_engine_error_before_the_gate_exits_three(tmp_path, monkeypatch, capsys):
    # A config that will not parse dies before any tool runs: exit 3, never
    # a silent 0 and never the strict-remapped 1 -- 3 is what the shim's
    # exit-code table and `drain --help` name as "engine error".
    root = _repo(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    (root / "aramid.toml").write_text("schema_version = [\n", encoding="utf-8")

    rc = cmd_check(root, Gate.PRE_COMMIT, "staged")

    assert rc == 3
    assert "engine error" in capsys.readouterr().err


def test_an_empty_ref_list_under_the_marker_exits_zero_and_runs_nothing(
        tmp_path, monkeypatch, capsys):
    root, sha, calls = _arm(tmp_path, monkeypatch)
    _hook_stdin(monkeypatch, sha, text="")

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 0
    assert calls == []
    assert "nothing to push" in capsys.readouterr().err
    assert _events(root, EventType.RUN_STARTED) == []


def test_refs_under_the_marker_reach_the_gate(tmp_path, monkeypatch):
    # The lines git hands the hook are the refs the gate certifies. A push
    # that ships something must RUN the gate; a bookkeeping slip that reads
    # those lines as empty would wave every real push through as "nothing
    # to push".
    root, sha, calls = _arm(tmp_path, monkeypatch)
    _hook_stdin(monkeypatch, sha)

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 0
    assert calls == ["ran"]
    started = _events(root, EventType.RUN_STARTED)[-1].payload
    assert started["hook"] is True
    assert started["refs"] and started["refs"][0]["local_sha"] == sha
