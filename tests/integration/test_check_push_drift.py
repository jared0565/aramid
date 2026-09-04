"""The pre-push gate certifies the refs git handed it and fails when one
moved while it ran (interop round 176; spec
docs/superpowers/specs/2026-09-04-aramid-push-drift-certification-design.md).

The seam: a fake runner registered in `pipeline.RUNNERS` that COMMITS on
the scratch repo. Runners run between `certify` (before `run_gate`) and
`drift` (after the last runner), which is exactly the window git leaves
open over smart HTTP.
"""
import io
import json
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


def _arm(tmp_path, monkeypatch, *, commit_during_gate: bool):
    """A scratch repo whose only pre-push runner is a fake that (optionally)
    commits mid-gate. Returns (root, sha_at_start, calls)."""
    root = _repo(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    calls = []

    def run(ctx):
        calls.append("ran")
        if commit_during_gate:
            (ctx.root / "b.py").write_text("y = 2\n", encoding="utf-8")
            _git(ctx.root, "add", "b.py")
            _git(ctx.root, "commit", "-q", "-m", "landed while the gate ran")
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


def test_a_commit_during_the_gate_fails_it_and_is_recorded(tmp_path, monkeypatch, capsys):
    root, sha, _ = _arm(tmp_path, monkeypatch, commit_during_gate=True)
    _hook_stdin(monkeypatch, sha)

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    new = _git(root, "rev-parse", "HEAD")
    assert rc == 1
    err = capsys.readouterr().err
    assert f"main moved during the gate: {sha[:7]} -> {new[:7]}; re-run the push" in err, err
    started = _events(root, EventType.RUN_STARTED)[-1].payload
    assert started["refs"] == [{"local_ref": "refs/heads/main", "local_sha": sha,
                               "remote_ref": "refs/heads/main", "remote_sha": ZERO}]
    assert started["head_at_start"] == sha and started["hook"] is True
    finished = _events(root, EventType.RUN_FINISHED)[-1].payload
    assert finished["refs_moved"] == [{"ref": "refs/heads/main", "before": sha, "after": new}]
    assert finished["head_at_exit"] == new


def test_no_movement_keeps_the_verdict_and_records_empty_drift(tmp_path, monkeypatch, capsys):
    root, sha, calls = _arm(tmp_path, monkeypatch, commit_during_gate=False)
    _hook_stdin(monkeypatch, sha)

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 0 and calls == ["ran"]
    assert "moved during the gate" not in capsys.readouterr().err
    finished = _events(root, EventType.RUN_FINISHED)[-1].payload
    assert finished["refs_moved"] == [] and finished["head_at_exit"] == sha


def test_empty_ref_list_under_the_marker_skips_the_gate(tmp_path, monkeypatch, capsys):
    """git's "Everything up-to-date": nothing ships, nothing to certify. No
    run row either -- a row with no tools would read as a skip and start a
    skip streak for a push that shipped nothing (spec 4.4)."""
    root, sha, calls = _arm(tmp_path, monkeypatch, commit_during_gate=False)
    _hook_stdin(monkeypatch, sha, text="")

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 0 and calls == []
    assert "nothing to push" in capsys.readouterr().err
    assert _events(root, EventType.RUN_STARTED) == []


def test_a_push_that_only_deletes_is_nothing_to_certify(tmp_path, monkeypatch, capsys):
    root, sha, calls = _arm(tmp_path, monkeypatch, commit_during_gate=False)
    _hook_stdin(monkeypatch, sha, text=f"(delete) {ZERO} refs/heads/gone {'c' * 40}\n")

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 0 and calls == []


def test_without_the_marker_stdin_is_ignored_and_head_is_still_certified(
        tmp_path, monkeypatch, capsys):
    """By hand: no marker, so the lines on stdin (whatever they are) are not
    read; HEAD at start vs HEAD at exit still catches the moved branch."""
    root, sha, _ = _arm(tmp_path, monkeypatch, commit_during_gate=True)
    monkeypatch.delenv(pushrefs.HOOK_ENV, raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"refs/heads/main {sha} refs/heads/main {ZERO}\n"))

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    new = _git(root, "rev-parse", "HEAD")
    assert rc == 1
    assert f"HEAD moved during the gate: {sha[:7]} -> {new[:7]}" in capsys.readouterr().err
    started = _events(root, EventType.RUN_STARTED)[-1].payload
    assert started["refs"] == [] and started["hook"] is False


def test_the_pre_commit_gate_does_not_certify(tmp_path, monkeypatch):
    root, sha, _ = _arm(tmp_path, monkeypatch, commit_during_gate=False)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])
    monkeypatch.setenv(pushrefs.HOOK_ENV, "pre-commit")
    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    rc = cmd_check(root, Gate.PRE_COMMIT, "staged")

    assert rc == 0
    started = _events(root, EventType.RUN_STARTED)[-1].payload
    assert "refs" not in started and "head_at_start" not in started


def test_json_report_carries_refs_moved(tmp_path, monkeypatch, capsys):
    root, sha, _ = _arm(tmp_path, monkeypatch, commit_during_gate=True)
    _hook_stdin(monkeypatch, sha)

    rc = cmd_check(root, Gate.PRE_PUSH, "range", as_json=True)

    assert rc == 1
    body = json.loads(capsys.readouterr().out)
    assert body["exit_code"] == 1
    assert body["refs_moved"][0]["ref"] == "refs/heads/main"
    assert body["refs_moved"][0]["before"] == sha
