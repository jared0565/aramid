"""integration: `aramid agent-hook session-start` -- the SessionStart
context injector. Fail-open is the contract under test as much as the
happy path: non-repo, un-onboarded repo, unknown event, and an internal
error must all exit 0 with NOTHING printed."""
import subprocess
import sys
from pathlib import Path

from aramid.commands import agent_hook, doctor, init
from aramid.commands import status as status_mod


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _repo(tmp_path, name="repo") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "app.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    _git(r, "add", "app.py")
    _git(r, "commit", "-q", "-m", "seed")
    return r


def _fake_present(root):
    return {
        "gitleaks": doctor.ToolStatus("gitleaks", True, "8.21.2"),
        "semgrep": doctor.ToolStatus("semgrep", True, "1.100.0"),
        "ruff": doctor.ToolStatus("ruff", True, "0.6.0"),
        "pip-audit": doctor.ToolStatus("pip-audit", True, "2.7.0"),
        "interpreter": doctor.ToolStatus("interpreter", True, sys.executable),
    }


def test_session_start_prints_posture_in_onboarded_repo(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0
    capsys.readouterr()

    rc = agent_hook.cmd_agent_hook("session-start", root=r)

    out = capsys.readouterr().out
    assert rc == 0
    lines = out.splitlines()
    assert lines[0] == ("aramid: this repo is GATED (pre-commit + pre-push"
                        " hooks). Read ARAMID.md; NEVER pass --no-verify.")
    assert lines[1].startswith("aramid: open findings:")
    assert lines[-1] == ('aramid: commands: aramid check --staged | aramid'
                         ' ledger filter --status open | aramid override'
                         ' <id> --reason "..."')


def test_session_start_is_silent_outside_a_repo(tmp_path, capsys):
    assert agent_hook.cmd_agent_hook("session-start", root=tmp_path) == 0
    assert capsys.readouterr().out == ""


def test_session_start_is_silent_in_un_onboarded_repo(tmp_path, capsys):
    r = _repo(tmp_path)
    assert agent_hook.cmd_agent_hook("session-start", root=r) == 0
    assert capsys.readouterr().out == ""


def test_unknown_event_is_a_silent_noop(tmp_path, capsys):
    # Forward compatibility: a harness sending an event this aramid version
    # does not know must get a clean no-op, never an argparse error.
    assert agent_hook.cmd_agent_hook("post-tool-use", root=tmp_path) == 0
    assert capsys.readouterr().out == ""


def test_internal_error_fails_open_with_no_partial_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0
    capsys.readouterr()

    def boom(state):
        raise RuntimeError("injected")
    monkeypatch.setattr(status_mod, "_open_counts_line", boom)

    assert agent_hook.cmd_agent_hook("session-start", root=r) == 0
    # single-print design: an exception mid-build must emit NOTHING,
    # not a half-rendered context block.
    assert capsys.readouterr().out == ""


def test_cli_wires_agent_hook(tmp_path, monkeypatch, capsys):
    from aramid import cli
    monkeypatch.chdir(tmp_path)
    assert cli.main(["agent-hook", "session-start"]) == 0
    assert capsys.readouterr().out == ""
