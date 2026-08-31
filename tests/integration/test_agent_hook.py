"""integration: `aramid agent-hook session-start` -- the SessionStart
context injector. Fail-open is the contract under test as much as the
happy path: non-repo, un-onboarded repo, unknown event, and an internal
error must all exit 0 with NOTHING printed."""
import io
import json
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


def _onboarded(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0
    return r


def _feed_stdin(monkeypatch, payload: dict) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))


def _hook_payload(command: str) -> dict:
    return {"session_id": "t", "cwd": ".", "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": command}}


def _arm_agent(r: Path) -> None:
    # NOT a raw append: init's stub already holds `agent_block_armed =
    # false`, and a duplicate key makes the TOML unparseable -- the hook
    # would then fail open and the armed tests would red for the wrong
    # reason. The real arm machinery rewrites the key in place.
    from aramid.commands.arm import cmd_arm
    assert cmd_arm(r, agent=True) == 0


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


def test_cli_agent_hook_tolerates_future_flags(tmp_path, monkeypatch, capsys):
    # A future template may append flags to the hook command line; an
    # OLDER deployed aramid must no-op cleanly rather than die in argparse.
    from aramid import cli
    monkeypatch.chdir(tmp_path)
    assert cli.main(["agent-hook", "session-start", "--future-flag", "x"]) == 0
    assert capsys.readouterr().out == ""


def test_pre_tool_use_non_matching_command_is_silent(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload("pytest -q tests/unit"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    assert capsys.readouterr().out == ""


def test_pre_tool_use_baking_advisory_full_object(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload("git commit --no-verify -m x"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    out = capsys.readouterr().out
    assert json.loads(out) == {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "additionalContext": (
            "aramid: `git commit` carrying `--no-verify` bypasses this "
            "repo's gate. The bypass is ledger-visible, and the armed "
            "version of this hook rejects the call outright -- re-run "
            "without it; suppress a specific finding with `aramid override "
            "<id> --reason \"...\"` instead."),
    }}


def test_pre_tool_use_armed_denies_full_object(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    _arm_agent(r)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload("git push --no-verify"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    out = capsys.readouterr().out
    assert json.loads(out) == {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": (
            "aramid: `git push` carrying `--no-verify` bypasses the gate "
            "and is REJECTED in this repo (agent surface armed). Re-run "
            "without the bypass; to suppress a specific blocking finding "
            "use `aramid override <id> --reason \"...\"` after `aramid "
            "ledger filter --status open`."),
    }}


def test_pre_tool_use_armed_denies_hookspath_wrapper(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    _arm_agent(r)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload("git -c core.hooksPath=/tmp/x commit -m y"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert parsed["hookSpecificOutput"]["permissionDecisionReason"] == (
        "aramid: `git commit` under `-c core.hooksPath=/tmp/x` bypasses "
        "the gate and is REJECTED in this repo (agent surface armed). "
        "Re-run without the bypass; to suppress a specific blocking "
        "finding use `aramid override <id> --reason \"...\"` after "
        "`aramid ledger filter --status open`.")


def test_pre_tool_use_dry_run_push_allowed_even_armed(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    _arm_agent(r)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload("git push -n origin main"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    assert capsys.readouterr().out == ""


def test_pre_tool_use_message_containing_flag_allowed(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    capsys.readouterr()
    _feed_stdin(monkeypatch, _hook_payload('git commit -m "docs: explain --no-verify"'))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    assert capsys.readouterr().out == ""


def test_pre_tool_use_unparseable_stdin_fails_open(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    capsys.readouterr()
    monkeypatch.setattr("sys.stdin", io.StringIO("not json {"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", r) == 0
    assert capsys.readouterr().out == ""


def test_pre_tool_use_outside_onboarded_repo_fails_open(tmp_path, monkeypatch, capsys):
    # A plain directory: no git repo, no aramid.toml -- even a matching
    # command allows silently.
    _feed_stdin(monkeypatch, _hook_payload("git commit --no-verify"))
    assert agent_hook.cmd_agent_hook("pre-tool-use", tmp_path) == 0
    assert capsys.readouterr().out == ""
