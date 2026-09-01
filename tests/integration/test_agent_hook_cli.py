"""integration, subprocess-level: `python -P -m aramid agent-hook ...` --
the `__main__.py` fast path (spec §5/§9, final-review finding I2) that
keeps `cli.py`'s whole command-tree imports off the pre-tool-use hook's
launch path.

LOAD-BEARING AT THE SUBPROCESS LEVEL: `tests/integration/test_agent_hook.py`
calls `agent_hook.cmd_agent_hook(...)` in-process, which exercises the
function's own logic but can never observe whether `python -m aramid
agent-hook ...` actually avoided importing `aramid.cli` -- that decision is
made in `__main__.py`, one frame above anything an in-process capsys test
can see. Only a real child process proves the fast path is wired in.

Every subprocess here is bound to THIS checkout via the suite-wide
`checkout_env` fixture (see tests/conftest.py and
tests/integration/test_cli_dispatch.py's own note on the two-aramid-machine
hazard) -- a bare child would resolve the installed wheel instead.
"""
import json
import subprocess
import sys
from pathlib import Path


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


def _armed_repo(tmp_path) -> Path:
    """Minimal armed repo, built by hand: `_repo_with_aramid` only needs
    `aramid.toml` to exist, and `load_config` merges an aramid.toml with
    nothing but the one key on top of the package defaults -- no `aramid
    init` (and its doctor gate / real runners) required."""
    r = _repo(tmp_path)
    (r / "aramid.toml").write_text("agent_block_armed = true\n", encoding="utf-8")
    return r


def _hook_payload(command: str) -> bytes:
    return json.dumps({"session_id": "t", "cwd": ".", "hook_event_name": "PreToolUse",
                       "tool_name": "Bash", "tool_input": {"command": command}}).encode("utf-8")


def _run(cwd, env, *args, input_bytes: bytes = b""):
    return subprocess.run([sys.executable, "-P", "-m", "aramid", *args],
                          cwd=cwd, env=env, input=input_bytes,
                          capture_output=True)


def test_armed_repo_denies_bypass_full_object(tmp_path, checkout_env):
    r = _armed_repo(tmp_path)
    out = _run(r, checkout_env, "agent-hook", "pre-tool-use",
              input_bytes=_hook_payload("git commit --no-verify -m x"))

    assert out.returncode == 0
    lines = out.stdout.decode("utf-8").splitlines()
    assert len(lines) == 1, out.stdout
    assert json.loads(lines[0]) == {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": (
            "aramid: `git commit` carrying `--no-verify` bypasses the gate "
            "and is REJECTED in this repo (agent surface armed). Re-run "
            "without the bypass; to suppress a specific blocking finding "
            "use `aramid override <id> --reason \"...\"` after `aramid "
            "ledger filter --status open`."),
    }}


def test_non_matching_command_is_silent(tmp_path, checkout_env):
    r = _armed_repo(tmp_path)
    out = _run(r, checkout_env, "agent-hook", "pre-tool-use",
              input_bytes=_hook_payload("pytest -q"))

    assert out.returncode == 0
    assert out.stdout == b""


def test_unknown_event_is_a_silent_noop(tmp_path, checkout_env):
    # No stdin fed at all: an unknown event must return before cmd_agent_hook
    # ever tries to read it.
    r = _repo(tmp_path)
    out = _run(r, checkout_env, "agent-hook", "some-future-event")

    assert out.returncode == 0
    assert out.stdout == b""


def test_no_event_token_is_a_silent_noop(tmp_path, checkout_env):
    r = _repo(tmp_path)
    out = _run(r, checkout_env, "agent-hook")

    assert out.returncode == 0
    assert out.stdout == b""
