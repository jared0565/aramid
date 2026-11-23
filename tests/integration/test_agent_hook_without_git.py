"""integration, subprocess-level: the agent hooks in a repo where git cannot
be started (interop round 341).

`gitutil.armed_root` found the repo with `git rev-parse`, and read a git it
could not start as "not an aramid repo". So with no git on the hook's PATH,
`agent-hook session-start` and `pre-tool-use` exited 0 with nothing on stdout:
no GATED banner, no handover notice, no --no-verify warning -- the same empty
output a clean allow gives. With the agent surface armed, a `git commit
--no-verify` invoked by absolute path was ALLOWED. Measured on 0.20.19,
2026-11-22, in a scratch repo; operator decision the same day: find the repo
without git.

The child's PATH is an EMPTY directory, not PATH minus its git entries: on
Linux and macOS git sits in /usr/bin beside everything else, so filtering
entries by name would leave it reachable and these tests would pass without
testing anything. `_without_git` checks that before any test relies on it.
Each child is bound to this checkout by `checkout_env` (tests/conftest.py).
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

GATED = ("aramid: this repo is GATED (pre-commit + pre-push hooks). Read ARAMID.md;"
         " NEVER pass --no-verify.")
NO_GIT = ("aramid: git was not found on PATH, so this hook found this repo from its"
          " .git and aramid.toml instead.")


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _repo(tmp_path, *, armed: bool) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "app.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    _git(r, "add", "app.py")
    _git(r, "commit", "-q", "-m", "seed")
    (r / "aramid.toml").write_text(f"agent_block_armed = {'true' if armed else 'false'}\n",
                                   encoding="utf-8")
    return r


def _without_git(checkout_env, tmp_path) -> dict[str, str]:
    empty = tmp_path / "empty-path"
    empty.mkdir()
    env = dict(checkout_env, PATH=str(empty))
    assert shutil.which("git", path=env["PATH"]) is None, "git is still on the child's PATH"
    if os.name == "nt":
        system32 = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32")
        assert not (system32 / "git.exe").exists(), "a git.exe in System32 is found without PATH"
    return env


def _payload(command: str, tool: str = "Bash") -> bytes:
    return json.dumps({"session_id": "t", "cwd": ".", "hook_event_name": "PreToolUse",
                       "tool_name": tool, "tool_input": {"command": command}}).encode("utf-8")


def _hook(cwd, env, event, input_bytes: bytes = b"{}"):
    return subprocess.run([sys.executable, "-P", "-m", "aramid", "agent-hook", event],
                          cwd=cwd, env=env, input=input_bytes, capture_output=True,
                          timeout=120)


def _git_by_absolute_path() -> str:
    found = shutil.which("git")
    assert found, "this test needs a git to name; the suite already does"
    return Path(found).resolve().as_posix()


def test_session_start_without_git_still_prints_the_banner(tmp_path, checkout_env):
    r = _repo(tmp_path, armed=False)

    out = _hook(r, _without_git(checkout_env, tmp_path), "session-start")

    assert out.returncode == 0, out.stderr
    lines = out.stdout.decode("utf-8").splitlines()
    assert lines[:2] == [NO_GIT, GATED], out.stdout
    assert lines[-1].startswith("aramid: commands: aramid check --staged"), out.stdout


def test_session_start_without_git_still_delivers_a_pending_handover(tmp_path, checkout_env):
    """The line saying how the repo was found leads, ahead of the gate banner
    it qualifies, and the handover follows the banner, as it does with git
    (round 342: the fixed lines lead; 0.20.4 had the handover first)."""
    from aramid import handover
    r = _repo(tmp_path, armed=False)
    handover.write(r, "resume at step 3\n")

    out = _hook(r, _without_git(checkout_env, tmp_path), "session-start")

    assert out.returncode == 0, out.stderr
    lines = out.stdout.decode("utf-8").splitlines()
    assert lines[:2] == [NO_GIT, GATED], out.stdout
    assert lines[3].startswith("aramid: PENDING HANDOVER written "), out.stdout
    assert lines[4] == "aramid: | resume at step 3", out.stdout


def test_armed_pre_tool_use_without_git_denies_a_bypass_by_absolute_path(tmp_path, checkout_env):
    """The case round 341 left unmeasured: armed, and the hook's PATH has no
    git while the command names one by its full path."""
    r = _repo(tmp_path, armed=True)
    command = f'"{_git_by_absolute_path()}" commit --no-verify -m x'

    out = _hook(r, _without_git(checkout_env, tmp_path), "pre-tool-use", _payload(command))

    assert out.returncode == 0, out.stderr
    decision = json.loads(out.stdout)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny", out.stdout
    assert "REJECTED in this repo (agent surface armed)" in decision["permissionDecisionReason"]


def test_baking_pre_tool_use_without_git_still_advises(tmp_path, checkout_env):
    r = _repo(tmp_path, armed=False)

    out = _hook(r, _without_git(checkout_env, tmp_path), "pre-tool-use",
                _payload("git commit --no-verify -m x"))

    assert out.returncode == 0, out.stderr
    body = json.loads(out.stdout)["hookSpecificOutput"]
    assert "permissionDecision" not in body, out.stdout
    assert body["additionalContext"].startswith(
        "aramid: `git commit` carrying `--no-verify` bypasses this repo's gate."), out.stdout


def test_session_start_without_git_is_still_silent_outside_a_repo(tmp_path, checkout_env):
    """Control: finding the repo without git must not find one that is not there."""
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    assert not any((d / ".git").exists() for d in (outside, *outside.parents)), (
        "the temp directory sits inside a git checkout; this control cannot run here")

    out = _hook(outside, _without_git(checkout_env, tmp_path), "session-start")

    assert out.returncode == 0, out.stderr
    assert out.stdout == b""
