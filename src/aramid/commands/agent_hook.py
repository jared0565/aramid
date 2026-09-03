"""agent_hook -- aramid's endpoint for agent-harness hooks (Claude Code).

Spec: docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md §5.

`session-start` prints a compact live-posture block to stdout; Claude Code
adds a SessionStart hook's stdout to the session's context, so an agent
opens every session in an onboarded repo already knowing the gate exists,
what is open, and which commands to use. The stdin JSON the harness sends
is deliberately ignored -- everything needed is derived from the repo at
cwd, which is where the harness runs the hook.

FAIL-OPEN IS THE WHOLE CONTRACT (spec §5/§9, stated as policy): outside a
git repo, in a repo without aramid.toml, for an event name this version
does not know (forward compatibility with newer harness configs), and on
ANY internal error, exit 0 with no output. The block is built fully before
a single print so a mid-build exception can never emit a half-rendered
context. The git-hook gate beneath still enforces; this layer only informs.

pre-tool-use screens each Bash/PowerShell tool call's command string for
git hook-bypass invocations (aramid.agent_bypass, token-level). While
baking it allows and surfaces an advisory through
hookSpecificOutput.additionalContext; armed (agent_block_armed = true) it
denies via permissionDecision: "deny". Contract pinned against Claude Code
2.1.252; both shapes ride stdout with exit 0, and a harness that ignores
the JSON fails open. `aramid.__main__` keeps cli.py's whole command-tree
imports off this hook's launch path with a fast path ahead of `import
aramid.cli` -- that is what makes every Bash/PowerShell tool call cheap,
not anything in this module. Within this module itself, heavy imports
(json, sys, aramid.agent_bypass, aramid.config, aramid.gitutil) stay
inside the matched branches, so the ones cmd_agent_hook doesn't take are
still free.

Two known residuals, both accepted (spec §6/§9): the armed screen is
SESSION-scoped, not target-repo-scoped -- `git -C /other/repo commit -n`
run from an armed session is denied even if `/other/repo` itself is not
onboarded or not armed, because the decision reads the SESSION's own cwd
repo, never the `-C`/`-c core.hooksPath` target; and unquoted flag text
sitting in another command's arguments can match (`echo git commit
--no-verify` tokenizes as a real `git` invocation) while the same text
quoted never does (`echo "git commit --no-verify"` is one token, not a
`git` invocation at all).

Budget: < 2 s. Reads only the local ledger and config -- no scans, no
network, no subprocesses beyond a single `git rev-parse` for repo
detection. Heavy imports stay inside functions so the non-matching paths
stay cheap.
"""
from pathlib import Path


def cmd_agent_hook(event: str, root: Path | None = None) -> int:
    try:
        if event == "session-start":
            return _session_start(root)
        if event == "pre-tool-use":
            return _pre_tool_use(root)
        return 0
    except Exception:
        return 0


def _repo_with_aramid(root: Path | None) -> Path | None:
    base = Path(root) if root is not None else Path.cwd()
    from aramid import gitutil
    try:
        repo = gitutil.repo_root(base)
    except Exception:
        return None
    if not (repo / "aramid.toml").is_file():
        return None
    return repo


def _session_start(root: Path | None) -> int:
    repo = _repo_with_aramid(root)
    if repo is None:
        return 0
    print(_session_context(repo), end="")
    return 0


def _pre_tool_use(root: Path | None) -> int:
    import json
    import sys
    try:
        payload = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return 0
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return 0
    from aramid.agent_bypass import find_bypass
    bypass = find_bypass(command)
    if bypass is None:
        return 0
    repo = _repo_with_aramid(root)
    if repo is None:
        return 0
    from aramid import config as config_mod
    cfg = config_mod.load_config(repo)
    print(_decision_json(bypass, armed=cfg.agent_block_armed))
    return 0


def _describe(bypass) -> str:
    if bypass.kind == "hooks-path":
        return f"`git {bypass.subcommand}` under `-c {bypass.token}`"
    return f"`git {bypass.subcommand}` carrying `{bypass.token}`"


def _decision_json(bypass, *, armed: bool) -> str:
    import json
    what = _describe(bypass)
    if armed:
        body = {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"aramid: {what} bypasses the gate and is REJECTED in this"
                f" repo (agent surface armed). Re-run without the bypass;"
                f" to suppress a specific blocking finding use `aramid"
                f" override <id> --reason \"...\"` after `aramid ledger"
                f" filter --status open`."),
        }
    else:
        body = {
            "hookEventName": "PreToolUse",
            "additionalContext": (
                f"aramid: {what} bypasses this repo's gate. The bypass is"
                f" ledger-visible, and the armed version of this hook"
                f" rejects the call outright -- re-run without it; suppress"
                f" a specific finding with `aramid override <id> --reason"
                f" \"...\"` instead."),
        }
    return json.dumps({"hookSpecificOutput": body})


def _session_context(repo: Path) -> str:
    from aramid import config as config_mod
    from aramid.commands import status as status_mod
    from aramid.ledger import Ledger

    cfg = config_mod.load_config(repo)
    ledger = Ledger(repo / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        lines = [
            "aramid: this repo is GATED (pre-commit + pre-push hooks)."
            " Read ARAMID.md; NEVER pass --no-verify.",
            "aramid: " + status_mod._open_counts_line(state),
            "aramid: " + status_mod._new_since_baseline_line(ledger, state),
        ]
        streaks = status_mod._skip_streak_lines(ledger)
        if streaks:
            lines.append("aramid: per-tool skip streaks:")
            lines.extend("aramid:   " + s.strip() for s in streaks)
        lines.extend("aramid: " + b.strip()
                     for b in status_mod._bake_lines(cfg, state))

        from datetime import datetime, timezone

        from aramid import fleet
        lines.extend("aramid: " + line for line in fleet.delivery_lines(
            repo, surface="session-start", now=datetime.now(timezone.utc).isoformat()))

        lines.append(
            'aramid: commands: aramid check --staged | aramid ledger filter'
            ' --status open | aramid override <id> --reason "..."')
        return "\n".join(lines) + "\n"
    finally:
        ledger.close()
