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

Budget: < 2 s. Reads only the local ledger and config -- no scans, no
network, no subprocesses beyond a single `git rev-parse` for repo
detection. Heavy imports stay inside functions so the non-matching paths
stay cheap.
"""
from pathlib import Path


def cmd_agent_hook(event: str, root: Path | None = None) -> int:
    try:
        if event != "session-start":
            return 0
        base = Path(root) if root is not None else Path.cwd()
        from aramid import gitutil
        try:
            repo = gitutil.repo_root(base)
        except Exception:
            return 0
        if not (repo / "aramid.toml").is_file():
            return 0
        print(_session_context(repo), end="")
        return 0
    except Exception:
        return 0


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
        lines.append(
            'aramid: commands: aramid check --staged | aramid ledger filter'
            ' --status open | aramid override <id> --reason "..."')
        return "\n".join(lines) + "\n"
    finally:
        ledger.close()
