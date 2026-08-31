"""uninstall -- reverse exactly what `init` installed: git hook shims,
ARAMID.md, the managed agent blocks (CLAUDE.md/AGENTS.md), and the gitignore
entries it appended. The ledger (`.aramid/`) is KEPT by default (CLI surface
table, design doc section 2) -- security/audit history should survive an
accidental or exploratory uninstall; delete `.aramid/` by hand if that history
is genuinely unwanted.
"""
import sys
from pathlib import Path

from aramid import agent_files, gitutil, hooks
from aramid.commands.init import GITIGNORE_ENTRIES


def _remove_gitignore_entries(root: Path) -> None:
    path = root / ".gitignore"
    if not path.exists():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if line.strip() not in GITIGNORE_ENTRIES]
    if kept == lines:
        return
    text = "\n".join(kept)
    if kept:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def cmd_uninstall(path) -> int:
    target = Path(path).resolve()
    try:
        root = gitutil.repo_root(target)
    except gitutil.NotARepo:
        print(f"aramid: uninstall: {target} is not inside a git repository "
              f"(`git rev-parse --show-toplevel` failed)", file=sys.stderr)
        return 3

    hooks.uninstall(root)

    from aramid import registry
    registry.deregister(root)

    md_path = root / "ARAMID.md"
    if md_path.exists():
        md_path.unlink()

    agent_actions = agent_files.remove_agent_blocks(root)
    for name, action in agent_actions:
        if action == "damaged":
            print(f"aramid: uninstall: {name} has an aramid fence with no"
                  f" closing marker -- left untouched; remove the fence by"
                  f" hand.", file=sys.stderr)
        elif action == "unreadable":
            print(f"aramid: uninstall: {name} could not be read as UTF-8 --"
                  f" left untouched; remove the fence by hand.", file=sys.stderr)

    _remove_gitignore_entries(root)

    print(f"aramid: uninstall: {root} -- hooks removed, ARAMID.md removed, agent "
          f"blocks removed, gitignore entries removed. The ledger (.aramid/) is "
          f"KEPT -- delete it by hand if you also want to discard finding/security "
          f"history.")
    return 0
