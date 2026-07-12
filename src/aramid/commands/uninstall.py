"""uninstall -- reverse exactly what `init` installed: git hook shims,
ARAMID.md, and the gitignore entries it appended. The ledger (`.aramid/`)
is KEPT by default (CLI surface table, design doc section 2) -- security/
audit history should survive an accidental or exploratory uninstall;
delete `.aramid/` by hand if that history is genuinely unwanted.
"""
import sys
from pathlib import Path

from aramid import gitutil, hooks
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

    md_path = root / "ARAMID.md"
    if md_path.exists():
        md_path.unlink()

    _remove_gitignore_entries(root)

    print(f"aramid: uninstall: {root} -- hooks removed, ARAMID.md removed, gitignore "
          f"entries removed. The ledger (.aramid/) is KEPT -- delete it by hand if you "
          f"also want to discard finding/security history.")
    return 0
