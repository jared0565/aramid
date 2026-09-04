"""Leftovers: what a killed consumer or a Windows file lock left in the
temp dir, and the worktree registrations that still point at them.

Every worktree consumer (mutation, js_mutation, fuzz) and the red-proof
gate step creates ``<tempdir>/aramid-<kind>-<random>/wt`` with ``git
worktree add`` and removes it in a ``finally``. That ``finally`` never runs
when the process is killed (a gate or drain budget, the scheduler, Ctrl-C),
and on Windows ``shutil.rmtree`` leaves a shell behind when a grandchild of
the run still holds a file open. Both leave a few KB of skeleton per run
and, when the kill came first, a stale registration in ``.git/worktrees``
that ``git worktree prune`` will not touch while the directory exists.
Measured on the machine that found it: 34 shells over six weeks, one or two
per scheduled drain.

The drain calls :func:`sweep` for every repo it probes. The rule is age
plus git's own lock flag, nothing cleverer: a shell older than
:data:`MIN_AGE_S` (hours beyond any consumer, gate or drain budget) is
dead; a registration git reports as locked is live whatever its age;
anything not under one of :data:`PREFIXES` is not ours and is never
touched. A dir that will not go is reported in ``failed``, never raised:
the sweep is hygiene and must not fail a drain.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from aramid import gitutil

PREFIXES = ("aramid-mut-", "aramid-red-", "aramid-fuzz-", "aramid-jsmut-")
MIN_AGE_S = 6 * 3600.0


@dataclass
class Sweep:
    """Shell dirs by verdict. Paths are the ``aramid-<kind>-<random>``
    dir, never the ``wt`` inside it."""
    removed: list[str] = field(default_factory=list)
    kept_young: list[str] = field(default_factory=list)
    kept_live: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


def temp_root() -> Path:
    """Where the consumers' ``mkdtemp`` puts them; one seam for tests."""
    return Path(tempfile.gettempdir())


def _key(p) -> str:
    return os.path.normcase(os.path.normpath(str(p)))


def _is_ours(shell: Path) -> bool:
    return shell.name.startswith(PREFIXES)


def _registrations(root: Path) -> list[tuple[Path, bool]]:
    """``(shell dir, locked)`` for every registered worktree of ``root``
    that lives in one of our shells; the main worktree is never one."""
    try:
        cp = gitutil._run(root, "worktree", "list", "--porcelain")
    except Exception:
        return []
    if cp.returncode != 0:
        return []
    out: list[tuple[Path, bool]] = []
    path: Path | None = None
    locked = False

    def flush() -> None:
        nonlocal path, locked
        if (path is not None and path.name == "wt" and _is_ours(path.parent)
                and _key(path) != _key(root)):
            out.append((path.parent, locked))
        path, locked = None, False

    for line in cp.stdout.splitlines():
        if line.startswith("worktree "):
            flush()
            path = Path(line[len("worktree "):])
        elif line == "locked" or line.startswith("locked "):
            locked = True
        elif not line.strip():
            flush()
    flush()
    return out


def _age_s(shell: Path, now: float) -> float:
    try:
        return now - shell.stat().st_mtime
    except OSError:
        return float("inf")      # already gone: as old as it gets


def _rm(shell: Path, report: Sweep) -> None:
    shutil.rmtree(shell, ignore_errors=True)
    (report.failed if shell.exists() else report.removed).append(str(shell))


def sweep(root: Path, *, temp: Path | None = None, now: float | None = None,
          min_age_s: float = MIN_AGE_S, dry_run: bool = False) -> Sweep:
    """Remove the dead leftovers of ``root``'s consumers and every dead
    shell under ``temp``; with ``dry_run`` only say what would go."""
    temp = temp_root() if temp is None else temp
    now = time.time() if now is None else now
    report = Sweep()
    seen: set[str] = set()

    def verdict(shell: Path, locked: bool) -> str:
        if locked:
            return "kept_live"
        if _age_s(shell, now) < min_age_s:
            return "kept_young"
        return "removed"

    # Registrations first: `worktree remove` wants the dir present, and an
    # rmtree of a registered dir would leave the registration dangling until
    # the prune below -- one order, no second pass.
    for shell, locked in _registrations(root):
        seen.add(_key(shell))
        v = verdict(shell, locked)
        if v != "removed":
            getattr(report, v).append(str(shell))
            continue
        if dry_run:
            report.removed.append(str(shell))
            continue
        gitutil._run(root, "worktree", "remove", "--force", str(shell / "wt"))
        _rm(shell, report)
    if not dry_run:
        gitutil._run(root, "worktree", "prune")

    try:
        entries = sorted(temp.iterdir())
    except OSError:
        entries = []
    for shell in entries:
        if _key(shell) in seen or not _is_ours(shell):
            continue
        if shell.is_symlink() or not shell.is_dir():
            continue
        v = verdict(shell, locked=False)
        if v != "removed":
            getattr(report, v).append(str(shell))
            continue
        if dry_run:
            report.removed.append(str(shell))
            continue
        _rm(shell, report)
    return report
