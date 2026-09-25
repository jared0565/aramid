"""registry -- the ONE piece of central state (spec section 4):
~/.aramid/repos.toml, the list of onboarded repos the drain iterates.
Everything else stays in per-repo ledgers."""
import os
import shutil
import sys
import tomllib
from pathlib import Path

import tomli_w

from aramid import leftovers
from aramid.fingerprint import normalize_path
from aramid.runners.base import CONSUMER_WORKTREE_ENV  # noqa: F401  (re-exported; set by every consumer subprocess)


def registry_path() -> Path:
    """Seam for tests -- monkeypatch this, never touch the real file."""
    return Path.home() / ".aramid" / "repos.toml"


def load_registry() -> list[dict]:
    p = registry_path()
    if not p.exists():
        return []
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        print(f"aramid: registry unreadable ({exc}); treating as empty", file=sys.stderr)
        return []
    return [e for e in data.get("repos", []) if isinstance(e, dict) and e.get("path")]


def _write(entries: list[dict]) -> None:
    p = registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tomli_w.dumps({"repos": entries}), encoding="utf-8")


def consumer_worktree(path: Path) -> str | None:
    """Why `path` is a consumer's checkout rather than a fleet member, or
    None. A consumer (mutation, fuzz, js-mutation, red-proof) runs the
    consumed repo's own commands in a throwaway checkout, and on 2026-09-18
    one of those commands ran `aramid init` on the checkout: two
    `aramid-fuzz-*/wt` paths landed here, the drain read `no rows: wt, wt`,
    and readiness could never start a streak. Two independent tells, either
    enough: the marker every consumer subprocess carries, and the location
    (`leftovers.shell_of`) -- the second holds even for a process launched
    with a scrubbed environment."""
    if os.environ.get(CONSUMER_WORKTREE_ENV):
        return f"{CONSUMER_WORKTREE_ENV} is set (a consumer subprocess)"
    shell = leftovers.shell_of(path)
    if shell is not None:
        return f"inside a consumer worktree ({shell.name})"
    return None


def register(path: Path, at: str) -> str | None:
    """Add `path` unless it is already there. Returns why it was refused
    (`consumer_worktree`), or None once the entry is present."""
    refused = consumer_worktree(path)
    if refused:
        return refused
    resolved = normalize_path(str(Path(path).resolve()))
    entries = load_registry()
    if any(normalize_path(e["path"]) == resolved for e in entries):
        return None
    entries.append({"path": str(Path(path).resolve()), "registered_at": at})
    _write(entries)
    return None


def deregister(path: Path) -> None:
    resolved = normalize_path(str(Path(path).resolve()))
    entries = [e for e in load_registry() if normalize_path(e["path"]) != resolved]
    _write(entries)


def remove(stored_path: str) -> int:
    """Remove every entry whose STORED path normalizes to `stored_path`, and
    return how many went. Deliberately not resolved: a repo that has left
    the disk, or a junction that now points elsewhere, must still match the
    string the file holds -- `deregister` resolves, so it cannot promise
    that (`aramid fleet deregister`, 1.0 blocker FN-1)."""
    target = normalize_path(stored_path)
    entries = load_registry()
    kept = [e for e in entries if normalize_path(e["path"]) != target]
    if len(kept) != len(entries):
        _write(kept)
    return len(entries) - len(kept)


def backup(tag: str) -> Path | None:
    """Copy the registry aside as `repos.toml.bak-<tag>` before a removal and
    return the copy, or None when there is no file to keep. Every hand-run
    cleanup of this file kept one (`repos.toml.bak-*-wt-cleanup`); the
    command keeps the habit rather than trusting itself."""
    p = registry_path()
    if not p.exists():
        return None
    dest = p.with_name(f"{p.name}.bak-{tag}")
    shutil.copy2(p, dest)
    return dest
