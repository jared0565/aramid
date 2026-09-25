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


# The shape version of repos.toml (1.0 blocker API-4). A file with no
# version key was written before 0.19.0 -- the same shape, read as is. One
# stamped higher, or with a version that is not an integer, came from an
# aramid newer than this one: it reads as empty (the unreadable-registry
# path, where the drain stops before judging anything) and it is never
# rewritten -- every aramid on the machine shares this one file.
REGISTRY_SCHEMA_VERSION = 1


class RegistryUnusable(RuntimeError):
    """repos.toml exists and cannot be read as a registry."""


class RegistryTooNew(RegistryUnusable):
    """repos.toml was written by an aramid newer than this one."""


def _too_new(p: Path, data: dict) -> RegistryTooNew | None:
    version = data.get("schema_version")
    if version is None:  # written before 0.19.0: the same shape, unversioned
        return None
    if (isinstance(version, int) and not isinstance(version, bool)
            and version <= REGISTRY_SCHEMA_VERSION):
        return None
    return RegistryTooNew(
        f"{p} was written by a newer aramid (registry schema {version!r}; this one "
        f"reads up to {REGISTRY_SCHEMA_VERSION}) -- upgrade aramid to use it")


def registry_path() -> Path:
    """Seam for tests -- monkeypatch this, never touch the real file."""
    return Path.home() / ".aramid" / "repos.toml"


def load_registry(*, strict: bool = False) -> list[dict]:
    """The registered entries. A file that exists but cannot be read -- or
    that a newer aramid wrote -- reads as empty with one stderr line, or,
    with `strict`, raises RegistryUnusable: the drain's choice, since a
    drain that took it for an empty fleet would exit 0 on every scheduled
    run and never drain again."""
    p = registry_path()
    if not p.exists():
        return []
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        if strict:
            raise RegistryUnusable(f"{p} is unreadable ({exc})") from exc
        print(f"aramid: registry unreadable ({exc}); treating as empty", file=sys.stderr)
        return []
    newer = _too_new(p, data)
    if newer is not None:
        if strict:
            raise newer
        print(f"aramid: registry: {newer}; treating as empty", file=sys.stderr)
        return []
    return [e for e in data.get("repos", []) if isinstance(e, dict) and e.get("path")]


def _write(entries: list[dict]) -> None:
    p = registry_path()
    if p.exists():
        try:
            newer = _too_new(p, tomllib.loads(p.read_text(encoding="utf-8")))
        except (tomllib.TOMLDecodeError, OSError):
            # Unreadable: overwritten, as it always was. Only a file that
            # READS as a newer aramid's is protected -- there is nothing in a
            # corrupt one to lose that `load_registry` could have seen.
            newer = None
        if newer is not None:
            raise newer
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tomli_w.dumps({"schema_version": REGISTRY_SCHEMA_VERSION,
                                "repos": entries}), encoding="utf-8")


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
    (`consumer_worktree`, or a registry a newer aramid wrote), or None once
    the entry is present."""
    refused = consumer_worktree(path)
    if refused:
        return refused
    resolved = normalize_path(str(Path(path).resolve()))
    entries = load_registry()
    if any(normalize_path(e["path"]) == resolved for e in entries):
        return None
    entries.append({"path": str(Path(path).resolve()), "registered_at": at})
    try:
        _write(entries)
    except RegistryTooNew as exc:
        return str(exc)
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
