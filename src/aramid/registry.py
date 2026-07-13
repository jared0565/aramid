"""registry -- the ONE piece of central state (spec section 4):
~/.aramid/repos.toml, the list of onboarded repos the drain iterates.
Everything else stays in per-repo ledgers."""
import sys
import tomllib
from pathlib import Path

import tomli_w

from aramid.fingerprint import normalize_path


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


def register(path: Path, at: str) -> None:
    resolved = normalize_path(str(Path(path).resolve()))
    entries = load_registry()
    if any(normalize_path(e["path"]) == resolved for e in entries):
        return
    entries.append({"path": str(Path(path).resolve()), "registered_at": at})
    _write(entries)


def deregister(path: Path) -> None:
    resolved = normalize_path(str(Path(path).resolve()))
    entries = [e for e in load_registry() if normalize_path(e["path"]) != resolved]
    _write(entries)
