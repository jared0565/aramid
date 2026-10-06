"""Restart / crash recovery that does not need the operator (0.20.4).

One file per repo, `.aramid/handover.json`, NEVER committed: `aramid init`
gitignores `.aramid/` everywhere. An agent writes it before a restart or a
long pause; a fresh session finds it first in the SessionStart hook and in
`aramid status`, resumes the work without asking anyone, then runs
`aramid handover done`, which ARCHIVES it under `.aramid/handovers/` --
never deleted, so what was handed over stays auditable.

Operator, 2026-10-06: "this must be true to all repo where Aramid is
running" -- per-agent memory exists in one repo for one agent; aramid is
already in every armed repo, so it carries the state.
"""
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PATH = Path(".aramid") / "handover.json"
ARCHIVE = Path(".aramid") / "handovers"
SCHEMA = 1


@dataclass(frozen=True)
class Pending:
    written_at: str
    head: str | None
    author: str | None
    body: str


class EmptyBody(ValueError):
    pass


class AlreadyPending(RuntimeError):
    pass


class Unreadable(RuntimeError):
    def __init__(self, path: Path):
        super().__init__(f"{path} is not a readable handover")
        self.path = path


def _head(root: Path) -> str | None:
    try:
        done = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"],  # noqa: S603,S607
                              cwd=root, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    sha = done.stdout.strip()
    return sha if done.returncode == 0 and sha else None


def read(root: Path) -> Pending | None:
    path = Path(root) / PATH
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        body = data["body"]
        if not isinstance(body, str):
            raise TypeError("body")
        head, author = data.get("head"), data.get("author")
        for name, value in (("head", head), ("author", author)):
            if value is not None and not isinstance(value, str):
                raise TypeError(name)
        return Pending(str(data.get("written_at") or ""), head, author, body)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise Unreadable(path) from exc


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _archive(root: Path) -> Path:
    src = Path(root) / PATH
    try:
        stamp = json.loads(src.read_text(encoding="utf-8")).get("written_at") or "unknown"
    except (OSError, ValueError, AttributeError):
        stamp = "unreadable"
    safe = "".join(c if c.isalnum() or c in "+-" else "-" for c in str(stamp))
    dest_dir = Path(root) / ARCHIVE
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{safe}.json"
    n = 1
    while dest.exists():
        n += 1
        dest = dest_dir / f"{safe}-{n}.json"
    os.replace(src, dest)
    return dest


def write(root: Path, body: str, *, author: str | None = None, replace: bool = False,
          now: datetime | None = None) -> Path:
    if not body.strip():
        raise EmptyBody("a handover needs a body")
    path = Path(root) / PATH
    if path.exists():
        if not replace:
            raise AlreadyPending(str(path))
        _archive(root)
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    _atomic_write(path, {"schema": SCHEMA, "written_at": stamp, "head": _head(Path(root)),
                         "author": author, "body": body})
    return path


def done(root: Path) -> Path | None:
    if not (Path(root) / PATH).exists():
        return None
    return _archive(root)


def age(written_at: str, now: datetime) -> str:
    try:
        then = datetime.fromisoformat(written_at)
    except (TypeError, ValueError):
        return "unknown"
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    secs = (now - then).total_seconds()
    if secs < 0:
        return "unknown"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{int(secs // size)}{unit}"
    return f"{int(secs)}s"
