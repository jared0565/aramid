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
import tempfile
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
    def __init__(self, path: Path, reason: str = "it is not valid handover JSON"):
        super().__init__(f"{path} is not a readable handover: {reason}")
        self.path = path
        self.reason = reason


class UnsafePath(RuntimeError):
    """A symlinked or escaping location: refused, never followed."""

    def __init__(self, path: Path, reason: str):
        super().__init__(f"refusing to use {path}: {reason}")
        self.path = path
        self.reason = reason


def _head(root: Path) -> str | None:
    try:
        run = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"],  # noqa: S603,S607
                             cwd=root, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    sha = run.stdout.strip()
    return sha if run.returncode == 0 and sha else None


def _tracked(root: Path) -> bool:
    """True only when git positively says the handover file is tracked. Any
    git failure (missing, not a repo, timeout) is NOT tracked."""
    try:
        run = subprocess.run(  # noqa: S603,S607
            ["git", "ls-files", "--error-unmatch", "--", PATH.as_posix()],
            cwd=root, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return run.returncode == 0


def _check_dirs(root: Path, *, archive: bool = False) -> None:
    """Refuse a symlinked `.aramid` (or `.aramid/handovers`), and any whose
    resolved location is outside the repo root."""
    real_root = Path(root).resolve()
    dirs = [Path(root) / PATH.parent]
    if archive:
        dirs.append(Path(root) / ARCHIVE)
    for d in dirs:
        if d.is_symlink():
            raise UnsafePath(d, "it is a symlink")
        if os.path.lexists(d):
            try:
                inside = d.resolve().is_relative_to(real_root)
            except (OSError, RuntimeError):
                inside = False
            if not inside:
                raise UnsafePath(d, "it resolves outside the repository")


def read(root: Path) -> Pending | None:
    path = Path(root) / PATH
    if not os.path.lexists(path) and not path.parent.is_symlink():
        return None
    try:
        _check_dirs(root)
    except UnsafePath as exc:
        raise Unreadable(path, f"{exc.path.name} is a symlink or escapes the "
                               "repository") from exc
    if not os.path.lexists(path):
        return None
    if path.is_symlink():
        raise Unreadable(path, "it is a symlink")
    if not path.is_file():
        raise Unreadable(path, "it is not a regular file")
    if _tracked(Path(root)):
        raise Unreadable(path, "it is tracked by git: a handover is machine-local, "
                               "a tracked one came from someone else")
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
    """Random exclusive temp name (never a fixed one a repo could pre-plant a
    symlink at), fsynced, then os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="handover.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(data, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _archive(root: Path) -> Path:
    src = Path(root) / PATH
    _check_dirs(root, archive=True)
    if src.is_symlink():
        raise UnsafePath(src, "it is a symlink")
    try:
        stamp = json.loads(src.read_text(encoding="utf-8")).get("written_at") or "unknown"
    except (OSError, ValueError, AttributeError):
        stamp = "unreadable"
    safe = "".join(c if c.isalnum() or c in "+-" else "-" for c in str(stamp))[:40]
    dest_dir = Path(root) / ARCHIVE
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{safe}.json"
    n = 1
    while os.path.lexists(dest):
        n += 1
        dest = dest_dir / f"{safe}-{n}.json"
    os.replace(src, dest)
    return dest


def write(root: Path, body: str, *, author: str | None = None, replace: bool = False,
          now: datetime | None = None) -> Path:
    if not body.strip():
        raise EmptyBody("a handover needs a body")
    path = Path(root) / PATH
    _check_dirs(root)
    if path.is_symlink():
        raise UnsafePath(path, "it is a symlink")
    if os.path.lexists(path):
        if not replace:
            raise AlreadyPending(str(path))
        _archive(root)
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    _atomic_write(path, {"schema": SCHEMA, "written_at": stamp, "head": _head(Path(root)),
                         "author": author, "body": body})
    return path


def done(root: Path) -> Path | None:
    if not os.path.lexists(Path(root) / PATH):
        return None
    return _archive(root)


def age(written_at: str, now: datetime) -> str:
    try:
        then = datetime.fromisoformat(written_at)
    except (TypeError, ValueError):
        return "unknown"
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    secs = (now - then).total_seconds()
    if secs < 0:
        return "unknown"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{int(secs // size)}{unit}"
    return f"{int(secs)}s"
