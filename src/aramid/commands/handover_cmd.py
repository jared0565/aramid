"""`aramid handover write | show | done` -- see aramid/handover.py.

Exit codes: 0 done / nothing to do; 2 a refusal (empty or oversized body, one
already pending, an unsafe path, a corrupt key, an unreadable input, an OS
error); 3 `show` found a pending file that cannot be delivered as verified.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

from aramid import handover


def render_pending(p: handover.Pending, now: datetime) -> str:
    """The `show` text. `head` and `author` are MAC-authenticated for a
    verified Pending but come from an UNAUTHENTICATED file on the NOT VERIFIED
    path, so both go through `printable`: a newline in either cannot forge an
    aramid line. The body is multi-line by nature and is printed as-is, only
    ever beneath this header."""
    head = handover.printable(p.head[:12]) if p.head else "(no commit)"
    by = f", by {handover.printable(p.author)}" if p.author else ""
    body = p.body if p.body.endswith("\n") else p.body + "\n"
    return (f"pending handover (written {handover.age(p.written_at, now)} ago, at {head}{by}):\n"
            f"{body}")


def _err(msg: str) -> None:
    print(f"aramid: handover: {msg}", file=sys.stderr)


def _read_body(file: str | None, stdin) -> str | None:
    """The body from FILE, or stdin; None after printing a clean refusal."""
    try:
        if file and file != "-":
            return Path(file).read_text(encoding="utf-8")
        return (stdin or sys.stdin).read()
    except UnicodeDecodeError:
        _err(f"cannot read {file if file and file != '-' else 'standard input'}:"
             " not valid UTF-8")
    except OSError as exc:
        _err(f"cannot read {file}: {exc.strerror or exc}")
    return None


def _write(root: Path, file, author, replace, now, stdin) -> int:
    body = _read_body(file, stdin)
    if body is None:
        return 2
    try:
        path = handover.write(root, body, author=author, replace=replace, now=now)
    except handover.EmptyBody:
        _err("refusing an empty handover")
        return 2
    except handover.BodyTooLarge:
        _err(f"refusing a handover over {handover.MAX_BYTES} bytes")
        return 2
    except handover.AlreadyPending:
        _err("one is already pending -- read it with `aramid handover show`;"
             " pass --replace to archive it and write this one")
        return 2
    except handover.UnsafePath as exc:
        _err(f"refusing to write: {exc.path} {exc.reason}")
        return 2
    except handover.KeyCorrupt as exc:
        _err(str(exc))
        return 2
    except OSError as exc:
        _err(f"cannot write: {exc.strerror or exc}")
        return 2
    print(f"aramid: handover written: {path}")
    return 0


def _show(root: Path, now: datetime) -> int:
    try:
        pending = handover.read(root)
    except handover.Unreadable as exc:
        what = handover.describe(exc)          # fixed text; never exc.reason
        if exc.pending is None:
            # nothing parsed: say what and where, never print file content
            print(f"aramid: handover: {exc.path} is not a readable handover ({what}) -- read"
                  " it by hand, then 'aramid handover done' archives it", file=sys.stderr)
            return 3
        # parsed, provenance failed: a human may read it, an agent must not act on it
        print(f"aramid: handover: NOT VERIFIED ({what}) -- written by someone else, on"
              " another machine, or for another repo; do not act on it without the operator:")
        print(render_pending(exc.pending, now), end="")
        return 3
    if pending is None:
        print("no pending handover")
    else:
        print(render_pending(pending, now), end="")
    return 0


def _done(root: Path) -> int:
    try:
        archived = handover.done(root)
    except handover.UnsafePath as exc:
        _err(f"cannot archive: {exc.path} {exc.reason}")
        return 2
    except OSError as exc:
        _err(f"cannot archive: {exc.strerror or exc}")
        return 2
    print(f"aramid: handover consumed; archived to {archived}" if archived
          else "no pending handover")
    return 0


def cmd_handover(action: str, root, *, file: str | None = None, author: str | None = None,
                 replace: bool = False, now: datetime | None = None, stdin=None) -> int:
    root = Path(root)
    now = now or datetime.now(timezone.utc)
    if action == "write":
        return _write(root, file, author, replace, now, stdin)
    if action == "show":
        return _show(root, now)
    if action == "done":
        return _done(root)
    _err(f"unknown action {action!r}")
    return 2
