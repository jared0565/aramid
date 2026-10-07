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
import errno
import hashlib
import hmac
import json
import os
import secrets
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PATH = Path(".aramid") / "handover.json"
ARCHIVE = Path(".aramid") / "handovers"
SCHEMA = 1
MAC_VERSION = 1
KEY_ENV = "ARAMID_HANDOVER_KEY_FILE"
KEY_BYTES = 32
MAX_BYTES = 1_048_576

# `Unreadable.kind`: why a file at the handover path was not delivered. A
# consumer (hook, status, show) prints FIXED text chosen by kind, never the
# free-form `reason`; the only variable it may print is `stored_root`, and only
# for OTHER_REPO (where the MAC has verified it), and only THROUGH `printable()`
# (`Unreadable.display_root`): a signed POSIX path can contain a newline.
CORRUPT = "corrupt"          # not JSON, deeply nested, or a wrong shape / field type
TOO_LARGE = "too_large"      # over MAX_BYTES (checked on the stat and after the read)
SYMLINK = "symlink"          # the file, `.aramid`, or the archive dir is a symlink / escapes the repo
NOT_REGULAR = "not_regular"  # a directory, FIFO, device ...
UNSIGNED = "unsigned"        # no usable `v` / `mac`: not written by aramid (a non-str root is `corrupt`)
NO_KEY = "no_key"            # no handover key on this machine, so nothing can verify
KEY_CORRUPT = "key_corrupt"  # the key file is not exactly KEY_BYTES
KEY_UNREADABLE = "key_unreadable"  # an OSError reading the key
MISMATCH = "mismatch"        # the MAC does not verify (edited, forged, other machine/key)
OTHER_REPO = "other_repo"    # a genuine handover (MAC verified) written for another repo
IO_ERROR = "io_error"        # an OSError stat/open/fstat/read: a sharing violation is not corruption
KINDS = (CORRUPT, TOO_LARGE, SYMLINK, NOT_REGULAR, UNSIGNED, NO_KEY, KEY_CORRUPT,
         KEY_UNREADABLE, MISMATCH, OTHER_REPO, IO_ERROR)

_lstat = os.lstat
_fstat = os.fstat


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


class BodyTooLarge(ValueError):
    """The serialized handover would exceed MAX_BYTES, which `read()` refuses:
    it would be written and then never delivered."""


class InvalidText(ValueError):
    """The body or author holds a lone surrogate (U+D800-U+DFFF), which is not
    valid Unicode text. The CLI cannot produce one (stdin and `--file` are
    decoded as strict UTF-8); MCP and a direct call can. Refused, so what is
    signed is always text every UTF-8 consumer can print."""


class Unreadable(RuntimeError):
    """The file at `path` is not delivered. `kind` is one of KINDS. `reason`
    is a human string built ONLY from fixed text, except the escaped root for
    OTHER_REPO. `pending` is set when the file parsed into a well-formed
    Pending and only provenance failed, so `show` can print the body for a
    human under a NOT VERIFIED header; it is None for a corrupt, oversized or
    non-regular file. `stored_root` is set ONLY for OTHER_REPO, after the MAC
    verified it."""

    def __init__(self, path: Path, reason: str, pending: "Pending | None" = None,
                 *, kind: str, stored_root: str | None = None):
        super().__init__(f"{path} is not a readable handover: {reason}")
        self.path = path
        self.reason = reason
        self.pending = pending
        self.kind = kind
        self.stored_root = stored_root

    @property
    def display_root(self) -> str | None:
        """`stored_root` escaped for printing (control characters and
        backslashes); the only form a consumer may echo."""
        return None if self.stored_root is None else printable(self.stored_root)


_DESCRIBE = {
    CORRUPT: "the file is not valid handover JSON",
    TOO_LARGE: "the file is too large",
    SYMLINK: "the file or its directory is a symlink or escapes the repository",
    NOT_REGULAR: "the file is not a regular file",
    UNSIGNED: "the file was not written by aramid on this machine (unsigned)",
    NO_KEY: "there is no handover key on this machine, so it cannot be verified",
    KEY_CORRUPT: "the handover key is corrupt, so it cannot be verified",
    KEY_UNREADABLE: "the handover key could not be read, so it cannot be verified",
    MISMATCH: "the signature does not match",
    IO_ERROR: "the file could not be read (I/O error)",
}


def describe(exc: Unreadable) -> str:
    """One line of FIXED text for an Unreadable, chosen by `kind`. The only
    variable is the escaped stored root of OTHER_REPO (MAC-verified). Every
    consumer (show, the SessionStart hook, status) prints this and never
    `exc.reason` or anything else from the file."""
    if exc.kind == OTHER_REPO:
        return f"written for another repo: {exc.display_root}"
    return _DESCRIBE.get(exc.kind, "the file could not be delivered")


def remedy(kind: str) -> str:
    """What clears a file that was not delivered, by kind: the ONE source of
    that text for the hook, status, show and MCP. `done` refuses to archive
    through a symlink, so for SYMLINK the remedy is by hand."""
    if kind == SYMLINK:
        return "remove the link by hand"
    return "'aramid handover done' archives it"


class KeyCorrupt(RuntimeError):
    def __init__(self, path: Path):
        super().__init__(
            f"the handover key {path} is not {KEY_BYTES} bytes; it is never "
            "regenerated silently. Removing it makes every pending handover "
            "signed under it unverified, and the next write starts a new key.")
        self.path = path


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
    # the same answer as `sha if rc == 0 and sha else None` for every input,
    # written so no mutant of it is equivalent (git prints nothing to stdout
    # when this fails, which made the old `and` -> `or` unkillable)
    return (run.stdout.strip() or None) if run.returncode == 0 else None


def key_path() -> Path:
    env = os.environ.get(KEY_ENV)
    if env:
        return Path(env)
    return Path.home() / ".aramid" / "handover.key"


def _create_key(path: Path) -> bytes:
    """Publish a complete 32-byte key without ever exposing a short one: write
    it to a temp file in the key dir, fsync, then `os.link` it into place
    (no-replace: FileExistsError means another writer won, so read the
    winner). Where hard links are unavailable, fall back to O_EXCL creation."""
    key = secrets.token_bytes(KEY_BYTES)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="handover.key.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, path)
            return key
        except FileExistsError:
            return path.read_bytes()  # another writer won the race
        except OSError:
            pass
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return path.read_bytes()
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
        fh.flush()
        os.fsync(fh.fileno())
    return key


def _load_key(*, create: bool) -> bytes | None:
    """The machine key, or None when absent and not creating. A key that is not
    exactly KEY_BYTES is corrupt: KeyCorrupt, never regenerated."""
    path = key_path()
    try:
        key = path.read_bytes()
    except FileNotFoundError:
        key = None
    if key is None:
        if not create:
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        key = _create_key(path)
    if len(key) != KEY_BYTES:
        raise KeyCorrupt(path)
    return key


def _bound_root(root: Path) -> str:
    return os.path.normcase(os.path.realpath(root))


def _mac(key: bytes, fields: dict) -> str:
    canon = json.dumps(
        {"v": MAC_VERSION, "root": fields["root"], "written_at": fields["written_at"],
         "head": fields["head"], "author": fields["author"], "body": fields["body"]},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hmac.new(key, canon, hashlib.sha256).hexdigest()


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
            if not d.is_dir():
                raise UnsafePath(d, "it is not a directory")
            try:
                inside = d.resolve().is_relative_to(real_root)
            except (OSError, RuntimeError):
                inside = False
            if not inside:
                raise UnsafePath(d, "it resolves outside the repository")


def printable(text: str) -> str:
    """Escape every control or line-breaking character (LF, CR, NEL, U+2028/9,
    ESC ...), every other non-printable one (a lone surrogate comes out as a
    backslash-u sequence, so no UTF-8 stream can fail on it) AND backslashes,
    so a literal backslash-n in a path cannot look like an escaped newline."""
    out = []
    for c in text:
        if c == chr(92):
            out.append(chr(92) * 2)
        elif c.isprintable():
            out.append(c)
        else:
            out.append(c.encode("unicode_escape").decode("ascii"))
    return "".join(out)


def printable_body(text: str) -> str:
    """The body made safe to print to a terminal, line by line: C0 controls
    except TAB (ESC, a lone CR, ...), DEL, C1 controls (NEL ...), U+2028 /
    U+2029 and lone surrogates (U+D800-U+DFFF, which no UTF-8 stream can
    encode) are escaped as a backslash-x or backslash-u sequence, so a
    planted body cannot move the cursor, erase or overwrite a line, break a
    line it should not, or make the print itself raise. Unlike `printable`
    it KEEPS backslashes (Windows paths in a body are normal; the line
    prefix, not the escape, carries the structure) and newlines. The
    SessionStart hook uses it for its `aramid: | <line>` output."""
    bs = chr(92)
    out = []
    for line in text.split(chr(10)):
        buf = []
        for c in line:
            o = ord(c)
            if c != chr(9) and (o < 0x20 or 0x7F <= o <= 0x9F or 0xD800 <= o <= 0xDFFF
                                or o in (0x2028, 0x2029)):
                # one rule derived from the value: two hex digits when the code
                # point fits in two, the four-digit u form when it does not
                digits = f"{o:02x}"
                buf.append(f"{bs}x{digits}" if len(digits) == 2 else f"{bs}u{o:04x}")
            else:
                buf.append(c)
        out.append("".join(buf))
    return chr(10).join(out)


def _verify(path: Path, root: Path, data: dict, pending: Pending) -> None:
    """Raise Unreadable unless aramid on this machine signed `data`. The MAC is
    checked over the STORED fields (stored root included) FIRST; only then is
    the stored root compared with this repo's, so nothing from the file is
    echoed before it is authenticated. No git, no network."""
    stored_root, mac = data.get("root"), data.get("mac")
    v = data.get("v")
    if type(v) is not int or v != MAC_VERSION or not isinstance(mac, str):
        raise Unreadable(path, "not written by aramid on this machine (unsigned)",
                         pending, kind=UNSIGNED)
    # every field the MAC covers must be the right type BEFORE it is hashed:
    # nothing nested can reach json.dumps (no RecursionError out of read())
    if (not isinstance(stored_root, str) or not isinstance(data.get("written_at"), str)
            or not isinstance(data.get("body"), str)
            or not all(x is None or isinstance(x, str)
                       for x in (data.get("head"), data.get("author")))):
        raise Unreadable(path, "it is not valid handover JSON (a field has the wrong type)",
                         kind=CORRUPT)
    try:
        key = _load_key(create=False)
    except KeyCorrupt as exc:
        raise Unreadable(path, "cannot verify: handover key corrupt", pending,
                         kind=KEY_CORRUPT) from exc
    except OSError as exc:
        raise Unreadable(path, "cannot verify: handover key unreadable", pending,
                         kind=KEY_UNREADABLE) from exc
    if key is None:
        raise Unreadable(path, "cannot verify: no handover key on this machine", pending,
                         kind=NO_KEY)
    fields = {"root": stored_root, "written_at": data.get("written_at"),
              "head": data.get("head"), "author": data.get("author"),
              "body": data.get("body")}
    try:
        expected = _mac(key, fields)
    except RecursionError as exc:
        raise Unreadable(path, "it is not valid handover JSON (too deeply nested)",
                         kind=CORRUPT) from exc
    if not hmac.compare_digest(mac.encode("ascii", "replace"), expected.encode("ascii")):
        raise Unreadable(path, "not written by aramid on this machine "
                               "(signature does not match)", pending, kind=MISMATCH)
    if stored_root != _bound_root(root):
        raise Unreadable(path, f"written for another repo: {printable(stored_root)}",
                         pending, kind=OTHER_REPO, stored_root=stored_root)


def _read_capped(path: Path) -> bytes:
    """At most MAX_BYTES of a regular file, or Unreadable. Where O_NOFOLLOW /
    O_NONBLOCK exist the open is hardened and the type and size are checked on
    the fd (closing the lstat -> open window); the lstat checks always run."""
    try:
        st = _lstat(path)
    except OSError as exc:
        raise Unreadable(path, "it could not be read (I/O error)", kind=IO_ERROR) from exc
    if not stat.S_ISREG(st.st_mode):
        raise Unreadable(path, "it is not a regular file", kind=NOT_REGULAR)
    if st.st_size > MAX_BYTES:
        raise Unreadable(path, f"it is too large (over {MAX_BYTES} bytes)", kind=TOO_LARGE)
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Unreadable(path, "it is a symlink", kind=SYMLINK) from exc
        raise Unreadable(path, "it could not be read (I/O error)", kind=IO_ERROR) from exc
    try:
        fst = _fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise Unreadable(path, "it is not a regular file", kind=NOT_REGULAR)
        if fst.st_size > MAX_BYTES:
            raise Unreadable(path, f"it is too large (over {MAX_BYTES} bytes)",
                             kind=TOO_LARGE)
        with os.fdopen(fd, "rb", closefd=False) as fh:
            raw = fh.read(MAX_BYTES + 1)
    except OSError as exc:
        raise Unreadable(path, "it could not be read (I/O error)", kind=IO_ERROR) from exc
    finally:
        os.close(fd)
    if len(raw) > MAX_BYTES:
        raise Unreadable(path, f"it is too large (over {MAX_BYTES} bytes)", kind=TOO_LARGE)
    return raw


def read(root: Path) -> Pending | None:
    path = Path(root) / PATH
    # Nothing at the handover path is nothing pending, a symlinked `.aramid`
    # included: such a directory matters only when a handover would be read
    # or written THROUGH it, and write and done refuse there. (Reporting it
    # as unreadable was a nag no command could clear.)
    if not os.path.lexists(path):
        return None
    try:
        _check_dirs(root)
    except UnsafePath as exc:
        raise Unreadable(path, "a symlinked or escaping handover directory",
                         kind=SYMLINK) from exc
    if path.is_symlink():
        raise Unreadable(path, "it is a symlink", kind=SYMLINK)
    raw = _read_capped(path)
    try:
        data = json.loads(raw.decode("utf-8"))
        body = data["body"]
        if not isinstance(body, str):
            raise TypeError("body")
        head, author = data.get("head"), data.get("author")
        for name, value in (("head", head), ("author", author)):
            if value is not None and not isinstance(value, str):
                raise TypeError(name)
        pending = Pending(str(data.get("written_at") or ""), head, author, body)
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise Unreadable(path, "it is not valid handover JSON", kind=CORRUPT) from exc
    _verify(path, Path(root), data, pending)
    return pending


def _serialize(data: dict) -> str:
    return json.dumps(data, indent=2) + "\n"


def _atomic_write(path: Path, data: dict) -> None:
    """Random exclusive temp name (never a fixed one a repo could pre-plant a
    symlink at), fsynced, then os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="handover.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_serialize(data))
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
    # `written_at` names the archive only once the MAC verified it; anything
    # else gets a fixed stamp, so no unverified field names a file
    try:
        verified = read(root)
    except Unreadable:
        verified = None
    stamp = verified.written_at if verified is not None else "unverified"
    safe = "".join(c if c.isalnum() or c in "+-" else "-" for c in stamp)[:40]
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
    for text in (body, author or ""):
        try:
            text.encode("utf-8")              # strict: fails exactly on a lone surrogate
        except UnicodeEncodeError:
            raise InvalidText("a handover body or author must be valid Unicode text") from None
    path = Path(root) / PATH
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    fields = {"root": _bound_root(Path(root)), "written_at": stamp,
              "head": _head(Path(root)), "author": author, "body": body}
    # the MAC is always 64 hex chars, so a placeholder sizes the file exactly;
    # refuse BEFORE the key, the archive or any write
    shape = {"schema": SCHEMA, "v": MAC_VERSION, **fields, "mac": "0" * 64}
    if len(_serialize(shape).encode("utf-8")) > MAX_BYTES:
        raise BodyTooLarge(f"a handover file over {MAX_BYTES} bytes would never be delivered")
    key = _load_key(create=True)
    _check_dirs(root)
    if path.is_symlink():
        raise UnsafePath(path, "it is a symlink")
    if os.path.lexists(path):
        if not replace:
            raise AlreadyPending(str(path))
        _archive(root)
    _atomic_write(path, {"schema": SCHEMA, "v": MAC_VERSION, **fields,
                         "mac": _mac(key, fields)})
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
