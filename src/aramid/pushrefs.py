"""The git pre-push stdin contract: what a pre-push gate certifies.

git hands every pre-push hook one line per ref on stdin --
`<local ref> <local sha> <remote ref> <remote sha>` -- and, over a native
transport, ships exactly those local shas. Over smart HTTP it does not:
the parent runs the hook first, then `git-remote-http` spawns
`git send-pack --stdin`, which is handed the refspec by NAME and resolves
it itself, at hook EXIT. A commit made on the branch while the hook runs
therefore ships, ungated, while `git push` prints the pre-hook range.
Measured 2026-09-04 (git 2.53.0.windows.1, `file://` control vs a
`git http-backend` shim; interop round 176 saw it first, in production:
an 18-minute gate certified `12a1d68`, GitHub received `673c804`).

So the gate has to (1) know which refs it certified -- the lines above --
and (2) re-resolve them when it is done, and fail if one moved. This
module owns both halves; `commands.check` calls `certify` before the
runners and `pipeline.run_gate` calls `drift` after the last one.

Stdin is read ONLY under `ARAMID_HOOK` (the managed shim exports it).
By hand and in CI the process may have an empty non-tty stdin too, and
reading it there would turn CI's pre-push-tier run into "nothing to push".
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from aramid import gitutil

HOOK_ENV = "ARAMID_HOOK"
_ZERO = "0" * 40
_DELETE = "(delete)"


@dataclass(frozen=True)
class PushRef:
    local_ref: str
    local_sha: str
    remote_ref: str
    remote_sha: str


@dataclass(frozen=True)
class Certification:
    refs: tuple[PushRef, ...]
    head_at_start: str | None
    hook: bool          # True when the refs came from git's stdin under the marker


@dataclass(frozen=True)
class Moved:
    ref: str
    before: str
    after: str | None   # None: the ref no longer resolves -- also not certified


def parse_push_lines(text: str) -> list[PushRef]:
    """One `PushRef` per well-formed stdin line. A malformed line is skipped
    rather than raised on -- this runs inside a gate -- and a deletion
    (`(delete)` / all-zero local sha) is dropped: nothing ships, nothing to
    certify."""
    out: list[PushRef] = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        local_ref, local_sha, remote_ref, remote_sha = parts
        if local_ref == _DELETE or local_sha == _ZERO:
            continue
        out.append(PushRef(local_ref, local_sha, remote_ref, remote_sha))
    return out


def read_hook_stdin() -> str | None:
    """The whole of stdin when the managed shim says git is on the other end
    of it (`ARAMID_HOOK` set) and it is not a terminal; else None. Never
    blocks: git closes the pipe after writing the lines, and a terminal is
    never read."""
    if not os.environ.get(HOOK_ENV):
        return None
    stream = sys.stdin
    if stream is None:
        return None
    try:
        if stream.isatty():
            return None
        return stream.read()
    except (OSError, ValueError, AttributeError):
        return None


def _rev_parse(root: Path, spec: str) -> str | None:
    try:
        cp = gitutil._run(root, "rev-parse", "--verify", "--quiet", spec)
    except Exception:
        return None
    sha = (cp.stdout or "").strip()
    return sha if cp.returncode == 0 and sha else None


def _resolve(root: Path, ref: str) -> str | None:
    """The COMMIT a rev peels to -- right for HEAD, wrong for a pushed ref."""
    return _rev_parse(root, f"{ref}^{{commit}}")


def _resolve_object(root: Path, ref: str) -> str | None:
    """The object a ref names, UNPEELED: for an annotated tag the tag object,
    which is what git's pre-push stdin carries and what send-pack ships at
    exit. Comparing a peeled re-resolution against it read every annotated
    tag push as "moved" (interop round 193)."""
    return _rev_parse(root, ref)


def head(root: Path) -> str | None:
    """HEAD's commit sha now, or None outside a repo / on an unborn branch."""
    return _resolve(Path(root), "HEAD")


def certify(root: Path, refs, hook: bool) -> Certification:
    """Pin what this gate run is certifying: the refs git named (already
    carrying the shas git resolved) and HEAD as of now."""
    return Certification(tuple(refs), _resolve(Path(root), "HEAD"), bool(hook))


def drift(root: Path, cert: Certification) -> list[Moved]:
    """Every certified ref re-resolved, unpeeled, like with like: git handed
    the hook each ref's object id (a tag object for an annotated tag) and
    ships whatever the ref names at exit. A ref whose object differs from the
    one git handed the hook has moved; one that no longer resolves is reported
    moved with `after=None` -- fail closed, it is not what was certified.
    With no refs (by hand, no marker) HEAD at start is compared with HEAD
    now, under the name `HEAD`."""
    root = Path(root)
    moved: list[Moved] = []
    if cert.refs:
        for r in cert.refs:
            now = _resolve_object(root, r.local_ref)
            if now != r.local_sha:
                moved.append(Moved(r.local_ref, r.local_sha, now))
        return moved
    if cert.head_at_start is None:
        return moved
    now = _resolve(root, "HEAD")
    if now != cert.head_at_start:
        moved.append(Moved("HEAD", cert.head_at_start, now))
    return moved


def short_ref(ref: str) -> str:
    for prefix in ("refs/heads/", "refs/tags/"):
        if ref.startswith(prefix):
            return ref[len(prefix):]
    return ref


def render(moved) -> str:
    """One line per moved ref, the shape round 176 asked for."""
    lines = []
    for m in moved:
        after = m.after[:7] if m.after else "(no longer resolves)"
        lines.append(f"{short_ref(m.ref)} moved during the gate: {m.before[:7]} -> {after}; "
                     f"re-run the push")
    return "\n".join(lines)


def payload_refs(cert: Certification) -> list[dict]:
    return [{"local_ref": r.local_ref, "local_sha": r.local_sha,
             "remote_ref": r.remote_ref, "remote_sha": r.remote_sha} for r in cert.refs]


def payload_moved(moved) -> list[dict]:
    return [{"ref": m.ref, "before": m.before, "after": m.after} for m in moved]
