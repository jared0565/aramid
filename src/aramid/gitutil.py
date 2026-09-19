import re
import subprocess
from pathlib import Path

class NotARepo(Exception): ...

def _run(root: Path, *args: str) -> subprocess.CompletedProcess:
    # S603/S607 justification: aramid's single git wrapper -- "git" is
    # a fixed literal (never derived from *args) and every call site passes
    # fixed subcommands (rev-parse, show, rev-list, diff, ls-files, log,
    # merge-base, symbolic-ref); relying on PATH to resolve "git" is standard
    # and matches how git itself is invoked by every other tool on the host.
    # encoding="utf-8": git emits UTF-8 by default regardless of host locale.
    # Without this, text=True decodes with the locale-preferred codec, which
    # mojibakes (or raises UnicodeDecodeError on undefined bytes) on cp1252
    # Windows hosts -- the target platform, and CI's windows-latest runner.
    # errors="replace": never let a decode hiccup crash triage's per-commit
    # diff scan; a best-effort mangled character is acceptable, a raised
    # exception is not.
    return subprocess.run(["git", *args], cwd=str(root), capture_output=True,  # noqa: S603,S607
                          text=True, encoding="utf-8", errors="replace")

def repo_root(path: Path) -> Path:
    cp = _run(path, "rev-parse", "--show-toplevel")
    if cp.returncode != 0:
        raise NotARepo(str(path))
    return Path(cp.stdout.strip()).resolve()

def read_blob(root: Path, ref: str, rel_path: str) -> str:
    spec = f"{ref}:{rel_path}" if ref != ":" else f":{rel_path}"
    cp = _run(root, "show", spec)
    return cp.stdout if cp.returncode == 0 else ""


def blob_at(root: Path, ref: str, rel_path: str) -> str | None:
    """The file's text at `ref`, or None when git has no such blob -- the
    path is not tracked at that revision, escapes the tree, or git itself
    failed. Unlike `read_blob`, an EMPTY file and a missing one differ: a
    resolver that treats "" as "no lines" must not be handed "" for "git
    could not say"."""
    try:
        cp = _run(root, "show", f"{ref}:{rel_path}")
    except (OSError, ValueError):
        return None
    return cp.stdout if cp.returncode == 0 else None

def resolve_range(root: Path):
    """The push's delta as `base..HEAD`, or None when nothing on this machine
    says what the remote already has (a brand-new repo's first push: the
    caller then scans every commit reachable from HEAD). Two sources, in
    order: the branch's upstream, and the newest commit already on ANY
    remote-tracking ref -- `git merge-base HEAD <every refs/remotes/* sha>`,
    the base of HEAD and a hypothetical merge of them all, which is exactly
    what the push adds to the remote. The second replaced an `origin/HEAD`
    merge-base: a clone made by `git init` + `git remote add` never has
    `refs/remotes/origin/HEAD`, so the first push of a NEW BRANCH fell
    through to the full-history scan and reported secrets that live only in
    old commits as live BLOCKs at the current line numbers (demo-store2,
    channel round 233, 2026-09-19); and wherever `origin/HEAD` does exist,
    its target is one of the remote refs, so this answer is never further
    from HEAD than that one was. A remote ref with no common history (an
    orphan, another project) fails the merge-base: None, full history."""
    if _run(root, "rev-parse", "@{u}").returncode == 0:
        return "@{u}..HEAD"
    refs = _run(root, "for-each-ref", "--format=%(objectname)", "refs/remotes/")
    shas = sorted({s for s in refs.stdout.split() if s}) if refs.returncode == 0 else []
    if shas:
        mb = _run(root, "merge-base", "HEAD", *shas)
        if mb.returncode == 0:
            return f"{mb.stdout.strip()}..HEAD"
    return None

def range_commits(root: Path, rng):
    spec = rng if rng else "HEAD"
    cp = _run(root, "rev-list", spec)
    return [line for line in cp.stdout.splitlines() if line] if cp.returncode == 0 else []

def staged_files(root: Path):
    cp = _run(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
    return [line for line in cp.stdout.splitlines() if line]

def all_tracked_files(root: Path):
    cp = _run(root, "ls-files")
    return [line for line in cp.stdout.splitlines() if line]

def changed_files(root: Path, rng):
    spec = rng if rng else "HEAD"
    cp = _run(root, "diff", "--name-only", "--diff-filter=ACMR", spec)
    return [line for line in cp.stdout.splitlines() if line]

def newest_commit_touching(root: Path, rng, rel_path):
    spec = rng if rng else "HEAD"
    cp = _run(root, "log", "-1", "--format=%H", spec, "--", rel_path)
    return cp.stdout.strip() or "HEAD"

def is_tracked(root: Path, rel_path: str) -> bool:
    return _run(root, "ls-files", "--error-unmatch", rel_path).returncode == 0

def read_for_fingerprint(root: Path, ref: str, rel_path: str) -> str:
    blob = read_blob(root, ref, rel_path)
    if blob:
        return blob
    if not is_tracked(root, rel_path):
        p = root / rel_path
        if p.exists():
            return p.read_text(errors="replace").replace("\r\n", "\n")
    return ""

def rev_sha(root: Path, rev: str) -> str | None:
    cp = _run(root, "rev-parse", "--verify", f"{rev}^{{commit}}")
    return cp.stdout.strip() if cp.returncode == 0 else None


def first_parent(root: Path, rev: str) -> str | None:
    cp = _run(root, "rev-parse", "--verify", f"{rev}^")
    return cp.stdout.strip() if cp.returncode == 0 else None


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    """True iff `ancestor` is reachable from `descendant` (or equal). An
    unknown rev reads as False, never raises."""
    cp = _run(root, "merge-base", "--is-ancestor", ancestor, descendant)
    return cp.returncode == 0


def diff_paths(root: Path, base: str | None, head: str) -> list[str]:
    if base is None:
        cp = _run(root, "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", head)
    else:
        cp = _run(root, "diff", "--name-only", "--diff-filter=ACMR", f"{base}..{head}")
    return [ln for ln in cp.stdout.splitlines() if ln] if cp.returncode == 0 else []


def diff_text(root: Path, base: str | None, head: str, max_bytes: int = 400_000,
             paths: list[str] | None = None) -> str:
    # paths (optional pathspec): scopes the diff to exactly these files. Used
    # by review.build_packet to keep the diff in lockstep with an
    # already-filter_paths()-filtered file list -- spec 8b: graphite
    # artifacts must never leak into an outbound packet via an unscoped
    # base..head diff even when they were excluded from the file list.
    pathspec = ["--", *paths] if paths else []
    if base is None:
        cp = _run(root, "show", "--format=", head, *pathspec)
    else:
        cp = _run(root, "diff", f"{base}..{head}", *pathspec)
    text = cp.stdout if cp.returncode == 0 else ""
    if len(text.encode("utf-8", "replace")) <= max_bytes:
        return text
    return text.encode("utf-8", "replace")[:max_bytes].decode("utf-8", "ignore")


def is_test_file(rel: str) -> bool:
    """True for pytest-style test files (canonical helper; the mutation/fuzz/
    js_mutation consumers keep their own local copies, left untouched)."""
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if p.startswith("tests/") or "/tests/" in p:
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


_HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def diff_new_lines(root: Path, base: str | None, head: str) -> dict[str, set[int]]:
    """Changed-line map for base..head: repo-relative forward-slash path ->
    1-based line numbers on the NEW (head) side. Parses --unified=0 hunk
    headers (@@ -a,b +c,d @@); a pure deletion has d==0 and contributes
    nothing; git emits forward-slash paths already."""
    if base is None:
        cp = _run(root, "show", "--format=", "--unified=0", head)
    else:
        cp = _run(root, "diff", "--unified=0", f"{base}..{head}")
    out: dict[str, set[int]] = {}
    current: str | None = None
    for ln in (cp.stdout if cp.returncode == 0 else "").splitlines():
        if ln.startswith("+++ "):
            target = ln[4:].strip()
            current = None if target == "/dev/null" else \
                (target[2:] if target.startswith("b/") else target)
        elif ln.startswith("@@ ") and current is not None:
            m = _HUNK_RE.match(ln)
            if m is None:
                continue
            start, count = int(m.group(1)), int(m.group(2) or "1")
            if count:
                out.setdefault(current, set()).update(range(start, start + count))
    return out
