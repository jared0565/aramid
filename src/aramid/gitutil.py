import subprocess
from pathlib import Path

class NotARepo(Exception): ...

def _run(root: Path, *args: str) -> subprocess.CompletedProcess:
    # noqa justification (S603/S607): aramid's single git wrapper -- "git" is
    # a fixed literal (never derived from *args) and every call site passes
    # fixed subcommands (rev-parse, show, rev-list, diff, ls-files, log,
    # merge-base, symbolic-ref); relying on PATH to resolve "git" is standard
    # and matches how git itself is invoked by every other tool on the host.
    return subprocess.run(["git", *args], cwd=str(root), capture_output=True, text=True)  # noqa: S603,S607

def repo_root(path: Path) -> Path:
    cp = _run(path, "rev-parse", "--show-toplevel")
    if cp.returncode != 0:
        raise NotARepo(str(path))
    return Path(cp.stdout.strip()).resolve()

def read_blob(root: Path, ref: str, rel_path: str) -> str:
    spec = f"{ref}:{rel_path}" if ref != ":" else f":{rel_path}"
    cp = _run(root, "show", spec)
    return cp.stdout if cp.returncode == 0 else ""

def resolve_range(root: Path):
    if _run(root, "rev-parse", "@{u}").returncode == 0:
        return "@{u}..HEAD"
    head = _run(root, "symbolic-ref", "refs/remotes/origin/HEAD")
    if head.returncode == 0:
        base = head.stdout.strip()
        mb = _run(root, "merge-base", base, "HEAD")
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


def diff_paths(root: Path, base: str | None, head: str) -> list[str]:
    if base is None:
        cp = _run(root, "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", head)
    else:
        cp = _run(root, "diff", "--name-only", "--diff-filter=ACMR", f"{base}..{head}")
    return [ln for ln in cp.stdout.splitlines() if ln] if cp.returncode == 0 else []


def diff_text(root: Path, base: str | None, head: str, max_bytes: int = 400_000) -> str:
    if base is None:
        cp = _run(root, "show", "--format=", head)
    else:
        cp = _run(root, "diff", f"{base}..{head}")
    text = cp.stdout if cp.returncode == 0 else ""
    if len(text.encode("utf-8", "replace")) <= max_bytes:
        return text
    return text.encode("utf-8", "replace")[:max_bytes].decode("utf-8", "ignore")
