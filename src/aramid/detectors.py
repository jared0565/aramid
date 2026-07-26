import json
import os
from pathlib import Path

# Vendored/build trees that must never contribute a stack or test signal.
# Named explicitly (not dot-prefixed) so they need their own entry alongside
# the dot-directory rule in `_iter_files` below (`.venv`, `.git`, etc. are
# already caught by that rule). Kept local to this module: init.py's
# `--discover` skip-list serves a different walk (finding nested repos) and
# is not reused here.
_EXCLUDED_DIRS = {"node_modules", "venv", "build"}


def _iter_files(base: Path):
    """Yield every file under `base`, pruning `_EXCLUDED_DIRS` and any
    dot-directory in place so os.walk never descends into them.

    `base` itself is always walked regardless of its own name or its
    ancestors' names -- only child directories encountered *during* the walk
    are filtered, so a dot-directory somewhere above `base` (e.g. `base`
    living under `<tmp>/.local/src/repo`) cannot blank out the result.
    """
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS and not d.startswith(".")]
        for name in filenames:
            yield Path(dirpath) / name


def _is_pytest_file(name: str) -> bool:
    """True for `conftest.py`, `test_*.py`, or `*_test.py` -- the three
    positive pytest signals (deliberate; a bare `tests/` directory is not
    one of them -- see detect_tests)."""
    if name == "conftest.py":
        return True
    if name.endswith("_test.py"):
        return True
    return name.startswith("test_") and name.endswith(".py")


def detect_stacks(root: Path, scope: Path) -> set[str]:
    s = set()
    # `scope` (not `root`) bases the walk: it's the only path guaranteed to
    # prefix what the walk yields (init.py may pass a subdirectory here;
    # pipeline.py passes `root`). `or` short-circuits, so a `pyproject.toml`
    # at root skips the walk entirely.
    if (root / "pyproject.toml").exists() or any(p.suffix == ".py" for p in _iter_files(scope)):
        s.add("python")
    if (root / "package.json").exists():
        s.add("js")
    return s

def detect_package_manager(root: Path):
    for f, name in (("package-lock.json", "npm"), ("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn")):
        if (root / f).exists():
            return name
    return None

def detect_tests(root: Path) -> set[str]:
    out = set()
    # A bare `tests/` directory is deliberately NOT a signal -- that was the
    # false-positive bug (a TS repo's tests/*.test.ts directory made this
    # true). Only a real Python test file counts.
    for p in _iter_files(root):
        if _is_pytest_file(p.name):
            out.add("pytest")
            break
    pj = root / "package.json"
    if pj.exists():
        try:
            if "test" in json.loads(pj.read_text()).get("scripts", {}):
                out.add("npm")
        except (ValueError, OSError):
            pass
    return out

def nested_git_dirs(root: Path) -> list[Path]:
    return [p.parent for p in root.rglob(".git")
            if p.parent.resolve() != root.resolve() and "node_modules" not in p.parts]
