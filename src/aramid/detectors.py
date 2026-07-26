import json
import os
from pathlib import Path

# Vendored/build trees that must never contribute a stack or test signal.
# Named explicitly (not dot-prefixed) so they need their own entry alongside
# the dot-directory rule in `_iter_files` below (`.venv`, `.git`, etc. are
# already caught by that rule). Kept local to this module: init.py's
# `--discover` skip-list serves a different walk (finding nested repos) and
# is not reused here.
#
# [MUST FIX 1, whole-branch review] Exactly the six names review B6
# mandated -- `node_modules`, `graph-out`, `venv`, `env`, `build`,
# `site-packages` -- not the three this module originally shipped with.
# `env` and `site-packages` are the two that matter most: `python -m venv
# env` is at least as common a convention as `venv`, and the dot-directory
# rule does not cover it, so a bare `env/` virtualenv was reopening the
# EXACT bug this whole module exists to fix (a TypeScript repo's vendored
# `conftest.py`/`test_*.py` under `env/Lib/site-packages/` made
# detect_stacks/detect_tests report "python"/"pytest", which then ran
# `pytest -q` at the repo root and blocked every push with exit 5) --
# reached by a different vector than the original bug report. `site-
# packages` is excluded independently of `env`/`venv` too, since some
# virtualenv tools and vendoring conventions place it directly under a
# differently-named (or no) wrapper directory. `graph-out/` mirrors
# `defaults.toml`'s own `ignore_paths` entry for aramid's graphite
# artifacts. DELIBERATE ACCEPTED TRADE-OFF: a real, non-virtualenv source
# directory that happens to be named exactly `env/` (or any of the other
# five names) is invisible to both walks below -- same as `venv`/`build`
# always were. Renaming such a directory, or adding a real pytest-shaped
# file elsewhere in the repo, are the two ways around it; this module does
# not attempt to distinguish "a directory named env that IS a virtualenv"
# from "a directory named env that ISN'T".
_EXCLUDED_DIRS = {"node_modules", "graph-out", "venv", "env", "build", "site-packages"}


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
    one of them -- see detect_tests).

    [MUST FIX 5, whole-branch review / deferred #2] Matching is a plain
    string comparison, hence deliberately CASE-SENSITIVE on every platform
    -- `TEST_FOO.PY` / `Conftest.PY` / `BAR_TEST.PY` do not match. This is
    a decision, not an accidental narrowing: the code this module replaced
    used `Path.rglob("test_*.py")` / `Path.rglob("*.py")`, whose case
    sensitivity is platform-dependent (case-insensitive on Windows/macOS's
    default filesystems, case-sensitive on Linux) -- the OLD behaviour was
    already platform-divergent, not a stable contract this module is
    weakening. Uniform case-sensitivity matches CI (which runs on Linux)
    on every platform, including this one. Accepted trade-off: pytest
    itself WOULD collect `TEST_FOO.PY` on Windows (its own collection
    globbing normcases there), so this is a real, deliberate false
    negative on Windows for an all-caps filename -- traded for a detector
    that agrees with itself regardless of which OS aramid runs on."""
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
    # at root skips the walk entirely. `.suffix == ".py"` is deliberately
    # case-sensitive, same decision and rationale as _is_pytest_file's own
    # docstring (MUST FIX 5, whole-branch review) -- a `BAR.PY` file is not
    # detected on any platform.
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
