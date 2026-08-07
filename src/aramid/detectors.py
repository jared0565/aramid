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
    if (root / "Cargo.toml").exists():
        s.add("rust")
    return s

def detect_package_manager(root: Path):
    for f, name in (("package-lock.json", "npm"), ("pnpm-lock.yaml", "pnpm"),
                     ("yarn.lock", "yarn"), ("Cargo.lock", "cargo")):
        if (root / f).exists():
            return name
    return None

def detect_tests(root: Path) -> set[str]:
    out = set()
    # A bare `tests/` directory is deliberately NOT a signal -- that was the
    # false-positive bug (a TS repo's tests/*.test.ts directory made this
    # true). Only a real Python test file counts.
    #
    # cargo/go are gated on their MANIFEST first so the extra filename checks
    # below cost nothing in a repo that is neither. Both are FILENAME-ONLY,
    # measured rather than assumed: sniffing `.rs` contents for
    # #[test]/#[cfg(test)] would also catch inline unit tests -- the commoner
    # Rust layout -- but cost 409 ms against 4 ms for the filename walk on 500
    # files / 2.5 MB, in a function that runs on every gate, in a module whose
    # history is a series of detector-walk regressions. An inline-only crate
    # falls through to pipeline's "no suite detected" WARN, which names
    # [tests].command -- an honest, loud degradation instead of silence.
    #
    # Keyed on the walk rather than a root-level glob so a workspace member
    # (crates/<name>/tests/*.rs) counts too.
    need_pytest = True
    need_cargo = (root / "Cargo.toml").exists()
    need_go = (root / "go.mod").exists()
    for p in _iter_files(root):
        if need_pytest and _is_pytest_file(p.name):
            out.add("pytest")
            need_pytest = False
        if need_cargo and p.suffix == ".rs" and p.parent.name == "tests":
            out.add("cargo")
            need_cargo = False
        if need_go and p.name.endswith("_test.go"):
            out.add("go")
            need_go = False
        # Early exit preserved exactly for the pytest-only case that had it:
        # with no Cargo.toml and no go.mod both flags start False, so this
        # breaks on the first pytest file just as `break` used to.
        if not (need_pytest or need_cargo or need_go):
            break
    pj = root / "package.json"
    if pj.exists():
        try:
            if "test" in json.loads(pj.read_text()).get("scripts", {}):
                out.add("npm")
        except (ValueError, OSError):
            pass
    return out

# Stacks that are gated ONLY by a root marker file, mapped to that marker
# and to the sibling files (if any) required to believe a nested copy is a
# real project. Python is deliberately absent: it alone has a walk fallback
# in detect_stacks, so it cannot end up in the state this table describes.
#
# rust needs no corroborating file -- a nested Cargo.toml with no root
# manifest CANNOT be a workspace member, because a workspace is declared by
# the very root manifest whose absence puts us here. It is a standalone
# crate every time.
#
# js does, and this asymmetry is the whole point. A bare nested
# package.json is weak evidence: a docs site, a widget, or a test fixture
# legitimately carries one that nobody wants npm-audited, and telling an
# operator they have missing JS coverage there is the same false-positive
# class as running pytest against a TS repo (the bug _EXCLUDED_DIRS above
# exists to fix). A lockfile beside it is the "real installed project"
# signal detect_package_manager and runners/tests.py's C1 gate already use.
_ROOT_GATED_STACKS: dict[str, tuple[str, tuple[str, ...]]] = {
    "rust": ("Cargo.toml", ()),
    "js": ("package.json", ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")),
}

# (tool list, remedy) per stack. Named here rather than derived from the
# runner registry: detectors.py imports nothing from aramid (it is the bottom
# of the layering, which is why both pipeline.py and commands/init.py can
# share this text without a cycle), and these are display strings, not
# dispatch keys.
#
# The remedies differ because only one of them is honest advice. A root
# `[workspace]` manifest is the idiomatic way to own several crates, so
# suggesting it to a Rust operator costs them nothing they wouldn't want
# anyway. There is no equivalent for JS -- nobody should add a root
# package.json merely to satisfy a linter -- so that side only offers the
# remedy that is actually reasonable.
_ROOT_GATED_HELP = {
    "rust": ("clippy, cargo-audit",
             "Add a root Cargo.toml declaring a [workspace] over these "
             "crates, or run aramid from that subdirectory."),
    "js": ("eslint, npm/pnpm/yarn",
           "Run aramid from that subdirectory (onboard it as its own repo "
           "with `aramid init <dir>`)."),
}

_MAX_DIRS_SHOWN = 3


def detect_unrooted_stacks(root: Path) -> dict[str, list[str]]:
    """Stacks whose marker manifest exists BELOW `root` but not AT it --
    i.e. code aramid can see but structurally cannot gate.

    detect_stacks keys "rust" and "js" off a ROOT manifest, so a repo whose
    crate lives in `backend/` reports no rust stack, selects neither clippy
    nor cargo-audit, and produces a clean run indistinguishable from a repo
    with no Rust in it. That is the failure class this engine exists to
    prevent, so the state at least has to be nameable.

    Returns `{stack: [posix relative dirs]}`, sorted, empty when there is
    nothing to say. Costs one walk, and only when a root marker is actually
    missing -- a repo whose stacks are all rooted (the common case, and
    every Cargo workspace) short-circuits before `_iter_files` is touched.
    """
    wanted = {name: spec for name, spec in _ROOT_GATED_STACKS.items()
              if not (root / spec[0]).exists()}
    if not wanted:
        return {}
    by_marker = {spec[0]: (name, spec[1]) for name, spec in wanted.items()}
    found: dict[str, set[str]] = {}
    # Shares _iter_files, so node_modules/ and dot-directories are pruned --
    # a vendored manifest must never manufacture a phantom ungated stack.
    for p in _iter_files(root):
        entry = by_marker.get(p.name)
        if entry is None:
            continue
        name, required = entry
        if required and not any((p.parent / lock).exists() for lock in required):
            continue
        found.setdefault(name, set()).add(p.parent.relative_to(root).as_posix())
    return {name: sorted(dirs) for name, dirs in sorted(found.items())}


def unrooted_stack_notices(root: Path) -> list[str]:
    """One operator-facing line per ungated stack. Phrased as what aramid is
    NOT doing, never as an accusation that the layout is wrong -- a
    subdirectory crate is a perfectly ordinary way to organize a repo, and
    the actionable fact is simply that these gates are not covering it."""
    notices = []
    for stack, dirs in detect_unrooted_stacks(root).items():
        shown = ", ".join(f"{d}/" for d in dirs[:_MAX_DIRS_SHOWN])
        if len(dirs) > _MAX_DIRS_SHOWN:
            shown += f" (+{len(dirs) - _MAX_DIRS_SHOWN} more)"
        marker = _ROOT_GATED_STACKS[stack][0]
        tools, remedy = _ROOT_GATED_HELP[stack]
        notices.append(
            f"aramid: {stack}: found {marker} under {shown} but none at the "
            f"repository root -- aramid's {stack} gates ({tools}) are NOT "
            f"running for this repo, because they execute from the root. A "
            f"clean {stack} result here means 'not checked', not 'no "
            f"findings'. {remedy}")
    return notices


def nested_git_dirs(root: Path) -> list[Path]:
    return [p.parent for p in root.rglob(".git")
            if p.parent.resolve() != root.resolve() and "node_modules" not in p.parts]
