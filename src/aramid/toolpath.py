"""toolpath -- the ONE place aramid decides where a tool binary lives.

Why this module exists: doctor and the runners used to resolve tools
independently. `doctor --fix` downloads gitleaks into `~/.aramid/tools/`;
doctor's probe looked there and reported "OK gitleaks", while
`runners.base.run_subprocess` resolved the bare name through `shutil.which`
alone -- which never sees that directory. The gate then skipped gitleaks as
MISSING while doctor reported a healthy toolchain. An operator running the
REPAIR command was told secrets were being scanned when they were not, and CI
could not catch it because CI installs gitleaks onto the real PATH.

The invariant, which `tests/unit/test_toolpath.py` pins directly: **if doctor
reports a tool present, the gate must be able to execute it.** Two resolution
paths cannot hold that invariant, so there is exactly one, here.

Search order is deliberate:
  1. PATH            -- the operator's own toolchain always wins. aramid's
                        managed copy is a fallback, never an override.
  2. console scripts -- pip installs (ruff/semgrep/pip-audit) can land in a
                        user-scheme scripts dir that is not on PATH.
  3. ~/.aramid/tools -- binaries aramid downloaded itself (gitleaks).
"""
import os
import shutil
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path


def exe_name(name: str) -> str:
    return f"{name}.exe" if sys.platform == "win32" else name


TOOLS_DIR_ENV = "ARAMID_TOOLS_DIR"


def tools_dir() -> Path:
    """aramid's own managed binaries. The single seam for redirecting them,
    so doctor and the runners always move together -- the property the old
    two-seam arrangement lacked.

    Honors `$ARAMID_TOOLS_DIR`. That is an ENV VAR rather than only a
    monkeypatch point because the gate runs in spawned processes: a git hook
    shells out to `aramid check`, so a test (or an operator) that needs to
    relocate this cannot reach the child by patching a function in the parent.
    An env var is inherited down the whole chain -- git hook -> sh shim ->
    interpreter -> `aramid check` -- which is exactly where the tool actually
    gets resolved."""
    override = os.environ.get(TOOLS_DIR_ENV)
    if override:
        return Path(override)
    return Path.home() / ".aramid" / "tools"


def scripts_dirs() -> list[Path]:
    """Every plausible console-script location for this interpreter: the
    default sysconfig scheme plus the per-user scheme (an editable/`--user`
    install lands scripts under the user scheme, which the default scheme
    alone does not report)."""
    dirs = [Path(sysconfig.get_path("scripts"))]
    user_scheme = "nt_user" if os.name == "nt" else "posix_user"
    try:
        user_dir = Path(sysconfig.get_path("scripts", user_scheme))
        if user_dir not in dirs:
            dirs.append(user_dir)
    except (KeyError, ValueError):
        pass
    return dirs


DEPENDENCY_TOOLS = frozenset({"ruff", "semgrep", "pip-audit"})
"""Tools aramid DECLARES as runtime dependencies in pyproject, and therefore
ships a specific resolved version of into its own environment. gitleaks is
deliberately absent: it is a binary aramid DOWNLOADS into `~/.aramid/tools`,
and PATH beating that copy is the intended behaviour this module's docstring
describes. Kept honest by
`test_the_dependency_list_matches_what_the_package_actually_declares`, which
checks it against the installed metadata -- a hand-maintained list like this
is exactly what goes stale in silence."""


@dataclass(frozen=True)
class Divergence:
    """`resolved` is what the gate will actually execute; `dependency_copy` is
    the one pip installed beside aramid. Both are real, and they are not the
    same file."""
    tool: str
    resolved: Path
    dependency_copy: Path


def _same_file(a: Path, b: Path) -> bool:
    """Two strings can name one file -- a trailing separator, differing case
    on Windows, one side unresolved. `os.path.samefile` answers on inode /
    file-id rather than spelling; `resolve()` is the fallback when either
    path has gone away between the two lookups."""
    try:
        return os.path.samefile(a, b)
    except OSError:
        return a.resolve() == b.resolve()


def divergence(name: str) -> Divergence | None:
    """Is aramid about to run a DIFFERENT copy of a declared dependency than
    the one pip installed alongside it? Returns None when it is not, when
    `name` is not a declared dependency, or when either copy is absent.

    THE ORDER IS NOT CHANGED BY THIS, and must not be. PATH-first is
    deliberate (module docstring: "the operator's own toolchain always wins"),
    and a per-tool exception would restore the two-resolution-path arrangement
    this module exists to collapse. Venv-first would not buy determinism
    anyway -- `ruff>=0.6,<0.17` still resolves differently on machines that
    installed aramid months apart.

    What WAS wrong is that the divergence was silent. Measured on the
    published 0.2.0 artifact in a clean venv, same file: PATH's ruff 0.15.18
    reported `F401`; the venv's ruff 0.16.2 reported `F401` + `I001` +
    `PLW1510`. Same aramid, same input, three findings versus one. Two
    consequences follow, and both are quiet:

      - The ratchet. A finding that exists under one analyzer version and not
        the other is NEW to whichever side sees it first, so CI can block a
        push for something the developer's own gate never showed. That is
        precisely the local-vs-CI divergence `[hooks].pre_push_match_ci`
        exists to close, defeated one layer underneath it.
      - Fingerprints. A different rule id is a different finding id, so
        baselines and `.aramid-suppressions.toml` entries stop matching.

    `scripts_dirs()` is evaluated INDEPENDENTLY here, not reused from
    `resolve()`: `resolve()` returns on the `shutil.which` hit and never
    computes bucket 2 at all, so the question "what would the dependency copy
    have been?" has no answer to borrow.
    """
    if name not in DEPENDENCY_TOOLS:
        return None
    try:
        resolved = resolve(name)
        if resolved is None:
            return None
        for d in scripts_dirs():
            candidate = d / exe_name(name)
            if not candidate.exists():
                continue
            if _same_file(candidate, resolved):
                return None
            return Divergence(tool=name, resolved=resolved, dependency_copy=candidate)
    except OSError:
        return None
    return None


def divergences() -> list[Divergence]:
    """Every declared dependency aramid is about to run a foreign copy of.
    Sorted so output is stable run to run."""
    found = (divergence(t) for t in sorted(DEPENDENCY_TOOLS))
    return [d for d in found if d is not None]


def resolve(name: str) -> Path | None:
    """Absolute path to `name`, or None if it is genuinely unavailable.

    Never raises: resolution failure must surface as a MISSING/degraded tool
    through the normal fail-open path, never as an exception inside a gate."""
    try:
        exe = shutil.which(name)
        if exe:
            return Path(exe)

        # An absolute/relative path handed straight through (not a bare name).
        direct = Path(name)
        if direct.exists() and direct.is_file():
            return direct

        for d in (*scripts_dirs(), tools_dir()):
            candidate = d / exe_name(name)
            if candidate.exists():
                return candidate
    except OSError:
        return None
    return None
