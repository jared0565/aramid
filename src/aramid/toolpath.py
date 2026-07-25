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
