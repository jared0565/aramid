"""e2e: Windows-specific real `git commit` through the INSTALLED shim, live
ruff blocking a real commit, foreign-hook chaining, and uninstall reversal --
the full-stack scenario `tests/e2e/test_hook_fires.py` (Task 6.1/M6a)
explicitly deferred to this module once `aramid check` existed (Task 7.1;
see that module's own docstring).

Skips cleanly off win32 (`pytestmark` below): shim generation is `sh`-script
based and the CRLF/interpreter-path/PATH concerns this module exists to
catch are Windows-specific by construction (hooks.py's own module docstring).

Environment on this host, confirmed empirically (not assumed) before writing
these tests -- see the manual smoke test this module's assertions mirror:
  - ruff IS installed but into the per-user pip Scripts dir
    (`...\\AppData\\Roaming\\Python\\PythonXXX\\Scripts`), NOT on PATH by
    default -- same discovery pattern as tests/integration/test_semgrep_rules.py's
    `_find_semgrep` / tests/integration/test_gates_end_to_end.py's `_find_tool`,
    generalized here to just ruff via `_find_ruff`. A real `ruff check` on a
    one-line `exec(x)` file completed in ~0.17s, comfortably inside the 5s
    `pre_commit` wall-clock budget (data/defaults.toml `[timeouts]`).
  - gitleaks is NOT installed, no network in this environment. This does not
    threaten either assertion below: pipeline.run_gate's ONLY route to
    exit_code 1 that isn't gated behind `gate is PRE_PUSH` is a genuine BLOCK
    finding (`block_findings`); a MISSING BLOCK-tier tool at pre-commit only
    ever contributes to `degraded_tools` -> exit 2 at worst, and the shim's
    own pre-commit exit-code mapping is `{2,3}->0` (fail-open; hooks.py's
    module docstring) -- confirmed live below (clean commit succeeds despite
    gitleaks being reported "skipped (degraded tools)").
  - `hooks.install()` is called directly (not `aramid init`), bypassing
    `init`'s own `doctor` gate (which refuses to arm hooks while gitleaks/
    semgrep are missing) -- the same choice task-8.2's brief offers and the
    one M6a's `test_hook_fires.py` already made. This module exercises
    hooks.py's real git dispatch + the real `aramid check` engine end to
    end; it is not a re-test of `init`'s own gate (covered by
    tests/integration/test_init.py / test_doctor.py).
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aramid import hooks
from aramid.ledger import Ledger
from aramid.models import EventType

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific shim/PATH E2E")


# --- live-tool discovery ------------------------------------------------
# Same search strategy as test_semgrep_rules.py's `_find_semgrep` /
# test_gates_end_to_end.py's `_find_tool`, narrowed to just ruff (the only
# live tool this module's assertions depend on -- gitleaks is deliberately
# left MISSING per the module docstring above).

def _find_ruff() -> Path | None:
    candidates: list[Path] = []
    which = shutil.which("ruff")
    if which:
        candidates.append(Path(which))
    exe_dir = Path(sys.executable).parent
    candidates.append(exe_dir / "Scripts" / "ruff.exe")
    candidates.append(exe_dir / "ruff")
    for entry in sys.path:
        p = Path(entry)
        if p.name == "site-packages":
            candidates.append(p.parent / "Scripts" / "ruff.exe")
            candidates.append(p.parent / "bin" / "ruff")
    for c in candidates:
        if c.exists():
            return c
    return None


_RUFF_BIN = _find_ruff()
_SKIP_RUFF = ("ruff console-script not found via shutil.which, next to sys.executable, or "
              "next to any sys.path site-packages dir -- cannot exercise a live pre-commit "
              "BLOCK in this environment.")


def _live_ruff_env() -> dict:
    """PATH extended with ruff's own directory. The REAL `aramid check`
    process spawned through git's hook dispatch inherits this all the way
    down the chain (git commit -> sh hook -> baked interpreter -> `aramid
    check` subprocess) -- git does not sanitize hook environments (hooks.py's
    module docstring) -- and `aramid.runners.base.run_subprocess` gates on
    `shutil.which(argv[0])` before it will even attempt to run "ruff"."""
    assert _RUFF_BIN is not None
    return {**os.environ, "PATH": str(_RUFF_BIN.parent) + os.pathsep + os.environ.get("PATH", "")}


# --- repo helpers ---------------------------------------------------------

def _git(root: Path, *a: str, env: dict | None = None, timeout: float = 60.0):
    e = {**os.environ, **(env or {})}
    return subprocess.run(["git", *a], cwd=str(root), capture_output=True, text=True,
                           env=e, timeout=timeout)


def _repo(tmp_path: Path, name: str = "r") -> Path:
    r = tmp_path / name
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=r, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=r, check=True, capture_output=True)
    return r


def _commit_count(root: Path) -> int:
    cp = subprocess.run(["git", "log", "--oneline"], cwd=str(root), capture_output=True, text=True)
    return len(cp.stdout.splitlines()) if cp.returncode == 0 else 0


def _ledger_ran(root: Path) -> bool:
    """True iff a real `aramid check` process actually ran the gate pipeline
    against this repo -- opens the ledger `check.py`'s Ledger(...) call
    creates on invocation and looks for a RUN_FINISHED event, not just the
    ledger.db file's existence (a stronger signal that the engine executed
    the pipeline, not merely that the process started)."""
    db = root / ".aramid" / "ledger.db"
    if not db.exists():
        return False
    ledger = Ledger(db)
    try:
        return any(e.type is EventType.RUN_FINISHED for e in ledger.events())
    finally:
        ledger.close()


# --- 1. real pre-commit BLOCK via live ruff, then a real clean commit ----

@pytest.mark.skipif(_RUFF_BIN is None, reason=_SKIP_RUFF)
def test_real_precommit_blocks_on_live_ruff_s102_then_clean_commit_succeeds(tmp_path):
    r = _repo(tmp_path)
    hooks.install(r, Path(sys.executable))
    assert (r / ".git" / "hooks" / "pre-commit").exists()

    env = _live_ruff_env()

    # --- BLOCK path: exec(x) trips ruff S102, a curated BLOCK-tier rule
    # (data/block_rules.toml [ruff].block) -- real ruff, real git dispatch,
    # not cmd_check called directly.
    (r / "bad.py").write_text("def f(x):\n    exec(x)\n", encoding="utf-8")
    _git(r, "add", "bad.py")
    cp = _git(r, "commit", "-m", "bad", env=env)

    assert cp.returncode != 0, cp.stdout + cp.stderr
    assert _commit_count(r) == 0, "a blocked commit must never land in git log"
    # proves the shim actually dispatched into `aramid check`, which shelled
    # out to a REAL ruff that found the S102 rule -- not just "something
    # non-zero happened" (e.g. a missing-interpreter shim failure, which
    # would also be non-zero but for the wrong reason).
    assert "S102" in cp.stdout + cp.stderr, cp.stdout + cp.stderr

    # --- clean path: unstage the blocking file, stage a clean one, commit
    # again in the SAME repo -- exit 0 path. gitleaks stays MISSING
    # throughout (not installed in this environment) -- proving this commit
    # succeeds anyway is exactly the fail-open assertion the shim's
    # pre-commit `{2,3}->0` mapping exists for (hooks.py module docstring).
    _git(r, "reset")
    (r / "good.py").write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
    _git(r, "add", "good.py")
    cp2 = _git(r, "commit", "-m", "good", env=env)

    assert cp2.returncode == 0, cp2.stdout + cp2.stderr
    assert _commit_count(r) == 1
    assert "gitleaks" in cp2.stdout + cp2.stderr  # reported as a skipped/degraded tool


# --- 2. chaining: a foreign pre-commit hook runs alongside aramid's own --

def test_chained_foreign_hook_runs_alongside_aramid_through_real_git_dispatch(tmp_path):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    marker = r / "foreign-ran.txt"
    foreign_content = f'#!/bin/sh\necho ran > "{hooks.win_sh_path(marker)}"\nexit 0\n'.encode()
    foreign = hdir / "pre-commit"
    foreign.write_bytes(foreign_content)
    foreign.chmod(foreign.stat().st_mode | 0o111)

    hooks.install(r, Path(sys.executable))
    assert (hdir / "pre-commit.aramid-chained").exists()
    assert hooks.MARKER_START.encode() in (hdir / "pre-commit").read_bytes()

    # a clean commit must succeed (gitleaks MISSING fail-opens at pre-commit,
    # same as scenario 1) AND run BOTH the chained foreign hook and aramid's
    # own real engine.
    (r / "clean.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "clean.py")
    cp = _git(r, "commit", "-m", "c1")

    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert marker.exists(), "chained foreign hook must actually run through real git dispatch"
    assert _ledger_ran(r), "aramid's real engine must have run the gate pipeline (ledger RUN_FINISHED)"

    marker.unlink()

    # --- uninstall reverses the chain: foreign hook restored verbatim and
    # still fires live.
    hooks.uninstall(r)

    assert not (hdir / "pre-commit.aramid-chained").exists()
    assert foreign.read_bytes() == foreign_content, "original foreign hook must be restored verbatim"

    (r / "clean2.py").write_text("y = 2\n", encoding="utf-8")
    _git(r, "add", "clean2.py")
    cp2 = _git(r, "commit", "-m", "c2")

    assert cp2.returncode == 0, cp2.stdout + cp2.stderr
    assert marker.exists(), "restored foreign hook must actually execute through real git dispatch"


# --- 3. uninstall reversal: shim gone, chained original restored, ledger kept

def test_uninstall_removes_shim_restores_chained_original_and_keeps_ledger(tmp_path):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    foreign_content = b"#!/bin/sh\nexit 0\n"
    (hdir / "pre-commit").write_bytes(foreign_content)

    hooks.install(r, Path(sys.executable))

    (r / "clean.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "clean.py")
    cp = _git(r, "commit", "-m", "c1")
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert _ledger_ran(r), "aramid's real engine must have run before uninstall"

    hooks.uninstall(r)

    pre_commit_bytes = (hdir / "pre-commit").read_bytes()
    assert hooks.MARKER_START.encode() not in pre_commit_bytes, "aramid's own shim must be gone"
    assert pre_commit_bytes == foreign_content, ".aramid-chained original restored verbatim"
    assert not (hdir / "pre-commit.aramid-chained").exists()
    assert not (hdir / "pre-push").exists(), "pre-push shim (no chained original) fully removed"

    # the ledger (.aramid/) is KEPT by default post-uninstall (design doc
    # section 2 / uninstall.py's own module docstring) -- security/audit
    # history must survive an uninstall.
    assert _ledger_ran(r), "ledger must be KEPT (and still readable) after uninstall"
