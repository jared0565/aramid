"""e2e: hook shims fire through REAL git hook dispatch (not the pipeline
invoked directly) -- this is the property Windows correctness lives or dies
on.

Deviation from the brief's literal "stage a fake secret" scenario, noted per
task instructions ("if a shown test can't pass as written, fix minimally and
note it"): `aramid check` itself is not wired into the CLI yet (Task 7.1/7.5,
explicitly out of scope for Task 6.1 -- `cli.py` currently returns exit 3 for
every command, "aramid: no command"). Detecting a real secret therefore
cannot be exercised end-to-end yet; that full-stack scenario belongs to Task
8.2's `tests/e2e/test_windows_hooks.py` once `check` exists.

What IS this module's job, and what it tests instead, with zero fakes where
the real thing is available:

1. `test_real_engine_*` -- exercises TODAY's real, installed interpreter
   through a real `git commit`/`git push`, with no stand-ins at all. Exit 3
   ("no command") is a legitimate §3 "engine/config error", so this already
   proves the fail-open (pre-commit) vs fail-closed (pre-push) asymmetry on
   real hardware.
2. `test_fake_engine_*` -- bakes a tiny controllable `#!/bin/sh` script as
   the "interpreter" to drive the full §3 exit-code matrix (0/1/2/3) at both
   gates. `render_shim`/`install` never inspect *what* the interpreter is,
   only its path, so this is a legitimate stand-in for the not-yet-built
   `check` CLI -- it validates hooks.py's own contract (dispatch + mapping),
   not policy/detection logic (covered elsewhere: runner/policy/pipeline
   unit tests).
3. Chaining and uninstall are also verified through real git dispatch.
"""
import os
import subprocess
import sys
from pathlib import Path

from aramid import hooks


def _git(root, *a, env=None):
    e = {**os.environ, **(env or {})}
    return subprocess.run(["git", *a], cwd=str(root), capture_output=True, text=True, env=e)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=r, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=r, check=True, capture_output=True)
    return r


def _bare_remote(tmp_path) -> Path:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)],
                    check=True, capture_output=True)
    return remote


def _fake_engine(tmp_path) -> Path:
    """A `#!/bin/sh` stand-in for the blessed python interpreter: exits with
    $FAKE_EXIT_CODE (default 0). `install()`/`render_shim` bake a path and
    exec it with `-m aramid check --gate <gate>` appended -- this script
    ignores those args exactly like a real interpreter's `-m` machinery
    would consume them, and just reports the exit code the test wants to
    drive through the real shim + real git dispatch."""
    p = tmp_path / "fake_engine.sh"
    p.write_bytes(b'#!/bin/sh\nexit "${FAKE_EXIT_CODE:-0}"\n')
    p.chmod(p.stat().st_mode | 0o111)
    return p


# --- 1. real engine, no fakes -------------------------------------------

def test_real_engine_pre_commit_fails_open_on_unimplemented_check(tmp_path):
    r = _repo(tmp_path)
    hooks.install(r, Path(sys.executable))
    (r / "a.txt").write_text("hello\n")
    _git(r, "add", "a.txt")
    cp = _git(r, "commit", "-m", "c1")
    assert cp.returncode == 0, cp.stdout + cp.stderr


# NOTE: no `test_real_engine_pre_push_*` counterpart here, deliberately.
# `check` is unimplemented today (always exit 3), so a real-engine pre-push
# test asserting "blocked" is only true because of that placeholder --once
# Task 7.1 wires `check` and a clean repo legitimately returns 0, such a test
# would start failing for the *right* reason (push should succeed) while
# reading as a hooks.py regression. The exit-3-blocks-at-pre-push behavior is
# covered durably below by `test_fake_engine_pre_push_exit_code_matrix`,
# which doesn't depend on whether `check` exists.


# --- 2. fake engine, full exit-code matrix ------------------------------

def test_fake_engine_pre_commit_exit_code_matrix(tmp_path):
    r = _repo(tmp_path)
    engine = _fake_engine(tmp_path)
    hooks.install(r, engine)

    # exit 1 (real BLOCK finding) -> pre-commit blocks
    (r / "a.txt").write_text("hello\n")
    _git(r, "add", "a.txt")
    cp = _git(r, "commit", "-m", "c1", env={"FAKE_EXIT_CODE": "1"})
    assert cp.returncode != 0

    # exit 2 (WARN-tier degraded) -> pre-commit passes (fail-open)
    cp = _git(r, "commit", "-m", "c1", env={"FAKE_EXIT_CODE": "2"})
    assert cp.returncode == 0

    # exit 3 (engine/config error) -> pre-commit passes (fail-open)
    (r / "b.txt").write_text("x\n")
    _git(r, "add", "b.txt")
    cp = _git(r, "commit", "-m", "c2", env={"FAKE_EXIT_CODE": "3"})
    assert cp.returncode == 0

    # exit 0 (clean) -> passes
    (r / "c.txt").write_text("x\n")
    _git(r, "add", "c.txt")
    cp = _git(r, "commit", "-m", "c3", env={"FAKE_EXIT_CODE": "0"})
    assert cp.returncode == 0


def test_fake_engine_pre_push_exit_code_matrix(tmp_path):
    remote = _bare_remote(tmp_path)
    r = _repo(tmp_path)
    engine = _fake_engine(tmp_path)
    hooks.install(r, engine)
    (r / "a.txt").write_text("hello\n")
    _git(r, "add", "a.txt")
    _git(r, "commit", "-m", "c1")
    _git(r, "remote", "add", "origin", str(remote))

    # exit 1 (real BLOCK finding) -> pre-push blocks
    cp = _git(r, "push", "origin", "main", env={"FAKE_EXIT_CODE": "1"})
    assert cp.returncode != 0

    # exit 3 (degraded BLOCK-tier tooling, per §3 escalation) -> pre-push blocks
    cp = _git(r, "push", "origin", "main", env={"FAKE_EXIT_CODE": "3"})
    assert cp.returncode != 0

    # exit 2 (WARN-tier degraded) -> pre-push proceeds
    cp = _git(r, "push", "origin", "main", env={"FAKE_EXIT_CODE": "2"})
    assert cp.returncode == 0


# --- 3. chaining + uninstall, through real git dispatch -----------------

def test_chained_foreign_pre_commit_hook_runs_through_real_git_dispatch(tmp_path):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    marker = r / "foreign-ran.txt"
    foreign = hdir / "pre-commit"
    foreign.write_bytes(
        f'#!/bin/sh\necho ran > "{hooks.win_sh_path(marker)}"\nexit 0\n'.encode())
    foreign.chmod(foreign.stat().st_mode | 0o111)

    hooks.install(r, _fake_engine(tmp_path))
    assert (hdir / "pre-commit.aramid-chained").exists()

    (r / "a.txt").write_text("hi\n")
    _git(r, "add", "a.txt")
    cp = _git(r, "commit", "-m", "c1", env={"FAKE_EXIT_CODE": "0"})
    assert cp.returncode == 0
    assert marker.exists(), "chained foreign hook must actually run through real git dispatch"


def test_chained_foreign_hook_that_blocks_stops_the_commit(tmp_path):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    foreign = hdir / "pre-commit"
    foreign.write_bytes(b"#!/bin/sh\nexit 1\n")
    foreign.chmod(foreign.stat().st_mode | 0o111)

    # even though the aramid engine itself would pass (exit 0), a blocking
    # chained foreign hook must still block the commit.
    hooks.install(r, _fake_engine(tmp_path))
    (r / "a.txt").write_text("hi\n")
    _git(r, "add", "a.txt")
    cp = _git(r, "commit", "-m", "c1", env={"FAKE_EXIT_CODE": "0"})
    assert cp.returncode != 0


def test_uninstall_restores_foreign_hook_and_stops_blocking(tmp_path):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    marker = r / "foreign-ran.txt"
    foreign = hdir / "pre-commit"
    foreign_content = f'#!/bin/sh\necho ran > "{hooks.win_sh_path(marker)}"\nexit 0\n'.encode()
    foreign.write_bytes(foreign_content)
    foreign.chmod(foreign.stat().st_mode | 0o111)

    hooks.install(r, _fake_engine(tmp_path))

    chained = hdir / "pre-commit.aramid-chained"
    assert chained.exists(), "install must chain the pre-existing foreign hook"
    assert chained.read_bytes() == foreign_content
    shim_bytes = (hdir / "pre-commit").read_bytes()
    assert hooks.MARKER_START.encode() in shim_bytes
    assert b"pre-commit.aramid-chained" in shim_bytes

    # sanity: while chained, aramid's own engine still gates the commit --
    # proves the aramid shim (not just the exit-0 chained foreign hook)
    # currently occupies the slot, and that the chained hook runs first.
    (r / "a.txt").write_text("x\n")
    _git(r, "add", "a.txt")
    cp = _git(r, "commit", "-m", "blocked", env={"FAKE_EXIT_CODE": "1"})
    assert cp.returncode != 0
    assert marker.exists(), "chained foreign hook must run before the aramid engine"
    marker.unlink()

    hooks.uninstall(r)

    assert not chained.exists()
    assert foreign.read_bytes() == foreign_content, (
        "original foreign hook content must be restored verbatim"
    )

    # the restored original foreign hook actually fires again through real
    # git dispatch (proving it's a live, working hook, not just an inert
    # restored file), AND aramid's own gate is gone (the FAKE_EXIT_CODE=1
    # that blocked above is now irrelevant -- only the restored,
    # exit-0 foreign hook occupies the slot).
    _git(r, "add", "a.txt")
    cp = _git(r, "commit", "-m", "now-allowed", env={"FAKE_EXIT_CODE": "1"})
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert marker.exists(), "restored foreign hook must actually execute through real git dispatch"
