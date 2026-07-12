import subprocess
from pathlib import Path

from aramid.hooks import (
    MARKER_START,
    hooks_dir,
    install,
    render_shim,
    uninstall,
    win_sh_path,
)
from aramid.models import Gate


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    return r


# --- win_sh_path ---------------------------------------------------------

def test_win_sh_path_converts_drive_letter():
    assert win_sh_path(Path("C:\\x\\y")) == "/c/x/y"


def test_win_sh_path_lowercases_drive_letter_and_handles_forward_slashes():
    assert win_sh_path(Path("D:/foo/bar.exe")) == "/d/foo/bar.exe"


def test_win_sh_path_bare_drive_root():
    assert win_sh_path(Path("C:\\")) == "/c/"


# --- render_shim ----------------------------------------------------------

def test_render_shim_returns_bytes_with_no_cr():
    data = render_shim(Gate.PRE_COMMIT, Path("C:/Users/t/venv/Scripts/python.exe"))
    assert isinstance(data, bytes)
    assert b"\r" not in data


def test_render_shim_contains_marker_and_baked_interpreter_path():
    interp = Path("C:/Users/t/venv/Scripts/python.exe")
    data = render_shim(Gate.PRE_COMMIT, interp)
    assert MARKER_START.encode() in data
    assert win_sh_path(interp).encode() in data
    # baked path is double-quoted when exec'd
    assert f'"{win_sh_path(interp)}"'.encode() in data


def test_render_shim_has_py_launcher_fallback():
    data = render_shim(Gate.PRE_COMMIT, Path("C:/py/python.exe")).decode()
    assert "command -v py" in data
    assert "py -3" in data


def test_render_shim_invokes_check_with_gate():
    data = render_shim(Gate.PRE_COMMIT, Path("C:/py/python.exe")).decode()
    assert "-m aramid check --gate pre-commit" in data
    data2 = render_shim(Gate.PRE_PUSH, Path("C:/py/python.exe")).decode()
    assert "-m aramid check --gate pre-push" in data2


def test_render_shim_pre_commit_maps_2_and_3_to_0():
    data = render_shim(Gate.PRE_COMMIT, Path("C:/py/python.exe")).decode()
    assert "2|3) exit 0 ;;" in data


def test_render_shim_pre_push_maps_only_2_to_0():
    data = render_shim(Gate.PRE_PUSH, Path("C:/py/python.exe")).decode()
    assert "2) exit 0 ;;" in data
    assert "2|3" not in data  # 1 and 3 must pass through unmapped (block)


def test_render_shim_has_chain_check_block():
    data = render_shim(Gate.PRE_COMMIT, Path("C:/py/python.exe")).decode()
    assert "pre-commit.aramid-chained" in data


# --- hooks_dir --------------------------------------------------------------

def test_hooks_dir_default_is_git_hooks(tmp_path):
    r = _repo(tmp_path)
    assert hooks_dir(r) == (r / ".git" / "hooks")


def test_hooks_dir_respects_core_hooks_path(tmp_path):
    r = _repo(tmp_path)
    (r / "custom-hooks").mkdir()
    _git(r, "config", "core.hooksPath", "custom-hooks")
    assert hooks_dir(r) == (r / "custom-hooks").resolve()


# --- install / uninstall -----------------------------------------------

def test_install_writes_both_gate_shims_with_marker_and_no_cr(tmp_path):
    r = _repo(tmp_path)
    install(r, Path("C:/py/python.exe"))
    pre_commit = r / ".git" / "hooks" / "pre-commit"
    pre_push = r / ".git" / "hooks" / "pre-push"
    assert pre_commit.exists() and pre_push.exists()
    pc_bytes = pre_commit.read_bytes()
    pp_bytes = pre_push.read_bytes()
    assert MARKER_START.encode() in pc_bytes
    assert MARKER_START.encode() in pp_bytes
    assert b"\r" not in pc_bytes
    assert b"\r" not in pp_bytes


def test_install_chains_foreign_pre_commit_hook(tmp_path):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    foreign_content = b"#!/bin/sh\necho foreign-hook-ran\n"
    (hdir / "pre-commit").write_bytes(foreign_content)

    install(r, Path("C:/py/python.exe"))

    chained = hdir / "pre-commit.aramid-chained"
    assert chained.exists()
    assert chained.read_bytes() == foreign_content
    shim_bytes = (hdir / "pre-commit").read_bytes()
    assert MARKER_START.encode() in shim_bytes
    assert b"pre-commit.aramid-chained" in shim_bytes


def test_install_is_idempotent_never_double_chains(tmp_path):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    foreign_content = b"#!/bin/sh\necho foreign-hook-ran\n"
    (hdir / "pre-commit").write_bytes(foreign_content)

    install(r, Path("C:/py/python.exe"))
    install(r, Path("C:/py/python.exe"))  # second install must not re-chain

    chained = hdir / "pre-commit.aramid-chained"
    assert chained.exists()
    assert chained.read_bytes() == foreign_content
    assert not (hdir / "pre-commit.aramid-chained.aramid-chained").exists()


def test_install_over_existing_aramid_shim_regenerates_in_place(tmp_path):
    r = _repo(tmp_path)
    install(r, Path("C:/py/python.exe"))
    install(r, Path("C:/other/python.exe"))  # re-init with a different interpreter
    shim_bytes = (r / ".git" / "hooks" / "pre-commit").read_bytes()
    assert win_sh_path(Path("C:/other/python.exe")).encode() in shim_bytes
    assert not (r / ".git" / "hooks" / "pre-commit.aramid-chained").exists()


def test_uninstall_removes_shim_and_restores_chained_original(tmp_path):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    foreign_content = b"#!/bin/sh\necho foreign-hook-ran\n"
    (hdir / "pre-commit").write_bytes(foreign_content)

    install(r, Path("C:/py/python.exe"))
    uninstall(r)

    assert (hdir / "pre-commit").read_bytes() == foreign_content
    assert not (hdir / "pre-commit.aramid-chained").exists()
    assert not (hdir / "pre-push").exists()


def test_uninstall_with_no_foreign_hook_just_removes_shim(tmp_path):
    r = _repo(tmp_path)
    install(r, Path("C:/py/python.exe"))
    uninstall(r)
    assert not (r / ".git" / "hooks" / "pre-commit").exists()
    assert not (r / ".git" / "hooks" / "pre-push").exists()


def test_uninstall_on_never_installed_repo_is_a_noop(tmp_path):
    r = _repo(tmp_path)
    uninstall(r)  # must not raise


def test_uninstall_does_not_clobber_live_foreign_hook_that_replaced_the_shim(tmp_path, capsys):
    """Guard: if a third-party hook manager (e.g. husky's `prepare` script)
    rewrites `<hook>` directly after aramid installed -- so a LIVE foreign
    hook (no aramid marker) now occupies the slot -- `uninstall()` must NOT
    overwrite it with the stale `.aramid-chained` original. It must leave
    the live foreign hook untouched and discard the orphaned backup."""
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    original_foreign = b"#!/bin/sh\necho original-foreign-hook\n"
    (hdir / "pre-commit").write_bytes(original_foreign)

    install(r, Path("C:/py/python.exe"))  # chains original_foreign into .aramid-chained

    chained = hdir / "pre-commit.aramid-chained"
    assert chained.exists()
    assert chained.read_bytes() == original_foreign

    # A third party overwrites aramid's shim directly -- no aramid marker,
    # aramid has no idea this happened.
    new_foreign = b"#!/bin/sh\necho new-foreign-hook-installed-by-husky\n"
    (hdir / "pre-commit").write_bytes(new_foreign)

    uninstall(r)

    assert (hdir / "pre-commit").read_bytes() == new_foreign, (
        "live foreign hook must be preserved, not clobbered by the stale chained backup"
    )
    assert not chained.exists(), "orphaned .aramid-chained backup must be discarded"
    assert "foreign hook" in capsys.readouterr().err
