import subprocess
import sys
from pathlib import Path

import pytest

from aramid.hooks import (
    MARKER_START,
    hooks_dir,
    install,
    render_shim,
    render_triage_shim,
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
#
# The drive-letter branch is only REACHABLE on Windows: `win_sh_path` re-casts
# its argument with `Path(p)` (hooks.py:49), and on POSIX `Path("C:\\x\\y")` is
# a single filename with an empty `.drive` -- there is no drive to convert, so
# the input never reaches that branch. Passing a `PureWindowsPath` does not
# help; the internal re-cast discards it.
#
# So the drive tests are win32-gated, and the pass-through branch -- the one
# that actually executes when hooks are installed on Linux/macOS -- gets its
# own test below, which previously had none.

_WIN_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="drive-letter branch is unreachable off Windows (Path() has no .drive there)")


@_WIN_ONLY
def test_win_sh_path_converts_drive_letter():
    assert win_sh_path(Path("C:\\x\\y")) == "/c/x/y"


@_WIN_ONLY
def test_win_sh_path_lowercases_drive_letter_and_handles_forward_slashes():
    assert win_sh_path(Path("D:/foo/bar.exe")) == "/d/foo/bar.exe"


@_WIN_ONLY
def test_win_sh_path_bare_drive_root():
    assert win_sh_path(Path("C:\\")) == "/c/"


def test_win_sh_path_passes_posix_paths_through_unchanged():
    """Runs EVERYWHERE, and is the branch that matters off Windows: installing
    hooks on Linux/macOS bakes `sys.executable` into the shim via this
    function, so a POSIX interpreter path must survive it untouched. Before
    the platform matrix this branch had no test at all -- the three tests
    above only covered the Windows half."""
    assert win_sh_path(Path("/usr/bin/python3")) == "/usr/bin/python3"
    assert win_sh_path(Path("/opt/py 3.14/bin/python")) == "/opt/py 3.14/bin/python"


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


# --- foreign-MANAGED hook (another tool's own trampoline) ------------------
#
# A hook already carrying SOME tool's `# >>> <tool> managed >>>` marker is not
# an ordinary foreign hook (a human's script, terminal once chained) -- it is
# itself a live trampoline that calls onward. Chaining it the same way as a
# plain foreign hook (rename-and-exec-first) means the OTHER tool's gate runs
# via the chain AND aramid's own new shim runs its own check afterward --
# double execution -- and later makes `uninstall()`'s restore put that live
# trampoline back in the hook slot while reporting success, silently leaving
# enforcement running. `install()` must refuse to chain a foreign-managed
# hook instead.

def test_install_refuses_to_chain_a_foreign_managed_hook(tmp_path, capsys):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    other_tool_hook = (
        b"#!/bin/sh\n# >>> graphite managed >>>\necho graphite-trampoline-ran\n"
        b"# <<< graphite managed <<<\n"
    )
    (hdir / "pre-commit").write_bytes(other_tool_hook)

    install(r, Path("C:/py/python.exe"))

    assert (hdir / "pre-commit").read_bytes() == other_tool_hook, (
        "a foreign-managed hook must be left completely untouched")
    assert not (hdir / "pre-commit.aramid-chained").exists(), (
        "must not chain (rename aside) a foreign-managed hook")
    err = capsys.readouterr().err
    assert "graphite" in err
    assert "pre-commit" in err


def test_install_refuses_to_chain_a_foreign_managed_post_commit_hook(tmp_path, capsys):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    other_tool_hook = b"#!/bin/sh\n# >>> graphite managed >>>\necho gt\n# <<< graphite managed <<<\n"
    (hdir / "post-commit").write_bytes(other_tool_hook)

    install(r, Path("C:/py/python.exe"))

    assert (hdir / "post-commit").read_bytes() == other_tool_hook
    assert not (hdir / "post-commit.aramid-chained").exists()
    assert "graphite" in capsys.readouterr().err


def test_install_softens_warning_when_a_chained_aramid_shim_survives(tmp_path, capsys):
    """After a foreign tool RELOCATES aramid's own shim byte-identically
    (e.g. graphite's `.local` convention: `.git/hooks/pre-commit` ->
    `.githooks/pre-commit.local`, unchanged) rather than wrapping it, aramid's
    own gate is still alive -- it just isn't refreshed in place. The stronger
    "NOT installed ... resolve manually" wording is wrong for that case: there
    is nothing to resolve. install() must detect the surviving sibling (by
    marker content, not by hardcoding any other tool's suffix) and soften the
    message instead of alarming over a fine situation."""
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    other_tool_hook = (
        b"#!/bin/sh\n# >>> graphite managed >>>\necho graphite-trampoline-ran\n"
        b"# <<< graphite managed <<<\n"
    )
    (hdir / "pre-commit").write_bytes(other_tool_hook)
    # The byte-identical relocated original -- still aramid's own shim.
    (hdir / "pre-commit.local").write_bytes(
        render_shim(Gate.PRE_COMMIT, Path("C:/py/python.exe"))
    )

    install(r, Path("C:/py/python.exe"))

    assert (hdir / "pre-commit").read_bytes() == other_tool_hook, (
        "still must not touch the foreign-managed hook itself")
    err = capsys.readouterr().err
    assert "graphite" in err
    assert "pre-commit" in err
    assert "resolve manually" not in err.lower() and "resolved manually" not in err.lower(), (
        "a surviving chained shim means there is nothing to manually resolve")
    assert "pre-commit.local" in err, (
        "should name the surviving sibling so the operator can confirm it")


def test_install_softens_warning_for_post_commit_when_local_shim_survives(tmp_path, capsys):
    """Same as above for TRIAGE_HOOK (post-commit) -- the one hook graphite's
    trigger set actually contends for, so this is the case that fires on
    every real graphite-migrated repo, not just a hypothetical."""
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    other_tool_hook = b"#!/bin/sh\n# >>> graphite managed >>>\necho gt\n# <<< graphite managed <<<\n"
    (hdir / "post-commit").write_bytes(other_tool_hook)
    (hdir / "post-commit.local").write_bytes(
        render_triage_shim(Path("C:/py/python.exe"))
    )

    install(r, Path("C:/py/python.exe"))

    assert (hdir / "post-commit").read_bytes() == other_tool_hook
    err = capsys.readouterr().err
    assert "graphite" in err
    assert "resolve manually" not in err.lower() and "resolved manually" not in err.lower()
    assert "post-commit.local" in err


def test_install_still_chains_a_genuinely_unmanaged_foreign_hook(tmp_path):
    """Regression guard: the refusal above must be specific to a MANAGED
    foreign hook (carries a marker) -- an ordinary foreign hook (no marker
    at all, e.g. a human-authored script) must still be chained exactly as
    before this fix."""
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    foreign_content = b"#!/bin/sh\necho plain-human-hook\n"
    (hdir / "pre-commit").write_bytes(foreign_content)

    install(r, Path("C:/py/python.exe"))

    chained = hdir / "pre-commit.aramid-chained"
    assert chained.exists()
    assert chained.read_bytes() == foreign_content
    assert MARKER_START.encode() in (hdir / "pre-commit").read_bytes()


def test_uninstall_warns_when_restoring_a_foreign_managed_chained_original(tmp_path, capsys):
    """Defense in depth for a repo that reached this state before the
    install()-side guard existed (or via any other route): if the
    `.aramid-chained` backup itself carries another tool's managed marker,
    `uninstall()` must still restore it (deleting it instead would silently
    break the OTHER tool's live hook) but must say out loud that it cannot
    verify aramid's own gate is fully gone -- never claim a silent, clean
    uninstall over a hook it does not fully understand."""
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    (hdir / "pre-push").write_bytes(render_shim(Gate.PRE_PUSH, Path("C:/py/python.exe")))
    other_tool_hook = (
        b"#!/bin/sh\n# >>> graphite managed >>>\necho gt\n# <<< graphite managed <<<\n"
    )
    (hdir / "pre-push.aramid-chained").write_bytes(other_tool_hook)

    uninstall(r)

    assert (hdir / "pre-push").read_bytes() == other_tool_hook, (
        "the other tool's live hook must still end up back in the slot")
    assert not (hdir / "pre-push.aramid-chained").exists()
    err = capsys.readouterr().err
    assert "graphite" in err
    assert "pre-push" in err


def test_hooks_dir_decodes_utf8_hooks_path(tmp_path):
    # git emits config values as UTF-8 regardless of host locale. Without
    # encoding="utf-8" in _git_config, cp1252 hosts mojibake a non-ASCII
    # core.hooksPath ("café" -> "cafÃ©") and hooks_dir resolves a wrong dir.
    r = _repo(tmp_path)
    with (r / ".git" / "config").open("a", encoding="utf-8") as f:
        f.write("[core]\n\thooksPath = hooks-café\n")
    assert hooks_dir(r) == (r / "hooks-café").resolve()


def test_install_writes_post_commit_shim_fail_open(tmp_path):
    r = _repo(tmp_path)
    install(r, Path("C:/py/python.exe"))
    shim = r / ".git" / "hooks" / "post-commit"
    assert shim.exists()
    raw = shim.read_bytes()
    assert MARKER_START.encode() in raw
    assert b"\r" not in raw
    text = raw.decode()
    assert "-m aramid triage HEAD --budget 15" in text
    # fail-open: the LAST executable line is an unconditional exit 0, and the
    # triage invocation itself cannot propagate a failure (|| true)
    assert "|| true" in text
    assert text.rstrip().endswith("exit 0")


def test_install_chains_foreign_post_commit_and_uninstall_restores(tmp_path):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    foreign = b"#!/bin/sh\necho foreign\n"
    (hdir / "post-commit").write_bytes(foreign)
    install(r, Path("C:/py/python.exe"))
    assert (hdir / "post-commit.aramid-chained").read_bytes() == foreign
    assert MARKER_START.encode() in (hdir / "post-commit").read_bytes()
    uninstall(r)
    assert (hdir / "post-commit").read_bytes() == foreign
    assert not (hdir / "post-commit.aramid-chained").exists()


# --- [hooks].pre_push_match_ci ---------------------------------------------
# The shim runs `check --gate pre-push` with NO scope flag, which
# cli._check_mode resolves to `range` -- only files changed against upstream.
# CI runs `--all --strict`. So a finding sitting in a file you did not touch
# is invisible locally and caught in CI, which is the main generator of
# "green on push, red on CI" here.
#
# OPT-IN, and the default must not move. Switching a repo from range to --all
# surfaces every previously-unscanned finding at once; those are ids the
# ledger has never seen, so the ratchet treats them as NEW and escalates them
# to BLOCK -- the first push after such a change would be blocked by findings
# the developer did not introduce. `aramid rebaseline` is the remedy, but it
# has to be a deliberate step, not a surprise inflicted by an upgrade.

def test_default_pre_push_shim_is_unchanged(tmp_path):
    """Regression guard for every existing consumer: with no config, the
    rendered bytes must be exactly what they were before this option."""
    default = render_shim(Gate.PRE_PUSH, Path("C:/py/python.exe")).decode()

    assert "-m aramid check --gate pre-push\n" in default
    assert "--all" not in default and "--strict" not in default
    assert "2) exit 0 ;;" in default


def test_match_ci_uses_the_same_argv_as_the_CI_step():
    data = render_shim(Gate.PRE_PUSH, Path("C:/py/python.exe"), match_ci=True).decode()

    assert "-m aramid check --gate pre-push --all --strict" in data


def test_shim_tells_the_gate_that_git_is_on_stdin():
    """`ARAMID_HOOK=<gate>` on BOTH interpreter arms. The gate reads the
    pre-push ref lines git writes to the hook's stdin only under that
    marker: by hand and in CI the process has an empty non-tty stdin too,
    and reading it there would turn CI's pre-push-tier run into "nothing
    to push" (interop round 176; spec 4.1)."""
    for match_ci in (False, True):
        data = render_shim(Gate.PRE_PUSH, Path("C:/py/python.exe"), match_ci=match_ci).decode()
        assert 'ARAMID_HOOK=pre-push "$INTERP" -P -m aramid check --gate pre-push' in data
        assert "ARAMID_HOOK=pre-push py -3 -P -m aramid check --gate pre-push" in data
    commit = render_shim(Gate.PRE_COMMIT, Path("C:/py/python.exe")).decode()
    assert 'ARAMID_HOOK=pre-commit "$INTERP" -P -m aramid check --gate pre-commit' in commit
    # The global template shim invokes the gate as a hook too.
    from aramid.hooks import render_template_shim
    tmpl = render_template_shim(Gate.PRE_PUSH, Path("C:/py/python.exe")).decode()
    assert 'ARAMID_HOOK=pre-push "$INTERP" -P -m aramid check --gate pre-push' in tmpl
    assert "ARAMID_HOOK=pre-push py -3 -P -m aramid check --gate pre-push" in tmpl


def test_match_ci_stops_swallowing_a_degraded_run():
    """`2) exit 0` is what makes the hook weaker than CI for a WARN-tier
    degradation. A BLOCK-tier degradation already exits 1 via
    policy.escalate_degraded, so only exit 2 was ever being softened -- but
    "couldn't tell" still must not read as "passed" when the point of the
    option is CI parity."""
    data = render_shim(Gate.PRE_PUSH, Path("C:/py/python.exe"), match_ci=True).decode()

    assert "2) exit 0" not in data
    assert 'exit "$status"' in data


def test_match_ci_does_not_touch_the_pre_commit_shim():
    """pre-commit is the fast local filter and maps BOTH 2 and 3 to 0 by
    design; CI parity is a statement about the pre-push gate only."""
    on = render_shim(Gate.PRE_COMMIT, Path("C:/py/python.exe"), match_ci=True)
    off = render_shim(Gate.PRE_COMMIT, Path("C:/py/python.exe"))

    assert on == off


def test_install_reads_the_option_from_the_repo_config(tmp_path):
    root = tmp_path / "r"
    (root / ".git" / "hooks").mkdir(parents=True)
    (root / "aramid.toml").write_text(
        "[hooks]\npre_push_match_ci = true\n", encoding="utf-8")

    install(root, Path(sys.executable))

    body = (root / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert "--all --strict" in body
    # ...and the pre-commit shim beside it is untouched by the option
    pc = (root / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert "--all" not in pc


def test_install_defaults_to_the_narrow_shim_without_config(tmp_path):
    root = tmp_path / "r2"
    (root / ".git" / "hooks").mkdir(parents=True)

    install(root, Path(sys.executable))

    body = (root / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert "--all" not in body


def _stale(shim: bytes) -> bytes:
    """A genuine aramid-managed shim from BEFORE the round-57 `-P` fix:
    identical to what the current template emits except for the guard. Built
    by removing `-P` from the live template rather than pasting a literal, so
    it cannot drift into testing a shape the generator never produced."""
    out = shim.replace(b" -P -m aramid", b" -m aramid")
    assert out != shim, "fixture must actually differ from the current template"
    return out


_FOREIGN = (b"#!/bin/sh\n# >>> graphite managed >>>\necho gt\n"
            b"# <<< graphite managed <<<\n")


def test_install_regenerates_a_stale_relocated_triage_shim_in_place(tmp_path):
    """The relocated shim is aramid's OWN file, and `install()` skipping it
    means it can never receive a template fix for as long as the other tool
    occupies the slot -- so the round-57 `-P` guard never reaches it. Refusing
    the FOREIGN slot is correct and must stay; refusing to refresh aramid's own
    relocated sibling was a consequence of the slot-level skip, not the intent.
    Interop round 112."""
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    interp = Path("C:/py/python.exe")
    current = render_triage_shim(interp)
    (hdir / "post-commit").write_bytes(_FOREIGN)
    (hdir / "post-commit.local").write_bytes(_stale(current))

    install(r, interp)

    assert (hdir / "post-commit").read_bytes() == _FOREIGN, (
        "the foreign-managed slot itself must STILL be left untouched")
    assert (hdir / "post-commit.local").read_bytes() == current, (
        "aramid's own relocated shim must be regenerated to the current template")


def test_install_regenerates_a_stale_relocated_gate_shim_in_place(tmp_path):
    """Same property for a GATE slot, so the fix is not triage-specific."""
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    interp = Path("C:/py/python.exe")
    current = render_shim(Gate.PRE_COMMIT, interp)
    (hdir / "pre-commit").write_bytes(_FOREIGN)
    (hdir / "pre-commit.local").write_bytes(_stale(current))

    install(r, interp)

    assert (hdir / "pre-commit").read_bytes() == _FOREIGN
    assert (hdir / "pre-commit.local").read_bytes() == current


def test_install_does_not_claim_a_regenerated_shim_was_never_stale(tmp_path, capsys):
    """The notice used to assert `not stale, nothing to resolve` from a check
    that only established the shim was still ARMED. Arming and staleness are
    different questions, and answering the second with the first is what hid a
    pre-`-P` shim on every commit in every graphite-managed repo."""
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    interp = Path("C:/py/python.exe")
    (hdir / "post-commit").write_bytes(_FOREIGN)
    (hdir / "post-commit.local").write_bytes(_stale(render_triage_shim(interp)))

    install(r, interp)

    err = capsys.readouterr().err
    assert "not stale" not in err.lower(), (
        "it WAS stale -- the notice must not assert otherwise")
    assert "post-commit.local" in err, "still must name the sibling it acted on"


def test_install_never_regenerates_the_chained_sibling_into_itself(tmp_path):
    """`<hook>.aramid-chained` is what a shim EXECS. Writing a shim into it
    would make it exec itself -- an unbounded loop on every commit. It matches
    the same `startswith(hook)` + aramid-marker test as a relocation, so the
    regeneration must exclude it explicitly."""
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    interp = Path("C:/py/python.exe")
    victim = _stale(render_triage_shim(interp))
    (hdir / "post-commit").write_bytes(_FOREIGN)
    (hdir / "post-commit.aramid-chained").write_bytes(victim)

    install(r, interp)

    assert (hdir / "post-commit.aramid-chained").read_bytes() == victim, (
        "must not rewrite the exec target into a self-referential shim")


def test_install_does_not_call_an_unrefreshable_stale_shim_current(
        tmp_path, capsys, monkeypatch):
    """Regeneration is best-effort -- a read-only or locked file must not fail
    the whole install. But "we could not rewrite it" and "it did not need
    rewriting" are different facts, and reporting the first as the second is
    the SAME lie this change set exists to remove: the operator is told the
    shim is current while a pre-`-P` shim keeps firing on every commit."""
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    interp = Path("C:/py/python.exe")
    stale = _stale(render_triage_shim(interp))
    (hdir / "post-commit").write_bytes(_FOREIGN)
    (hdir / "post-commit.local").write_bytes(stale)

    real_write = Path.write_bytes

    def refuse(self, data):
        if self.name == "post-commit.local":
            raise OSError("read-only file system")
        return real_write(self, data)

    monkeypatch.setattr(Path, "write_bytes", refuse)
    install(r, interp)

    assert (hdir / "post-commit.local").read_bytes() == stale, (
        "precondition: the write really was refused, so it is still stale")
    err = capsys.readouterr().err
    assert "already current" not in err, (
        "it is stale and we failed to fix it -- must not report it as current")
    assert "post-commit.local" in err
