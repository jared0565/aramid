"""Global git-template shims (`aramid hooks install`).

Git copies `init.templateDir`'s hooks into EVERY new `git init` / `git clone`,
so unlike the per-repo shims these land in repos nobody onboarded. The whole
point of the variant is therefore its opt-in guard: no `aramid.toml` at the
repo root -> exit 0 without invoking the gate at all.

These tests execute the rendered shim with a real `sh` and a fake interpreter
that drops a marker file, so they assert what the shim DOES, not what its bytes
contain -- a text assertion would pass on a shim whose guard never runs.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

from aramid import hooks
from aramid.models import Gate

_SH = shutil.which("sh")
pytestmark = pytest.mark.skipif(_SH is None, reason="needs `sh` to execute a shim")


def _repo(tmp_path, onboarded: bool):
    r = tmp_path / ("on" if onboarded else "off")
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r,
                   check=True, capture_output=True)
    if onboarded:
        (r / "aramid.toml").write_text("[tool]\n", encoding="utf-8")
    return r


def _fake_interp(tmp_path, marker: Path) -> Path:
    """An executable stand-in for the baked python. If the guard lets the
    gate through, this runs and the marker appears; if the guard no-ops,
    it never runs and the marker stays absent. That absence IS the assertion."""
    p = tmp_path / "fake_interp.sh"
    p.write_bytes(b'#!/bin/sh\necho ran > "' +
                  hooks.win_sh_path(marker).encode() + b'"\nexit 0\n')
    p.chmod(0o755)
    return p


def _run_shim(root: Path, gate: Gate, interpreter: Path):
    shim = root / "shim.sh"
    shim.write_bytes(hooks.render_template_shim(gate, interpreter))
    shim.chmod(0o755)
    return subprocess.run([_SH, str(shim)], cwd=str(root),
                          capture_output=True, text=True)


def test_template_shim_no_ops_in_repo_without_aramid_toml(tmp_path):
    """The case that makes the template safe to install machine-wide."""
    root = _repo(tmp_path, onboarded=False)
    marker = tmp_path / "ran.txt"
    cp = _run_shim(root, Gate.PRE_COMMIT, _fake_interp(tmp_path, marker))

    assert cp.returncode == 0, cp.stderr
    assert not marker.exists(), "gate ran in a repo that was never onboarded"


def test_template_shim_runs_gate_when_aramid_toml_present(tmp_path):
    """The counterfactual: without it, the test above would pass on a shim
    that no-ops unconditionally (i.e. on a guard that is simply broken)."""
    root = _repo(tmp_path, onboarded=True)
    marker = tmp_path / "ran.txt"
    cp = _run_shim(root, Gate.PRE_COMMIT, _fake_interp(tmp_path, marker))

    assert cp.returncode == 0, cp.stderr
    assert marker.exists(), "onboarded repo did not reach the gate"


def test_template_shim_exits_zero_outside_a_git_repo(tmp_path):
    """`git rev-parse` fails here; the shim must fail OPEN, never non-zero --
    a template hook that errors would break unrelated repos machine-wide."""
    root = tmp_path / "bare"
    root.mkdir()
    marker = tmp_path / "ran.txt"
    cp = _run_shim(root, Gate.PRE_COMMIT, _fake_interp(tmp_path, marker))

    assert cp.returncode == 0, cp.stderr
    assert not marker.exists()


def test_pre_push_variant_is_guarded_too(tmp_path):
    """pre-push carries the BLOCK-capable exit mapping, so an unguarded one
    could actually reject a push in an un-onboarded repo."""
    root = _repo(tmp_path, onboarded=False)
    marker = tmp_path / "ran.txt"
    cp = _run_shim(root, Gate.PRE_PUSH, _fake_interp(tmp_path, marker))

    assert cp.returncode == 0, cp.stderr
    assert not marker.exists()


def test_install_template_writes_both_shims_into_hooks_subdir(tmp_path):
    """git looks for `<templateDir>/hooks/<name>`, not `<templateDir>/<name>`."""
    written = hooks.install_template(tmp_path / "tpl", Path("/usr/bin/python3"))

    hdir = tmp_path / "tpl" / "hooks"
    assert (hdir / "pre-commit").exists()
    assert (hdir / "pre-push").exists()
    assert set(written) == {hdir / "pre-commit", hdir / "pre-push"}
    for p in written:
        assert p.read_bytes().startswith(b"#!/bin/sh\n")
        assert b"\r\n" not in p.read_bytes(), "CRLF would break the sh shebang"


def test_installed_template_shims_carry_the_guard(tmp_path):
    """Ties install_template to the guarded renderer -- catches a future edit
    that wires install_template to render_shim (the UNguarded variant)."""
    hooks.install_template(tmp_path / "tpl", Path("/usr/bin/python3"))
    body = (tmp_path / "tpl" / "hooks" / "pre-commit").read_bytes()
    assert b"aramid.toml" in body, "installed template shim has no opt-in guard"
