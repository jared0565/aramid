"""integration: FN-32 -- the pre-push gate runs ruff over the pushed range.

ruff used to run only at pre-commit, over the staged files. A commit that
never went through that hook (`git commit --no-verify`, a commit made in a
clone without the hooks, a commit made before `aramid init`) therefore
reached the push with nothing local ever having linted it: the pre-push
gate's own runner list had no ruff in it. Measured 2026-10-08 under 0.20.5:
`check --gate pre-push --all --strict --json` over a committed S105 read
rc 0.

These tests run the REAL runner list (`GATE_RUNNER_KEYS[Gate.PRE_PUSH]`, never
patched) and the REAL ruff, and swap every OTHER pre-push runner for a clean
double, so the only thing that can produce a finding is ruff -- and ruff can
only produce one if the pre-push list names it. Each repo has a real bare
origin, so the gate resolves a genuine `@{u}..HEAD` range rather than the
new-repo full scan.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import config as config_mod
from aramid import pipeline
from aramid.commands.check import cmd_check
from aramid.models import Gate
from aramid.runners.base import RunnerResult, ToolState


def _find_tool(name: str) -> Path | None:
    # Same search as test_prepush_new_repo_full_scan.py: ruff installs into
    # the interpreter's per-user Scripts dir here, which is not on PATH.
    candidates: list[Path] = []
    which = shutil.which(name)
    if which:
        candidates.append(Path(which))
    exe_dir = Path(sys.executable).parent
    candidates.append(exe_dir / "Scripts" / f"{name}.exe")
    candidates.append(exe_dir / name)
    for entry in sys.path:
        p = Path(entry)
        if p.name == "site-packages":
            candidates.append(p.parent / "Scripts" / f"{name}.exe")
            candidates.append(p.parent / "bin" / name)
    for c in candidates:
        if c.exists():
            return c
    return None


_RUFF_BIN = _find_tool("ruff")
pytestmark = pytest.mark.skipif(_RUFF_BIN is None, reason="ruff console-script not found")


@pytest.fixture
def live_ruff(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(_RUFF_BIN.parent) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")


@pytest.fixture
def only_ruff_is_real(monkeypatch):
    """Every pre-push runner except ruff becomes a clean no-op. The list itself
    is left alone: patching it would test the patch, not the gate."""
    for key in pipeline.GATE_RUNNER_KEYS[Gate.PRE_PUSH]:
        if key != "ruff":
            monkeypatch.setitem(pipeline.RUNNERS, key, SimpleNamespace(
                run=lambda ctx, _k=key: RunnerResult(_k, ToolState.OK),
                parse=lambda result, ctx: []))


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True, text=True)


def _pushed_repo(tmp_path: Path) -> Path:
    """A repo with an upstream: one Python file already pushed to a bare
    origin, so the next gate run scans `@{u}..HEAD` and nothing else."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)],
                   check=True, capture_output=True, text=True)
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    (root / "seed.py").write_text("X = 1\n", encoding="utf-8")
    _git(root, "add", "seed.py")
    _git(root, "commit", "-q", "-m", "seed")
    _git(root, "remote", "add", "origin", str(origin))
    _git(root, "push", "-q", "-u", "origin", "main")
    return root


def _commit(root: Path, name: str, text: str) -> None:
    # No hook runs here: these repos have none, which is exactly the state of a
    # commit that skipped the pre-commit gate.
    (root / name).write_text(text, encoding="utf-8")
    _git(root, "add", name)
    _git(root, "commit", "-q", "-m", f"add {name}")


def _push_gate(root: Path) -> tuple[int, dict]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_check(root, Gate.PRE_PUSH, "range", as_json=True)
    return rc, json.loads(buf.getvalue())


def _ruff(payload: dict) -> list[dict]:
    return [f for f in payload["findings"] if f["tool"] == "ruff"]


def test_a_clean_python_commit_passes_the_push_gate_with_ruff_having_run(
        tmp_path, live_ruff, only_ruff_is_real):
    """The control: ruff runs at pre-push and a clean range passes. Without
    `ruff` in `tools_ran` the two refusals below could not be told apart from
    a gate that never looked."""
    root = _pushed_repo(tmp_path)
    _commit(root, "clean.py", "VALUE = 2\n")

    rc, payload = _push_gate(root)

    assert rc == 0, payload
    assert "ruff" in payload["tools_ran"], payload["tools_ran"]
    assert _ruff(payload) == []


def test_a_hookless_commit_with_a_hardcoded_password_is_refused_at_push(
        tmp_path, live_ruff, only_ruff_is_real):
    """S105 is in the curated BLOCK set. A commit that skipped the pre-commit
    hook used to carry it through the push untouched."""
    root = _pushed_repo(tmp_path)
    _commit(root, "clean.py", "VALUE = 2\n")
    assert _push_gate(root)[0] == 0          # writes this ledger's baseline
    _git(root, "push", "-q", "origin", "main")

    _commit(root, "creds.py", 'password = "hunter2-very-secret"\n')
    rc, payload = _push_gate(root)

    s105 = [f for f in _ruff(payload) if f["rule"] == "S105"]
    assert rc == 1, payload
    assert s105 and all(f["verdict"] == "block" and f["file"] == "creds.py" for f in s105), \
        _ruff(payload)
    assert not any(f.get("escalated_by_ratchet") for f in s105), \
        "S105 is an intrinsic BLOCK, not a ratchet escalation"


def test_a_ruff_warning_already_in_the_tree_at_init_does_not_block_the_first_push(
        tmp_path, monkeypatch, live_ruff, only_ruff_is_real):
    """Day one. A repo onboards with a ruff WARN already committed and not yet
    pushed. `aramid init` writes its baseline from a `Gate.ALL` run, which has
    included ruff since 0.7.0, so the warning is seen before the push gate
    ever runs: it stays a WARN there and the push passes. If init's baseline
    ever stops covering ruff, every such repo's first push after upgrading
    is refused on a warning nobody introduced in it."""
    from aramid.commands import doctor, init

    root = _pushed_repo(tmp_path)
    _commit(root, "unused.py", "import os\n")       # before init: no hooks yet
    monkeypatch.setattr(doctor, "probe_toolchain", lambda r: {
        name: doctor.ToolStatus(name, True, "1") for name in
        ("gitleaks", "semgrep", "ruff", "pip-audit")} | {
        "interpreter": doctor.ToolStatus("interpreter", True, sys.executable)})
    assert init.cmd_init(root) == 0

    rc, payload = _push_gate(root)

    f401 = [f for f in _ruff(payload) if f["rule"] == "F401"]
    assert f401, "the push gate never linted unused.py -- this test would pass by looking at nothing"
    assert rc == 0, payload
    assert all(f["verdict"] == "warn" and not f.get("escalated_by_ratchet") for f in f401), f401


def test_a_new_ruff_warning_first_seen_at_push_is_escalated_by_the_ratchet(
        tmp_path, live_ruff, only_ruff_is_real):
    """F401 is WARN-tier. Seen first at pre-commit it would stay a WARN there
    and be "seen" by the push. Seen first at the push -- the commit skipped the
    hook -- it is a new warning, and the no-new-warnings ratchet escalates it
    exactly as it does clippy's: a lint the author wrote and can fix."""
    root = _pushed_repo(tmp_path)
    _commit(root, "clean.py", "VALUE = 2\n")
    assert _push_gate(root)[0] == 0          # writes this ledger's baseline
    _git(root, "push", "-q", "origin", "main")

    _commit(root, "unused.py", "import os\n")
    rc, payload = _push_gate(root)

    f401 = [f for f in _ruff(payload) if f["rule"] == "F401"]
    assert rc == 1, payload
    assert f401 and all(f["verdict"] == "block" and f.get("escalated_by_ratchet")
                        and f.get("verdict_before_ratchet") == "warn" for f in f401), f401
