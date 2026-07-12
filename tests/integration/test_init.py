"""integration: `aramid init` -- onboarding orchestration.

gitleaks/semgrep/ruff are not real, invokable binaries in this dev/CI
environment (verified: `shutil.which` returns None for all three here, and
`aramid.runners.base.run_subprocess` gates on exactly that check) -- every
real runner therefore degrades to MISSING during these tests, contributing
zero findings. Tests below assert the onboarding *mechanics* (artifacts,
hook shim, ledger baseline existence, idempotency) rather than any specific
finding being detected; the `.py` file containing `exec()` in `_repo()`
mirrors the brief's bait scenario ("doesn't crash on a realistic repo"), not
a claim that it is actually caught by a degraded/missing tool here.

The doctor gate itself is monkeypatched present (`doctor.probe_toolchain`)
per the brief -- this is the one thing that must be faked for `cmd_init` to
get past step 3 at all; everything downstream tolerates real tools being
absent by design (graceful MISSING degradation, proven elsewhere by the
pipeline/runner test suites).
"""
import subprocess
import sys
from pathlib import Path

from aramid import hooks
from aramid.commands import doctor, init
from aramid.ledger import Ledger


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _repo(tmp_path, name="repo") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "app.py").write_text("def run(cmd):\n    exec(cmd)\n", encoding="utf-8")
    _git(r, "add", "app.py")
    _git(r, "commit", "-q", "-m", "seed")
    return r


def _fake_present(root):
    return {
        "gitleaks": doctor.ToolStatus("gitleaks", True, "8.21.2"),
        "semgrep": doctor.ToolStatus("semgrep", True, "1.100.0"),
        "ruff": doctor.ToolStatus("ruff", True, "0.6.0"),
        "pip-audit": doctor.ToolStatus("pip-audit", True, "2.7.0"),
        "interpreter": doctor.ToolStatus("interpreter", True, sys.executable),
    }


def _ledger(root) -> Ledger:
    return Ledger(root / ".aramid" / "ledger.db")


# --- core onboarding scenario (brief step 1) --------------------------------

def test_init_arms_a_fresh_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    rc = init.cmd_init(r)

    assert rc == 0
    assert (r / "aramid.toml").exists()
    assert (r / "ARAMID.md").exists()

    gitignore_text = (r / ".gitignore").read_text(encoding="utf-8")
    for entry in (".aramid/", "graph-out/", ".graphite*", ".cache/"):
        assert entry in gitignore_text

    shim = r / ".git" / "hooks" / "pre-commit"
    assert shim.exists()
    assert hooks.MARKER_START.encode() in shim.read_bytes()
    push_shim = r / ".git" / "hooks" / "pre-push"
    assert push_shim.exists()
    assert hooks.MARKER_START.encode() in push_shim.read_bytes()

    ledger = _ledger(r)
    try:
        assert ledger.has_baseline()
    finally:
        ledger.close()


def test_init_refuses_non_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    not_repo = tmp_path / "not-a-repo"
    not_repo.mkdir()

    rc = init.cmd_init(not_repo)

    assert rc == 3
    assert not (not_repo / "aramid.toml").exists()


def test_init_refuses_to_arm_hooks_when_block_tier_tool_missing(tmp_path, monkeypatch):
    def fake_probe(root):
        statuses = _fake_present(root)
        statuses["gitleaks"] = doctor.ToolStatus("gitleaks", False, detail="not found")
        return statuses

    monkeypatch.setattr(doctor, "probe_toolchain", fake_probe)
    r = _repo(tmp_path)

    rc = init.cmd_init(r)

    assert rc == 3
    # full abort, no half-init: nothing written at all, hooks not installed.
    assert not (r / "aramid.toml").exists()
    assert not (r / "ARAMID.md").exists()
    assert not (r / ".git" / "hooks" / "pre-commit").exists()


# --- idempotency contract (brief global constraints) ------------------------

def test_second_init_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    assert init.cmd_init(r) == 0

    toml_path = r / "aramid.toml"
    edited = toml_path.read_text(encoding="utf-8") + '\ntest_command = "pytest -k smoke"\n'
    toml_path.write_text(edited, encoding="utf-8")

    (r / "ARAMID.md").write_text("stale hand-written notes\n", encoding="utf-8")

    ledger = _ledger(r)
    try:
        baseline_before = ledger.baseline_ids()
        baseline_events_before = sum(
            1 for e in ledger.events() if e.type.value == "baseline_snapshot")
    finally:
        ledger.close()

    rc = init.cmd_init(r)
    assert rc == 0

    # user-edited aramid.toml key survives re-init untouched.
    assert 'test_command = "pytest -k smoke"' in toml_path.read_text(encoding="utf-8")

    # ARAMID.md is always regenerated -- stale hand-edits are gone.
    md_text = (r / "ARAMID.md").read_text(encoding="utf-8")
    assert "stale hand-written notes" not in md_text

    # .gitignore has no duplicate lines and each mandated entry appears once.
    gitignore_text = (r / ".gitignore").read_text(encoding="utf-8")
    lines = [l for l in gitignore_text.splitlines() if l.strip()]
    assert len(lines) == len(set(lines))
    assert gitignore_text.count(".aramid/") == 1

    # baseline is written once, never rewritten by a later init.
    ledger = _ledger(r)
    try:
        baseline_after = ledger.baseline_ids()
        baseline_events_after = sum(
            1 for e in ledger.events() if e.type.value == "baseline_snapshot")
    finally:
        ledger.close()
    assert baseline_after == baseline_before
    assert baseline_events_after == baseline_events_before == 1


# --- scope subpath + nested .git exclusion (brief step 2) -------------------

def test_init_records_scope_subpath_when_target_is_subdir(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    sub = r / "sub"
    sub.mkdir()
    (sub / "b.py").write_text("y = 2\n", encoding="utf-8")

    rc = init.cmd_init(sub)

    assert rc == 0
    toml_text = (r / "aramid.toml").read_text(encoding="utf-8")
    assert 'scope_subpath = "sub"' in toml_text
    # hooks always install at the TRUE root, never inside the subdir.
    assert (r / ".git" / "hooks" / "pre-commit").exists()
    assert not (sub / ".git").exists()


def test_init_excludes_nested_git_dirs_from_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    nested = r / "vendor" / "sub"
    nested.mkdir(parents=True)
    _git(nested, "init", "-q", "-b", "main")

    rc = init.cmd_init(r)

    assert rc == 0
    toml_text = (r / "aramid.toml").read_text(encoding="utf-8")
    assert "vendor/sub" in toml_text


# --- --discover (brief: walk target, marker-based, skip ignore dirs) --------

def test_discover_finds_and_inits_multiple_repos_and_skips_non_repos(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    base = tmp_path / "base"
    base.mkdir()

    repo_a = _repo(base, name="repo-a")

    (base / "node_modules" / "pkg").mkdir(parents=True)
    not_repo = base / "just-a-folder"
    not_repo.mkdir()

    rc = init.cmd_init(base, discover=True)

    assert rc == 0
    assert (repo_a / "aramid.toml").exists()
    assert not (not_repo / "aramid.toml").exists()
    assert not (base / "node_modules" / "aramid.toml").exists()
