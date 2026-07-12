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

from aramid import config as config_mod
from aramid import hooks
from aramid.commands import doctor, init
from aramid.ledger import Ledger
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState


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


def _no_user_config(tmp_path, monkeypatch) -> None:
    """Never let a test read a real ~/.aramid/config.toml off this machine."""
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")


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


# --- MUST-FIX 2 (.superpowers/sdd/final-review.md §8b) -- history scan ------
# ignores graphite artifact paths ------------------------------------------
#
# `_scan_history` (the full-history gitleaks pass) previously passed its raw
# findings straight into `normalize()` with no ignore-path filtering at all
# -- unlike `pipeline.run_gate`, which applies `config.is_ignored` to every
# raw finding before it is ever fingerprinted/recorded (spec §8b: graphite
# artifacts are NEVER scanned/fingerprinted/recorded, in any mode). A hit
# gitleaks reports under graph-out/ (plausible: graph JSON can contain
# long hex/hash-like strings that trip entropy-based secret detectors) would
# have been recorded as a `historical: true` `finding_detected` ledger event
# -- exactly the "ledger noise from generated graph JSON" §8b calls a hard
# requirement to avoid. gitleaks itself is not installed on this machine
# (see the module docstring above) -- `gitleaks_runner.run`/`.parse` are
# faked directly, driving `_scan_history` itself rather than the full
# `cmd_init` orchestration.

def test_scan_history_drops_findings_under_ignored_graphite_paths(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    cfg = config_mod.load_config(r)
    ledger = _ledger(r)

    ignored_raw = RawFinding(tool="gitleaks", rule="generic-api-key", severity_raw="high",
                              file="graph-out/leak.json", line=1, message="found a key",
                              secret="AKIAFAKEFAKEFAKEFAKE")
    normal_raw = RawFinding(tool="gitleaks", rule="generic-api-key", severity_raw="high",
                             file="src/config.py", line=3, message="found a key",
                             secret="AKIAFAKEFAKEFAKEOTHER")

    monkeypatch.setattr(init.gitleaks_runner, "run",
                         lambda ctx: RunnerResult("gitleaks", ToolState.OK))
    monkeypatch.setattr(init.gitleaks_runner, "parse",
                         lambda result, ctx: [ignored_raw, normal_raw])

    try:
        count = init._scan_history(r, ledger, cfg)

        assert count == 1  # only the normal-path finding survives the filter

        historical_events = [
            e for e in ledger.events()
            if e.type.value == "finding_detected" and e.payload.get("historical")
        ]
        assert len(historical_events) == 1
        assert historical_events[0].payload["file"] == "src/config.py"
        assert not any(
            e.payload.get("file", "").startswith("graph-out/") for e in historical_events), \
            historical_events
    finally:
        ledger.close()
