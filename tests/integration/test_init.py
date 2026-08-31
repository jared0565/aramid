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

from aramid import agent_files, config as config_mod
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


def test_aramid_md_names_the_budget_keys_instead_of_hardcoding_them(tmp_path, monkeypatch):
    """ARAMID.md is rendered from a template that never sees the repo's
    config, so a literal "300s" in the budget table silently becomes a lie
    the moment a repo raises `[timeouts].pre_push` -- which aramid's own
    repo does. Name the key instead; it cannot drift."""
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    init.cmd_init(r)
    text = (r / "ARAMID.md").read_text(encoding="utf-8")

    assert "[timeouts].pre_push" in text
    assert "[timeouts].pre_commit" in text
    assert "| pre-push | 300s |" not in text
    assert "| pre-commit | 5s |" not in text


def test_aramid_md_documents_the_slow_suite_escape_hatch(tmp_path, monkeypatch):
    """tests is BLOCK-tier, so a suite slower than the gate budget blocks
    every push. The repo where an operator first hits that is exactly the
    repo they just ran `init` on -- so the fix has to be discoverable here,
    not only in the user guide."""
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    init.cmd_init(r)
    text = (r / "ARAMID.md").read_text(encoding="utf-8")

    assert "[tests]" in text
    assert "command" in text

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


def test_init_registers_repo_in_central_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    from aramid import registry
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "central" / "repos.toml")

    rc = init.cmd_init(r)

    assert rc == 0
    assert any(Path(e["path"]).resolve() == r.resolve() for e in registry.load_registry())


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
    lines = [ln for ln in gitignore_text.splitlines() if ln.strip()]
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

def test_scan_history_honours_committed_suppressions(tmp_path, monkeypatch):
    """A reviewed, committed `.aramid-suppressions.toml` entry must apply to the
    full-history scan, not only to gate runs.

    `_scan_history` applied the path-level ignore filter but never consulted
    `load_suppressions`, so the ONE mechanism aramid offers for a shared,
    reviewable "this is a fixture, not a credential" judgement was bypassed on
    exactly the path that produces those findings. The only remaining remedy
    was `ledger mark-not-a-secret`, which writes to the gitignored ledger and
    therefore cannot travel between clones -- so every new maintainer running
    `aramid init` re-discovered the same test fixtures as unrotated secrets.

    Measured on aramid's own repo before the fix: a fresh clone WITH a
    committed suppressions file still reported `historical: 10`.
    """
    r = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    cfg = config_mod.load_config(r)

    fixture_raw = RawFinding(tool="gitleaks", rule="generic-api-key", severity_raw="high",
                             file="tests/fixtures/creds.py", line=1, message="found a key",
                             secret="AKIAFAKEFAKEFAKEFAKE")
    real_raw = RawFinding(tool="gitleaks", rule="generic-api-key", severity_raw="high",
                          file="src/config.py", line=3, message="found a key",
                          secret="AKIAFAKEFAKEFAKEOTHER")
    monkeypatch.setattr(init.gitleaks_runner, "run",
                        lambda ctx: RunnerResult("gitleaks", ToolState.OK))
    monkeypatch.setattr(init.gitleaks_runner, "parse",
                        lambda result, ctx: [fixture_raw, real_raw])

    # Phase 1 -- learn the id the fixture finding actually gets, rather than
    # hard-coding a fingerprint that would rot the moment normalize() changes.
    ledger = _ledger(r)
    try:
        init._scan_history(r, ledger, cfg)
        ids = {e.payload["file"]: e.finding_id for e in ledger.events()
               if e.type.value == "finding_detected" and e.payload.get("historical")}
    finally:
        ledger.close()
    fixture_id = ids["tests/fixtures/creds.py"]

    # Phase 2 -- commit that judgement and rescan from a clean ledger.
    (r / ".aramid-suppressions.toml").write_text(
        "[[suppress]]\n"
        f'id = "{fixture_id}"\n'
        'tool = "gitleaks"\n'
        'rule = "generic-api-key"\n'
        'path = "tests/fixtures/creds.py"\n'
        'reason = "deliberate test fixture, not a live credential"\n',
        encoding="utf-8")
    (r / ".aramid" / "ledger.db").unlink()

    ledger = _ledger(r)
    try:
        count = init._scan_history(r, ledger, cfg)

        assert count == 1, "the suppressed fixture should not be recorded"
        files = [e.payload["file"] for e in ledger.events()
                 if e.type.value == "finding_detected" and e.payload.get("historical")]
        assert files == ["src/config.py"], files
    finally:
        ledger.close()


def test_scan_history_suppression_does_not_hide_unlisted_secrets(tmp_path, monkeypatch):
    """The other half: suppressing one finding must not blanket the scan. A
    secret with no committed entry still gets recorded, so this cannot become
    an accidental off switch for the history scan."""
    r = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    cfg = config_mod.load_config(r)

    real_raw = RawFinding(tool="gitleaks", rule="generic-api-key", severity_raw="high",
                          file="src/config.py", line=3, message="found a key",
                          secret="AKIAFAKEFAKEFAKEOTHER")
    monkeypatch.setattr(init.gitleaks_runner, "run",
                        lambda ctx: RunnerResult("gitleaks", ToolState.OK))
    monkeypatch.setattr(init.gitleaks_runner, "parse",
                        lambda result, ctx: [real_raw])
    # An entry for a DIFFERENT finding entirely.
    (r / ".aramid-suppressions.toml").write_text(
        "[[suppress]]\n"
        'id = "' + "0" * 64 + '"\n'
        'tool = "gitleaks"\n'
        'rule = "generic-api-key"\n'
        'path = "somewhere/else.py"\n'
        'reason = "unrelated"\n',
        encoding="utf-8")

    ledger = _ledger(r)
    try:
        assert init._scan_history(r, ledger, cfg) == 1
    finally:
        ledger.close()


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


# --- Task 7 follow-up: _validate_hook_shim must also cover the post-commit --
# triage shim (`hooks.TRIAGE_HOOK`), not just `hooks.GATES` -----------------
#
# Before this fix, `_validate_hook_shim` looped only `for gate in hooks.GATES`
# (pre-commit, pre-push) -- so a post-commit shim that silently failed to
# write would still let `init` print "hooks armed: yes". This test drives
# `_validate_hook_shim` directly (the `cmd_init` return code doesn't depend
# on `shim_ok` at all -- it only feeds the printed summary) so it actually
# exercises the change: run a real `cmd_init`, confirm the post-commit shim
# it wrote exists and carries aramid's marker, then delete it and confirm
# `_validate_hook_shim` now reports the repo as NOT fully armed.

def test_validate_hook_shim_detects_missing_post_commit_triage_shim(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    assert init.cmd_init(r) == 0

    post_commit = hooks.hooks_dir(r) / hooks.TRIAGE_HOOK
    assert post_commit.exists()
    assert hooks.MARKER_START.encode() in post_commit.read_bytes()
    assert init._validate_hook_shim(r) is True

    post_commit.unlink()

    assert init._validate_hook_shim(r) is False


def test_validate_hook_shim_accepts_a_foreign_managed_slot_with_relocated_shim(
        tmp_path, monkeypatch):
    """Regression: `hooks armed: NO` on every graphite-managed repo.

    Measured live against a real repo (operation-firewall, 2026-07-31) where
    graphite owns `post-commit`. `install()` deliberately refuses to clobber
    another tool's managed hook, relocates aramid's own shim to a sibling,
    and says so: "not stale, nothing to resolve". `_validate_hook_shim` then
    contradicted it three lines later, because it only checked whether the
    CANONICAL slot carried aramid's marker -- which a foreign-managed slot
    never does. Result: a fully-armed repo reported NOT armed, and the
    obvious operator "fix" is to clobber the other tool's hook.

    `hooks._find_chained_aramid_shim` already recognizes such a relocation
    generically (by marker content, not by hardcoding any suffix); this
    check simply has to consult it. The genuine-gap case must still fail --
    that is the next test, which stays green.
    """
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0

    hdir = hooks.hooks_dir(r)
    slot = hdir / hooks.TRIAGE_HOOK
    ours = slot.read_bytes()
    assert hooks.MARKER_START.encode() in ours

    # Exactly what graphite does: relocate aramid's shim under its own
    # suffix, then take the slot with its own managed trampoline.
    (hdir / f"{hooks.TRIAGE_HOOK}.local").write_bytes(ours)
    slot.write_bytes(b"#!/bin/sh\n# >>> graphite managed >>>\nexit 0\n")

    assert hooks._foreign_managed_tool(slot) == "graphite"
    assert hooks._find_chained_aramid_shim(hdir, hooks.TRIAGE_HOOK) is not None
    assert init._validate_hook_shim(r) is True


def test_validate_hook_shim_still_fails_when_slot_is_missing_despite_relocation(
        tmp_path, monkeypatch):
    """The third case (graphite, round 14): a relocated sibling is only
    reachable because a foreign tool's trampoline occupies the slot and
    chains to it. With the slot EMPTY there is nothing for git to dispatch,
    so the sibling never runs and this is a genuine gap -- the relocation
    must not be read as "armed" on its own. This is the case the round-12
    fix could most easily have got wrong by testing only for a surviving
    shim and not for something in the slot to reach it."""
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0

    hdir = hooks.hooks_dir(r)
    slot = hdir / hooks.TRIAGE_HOOK
    (hdir / f"{hooks.TRIAGE_HOOK}.local").write_bytes(slot.read_bytes())
    slot.unlink()

    assert hooks._find_chained_aramid_shim(hdir, hooks.TRIAGE_HOOK) is not None
    assert init._validate_hook_shim(r) is False


def test_validate_hook_shim_still_fails_when_foreign_slot_has_no_relocation(
        tmp_path, monkeypatch):
    """The other half: a foreign-managed slot with NO surviving aramid shim
    anywhere is a genuine gap, and must still report NOT armed. Without this,
    the fix above would turn the warning off for real breakage too."""
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0

    hdir = hooks.hooks_dir(r)
    slot = hdir / hooks.TRIAGE_HOOK
    slot.write_bytes(b"#!/bin/sh\n# >>> graphite managed >>>\nexit 0\n")

    assert hooks._find_chained_aramid_shim(hdir, hooks.TRIAGE_HOOK) is None
    assert init._validate_hook_shim(r) is False


def test_init_installs_hooks_on_a_configured_but_unenforced_repo(tmp_path, monkeypatch):
    """Regression: the fresh-clone deadlock.

    `aramid.toml` is committed, so a CLONE of an onboarded repo arrives with
    config and no hooks. doctor reports that as "configured but NOT enforced"
    and returns 2 -- and init's gate used to key on `cmd_doctor(root) != 0`,
    so init refused to install the very hooks whose absence caused the 2,
    while blaming a missing BLOCK-tier tool that was present. doctor's own
    remedy line says "run `aramid init .`", which could not work.

    All BLOCK-tier tools are present here; the ONLY unusual thing is the
    pre-existing aramid.toml. init must succeed and install the shims."""
    r = _repo(tmp_path)
    (r / "aramid.toml").write_text("# pre-existing, as a clone would have\n",
                                   encoding="utf-8")
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)

    rc = init.cmd_init(r)

    assert rc != 3, "init refused on the very state it exists to fix"
    assert (hooks.hooks_dir(r) / "pre-commit").exists()
    assert (hooks.hooks_dir(r) / "pre-push").exists()


# --- onboarding date is a historical fact, not a build stamp ----------------

def _onboarded(root: Path) -> str:
    import re
    m = re.search(r"^- \*\*Onboarded:\*\* (.+)$",
                  (root / "ARAMID.md").read_text(encoding="utf-8"), re.M)
    assert m is not None, "ARAMID.md has no Onboarded line"
    return m.group(1).strip()


def test_reinit_preserves_the_original_onboarding_date(tmp_path, monkeypatch):
    """`_render_aramid_md` stamps `date.today()`, and ARAMID.md is ALWAYS
    regenerated -- so every later `init` re-run silently overwrote a
    historical fact with a build stamp.

    Found in a consumer repo (operation-firewall), where a re-run moved
    "Onboarded" from 2026-07-30 to 2026-07-31; the ledger's earliest event
    proved the original right. aramid's own repo had been pinning its date
    with a unit test since it happened here twice -- but that test guards
    THIS repo only, so every consumer stayed exposed. Fixing it in `init`
    is the fix; that test becomes a second line of defence rather than the
    only one.

    Simulated by recording a past date and re-running, which is exactly the
    state a repo onboarded on any earlier day is in.
    """
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0

    md = r / "ARAMID.md"
    md.write_text(md.read_text(encoding="utf-8").replace(
        f"- **Onboarded:** {_onboarded(r)}", "- **Onboarded:** 2026-07-30"),
        encoding="utf-8")

    assert init.cmd_init(r) == 0

    assert _onboarded(r) == "2026-07-30"
    # ...and the file is still genuinely regenerated, not skipped.
    assert "## What aramid checks" in md.read_text(encoding="utf-8")


def test_first_init_stamps_today(tmp_path, monkeypatch):
    """The other side: with no ARAMID.md there is no history to preserve, so
    today IS the onboarding date. Without this, 'preserve' could be
    implemented as 'never write a date at all' and still pass above."""
    from datetime import date

    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0

    assert _onboarded(r) == date.today().isoformat()


def test_reinit_over_an_unparseable_aramid_md_falls_back_to_today(tmp_path, monkeypatch):
    """A hand-mangled ARAMID.md carries no date to preserve. Falling back to
    today is the only option, and it must not crash -- the existing
    idempotency test overwrites ARAMID.md with prose for exactly this
    reason."""
    from datetime import date

    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0
    (r / "ARAMID.md").write_text("stale hand-written notes\n", encoding="utf-8")

    assert init.cmd_init(r) == 0
    assert _onboarded(r) == date.today().isoformat()


def test_preserving_the_date_changes_nothing_else(tmp_path, monkeypatch):
    r"""The date substitution must rewrite the date and NOTHING else.

    Regression guard with a specific history: the first version of
    `_ONBOARDED_RE` ended `\s*$`, and `\s` matches newlines -- so under
    MULTILINE it ran past the end of its own line and `sub` deleted the blank
    line separating the header block from `## What aramid checks`. Every
    date-value assertion above stayed green while the file was quietly losing
    a line, which is why this asserts the SHAPE rather than the date.

    `aramid.commands.arm`'s key-rewrite family documents the same trap and
    solves it the same way ([^\S\n] instead of \s).
    """
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0

    md = r / "ARAMID.md"
    original = md.read_text(encoding="utf-8")
    md.write_text(original.replace(f"- **Onboarded:** {_onboarded(r)}",
                                   "- **Onboarded:** 2026-07-30"), encoding="utf-8")
    assert init.cmd_init(r) == 0

    before, after = original.splitlines(), md.read_text(encoding="utf-8").splitlines()
    assert len(before) == len(after), (
        f"line count changed ({len(before)} -> {len(after)}): the substitution "
        "consumed something beyond its own line")
    differing = [(a, b) for a, b in zip(before, after) if a != b]
    assert len(differing) == 1, f"expected only the date line to change, got {differing}"
    assert differing[0][1] == "- **Onboarded:** 2026-07-30"


# --- unrooted stacks: onboarding a repo whose gates cannot reach its code ---

def test_init_warns_when_a_stack_lives_below_the_root(tmp_path, monkeypatch, capsys):
    """Onboarding is where this matters most. detect_stacks keys "rust" off
    a ROOT Cargo.toml, so a repo whose crate is in `backend/` is onboarded
    with no rust stack at all -- ARAMID.md records that, aramid.toml is
    written from it, and every subsequent run is silently clean for Rust.
    The operator is standing right here when it happens; say so now rather
    than only on stderr of some later CI run nobody reads."""
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    _no_user_config(tmp_path, monkeypatch)
    r = _repo(tmp_path)
    crate = r / "backend"
    crate.mkdir()
    (crate / "Cargo.toml").write_text("[package]\nname = 'svc'\n", encoding="utf-8")

    rc = init.cmd_init(r)

    assert rc == 0                      # advisory only -- never blocks onboarding
    err = capsys.readouterr().err
    assert "backend/" in err
    assert "clippy, cargo-audit" in err


def test_init_is_quiet_for_an_ordinary_rooted_repo(tmp_path, monkeypatch, capsys):
    """Control: onboarding a plain Python repo must not emit this."""
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    _no_user_config(tmp_path, monkeypatch)
    r = _repo(tmp_path)

    assert init.cmd_init(r) == 0
    assert "are NOT running for this repo" not in capsys.readouterr().err


def test_reinit_still_warns_when_a_stack_lives_below_the_root(tmp_path, monkeypatch, capsys):
    """The case transitive coverage misses. init only calls run_gate when no
    baseline exists (step 7's `else`), so on a RE-init the notice printed by
    run_gate never fires -- and re-init is exactly when this is most likely
    to be new information, because the crate was probably added after the
    repo was first onboarded. The warning has to come from init itself."""
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    _no_user_config(tmp_path, monkeypatch)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0                    # onboard while still pure Python
    crate = r / "backend"
    crate.mkdir()
    (crate / "Cargo.toml").write_text("[package]\nname = 'svc'\n", encoding="utf-8")
    capsys.readouterr()                             # discard the first init's output

    rc = init.cmd_init(r)

    assert rc == 0
    out = capsys.readouterr()
    assert "baseline already exists" in out.out      # sanity: run_gate really was skipped
    assert "backend/" in out.err


# --- managed agent instruction blocks (agent-enforcement sub-project 1) -----

def test_init_writes_agent_blocks_and_reinit_is_byte_stable(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    assert init.cmd_init(r) == 0

    for name in ("CLAUDE.md", "AGENTS.md"):
        assert (r / name).read_text(encoding="utf-8") == agent_files.render_block()
    first = (r / "CLAUDE.md").read_bytes()

    assert init.cmd_init(r) == 0
    assert (r / "CLAUDE.md").read_bytes() == first


def test_init_appends_to_user_authored_claude_md(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    user_text = "# House rules\n\nAlways run the linter.\n"
    (r / "CLAUDE.md").write_text(user_text, encoding="utf-8")

    assert init.cmd_init(r) == 0

    text = (r / "CLAUDE.md").read_text(encoding="utf-8")
    assert text == user_text + "\n" + agent_files.render_block()
