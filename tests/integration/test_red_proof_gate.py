"""Real-git integration for red_proof (sub-project 3): producer-level tests
on real repos (mirrors tests/integration/test_tdd_gate.py), a run_gate-level
ratchet-exemption test (mirrors test_pipeline.py's tdd exemption test -- the
only layer where a missing exemption genuinely flips the exit code; the
fresh-clone downgrade masks it at cmd_check level), and cmd_check e2e for
arming/fresh-clone (1b/2b pattern: GATE_RUNNER_KEYS emptied so the exit
code reflects only the gate producers)."""
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import config as config_mod
from aramid import gitutil, pipeline, red_proof
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import Gate, Verdict
from aramid.normalizer import RawFinding
from aramid.runners.base import RunContext


def _no_runners(monkeypatch):
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True,
                   capture_output=True, text=True)


def _repo_with_upstream(tmp_path) -> Path:
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True,
                   capture_output=True, text=True)
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "tests").mkdir()
    (r / "src" / "foo.py").write_text("def foo():\n    return 1\n",
                                      encoding="utf-8")
    # NOTE: fixture test bodies insert os.getcwd() -- run_subprocess runs
    # pytest with cwd = the worktree, so this resolves `from src.foo import
    # foo` against the tree under test (base or head) regardless of pytest's
    # own rootdir/sys.path insertion rules.
    (r / "tests" / "test_foo.py").write_text(
        "import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
        "from src.foo import foo\n\n\ndef test_foo():\n    assert foo() == 1\n",
        encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "initial")
    _git(r, "remote", "add", "origin", str(bare))
    _git(r, "push", "-u", "origin", "main")
    return r


def _commit_change_and_test(r, *, test_body):
    """Change src/foo.py to return 2 and rewrite the test file with test_body."""
    (r / "src" / "foo.py").write_text("def foo():\n    return 2\n",
                                      encoding="utf-8")
    (r / "tests" / "test_foo.py").write_text(test_body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "change foo + test")


NEVER_RED = ("import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
             "from src.foo import foo\n\n\ndef test_foo():\n"
             "    assert foo() == 1\n\n\ndef test_trivial():\n"
             "    assert True\n")
GENUINELY_RED = ("import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
                 "from src.foo import foo\n\n\ndef test_foo():\n"
                 "    assert foo() == 2\n")


def _scan(r):
    rng = gitutil.resolve_range(r)
    files = gitutil.changed_files(r, rng)
    assert rng, "resolve_range returned no upstream range -- plumbing degenerated"
    assert any(gitutil.is_test_file(f) for f in files), \
        "no test file in the real diff -- result would be vacuous"
    ctx = RunContext(root=r, files=files, rng=rng)
    return red_proof.scan(ctx, SimpleNamespace(red_proof={"enabled": True}))


def _no_leaked_worktrees(r):
    cp = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                        capture_output=True, text=True)
    assert len([ln for ln in cp.stdout.splitlines() if ln.strip()]) == 1


def test_real_never_red_push_flags(tmp_path):
    r = _repo_with_upstream(tmp_path)
    _commit_change_and_test(r, test_body=NEVER_RED)
    # NEVER_RED asserts the OLD behavior (foo() == 1) -- it passes on base.
    findings = _scan(r)
    assert [f.file for f in findings] == ["tests/test_foo.py"]
    assert findings[0].tool == "red-proof" and findings[0].line == 0
    _no_leaked_worktrees(r)


def test_real_genuinely_red_push_is_clean(tmp_path):
    r = _repo_with_upstream(tmp_path)
    _commit_change_and_test(r, test_body=GENUINELY_RED)
    # GENUINELY_RED asserts the NEW behavior (foo() == 2) -- red on base.
    assert _scan(r) == []
    _no_leaked_worktrees(r)


def test_new_test_importing_new_module_is_red(tmp_path):
    r = _repo_with_upstream(tmp_path)
    (r / "src" / "bar.py").write_text("def bar():\n    return 3\n",
                                      encoding="utf-8")
    (r / "tests" / "test_bar.py").write_text(
        "import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
        "from src.bar import bar\n\n\ndef test_bar():\n    assert bar() == 3\n",
        encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "new module + its test")
    # src/bar.py does not exist on base -> collection error -> red -> clean.
    assert _scan(r) == []
    _no_leaked_worktrees(r)


def test_fingerprint_stable_across_pushes(tmp_path):
    """Spec s11: same never-red file across two pushes -> same finding id.
    line=0 reads no content, so the id normalize() mints is a function of
    tool+rule+path only -- derive it exactly as normalize() does and compare
    across two real pushes with entirely different file content."""
    from aramid.fingerprint import compute_fingerprint

    r = _repo_with_upstream(tmp_path)
    _commit_change_and_test(r, test_body=NEVER_RED)
    first = _scan(r)[0]
    _git(r, "push", "origin", "main")   # push 1 lands; the base advances
    # Second push: assert the now-landed behavior (foo() == 2) -- it passes
    # on the NEW base, so it is never-red again with different content.
    (r / "tests" / "test_foo.py").write_text(GENUINELY_RED, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "still never red")
    second = _scan(r)[0]
    ids = {compute_fingerprint(f.tool, f.rule, f.file, "", 0)
           for f in (first, second)}
    assert len(ids) == 1


def _arm(r):
    (r / "aramid.toml").write_text(
        "schema_version = 1\n\n[red_proof]\nred_proof_block_armed = true\n",
        encoding="utf-8")


def test_run_gate_disarmed_red_proof_is_ratchet_exempt(tmp_path, monkeypatch):
    """The exemption's REAL red-proof (mirrors tests/unit/test_pipeline.py::
    test_tdd_disarmed_warns_and_is_ratchet_exempt): at the run_gate layer no
    fresh-clone downgrade exists, so omitting "red-proof" from the ratchet
    exclusion genuinely escalates the WARN to BLOCK and flips exit_code to 1.
    (cmd_check-level disarmed e2e CANNOT pin this -- on a fresh ledger the
    downgrade masks a missing exemption.)"""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _commit_change_and_test(r, test_body=NEVER_RED)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    raw = RawFinding(tool="red-proof", rule="test-not-red",
                     severity_raw="medium", file="tests/test_foo.py",
                     line=0, message="m")
    monkeypatch.setattr(red_proof, "scan", lambda ctx, cfg: [raw])
    monkeypatch.setattr(pipeline.tdd, "scan", lambda ctx, cfg: [])
    cfg = config_mod.load_config(r)
    ledger = Ledger(r / ".aramid" / "ledger.db")
    try:
        result = pipeline.run_gate(r, Gate.PRE_PUSH, "range", cfg, ledger)
    finally:
        ledger.close()
    rp = [f for f in result.findings if f.tool == "red-proof"]
    assert len(rp) == 1
    assert rp[0].verdict is Verdict.WARN     # ratchet-exempt, not escalated
    assert result.exit_code == 0


def test_e2e_disarmed_warns_never_blocks(tmp_path, monkeypatch):
    """End-to-end disarmed behavior through cmd_check. NOTE: this does NOT
    pin the ratchet exemption -- on a fresh ledger the fresh-clone downgrade
    would mask a missing exemption; test_run_gate_disarmed_red_proof_is_
    ratchet_exempt above is the exemption's red-proof."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _commit_change_and_test(r, test_body=NEVER_RED)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1


def test_e2e_armed_never_red_blocks(tmp_path, monkeypatch):
    """Armed block on a BASELINED (non-fresh) ledger -- the disarmed first
    run writes the baseline (1b/2b two-run precedent), so the downgrade
    logic never runs on the armed assertion. The fresh single-run case is
    test_e2e_armed_block_survives_fresh_baseline."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _commit_change_and_test(r, test_body=NEVER_RED)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1          # disarmed baking run writes the baseline
    _arm(r)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1


def test_e2e_armed_genuinely_red_passes(tmp_path, monkeypatch):
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm(r)
    _commit_change_and_test(r, test_body=GENUINELY_RED)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1


def test_e2e_armed_block_survives_fresh_baseline(tmp_path, monkeypatch):
    """First-ever cmd_check on the repo (fresh ledger, no baseline): the armed
    red-proof BLOCK is genuine via classify -> _has_genuine_block -> survives
    the fresh-clone downgrade."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm(r)
    _commit_change_and_test(r, test_body=NEVER_RED)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1
