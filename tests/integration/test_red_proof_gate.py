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
from aramid.models import Finding, Gate, Severity, Source, Verdict
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
# T-4's motivating bug, reproduced with real git + a real pytest subprocess:
# the only change is a non-test helper appended after the untouched
# test_foo() -- its name doesn't start with "test" (pytest never collects
# it) and the "def test_x():" text it happens to embed is inside a plain str
# argument, not a real def. Pre-T-4, subject selection had no content check
# at all, so this file (a changed line in a test FILE, full stop) still got
# a whole-file base rerun; test_foo() alone passes on base (foo() == 1
# unchanged), so pytest's rc was 0 and red-proof raised a false alarm on a
# file where literally nothing new was ever tested.
FIXTURE_REPAIR = ("import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
                  "from src.foo import foo\n\n\ndef test_foo():\n"
                  "    assert foo() == 1\n\n\n"
                  "def _write_broken_config(tmp_path):\n"
                  "    (tmp_path / 'conf.py').write_text(\n"
                  '        "def test_x():\\n    assert True\\n", encoding="utf-8")\n')
# T-4: GENUINELY_RED must include a genuinely NEW test-definition line among
# its added/changed lines, or the content gate (red_proof._new_test_def_lines)
# skips the subject before pytest ever runs -- an assertion-only edit to the
# existing test_foo() is exactly the "strengthened assertion" case the gate
# deliberately no longer scans (module docstring / README limitation 8). The
# appended test_new() is a pure addition relative to every base this constant
# is diffed against in this file, so it lands in the diff's added lines
# regardless of layout -- verified via real `git diff --unified=0` before
# this was written, not just reasoned about.
GENUINELY_RED = ("import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
                 "from src.foo import foo\n\n\ndef test_foo():\n"
                 "    assert foo() == 2\n\n\ndef test_new():\n"
                 "    assert True\n")
# Used only by test_fingerprint_stable_across_pushes, whose second push's
# base is push 1's LANDED NEVER_RED tree (not the original initial commit).
# Content gate note: this keeps test_trivial UNCHANGED (a rename would still
# diff as a same-offset line change and happen to satisfy the gate, but only
# by positional coincidence with whatever NEVER_RED looks like -- fragile).
# Appending test_extra instead is a pure addition, so the gate-passing
# def line is layout-independent -- verified via real `git diff --unified=0`
# against the landed NEVER_RED base before this was written.
STILL_NEVER_RED = ("import os\nimport sys\nsys.path.insert(0, os.getcwd())\n"
                   "from src.foo import foo\n\n\ndef test_foo():\n"
                   "    assert foo() == 2\n\n\ndef test_trivial():\n"
                   "    assert True\n\n\ndef test_extra():\n"
                   "    assert True\n")


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


def test_real_fixture_repair_is_not_flagged(tmp_path):
    """T-4 acceptance (a), with real git and a real pytest subprocess (not
    the unit tests' mocked plumbing): a commit that adds no new test
    DEFINITION at all -- only a non-test helper that happens to embed
    "def test_x():" text inside a string argument -- must not be flagged.
    src/foo.py is deliberately left untouched (unlike _commit_change_and_test):
    a fixture repair changes only the test file, and the base run must be
    genuinely all-green on its own merits (test_foo() unchanged, foo() == 1
    on both sides) so a finding here could only be explained by the missing
    content check T-4 closes."""
    r = _repo_with_upstream(tmp_path)
    (r / "tests" / "test_foo.py").write_text(FIXTURE_REPAIR, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "fixture repair: unrelated helper + embedded text")
    assert _scan(r) == []
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
    (r / "tests" / "test_foo.py").write_text(STILL_NEVER_RED, encoding="utf-8")
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
    monkeypatch.setattr(red_proof, "scan_scoped", lambda ctx, cfg: ([raw], set()))
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
    """Armed does not mean "always blocks": GENUINELY_RED is red on the base
    tree, so scan_scoped proves it red and emits no red-proof finding at all
    -- arming has nothing to escalate. test_e2e_armed_block_survives_fresh_
    baseline below already proves an armed BLOCK survives this exact fresh
    ledger / fresh-clone-downgrade path, so rc != 1 here can only mean no
    finding was produced, not that arming failed to take or that the
    downgrade silently masked a block."""
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


# ------------------------------------------ auto_resolve_red_proof (1a-F2) ---

def _seed_tdd(led, fid, file):
    """Seed an open tdd finding directly (mirrors test_pipeline.py's
    _seed_mut) -- used only by test_auto_resolve_skipped_outside_range_mode,
    where a red-proof seed cannot discriminate at all (red_proof.py:58-59
    empties proven_red whenever ctx.rng is falsy, on both sides of every
    counterfactual here)."""
    f = Finding(id=fid, tool="tdd", rule="code-without-test", severity_raw="medium",
                severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file, line=0,
                message="code changed with no new test in this range", evidence="",
                gate=Gate.ALL, source=Source.DETERMINISTIC)
    led.record_run("r0", "2026-07-21T12:00:00+00:00", "drain", set(), set(), [f])


def test_fire_then_resolve_two_push(tmp_path, monkeypatch):
    """spec section 5 e2e: push 1's never-red finding resolves once a LATER
    push proves the SAME file genuinely red. This is also the scoped-seam
    consumption proof (Step 2) -- nothing here is monkeypatched at the
    producer seam.

    Deliberately does NOT land push 1 (contrast test_tdd_gate.py's analogous
    test, which must land it): red-proof's verdict is base-relative, not
    source-touched-relative, and GENUINELY_RED asserts foo() == 2 -- if push
    1 landed, push 2's base would be push 1's tree where foo() ALREADY
    returns 2 (_commit_change_and_test always sets it), so GENUINELY_RED
    would pass there too (never-red again, exactly what
    test_fingerprint_stable_across_pushes above exploits on purpose) and
    nothing would resolve. Leaving push 1 unlanded keeps both scans' base at
    the original foo() == 1 commit, where GENUINELY_RED is actually red."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    cfg = config_mod.load_config(r)
    ledger = Ledger(r / ".aramid" / "ledger.db")
    try:
        _commit_change_and_test(r, test_body=NEVER_RED)
        result1 = pipeline.run_gate(r, Gate.PRE_PUSH, "range", cfg, ledger)
        rp = [f for f in result1.findings if f.tool == "red-proof"]
        assert len(rp) == 1
        fid = rp[0].id
        assert ledger.open_findings()[fid]["status"] == "open"

        _commit_change_and_test(r, test_body=GENUINELY_RED)
        pipeline.run_gate(r, Gate.PRE_PUSH, "range", cfg, ledger)
        assert ledger.open_findings()[fid]["status"] == "fixed"
    finally:
        ledger.close()


def test_auto_resolve_skipped_outside_range_mode(tmp_path, monkeypatch):
    """Guard 1's COARSE backstop: under mode == "all", scope_files is the
    whole tracked tree (pipeline.py:130, :308), not a push's delta --
    resolving on it would durably clear every open tdd finding on tracked
    source. Seeds a TDD finding (not red-proof: a red-proof seed cannot
    discriminate here at all, since ctx.rng is falsy under "all" on both
    sides of every counterfactual). _repo_with_upstream ships tests/test_foo.py
    tracked, which is load-bearing: with a tracked test file present,
    tdd.scan returns [] (tdd.py:47-52), so no real tdd id enters present_ids
    and the present_ids guard cannot mask the result."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    cfg = config_mod.load_config(r)
    ledger = Ledger(r / ".aramid" / "ledger.db")
    fid = "t" * 64
    try:
        _seed_tdd(ledger, fid, "src/foo.py")
        pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, ledger)
        assert ledger.open_findings()[fid]["status"] == "open"
    finally:
        ledger.close()


# ------- src-layout + an installed shadow: the base run must import BASE ----

def _src_layout_repo(tmp_path) -> Path:
    """A src-layout repo: the package lives at src/mypkg, so the repo root
    (which is pytest's cwd in the worktree) does NOT expose the package
    name. This is the layout aramid itself uses, and the one where an
    installed copy earlier on sys.path wins."""
    bare = tmp_path / "origin2.git"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True,
                   capture_output=True, text=True)
    r = tmp_path / "r2"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "src" / "mypkg").mkdir(parents=True)
    (r / "tests").mkdir()
    (r / "src" / "mypkg" / "__init__.py").write_text(
        'VALUE = "base"\n', encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "initial")
    _git(r, "remote", "add", "origin", str(bare))
    _git(r, "push", "-u", "origin", "main")
    return r


def test_base_run_imports_base_source_not_an_installed_shadow(tmp_path, monkeypatch):
    """A pip editable install puts the LIVE source dir on sys.path via a
    .pth file. red_proof materializes the BASE tree into a worktree and runs
    pytest there -- but with a src-layout package the worktree's `src` is on
    no path at all, so `import mypkg` resolves to the installed (i.e. NEW)
    code. The genuinely red-first test then PASSES on "base" and red_proof
    reports it as never-red: a false alarm -- the exact failure mode the
    whole-file design and the T-4 content gate exist to keep out short of a
    defect like this one (README, Red-first proof limitations).

    Every other fixture in this file dodges the bug by having its test body
    do `sys.path.insert(0, os.getcwd())`. Real test files do not -- they
    just import the package -- so this one imports normally. That fixture
    habit is precisely why the suite stayed green over this defect.

    The shadow on PYTHONPATH stands in for the editable install's .pth
    entry: both are sys.path entries that outrank a worktree nobody put on
    the path.
    """
    r = _src_layout_repo(tmp_path)

    shadow = tmp_path / "installed"
    (shadow / "mypkg").mkdir(parents=True)
    (shadow / "mypkg" / "__init__.py").write_text(
        'VALUE = "head"\n', encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(shadow))

    (r / "src" / "mypkg" / "__init__.py").write_text(
        'VALUE = "head"\n', encoding="utf-8")
    (r / "tests" / "test_value.py").write_text(
        "from mypkg import VALUE\n\n\ndef test_value():\n"
        '    assert VALUE == "head"\n', encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "bump VALUE + its test")

    # Red-first for real: against BASE, VALUE == "base", so the test fails.
    # Any finding here is the false alarm.
    assert _scan(r) == []
    _no_leaked_worktrees(r)


def test_worktree_src_outranks_the_shadow_but_does_not_discard_pythonpath(tmp_path, monkeypatch):
    """The fix prepends the worktree to PYTHONPATH -- it must PREPEND, not
    replace. run_subprocess merges its env over os.environ, so assigning
    PYTHONPATH outright would silently drop whatever the developer's
    environment already put there and break imports the base run needs."""
    r = _src_layout_repo(tmp_path)

    keep = tmp_path / "keepme"
    (keep / "sidecar").mkdir(parents=True)
    (keep / "sidecar" / "__init__.py").write_text("OK = 1\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(keep))

    (r / "src" / "mypkg" / "__init__.py").write_text(
        'VALUE = "head"\n', encoding="utf-8")
    (r / "tests" / "test_value.py").write_text(
        "import sidecar\nfrom mypkg import VALUE\n\n\ndef test_value():\n"
        '    assert sidecar.OK == 1 and VALUE == "base"\n', encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "bump VALUE + a test needing PYTHONPATH")

    # Passes on base only if BOTH hold: the inherited PYTHONPATH survived
    # (sidecar imports) AND the worktree won (VALUE == "base"). So a finding
    # here proves the base run genuinely saw base source with env intact.
    findings = _scan(r)
    assert [f.file for f in findings] == ["tests/test_value.py"]
    _no_leaked_worktrees(r)
