import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from aramid import config, gitutil, pipeline
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Source, Verdict
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState


# --------------------------------------------------------------- fixtures ----

def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("secret_line = 1\n")
    _git(r, "add", "a.py")
    _git(r, "commit", "-m", "initial")
    return r


def _cfg(root, tmp_path, monkeypatch) -> config.Config:
    # Never touch a real ~/.aramid/config.toml while running tests.
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    return config.load_config(root)


def _ledger(tmp_path, name="ledger.db") -> Ledger:
    return Ledger(tmp_path / name)


def _fake(run_result: RunnerResult, raws: list[RawFinding] | None = None,
          capture: list | None = None):
    """A minimal runner double: a plain namespace with run()/parse(), the
    same shape real runner modules expose (no `applies`/`name` needed --
    the pipeline never calls those, mirroring the real modules)."""
    def run(ctx):
        if capture is not None:
            capture.append(list(ctx.files))
        return run_result

    def parse(result, ctx):
        return raws or []

    return SimpleNamespace(run=run, parse=parse)


# -------------------------------------------------------------- (a) clean ----

def test_all_clean_exits_zero(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    monkeypatch.setitem(pipeline.RUNNERS, "fake", _fake(RunnerResult("fake", ToolState.OK)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-a")

    assert result.exit_code == 0
    assert result.findings == []
    assert result.degraded == []
    ledger.close()


# --------------------------------------------------------- (b) block finds ----

def test_one_block_finding_exits_one(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    # S102 is in the packaged block_rules.toml [ruff] block list -> BLOCK.
    raw = RawFinding(tool="ruff", rule="S102", severity_raw="high",
                      file="a.py", line=1, message="exec used")
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.OK), raws=[raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-b")

    assert result.exit_code == 1
    assert len(result.findings) == 1
    assert result.findings[0].verdict is Verdict.BLOCK
    assert result.new_ids == [result.findings[0].id]
    ledger.close()


# ------------------------------------------------- (c) degraded block-tier ---

def test_missing_block_tier_tool_at_prepush_exits_one(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    (root / "tests").mkdir()  # a test suite IS present -> "tests" stays
    # applicable (detect_tests non-empty); the fake below simulates the
    # runner itself self-reporting MISSING (e.g. pytest binary absent),
    # which is the scenario this test is actually about. A bare directory
    # is no longer a detect_tests() signal (Task 1) -- a real test file is
    # what keeps "tests" applicable here.
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    monkeypatch.setitem(pipeline.RUNNERS, "tests",
                         _fake(RunnerResult("tests", ToolState.MISSING)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-c1")

    assert result.exit_code == 1
    assert result.degraded == ["tests"]
    ledger.close()


def test_missing_block_tier_tool_with_accept_degraded_exits_two_and_logs_bypass(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    (root / "tests").mkdir()  # see comment above -- keeps "tests" applicable.
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    monkeypatch.setitem(pipeline.RUNNERS, "tests",
                         _fake(RunnerResult("tests", ToolState.MISSING)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger,
                                accept_degraded="ci runner has no test binary", run_id="run-c2")

    assert result.exit_code == 2
    bypass_events = [e for e in ledger.events() if e.type is EventType.INFRASTRUCTURE_BYPASS]
    assert len(bypass_events) == 1
    assert bypass_events[0].payload["reason"] == "ci runner has no test binary"
    ledger.close()


def test_accept_degraded_bypass_survives_single_suite_missing_tool_binary(tmp_path, monkeypatch):
    """Task 3 regression guard: exercises the REAL aramid.runners.tests
    module end to end (only run_subprocess is faked -- pipeline.RUNNERS
    is untouched), unlike every other accept_degraded test above, which
    replaces the whole "tests" entry with a double whose parse() ignores
    its argument. A single-suite repo whose ONE detected suite's tool
    binary can't be resolved must still take the pre-existing
    degraded-tool path (MISSING -> tests.parse() returns [] -> exit code
    governed by degraded_block_tier/accept_degraded), not the NEW
    tests-tool-missing BLOCK finding runners/tests.py added for a
    dual-suite aggregate's sub-result: with only ONE candidate tool here,
    `degraded_tools` already names it, so a Finding would be redundant, not
    disambiguating (contrast the dual-stack case in
    test_dual_stack_missing_sub_blocks_and_accept_degraded_bypasses below,
    where a sub-result Finding is the only thing that says WHICH suite
    never ran). [Updated, MUST FIX 2 whole-branch review] This docstring
    used to justify the same expectation by saying a BLOCK finding here
    would short-circuit past `--accept-degraded` entirely (run_gate's `if
    block_findings: exit_code = 1` checked before the accept_degraded
    elif) -- true at the time, but pipeline.run_gate now excludes any
    tests-tool-missing finding from that check by rule regardless of
    top-level-vs-sub, so that is no longer what protects this escape hatch
    either way; the redundancy argument above is the reason this
    single-suite case stays finding-free."""
    from aramid.runners import tests as tests_runner_mod

    root = _repo(tmp_path)
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    monkeypatch.setattr(
        tests_runner_mod, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="pytest", state=ToolState.MISSING))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger,
                                accept_degraded="ci runner has no test binary", run_id="run-c2-real")

    assert result.exit_code == 2
    assert not any(f.rule == "tests-tool-missing" for f in result.findings)
    bypass_events = [e for e in ledger.events() if e.type is EventType.INFRASTRUCTURE_BYPASS]
    assert len(bypass_events) == 1
    assert bypass_events[0].payload["reason"] == "ci runner has no test binary"
    ledger.close()


def test_dual_stack_missing_sub_blocks_and_accept_degraded_bypasses(tmp_path, monkeypatch):
    """MUST FIX 7 (deferred #7, upgraded), also the MUST FIX 2 regression
    guard: end-to-end proof through the REAL aramid.runners.tests module
    (only run_subprocess is faked -- pipeline.RUNNERS is untouched) that a
    dual-stack repo (pyproject.toml + tests/test_x.py + package.json test
    script + a JS lockfile, so the real dual-suite path in _dual_stack_run
    runs) whose npm binary can't be resolved:

      (1) blocks the push with NO --accept-degraded -- same shape as
          test_missing_block_tier_tool_at_prepush_exits_one's single-suite
          case, now proven for the dual-stack aggregate too, and
      (2) --accept-degraded still bypasses it (exit 2, one BYPASS event) --
          MUST FIX 2's fix. Before it, the tests-tool-missing BLOCK finding
          runners/tests.py emits for this exact sub-result short-circuited
          past `--accept-degraded` entirely (pipeline.py's `if
          block_findings: exit_code = 1` ran before the accept_degraded
          elif), the same way
          test_accept_degraded_bypass_survives_single_suite_missing_tool_
          binary above proves the single-suite case never did. No prior
          test drove this dual-stack MISSING sub through
          run_gate -> classify -> normalize at all (whole-branch review
          finding 7); this is that missing test, and its two scenarios are
          exactly the "one test, two assertions" the finding named."""
    from aramid.runners import tests as tests_runner_mod

    root = _repo(tmp_path)
    (root / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    (root / "package.json").write_text('{"scripts": {"test": "vitest"}}', encoding="utf-8")
    (root / "package-lock.json").write_text("{}", encoding="utf-8")  # lockfile gate passes
    cfg = _cfg(root, tmp_path, monkeypatch)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        if argv[0] == "pytest":
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        return RunnerResult(tool="npm", state=ToolState.MISSING)

    monkeypatch.setattr(tests_runner_mod, "run_subprocess", fake_run_subprocess)

    # (1) no --accept-degraded: blocks.
    ledger1 = _ledger(tmp_path, name="ledger1.db")
    result1 = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger1, run_id="run-f7-block")
    assert result1.exit_code == 1
    assert any(f.rule == "tests-tool-missing" and f.verdict is Verdict.BLOCK
               for f in result1.findings)
    # Isolates this proof from any OTHER PRE_PUSH producer (e.g. tdd.scan)
    # that might independently add an unrelated BLOCK finding -- without
    # this, scenario (2) below returning exit_code 1 could be misread as
    # MUST FIX 2's fix failing when it would really be a different finding
    # entirely.
    assert [f.verdict for f in result1.findings].count(Verdict.BLOCK) == 1
    ledger1.close()

    # (2) --accept-degraded: bypasses.
    ledger2 = _ledger(tmp_path, name="ledger2.db")
    result2 = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger2,
                                accept_degraded="ci runner has no npm binary", run_id="run-f7-bypass")
    assert result2.exit_code == 2
    bypass_events = [e for e in ledger2.events() if e.type is EventType.INFRASTRUCTURE_BYPASS]
    assert len(bypass_events) == 1
    assert bypass_events[0].payload["reason"] == "ci runner has no npm binary"
    ledger2.close()


def test_gitleaks_finding_named_tests_tool_missing_still_blocks_with_accept_degraded(
        tmp_path, monkeypatch):
    """Closer 1 (re-review round 2): the tests-tool-missing exemption in
    run_gate's exit-code gate MUST be scoped by TOOL, not rule alone. A
    repo's own `.gitleaks.toml` can name a custom rule anything, including
    literally "tests-tool-missing" -- `policy.classify`'s `tool ==
    "gitleaks"` branch is the very first branch in that function and is
    unconditional on rule, so a real secret reported under that rule name
    classifies BLOCK regardless. If the exemption matched on rule alone, that
    genuine secret finding would be silently excluded from
    `gating_block_findings` and bypassed by `--accept-degraded` anyway --
    exit 2 where a real secret must exit 1.

    Constructed via a fake gitleaks runner (no real .gitleaks.toml needed)
    so this is a controlled, deterministic proof, not a real-gitleaks
    integration test. A genuinely MISSING "tests" tool rides alongside it so
    degraded_block_tier is True and gate is PRE_PUSH + accept_degraded is
    supplied -- i.e. the accept_degraded branch is actually reachable at
    all -- proving it's specifically the gitleaks finding's tool that keeps
    this blocking, not merely the absence of any degraded tool."""
    root = _repo(tmp_path)
    (root / "tests").mkdir()  # keeps "tests" applicable (real detect_tests signal).
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    raw = RawFinding(tool="gitleaks", rule="tests-tool-missing", severity_raw="high",
                      file="secret.env", line=1,
                      message="a real secret, adversarially named to collide with the rule")
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                         _fake(RunnerResult("gitleaks", ToolState.OK), raws=[raw]))
    monkeypatch.setitem(pipeline.RUNNERS, "tests",
                         _fake(RunnerResult("tests", ToolState.MISSING)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["gitleaks", "tests"])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger,
                                accept_degraded="ci runner has no test binary",
                                run_id="run-closer1")

    assert result.exit_code == 1
    # Isolates the proof from any other PRE_PUSH producer -- see the same
    # isolation comment on test_dual_stack_missing_sub_blocks_and_accept_
    # degraded_bypasses above for why this matters.
    assert [f.verdict for f in result.findings].count(Verdict.BLOCK) == 1
    assert any(f.tool == "gitleaks" and f.rule == "tests-tool-missing"
               and f.verdict is Verdict.BLOCK for f in result.findings)
    bypass_events = [e for e in ledger.events() if e.type is EventType.INFRASTRUCTURE_BYPASS]
    assert len(bypass_events) == 0
    ledger.close()


# --------------------------------------- (c2) applicability -- no test setup -

def test_no_test_setup_at_prepush_tests_not_selected_clean_exit(tmp_path, monkeypatch):
    """Important #1 regression test: a repo with NO test setup (no tests/,
    no package.json test script) must never have `tests` selected at
    pre-push -- previously it was selected unconditionally, self-reported
    MISSING, and (as a BLOCK_TIER_KEYS member) forced exit_code=1 on every
    single pre-push. Real gitleaks/semgrep are stubbed clean here only so
    the test doesn't depend on those binaries being installed; `tests` is
    left as the REAL runner module specifically so a spy can prove it is
    never invoked at all."""
    root = _repo(tmp_path)  # only a.py -- no tests/, no package.json
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                         _fake(RunnerResult("gitleaks", ToolState.OK)))
    monkeypatch.setitem(pipeline.RUNNERS, "semgrep",
                         _fake(RunnerResult("semgrep", ToolState.OK)))

    calls: list = []
    real_tests_run = pipeline.RUNNERS["tests"].run
    monkeypatch.setattr(pipeline.RUNNERS["tests"], "run",
                         lambda ctx: (calls.append(1), real_tests_run(ctx))[1])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-h")

    assert calls == []                     # tests.run() never invoked
    assert "tests" not in result.degraded
    assert result.degraded == []
    assert result.exit_code == 0
    ledger.close()


# --------------------------------- (c3) [tests] config: command/timeout/off --

def _ctx_spy(result: RunnerResult):
    """A runner double that records the RunContext it was handed, so the
    cfg -> RunContext plumbing can be asserted from the runner's side."""
    seen: list = []

    def run(ctx):
        seen.append(ctx)
        return result

    return SimpleNamespace(run=run, parse=lambda r, c: []), seen


def test_tests_config_reaches_the_runner_via_the_run_context(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    (root / "tests").mkdir()
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)
    cfg.tests = {"enabled": True, "command": "pytest -q tests/unit", "timeout_s": 900}

    spy, seen = _ctx_spy(RunnerResult("pytest", ToolState.OK))
    monkeypatch.setitem(pipeline.RUNNERS, "tests", spy)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tc1")

    assert len(seen) == 1
    assert seen[0].test_command == "pytest -q tests/unit"
    assert seen[0].test_timeout_s == 900
    ledger.close()


def test_tests_disabled_by_config_is_never_selected(tmp_path, monkeypatch):
    """`[tests].enabled = false` takes the BLOCK-tier gate out entirely --
    the runner must not run, and its absence must NOT read as degraded
    (that would block every push, the very thing disabling it avoids)."""
    root = _repo(tmp_path)
    (root / "tests").mkdir()  # detection WOULD find a suite -- config wins
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)
    cfg.tests = {"enabled": False}

    spy, seen = _ctx_spy(RunnerResult("pytest", ToolState.OK))
    monkeypatch.setitem(pipeline.RUNNERS, "tests", spy)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tc2")

    assert seen == []
    assert result.degraded == []
    assert result.exit_code == 0
    ledger.close()


def test_configured_command_makes_tests_applicable_without_detection(tmp_path, monkeypatch):
    """A repo whose suite the pytest/npm heuristics don't recognize (a
    `make test` wrapper, a suite under a subpath) still gets the gate once
    it names a command -- otherwise configuring one would silently do
    nothing."""
    root = _repo(tmp_path)  # no tests/, no package.json
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)
    cfg.tests = {"command": "make test"}

    spy, seen = _ctx_spy(RunnerResult("make", ToolState.OK))
    monkeypatch.setitem(pipeline.RUNNERS, "tests", spy)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tc3")

    assert len(seen) == 1
    ledger.close()


def test_custom_command_degradation_still_escalates_block_tier(tmp_path, monkeypatch):
    """The invariant a custom command could plausibly break: BLOCK-tier
    escalation keys on the registry KEY ("tests"), not on
    RunnerResult.tool. A custom `make test` reports tool == "make", which
    name-matches nothing in BLOCK_TIER_KEYS -- if the escalation ever
    switched to name-matching, configuring a command would silently demote
    the test gate out of BLOCK tier. Exit 1 here is the whole point."""
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)
    cfg.tests = {"command": "make test"}

    monkeypatch.setitem(pipeline.RUNNERS, "tests",
                         _fake(RunnerResult("make", ToolState.TIMEOUT)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tc4")

    assert result.exit_code == 1
    assert result.degraded_block_tier is True
    assert result.degraded == ["make"]   # the NAME differs from the key
    ledger.close()


def test_legacy_top_level_test_command_is_honored(tmp_path, monkeypatch):
    """`test_command` shipped in schema v1, was documented, and had no read
    site at all. It is consumed as a fallback rather than orphaned beside a
    new key that does the same thing."""
    root = _repo(tmp_path)
    (root / "tests").mkdir()
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)
    cfg.test_command = "pytest -k smoke"

    spy, seen = _ctx_spy(RunnerResult("pytest", ToolState.OK))
    monkeypatch.setitem(pipeline.RUNNERS, "tests", spy)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tc5")

    assert seen[0].test_command == "pytest -k smoke"
    ledger.close()


def test_tests_command_wins_over_legacy_test_command(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    (root / "tests").mkdir()
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)
    cfg.test_command = "pytest -k smoke"
    cfg.tests = {"command": "pytest -q tests/unit"}

    spy, seen = _ctx_spy(RunnerResult("pytest", ToolState.OK))
    monkeypatch.setitem(pipeline.RUNNERS, "tests", spy)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tc6")

    assert seen[0].test_command == "pytest -q tests/unit"
    ledger.close()


# ---- (c4) [tests] misconfiguration must be loud, never silently weakening ---

def _ctx(root, **kw):
    from aramid.runners.base import RunContext
    return RunContext(root=root, **kw)


def test_notice_when_the_test_gate_is_disabled(tmp_path):
    root = tmp_path / "n1"
    (root / "tests").mkdir(parents=True)
    # A real test file, not a bare dir (Task 1) -- the notice only fires
    # when detect_tests(root) finds an actual suite to be silently skipped.
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    notices = pipeline._tests_config_notices(
        Gate.PRE_PUSH, _ctx(root, tests_enabled=False), budget_s=300)
    assert len(notices) == 1
    assert "disabled" in notices[0].lower()


def test_no_disabled_notice_at_a_gate_that_never_runs_tests(tmp_path):
    """pre-commit doesn't run the test gate, so `enabled = false` changes
    nothing there -- warning about it every commit would be noise."""
    root = tmp_path / "n2"
    (root / "tests").mkdir(parents=True)
    assert pipeline._tests_config_notices(
        Gate.PRE_COMMIT, _ctx(root, tests_enabled=False), budget_s=5) == []


def test_no_disabled_notice_when_the_repo_has_no_suite_anyway(tmp_path):
    root = tmp_path / "n3"
    root.mkdir()
    assert pipeline._tests_config_notices(
        Gate.PRE_PUSH, _ctx(root, tests_enabled=False), budget_s=300) == []


def test_notice_when_test_timeout_exceeds_the_gate_budget(tmp_path):
    """`timeout_s` is capped by the gate's wall-clock budget: run_gate
    abandons any runner still going at `budget_s`, so a larger timeout can
    never be reached. Silently ignoring the configured value is exactly the
    kind of false green light this engine exists to prevent."""
    root = tmp_path / "n4"
    (root / "tests").mkdir(parents=True)
    # A real test file, not a bare dir (Task 1 convention, matching
    # test_notice_when_the_test_gate_is_disabled above) -- a bare tests/
    # dir with nothing recognized inside it is now ALSO a signal for the
    # separate I3+B1 "suite present but not running" notice (review I3+B1),
    # and this test must isolate the timeout notice alone.
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    notices = pipeline._tests_config_notices(
        Gate.PRE_PUSH, _ctx(root, test_timeout_s=900.0), budget_s=300)
    assert len(notices) == 1
    assert "900" in notices[0] and "300" in notices[0]


def test_no_timeout_notice_when_within_the_budget(tmp_path):
    root = tmp_path / "n5"
    (root / "tests").mkdir(parents=True)
    # See comment above -- a real file keeps this isolated from the I3+B1
    # false-negative notice, which a bare tests/ dir would now also trigger.
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    assert pipeline._tests_config_notices(
        Gate.PRE_PUSH, _ctx(root, test_timeout_s=120.0), budget_s=300) == []


def test_run_gate_prints_the_tests_config_notices(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)
    cfg.tests = {"enabled": False}

    pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tc7")

    assert "[tests].enabled" in capsys.readouterr().err
    ledger.close()


# --------------------------------------- (c5) [review I5] notices accumulate -

def test_notices_accumulate_instead_of_short_circuiting_at_first_match(tmp_path):
    """[review I5] Two INDEPENDENT conditions true at once (a false-negative
    test setup, per I3+B1, and an over-budget timeout_s) must each produce
    their own notice. The pre-fix function returned at the first matching
    branch, which would silently hide the second one here."""
    root = tmp_path / "acc1"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "testfoo.py").write_text(
        "import unittest\nclass T(unittest.TestCase):\n"
        "    def test_x(self):\n        pass\n", encoding="utf-8")
    assert pipeline.detect_tests(root) == set()  # sanity: unittest-style name, unrecognized

    notices = pipeline._tests_config_notices(
        Gate.PRE_PUSH, _ctx(root, test_timeout_s=900.0), budget_s=300)

    assert len(notices) == 2
    assert any("900" in n and "300" in n for n in notices)
    assert any("[tests].command" in n for n in notices)


# ------------------------------------- (c6) [review I3+B1] suite not running -

def test_false_negative_notice_when_tests_dir_has_unittest_style_naming(tmp_path):
    """[review I3+B1 case 1] Task 1 tightened detect_tests() to require
    test_*.py / *_test.py / conftest.py -- a real unittest-style `testfoo.py`
    (no underscore after "test") is invisible to it, even though a tests/
    directory plainly exists."""
    root = tmp_path / "fn1"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "testfoo.py").write_text(
        "import unittest\nclass T(unittest.TestCase):\n"
        "    def test_x(self):\n        pass\n", encoding="utf-8")
    assert pipeline.detect_tests(root) == set()  # sanity

    notices = pipeline._tests_config_notices(Gate.PRE_PUSH, _ctx(root), budget_s=300)

    assert len(notices) == 1
    assert "[tests].command" in notices[0]


def test_false_negative_notice_when_pytest_ini_exists_with_no_tests_dir(tmp_path):
    """A second, independent signal (pytest.ini) -- proves the check is an
    OR over several markers, not hardcoded to a tests/ directory."""
    root = tmp_path / "fn2"
    root.mkdir()
    (root / "pytest.ini").write_text("[pytest]\npython_files = check_*.py\n", encoding="utf-8")
    (root / "check_foo.py").write_text("def check_x():\n    assert True\n", encoding="utf-8")
    assert pipeline.detect_tests(root) == set()  # sanity: custom python_files, unrecognized

    notices = pipeline._tests_config_notices(Gate.PRE_PUSH, _ctx(root), budget_s=300)

    assert len(notices) == 1
    assert "[tests].command" in notices[0]


def test_no_false_negative_notice_when_nothing_plausible_exists(tmp_path):
    """Negative control: a repo with no test setup at all (no tests/,
    test/, pytest.ini, tox.ini, or pyproject pytest section) must stay
    silent -- there's genuinely nothing to explain."""
    root = tmp_path / "fn3"
    root.mkdir()
    assert pipeline._tests_config_notices(Gate.PRE_PUSH, _ctx(root), budget_s=300) == []


def test_no_false_negative_notice_when_test_command_is_configured(tmp_path):
    """An explicit [tests].command IS the repo's answer -- it must suppress
    the false-negative notice even though detect_tests() would still find
    nothing and a tests/ dir with unrecognized content still exists."""
    root = tmp_path / "fn4"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "testfoo.py").write_text("def check(): pass\n", encoding="utf-8")
    assert pipeline._tests_config_notices(
        Gate.PRE_PUSH, _ctx(root, test_command="make test"), budget_s=300) == []


def _dual_stack_root(tmp_path, name, lockfile=None):
    root = tmp_path / name
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    tests_dir = root / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_x.py").write_text("def test_x():\n    assert True\n", encoding="utf-8")
    (root / "package.json").write_text('{"scripts": {"test": "vitest"}}', encoding="utf-8")
    if lockfile:
        (root / lockfile).write_text("{}", encoding="utf-8")
    return root


def test_mandatory_notice_when_dual_kinds_detected_but_no_lockfile(tmp_path):
    """[review I3+B1 case 2, MANDATORY] Both kinds detected (a real pytest
    file AND a package.json test script) but no JS lockfile -- the npm
    suite is silently skipped per the C1 decision. Rev 2's five Python-only
    signals all missed this: detect_tests() here is NON-empty (it finds
    "pytest" and "npm"), so the case-1 branch never fires, yet a real
    suite is still being dropped -- a Vitest/Jest repo with no tests/
    directory of its own would have matched none of the five."""
    root = _dual_stack_root(tmp_path, "mand1", lockfile=None)
    assert pipeline.detect_tests(root) == {"pytest", "npm"}  # sanity: not empty

    notices = pipeline._tests_config_notices(Gate.PRE_PUSH, _ctx(root), budget_s=300)

    assert len(notices) == 1
    assert "npm" in notices[0]
    assert "[tests].command" in notices[0]


def test_no_mandatory_notice_when_lockfile_present(tmp_path):
    root = _dual_stack_root(tmp_path, "mand2", lockfile="package-lock.json")
    assert pipeline._tests_config_notices(Gate.PRE_PUSH, _ctx(root), budget_s=300.0) == []


# ------------------------------------------- (c7) [review B5] dual-suite budget

def test_dual_suite_budget_notice_fires_when_effective_timeout_exceeds_budget(tmp_path):
    """[review B5] Lockfile present -- a real dual run WILL happen -- and
    the effective per-suite timeout (falls back to runners.tests.TIMEOUT_S
    since test_timeout_s is unset here) already exceeds the shared budget
    on its own, so the second suite is guaranteed a reduced allotment."""
    root = _dual_stack_root(tmp_path, "budget1", lockfile="package-lock.json")

    notices = pipeline._tests_config_notices(Gate.PRE_PUSH, _ctx(root), budget_s=60.0)

    assert len(notices) == 1
    assert "300" in notices[0]   # effective timeout (TIMEOUT_S fallback)
    assert "60" in notices[0]    # the shared budget


def test_no_dual_suite_budget_notice_at_stock_defaults(tmp_path):
    """[review B5] Regression guard for HALF of the stock-defaults story:
    rev 1's `2 x timeout_s > budget` rule fired here on every push for
    every dual-stack repo, which is the bug B5 replaced -- this pins that
    the always-fires bug has NOT returned.

    [MUST FIX 3, whole-branch review] This does NOT mean stock defaults are
    fully covered -- do not read the `== []` below as "nothing to see
    here". At timeout_s=pre_push=300, `effective_timeout > budget_s` is
    `300 > 300` = False by construction, so THIS notice is provably inert
    at stock defaults on every dual-stack repo, always -- yet the second
    suite still gets truncated below 300s by runners.tests.
    _run_one_within_deadline's `min(_timeout(ctx), remaining)` the moment
    the first suite consumes any wall-clock time at all. That gap is
    real, known, and deliberately NOT fixed in this round (see the
    `effective_timeout > budget_s` predicate's own comment above, a few
    lines up in pipeline.py, for why `>=` was rejected and what actually
    closing it would require). This test only certifies the narrower,
    already-fixed claim: the notice does not fire SPURIOUSLY at stock
    defaults, not that stock defaults need no notice at all."""
    root = _dual_stack_root(tmp_path, "budget2", lockfile="package-lock.json")
    assert pipeline._tests_config_notices(
        Gate.PRE_PUSH, _ctx(root), budget_s=300.0) == []


def test_no_dual_suite_budget_notice_when_test_command_configured(tmp_path):
    """An explicit [tests].command runs ONE invocation (run_custom), never
    the dual-suite path -- the notice must not fire even though dual kinds
    and a lockfile are both present and the budget is tiny."""
    root = _dual_stack_root(tmp_path, "budget4", lockfile="package-lock.json")
    assert pipeline._tests_config_notices(
        Gate.PRE_PUSH, _ctx(root, test_command="make test"), budget_s=1.0) == []


def test_no_dual_suite_budget_notice_for_single_suite_repo(tmp_path):
    """Only a pytest suite detected (no package.json at all) -- there is
    nothing to share the deadline with, so the notice must not fire even
    at a tiny budget."""
    root = tmp_path / "budget5"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    assert pipeline._tests_config_notices(
        Gate.PRE_PUSH, _ctx(root), budget_s=1.0) == []


# --------------------------------------------- (c8) [review M6+B7] caching ---

def test_detect_tests_walks_the_filesystem_only_once_per_gate_run(tmp_path, monkeypatch):
    """[review M6+B7] Before caching, a single pre-push gate run on a
    test-bearing repo called detect_tests() up to THREE times: pipeline.py's
    _is_applicable, pipeline.py's _tests_config_notices, and runners.tests's
    own run() -- each a fresh os.walk. Caching the result once on
    RunContext.detected_tests collapses this to exactly one call, no
    matter how many places read it."""
    from aramid.runners import tests as tests_runner_mod

    root = _repo(tmp_path)
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    calls: list = []
    real = pipeline.detect_tests

    def counting(r):
        calls.append(r)
        return real(r)

    monkeypatch.setattr(pipeline, "detect_tests", counting)
    monkeypatch.setattr(tests_runner_mod, "detect_tests", counting)
    monkeypatch.setattr(
        tests_runner_mod, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="pytest", state=ToolState.OK, returncode=0))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-cache1")

    assert len(calls) == 1
    ledger.close()


def test_run_gate_populates_detected_tests_on_the_context(tmp_path, monkeypatch):
    """Proves run_gate actually WIRES the cache through the RunContext it
    builds -- not merely that the field exists on the dataclass."""
    root = _repo(tmp_path)
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    spy, seen = _ctx_spy(RunnerResult("pytest", ToolState.OK))
    monkeypatch.setitem(pipeline.RUNNERS, "tests", spy)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-cache2")

    assert seen[0].detected_tests == {"pytest"}
    ledger.close()


def test_is_applicable_reads_the_cached_detected_tests_not_a_fresh_walk(tmp_path):
    """[review M6+B7] The cache must actually be CONSULTED, not merely
    stored: root has a real pytest file (a fresh walk WOULD find "pytest"),
    but the ctx explicitly caches an empty set, which must win."""
    root = tmp_path / "cache1"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    assert pipeline.detect_tests(root) == {"pytest"}  # sanity: a fresh walk WOULD find it

    ctx = _ctx(root, detected_tests=set())
    assert pipeline._is_applicable("tests", ctx) is False


def test_tests_config_notices_reads_the_cached_detected_tests_not_a_fresh_walk(tmp_path):
    root = tmp_path / "cache2"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    assert pipeline.detect_tests(root) == {"pytest"}  # sanity

    ctx = _ctx(root, tests_enabled=False, detected_tests=set())
    # A fresh walk would find "pytest" and fire the disabled-notice; the
    # cache says "nothing detected" and must be trusted instead.
    assert pipeline._tests_config_notices(Gate.PRE_PUSH, ctx, budget_s=300) == []


def test_bare_run_context_construction_still_works_after_caching_field_added(tmp_path):
    """[review M6+B7] The sentinel guarantee: a bare RunContext(root=...) --
    as ~137 call sites across tests/ construct it -- must behave exactly as
    before the `detected_tests` field was added (fall back to a fresh
    walk), never read as "no suite detected" just because the field
    defaults to unset."""
    root = tmp_path / "bare1"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    from aramid.runners.base import RunContext
    ctx = RunContext(root=root)
    assert ctx.detected_tests is None
    assert pipeline._is_applicable("tests", ctx) is True


# ------------------------------------------------- (d) graph-out/ ignore -----

def test_graph_out_path_never_reaches_runner_or_findings(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    monkeypatch.setattr(pipeline.gitutil, "staged_files",
                         lambda r: ["graph-out/x.json", "src/app.py"])

    captured_files: list = []
    # Simulate a range-scanning tool (like gitleaks) that reports a finding
    # for a path irrespective of ctx.files -- the second filter pass must
    # still drop it before fingerprinting.
    ignored_raw = RawFinding(tool="fake", rule="r1", severity_raw="high",
                              file="graph-out/x.json", line=1, message="m")
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.OK), raws=[ignored_raw],
                               capture=captured_files))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-d")

    assert captured_files == [["src/app.py"]]         # never handed to the runner
    assert result.findings == []                       # never fingerprinted
    ledger.close()


# --------------------------------------------------- (e) log redaction -------

def test_raw_secret_never_lands_in_scrubbed_log(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    secret = "AKIA1234567890AB"
    gitleaks_raw = RawFinding(tool="gitleaks", rule="aws-key", severity_raw="high",
                               file="a.py", line=1, message="found a key", secret=secret)
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                         _fake(RunnerResult("gitleaks", ToolState.OK), raws=[gitleaks_raw]))
    monkeypatch.setitem(pipeline.RUNNERS, "noisy",
                         _fake(RunnerResult("noisy", ToolState.CRASHED,
                                             stderr=f"leaked secret: {secret} in output")))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["gitleaks", "noisy"])

    pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-e")

    log_path = root / ".aramid" / "logs" / "noisy-run-e.log"
    content = log_path.read_text(encoding="utf-8")
    assert secret not in content
    assert f"AK{chr(0x2026)}AB" in content
    ledger.close()


# ---------------------------------------------- (f0) regression pack -------

def test_run_gate_sets_extra_semgrep_configs_when_pack_present(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    (root / ".aramid-rules").mkdir()
    (root / ".aramid-rules" / "regression.yml").write_text("rules:\n", encoding="utf-8")
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    captured_ctx: list = []

    def run(ctx):
        captured_ctx.append(ctx)
        return RunnerResult("fake", ToolState.OK)

    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         SimpleNamespace(run=run, parse=lambda r, c: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-pack")

    assert captured_ctx[0].extra_semgrep_configs == (
        str(root / ".aramid-rules" / "regression.yml"),)
    ledger.close()


def test_run_gate_no_extra_semgrep_configs_when_pack_absent(tmp_path, monkeypatch):
    root = _repo(tmp_path)  # no .aramid-rules/regression.yml
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    captured_ctx: list = []

    def run(ctx):
        captured_ctx.append(ctx)
        return RunnerResult("fake", ToolState.OK)

    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         SimpleNamespace(run=run, parse=lambda r, c: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-pack-absent")

    assert captured_ctx[0].extra_semgrep_configs == ()
    ledger.close()


def test_run_gate_no_extra_semgrep_configs_when_pack_disabled(tmp_path, monkeypatch):
    """run_gate gates pack replay on BOTH conditions: the file existing AND
    [pack].enabled -- the pack file is PRESENT here but aramid.toml disables
    the pack, so no extra --config may reach the semgrep runner."""
    root = _repo(tmp_path)
    (root / ".aramid-rules").mkdir()
    (root / ".aramid-rules" / "regression.yml").write_text("rules:\n", encoding="utf-8")
    (root / "aramid.toml").write_text("[pack]\nenabled = false\n", encoding="utf-8")
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    captured_ctx: list = []

    def run(ctx):
        captured_ctx.append(ctx)
        return RunnerResult("fake", ToolState.OK)

    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         SimpleNamespace(run=run, parse=lambda r, c: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-pack-disabled")

    assert cfg.pack.get("enabled") is False  # sanity: the toml layered in
    assert captured_ctx[0].extra_semgrep_configs == ()
    ledger.close()


# ------------------------------------------------------ (f) ratchet --------

def test_new_warn_finding_escalates_to_block_at_prepush(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)  # fresh ledger -> finding is unconditionally new

    # eslint rule not on any block-list -> classify() falls through to WARN.
    raw = RawFinding(tool="eslint", rule="no-unused-vars", severity_raw="1",
                      file="a.py", line=1, message="unused var")
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.OK), raws=[raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["fake"])
    # isolate from the real tdd producer (this repo's a.py has no test) so
    # this test only exercises the eslint ratchet-escalation path.
    monkeypatch.setattr(pipeline.tdd, "scan", lambda ctx, cfg: [])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-f")

    assert result.exit_code == 1
    assert len(result.findings) == 1
    assert result.findings[0].verdict is Verdict.BLOCK
    assert result.findings[0].id in result.new_ids
    ledger.close()


def test_shape_drift_warn_not_escalated_to_block_at_prepush(tmp_path, monkeypatch):
    # A pnpm/yarn shape-drift advisory (deps-audit-shape-unrecognized) is a WARN
    # that must stay WARN even as a NEW finding at pre-push: it is exempt from
    # the new-warning ratchet's BLOCK escalation, so a possible-false-positive
    # drift never hard-blocks a push / fails CI (spec section 8 mitigation).
    from aramid.runners import deps
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)  # fresh ledger -> finding is unconditionally new

    raw = RawFinding(tool="pnpm", rule=deps.DEPS_SHAPE_DRIFT_RULE, severity_raw="medium",
                      file="pnpm-lock.yaml", line=1, message="shape drift")
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.OK), raws=[raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["fake"])
    # isolate from the real tdd producer (this repo's a.py has no test) so
    # this test only exercises the deps-shape-drift ratchet-exemption path.
    monkeypatch.setattr(pipeline.tdd, "scan", lambda ctx, cfg: [])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-drift")

    assert len(result.findings) == 1
    assert result.findings[0].id in result.new_ids       # it IS a new finding
    assert result.findings[0].verdict is Verdict.WARN    # but NOT escalated to BLOCK
    assert result.exit_code != 1                          # -> does not block the push
    ledger.close()


def test_shape_drift_warn_does_not_fail_check_all(tmp_path, monkeypatch):
    # The mitigation's PRIMARY guarantee: CI's `check --all --strict` stays green
    # on a drift. CI runs gate=pre-commit (the --gate default) with mode="all",
    # so the pre-push ratchet never runs here; safety rests on deps NOT being
    # degraded (run_js stays OK) -> degraded_tools empty -> exit 0. --strict only
    # remaps exit 2/3, so a 0 stays 0 -> CI green. The WARN is still surfaced.
    from aramid.runners import deps
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    raw = RawFinding(tool="pnpm", rule=deps.DEPS_SHAPE_DRIFT_RULE, severity_raw="medium",
                      file="pnpm-lock.yaml", line=1, message="shape drift")
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.OK), raws=[raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="run-drift-all")

    assert result.exit_code == 0                          # not 1 (block), not 2 (degraded)
    assert [f.rule for f in result.findings] == [deps.DEPS_SHAPE_DRIFT_RULE]
    assert result.findings[0].verdict is Verdict.WARN     # visible, non-blocking
    ledger.close()


# ------------------------------------------------- mode="all" coverage ------

def test_mode_all_uses_tracked_files(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    captured_files: list = []
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.OK), capture=captured_files))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="run-g")

    assert captured_files == [["a.py"]]
    ledger.close()


# ---------------- MUST-FIX 1 (final-review.md) -- mode="range", no upstream -

def test_mode_range_no_upstream_scans_full_tracked_set_not_empty_diff(tmp_path):
    """A brand-new repo (no @{u}, no origin/HEAD) is the FIRST-PUSH case
    spec §3 calls out explicitly: "no remote refs at all -- first push of a
    new repo -- scan every commit reachable from HEAD. Never exit 3 merely
    because a branch is new." Pre-fix, `_discover_files` diffed a bare
    "HEAD" (`changed_files(root, None)`), which is empty on a clean working
    tree -- silently under-scanning. It must now fall back to the full
    tracked file set, and hand back `pipeline.FULL_HISTORY_RNG` ("") --
    NOT `None` -- so gitleaks' `_build_argv` (ctx.rng is not None) still
    routes to the full-history `git log` scan instead of `protect --staged`
    (see test_runner_gitleaks.py's own sentinel test and
    test_prepush_new_repo_full_scan.py's end-to-end proof)."""
    root = _repo(tmp_path)
    assert gitutil.resolve_range(root) is None  # sanity: genuinely no upstream/origin

    files, rng = pipeline._discover_files(root, "range")

    assert files == ["a.py"]
    assert rng == pipeline.FULL_HISTORY_RNG
    assert rng is not None


# --------------------------------------------- (i) wall-clock budget -------

def test_hung_runner_does_not_block_past_gate_budget(tmp_path, monkeypatch):
    """Important #2 regression test: a runner that hangs well past the
    gate's wall-clock budget must not block run_gate -- previously the
    ThreadPoolExecutor context manager's implicit shutdown(wait=True)
    joined every submitted thread, including hung ones, on the way out."""
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    cfg.timeouts["pre_commit"] = 0.2  # tiny budget

    def hang_run(ctx):
        time.sleep(2.0)  # far past the budget
        return RunnerResult("hangy", ToolState.OK)

    monkeypatch.setitem(pipeline.RUNNERS, "hangy",
                         SimpleNamespace(run=hang_run, parse=lambda r, c: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["hangy"])

    start = time.monotonic()
    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-timeout")
    elapsed = time.monotonic() - start

    assert elapsed < 1.0  # returned near the 0.2s budget, not after the 2s sleep
    assert result.degraded == ["hangy"]
    assert result.exit_code == 2  # WARN-tier degrade only (not a BLOCK_TIER_KEYS member)


# ------------------------- (i2) tests dual-suite: single deadline origin ---

def test_dual_suite_deadline_shares_one_origin_with_the_real_executor_wait(
        tmp_path, monkeypatch):
    """Task 3 B2 follow-up regression guard. Exercises the REAL
    aramid.pipeline._run_selected / ThreadPoolExecutor.wait() path through
    run_gate -- unlike runners/tests.py's own unit tests, which time
    _run_dual in isolation and never go through a real executor at all,
    this is the specific blind spot that let the two-clock-origins defect
    through review.

    Mechanism under test: runners/tests.py's run() calls a filesystem-walk
    equivalent BEFORE ever reaching the dual-suite budget logic, and that
    walk happens INSIDE the worker thread _run_selected dispatches, i.e.
    AFTER its wait(timeout=budget_s) has already started counting in the
    main thread. A `started = time.monotonic()` captured after that walk
    (the pre-94fc6e8 code) silently drops however long the walk took from
    the module's own budget accounting, so the two suites can be allotted
    time as if the walk were free -- letting the worker's real finish land
    AFTER wait()'s cutoff. When that happens, _run_selected treats the
    "tests" future as not_done and replaces the WHOLE aggregate with a bare
    RunnerResult("tests", TIMEOUT) carrying no sub_results at all -- a
    completed suite's real, already-produced finding is discarded and the
    push blocks naming "tests timeout" instead of the real cause.

    [Task 4 rearm] Before Task 4's detect_tests() caching, that in-worker
    walk WAS a literal `detect_tests(ctx.root)` call inside run(), so
    patching `tests_runner_mod.detect_tests` with a sleep faithfully
    simulated it. After caching, run() calls `_detected(ctx)` instead,
    which is a cache hit for any run_gate-built ctx (this test's ctx IS
    one) -- `detect_tests` is never reached on that path at all, so the
    old monkeypatch silently went dead and this test would pass whether or
    not the single-origin fix was even present. Verified concretely: the
    pre-94fc6e8 two-clock-origin arithmetic was temporarily reintroduced
    into runners/tests.py with Task 4's caching left intact, and this test
    (pre-rearm) still passed -- proof the guard had no live exposure path.
    Patching `tests_runner_mod._detected` instead -- the function run()
    ACTUALLY calls now -- restores a genuine in-worker delay on the live
    call site; pipeline.py's own `detect_tests` (the ONE walk that
    populates ctx.detected_tests, in run_gate, before _select_runners) is
    untouched by caching and is still faked the same way as before.

    run_subprocess is faked to HONESTLY enforce the timeout_s it's given
    (sleeps at most that long, and only reports a real result if actually
    given enough of it), mirroring what a real subprocess does -- a fake
    that ignores timeout_s outright would hide the very effect under test.

    [CI flake fix, whole-branch-fix round: CI run 30208508818 failed this
    test on `assert "exited 1" in pytest_findings[0].message` -- a loaded
    macOS runner got 'pytest timeout: test suite failed' instead. Root
    cause: the previous revision of this docstring analysed exactly ONE
    margin (below, M1) and let a "generous margins deliberately" claim
    about M1 stand in for a SEPARATE quantity, M2, that nobody had actually
    computed and that turned out to be razor-thin. Also corrects a stale
    attribution: the detect_tests() delay below is NOT inside
    _select_runners -- _select_runners never calls detect_tests itself, it
    only reads the ctx.detected_tests cache that run_gate's own
    `detect_tests(root)` call (pipeline.py:464) populates, in the MAIN
    thread, before ctx is even built (before _select_runners exists to call
    anything).]

    Numbers: budget_s=3.0 (cfg.timeouts["pre_push"]); a 1.0s delay in
    run_gate's `detect_tests(root)` call, MAIN thread, before ctx/dispatch;
    a 1.5s delay in tests_runner_mod._detected, WORKER thread, once run()
    starts. Three margins fall out, and they are three DIFFERENT
    quantities -- this is the distinction the pre-fix docstring collapsed:

    M1 (deadline vs. the real executor's wait() cutoff): the 1.0s
    pre-flight delay in the main thread means _run_selected's
    wait(timeout=budget_s) is only called at T0+1.0, so its cutoff is
    T0+4.0 -- 1.0s later than ctx.gate_deadline itself (T0+3.0). Proven
    safe in runners/tests.py's module docstring: every step between the
    deadline being set and wait() being called can only ADD elapsed time,
    never remove it, so wait()'s cutoff is provably >= gate_deadline. This
    is the ONLY margin the pre-fix docstring analysed.
    M2 (pytest's OWN allotment vs. what it needs -- the one that actually
    failed in CI): by the time pytest's _run_one_within_deadline call reads
    _remaining(ctx), the worker has spent 1.0s (pre-flight) + 1.5s
    (_detected) = 2.5s of the 3.0s budget, leaving a 0.5s allotment;
    fake_run_subprocess needs only 0.05s for "pytest" -- an absolute 0.45s
    of slack. At the PREVIOUS numbers (budget 0.6/0.2/0.3, pytest needing
    0.05 of a 0.1s allotment) this margin was a mere 0.05s: a loaded macOS
    runner overshooting either sleep by ~50ms (ordinary scheduler jitter,
    not a hang) drove `remaining` below `needed`, flipping
    fake_run_subprocess's branch from "completed rc=1" to TIMEOUT. 0.45s
    is a ~9x larger absolute margin on the identical real-clock primitives
    (real threads, real time.sleep) -- not immune to jitter in principle,
    but no longer razor's-edge either.
    M3 (npm still gets truncated -- now asserted directly below, not left
    to arithmetic alone): after pytest's 0.05s, npm's own
    _run_one_within_deadline call sees a ~0.45s allotment against a 2.0s
    need -- truncated with ~1.55s to spare, landing npm's fake sleep
    (`max(timeout_s, 0)` ~= 0.45s) at approximately gate_deadline, the
    designed worst case. If real scheduler overshoot ever consumed all of
    M2 and then some, npm could instead hit _run_one_within_deadline's
    `remaining <= 0` short-circuit and never reach fake_run_subprocess at
    all -- still a TIMEOUT, still the same finding and message, so the
    assertions below hold either way; this docstring does not claim the
    min()-path is the only route to npm's truncation, only the expected
    one.

    [review round 2, rearm-of-the-rearm] Patching `_detected` by NAME is
    not, by itself, proof the delay actually fires: `monkeypatch.setattr`
    only raises if the target attribute is missing entirely (an outright
    rename/removal of `_detected` would fail loudly). If a future change
    ever inlines `_detected`'s cache-check logic directly into run() while
    leaving `_detected` defined but unused, this patch would keep
    succeeding -- attribute still exists -- while never being called
    again, silently. That is the exact hollow-guard class this test was
    just rearmed to close, one level deeper. Both fakes below therefore
    record every call they receive, and the test asserts each fired at
    least once BEFORE trusting anything the timing assertions say --
    verified concretely: temporarily pointing the `_detected` patch at
    `detect_tests` instead (simulating exactly that orphaned-patch
    scenario -- a real, existing attribute `run()` no longer calls on the
    cached path) made the call-count assertion fail while the timing
    assertions below would have stayed green, i.e. exactly the silent
    vacuous-pass this guards against."""
    from aramid.runners import tests as tests_runner_mod

    root = _repo(tmp_path)
    (root / "package-lock.json").write_text("{}", encoding="utf-8")  # lockfile gate passes
    cfg = _cfg(root, tmp_path, monkeypatch)
    cfg.timeouts["pre_push"] = 3.0
    ledger = _ledger(tmp_path)

    pipeline_detect_calls: list = []
    detected_calls: list = []

    def fake_pipeline_detect_tests(r):
        pipeline_detect_calls.append(r)
        time.sleep(1.0)
        return {"pytest", "npm"}

    def fake_detected(ctx):
        detected_calls.append(ctx)
        time.sleep(1.5)
        return {"pytest", "npm"}

    monkeypatch.setattr(pipeline, "detect_tests", fake_pipeline_detect_tests)
    monkeypatch.setattr(tests_runner_mod, "_detected", fake_detected)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        needed = 0.05 if argv[0] == "pytest" else 2.0
        if timeout_s < needed:
            time.sleep(max(timeout_s, 0))
            return RunnerResult(tool=argv[0], state=ToolState.TIMEOUT)
        time.sleep(needed)
        if argv[0] == "pytest":
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=1, raw="1 failed\n")
        return RunnerResult(tool="npm", state=ToolState.OK, returncode=0)

    monkeypatch.setattr(tests_runner_mod, "run_subprocess", fake_run_subprocess)

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-b2-real")

    # [review round 2] Both injected delays must actually have fired -- an
    # orphaned patch (attribute exists, but nothing on the live path calls
    # it anymore) would leave the timing assertions below vacuously green.
    assert len(pipeline_detect_calls) >= 1
    assert len(detected_calls) >= 1

    tests_failed = [f for f in result.findings if f.rule == "tests-failed"]
    # pytest genuinely completed (rc=1) well inside its correctly-reduced
    # remaining allotment -- its real finding must survive, attributed to
    # ITSELF, not swallowed into one generic aggregate-level notice.
    pytest_findings = [f for f in tests_failed if f.tool == "pytest"]
    assert len(pytest_findings) == 1
    # [MUST FIX 4, whole-branch review -- third hole in this guard] Matching
    # on `f.tool == "pytest"` alone does NOT prove pytest actually ran to
    # completion: under the regression this guards against (sabotaging
    # pipeline.py's `gate_deadline = time.monotonic() + budget_s` down to
    # `gate_deadline = budget_s` -- a bare duration, not an absolute
    # instant), `_remaining(ctx)` goes deeply negative for BOTH sub-results,
    # `_run_one_within_deadline` returns a bare TIMEOUT for EACH one
    # WITHOUT ever calling run_subprocess, and parse()'s TIMEOUT branch
    # still produces a tool="pytest" tests-failed finding -- so the tool-
    # name-only assertion above passes whether or not pytest ever actually
    # ran. The MESSAGE is the only thing that distinguishes a genuine rc=1
    # completion ("pytest exited 1: test suite failed") from a same-tool
    # TIMEOUT ("pytest timeout: test suite failed"), so it must be pinned
    # too. Verified concretely (see report): with only the tool-name
    # assertion, the :430 sabotage above still made this test pass; adding
    # this message assertion is what makes it fail for the right reason.
    assert "exited 1" in pytest_findings[0].message
    assert "timeout" not in pytest_findings[0].message.lower()
    # [invariant 4, whole-branch-fix round] npm must still be the suite the
    # shared deadline truncates -- previously only implied by this
    # docstring's own arithmetic (M3 above), never asserted, so a change
    # that accidentally gave npm enough allotment to complete would have
    # passed silently. needed=2.0 against a ~0.45s allotment means npm's
    # own _run_one_within_deadline call reports TIMEOUT, and parse()'s
    # TIMEOUT branch (runners/tests.py) yields tool="npm",
    # message="npm timeout: test suite failed" -- a distinct finding from
    # pytest's (different `tool`, so a different fingerprint), meaning both
    # survive independently rather than colliding in the ledger. Verified
    # concretely (see report): temporarily lowering npm's `needed` below
    # its allotment (so it completes rc=0 instead of truncating) makes
    # `len(npm_findings) == 1` fail -- a real, running proof that this
    # assertion is load-bearing, not vacuous.
    npm_findings = [f for f in tests_failed if f.tool == "npm"]
    assert len(npm_findings) == 1
    assert "timeout" in npm_findings[0].message.lower()
    # The failure mode this guards: the whole future abandoned and replaced
    # by RunnerResult("tests", TIMEOUT) -- tool="tests" (the registry key,
    # never a real sub-tool), message naming "tests timeout" rather than
    # either suite's own outcome.
    assert not any(f.tool == "tests" and "timeout" in f.message.lower()
                   for f in tests_failed)
    ledger.close()
    ledger.close()


# ------------------------------------------- lock §8b: backslash paths -----

def test_backslash_path_under_ignored_dir_is_filtered_pre_fingerprint(tmp_path, monkeypatch):
    """Locks the §8b guarantee: config.is_ignored normalizes its input
    (normalize_path -- backslash-to-forward-slash + casefold) before
    matching, so a RawFinding.file reported with Windows-style backslashes
    under an ignored directory is still dropped by the layer-2 post-parse
    filter (pipeline.py's `raws_in_scope` comprehension), never reaching
    normalize()/fingerprinting."""
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    raw = RawFinding(tool="fake", rule="r1", severity_raw="high",
                      file="graph-out\\leak.json", line=1, message="m")
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.OK), raws=[raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-i")

    assert result.findings == []
    ledger.close()


def test_overrides_from_ledger_carries_reason(tmp_path):
    import uuid

    from aramid.models import Event, Finding, Severity

    led = _ledger(tmp_path)
    f = Finding("id1", "ruff", "S102", "high", Severity.HIGH, Verdict.WARN,
                "a.py", 1, "m", "e", Gate.PRE_PUSH)
    led.record_run("r1", "t", "pre-push", {"ruff"}, {"a.py"}, [f])
    led.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, "t2",
                     finding_id="id1", payload={"reason": "audit trail"}))
    records = pipeline._overrides_from_ledger(led)
    led.close()
    assert len(records) == 1
    assert records[0].id == "id1"
    assert records[0].reason == "audit trail"


def test_not_a_secret_is_not_an_override_at_gate_time(tmp_path):
    """Gate-inertness guard (not-a-secret sub-project, Constraint 4): a
    historical gitleaks finding marked not-a-secret must NEVER produce an
    OverrideRecord. mark-not-a-secret is a reporting-only reclassification
    of an already-inert historical finding -- it must never become a second,
    uncommitted BLOCK-suppression path that bypasses
    .aramid-suppressions.toml."""
    import uuid

    from aramid.models import Event, Finding, Severity

    led = _ledger(tmp_path)
    f = Finding("id2", "gitleaks", "aws-key", "high", Severity.HIGH, Verdict.BLOCK,
                "a.py", 1, "m", "e", Gate.PRE_PUSH, historical=True)
    led.record_run("r1", "t", "historical-scan", {"gitleaks"}, set(), [f])
    led.append(Event(EventType.FINDING_NOT_A_SECRET, uuid.uuid4().hex, "t2",
                     finding_id="id2", payload={"reason": "test fixture value"}))
    records = pipeline._overrides_from_ledger(led)
    assert led.open_findings()["id2"]["status"] == "not_a_secret"
    assert records == []
    led.close()


# ------------------------------------------------------- (tdd) pre-push ----

def test_tdd_disarmed_warns_and_is_ratchet_exempt(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    raw = RawFinding(tool="tdd", rule="code-without-test", severity_raw="medium",
                     file="a.py", line=0, message="code changed with no new test in this range")
    monkeypatch.setattr(pipeline.tdd, "scan", lambda ctx, cfg: [raw])
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, [])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tdd-w")

    tdd_findings = [f for f in result.findings if f.tool == "tdd"]
    assert len(tdd_findings) == 1
    assert tdd_findings[0].verdict is Verdict.WARN          # not escalated
    assert result.exit_code == 0                            # ratchet-exempt: does NOT block
    ledger.close()


def test_tdd_armed_blocks(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    cfg.tdd_block_armed = True
    ledger = _ledger(tmp_path)

    raw = RawFinding(tool="tdd", rule="code-without-test", severity_raw="medium",
                     file="a.py", line=0, message="code changed with no new test in this range")
    monkeypatch.setattr(pipeline.tdd, "scan", lambda ctx, cfg: [raw])
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, [])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tdd-a")

    tdd_findings = [f for f in result.findings if f.tool == "tdd"]
    assert tdd_findings[0].verdict is Verdict.BLOCK
    assert result.exit_code == 1
    ledger.close()


def test_tdd_producer_fires_only_at_pre_push(tmp_path, monkeypatch):
    """1a-F5: pipeline.py's `if gate is Gate.PRE_PUSH:` guard (currently
    line 278, immediately before `tdd.scan(ctx, cfg)`) is the ONLY thing that
    suppresses the real tdd producer -- mode is NOT a gate on it. Gate is the
    sole varying input across the three run_gate calls below; mode is fixed
    to "all" throughout, and GATE_RUNNER_KEYS is emptied for all three gates
    so no runner-selection difference leaks in. The real tdd.scan is
    reachable (unpatched) the whole time.

    _repo(tmp_path) ships only a.py, tracked, with NO test file, so the real
    producer genuinely fires whenever it is called at all -- ctx.rng is
    falsy under mode="all" (pipeline.py's `_discover_files` returns rng=None
    for "all"), which routes tdd.scan into its own "is any tracked file a
    test file" branch (tdd.py:47-52); with none tracked, that's always False,
    so a real invocation always yields a finding for a.py.

    PRE_PUSH + mode="all" is the positive control that makes the PRE_COMMIT/
    ALL negatives discriminating: it proves the producer WOULD fire in this
    fixture if called, so its absence at the other two gates is evidence of
    the gate guard, not of the fixture happening to be clean. Do NOT rewrite
    this as a mode-based test: mode="all" does not suppress the producer at
    PRE_PUSH (tdd.scan runs and fires here), so a mode-only variant on this
    fixture has no legal fix within Task 2's tests-only scope if it were
    ever green for the wrong reason.

    RED counterfactual: relaxing pipeline.py's `if gate is Gate.PRE_PUSH:` to
    `if gate is not Gate.ALL:` (or removing the guard) must make this fail --
    PRE_COMMIT would then also fire tdd.scan and gain a tdd finding."""
    root = _repo(tmp_path)  # tracked a.py, no test file -> real producer fires
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS", {
        **pipeline.GATE_RUNNER_KEYS,
        Gate.PRE_PUSH: [], Gate.PRE_COMMIT: [], Gate.ALL: []})

    push = pipeline.run_gate(root, Gate.PRE_PUSH, "all", cfg, ledger, run_id="run-tdd-push")
    commit = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="run-tdd-commit")
    allg = pipeline.run_gate(root, Gate.ALL, "all", cfg, ledger, run_id="run-tdd-all")

    assert [f.file for f in push.findings if f.tool == "tdd"] == ["a.py"]
    assert not any(f.tool == "tdd" for f in commit.findings)
    assert not any(f.tool == "tdd" for f in allg.findings)
    ledger.close()


_MUT_NOW = "2026-07-21T12:00:00+00:00"


def _mut_repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=r, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=r, check=True)
    (r / "src").mkdir()
    (r / "src" / "real.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=r, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "c1"], cwd=r, check=True)
    return r


def _seed_mut(led, fid="g" * 64, file="src/pkg/ghost.py"):
    # ghost.py is NOT in the repo -> auto_resolve_mutation never resolves it.
    f = Finding(id=fid, tool="mutation", rule="flip_comparison",
                severity_raw="medium", severity=Severity.MEDIUM,
                verdict=Verdict.WARN, file=file, line=7,
                message="mutant survived: flip_comparison", evidence="",
                gate=Gate.ALL, source=Source.DETERMINISTIC)
    led.record_run("r0", _MUT_NOW, "drain", set(), set(), [f])


def test_pre_push_surfaces_mutation_finding(tmp_path, monkeypatch):
    r = _mut_repo(tmp_path)
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})
    cfg = config.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        _seed_mut(led)
        got = pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led)
        assert got.exit_code == 0                       # disarmed WARN, ratchet-exempt
        assert any(f.tool == "mutation" and f.verdict is Verdict.WARN
                   for f in got.findings)

        cfg.mutation["mutation_block_armed"] = True
        got = pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led)
        assert got.exit_code == 1                       # armed -> BLOCK
        assert any(f.tool == "mutation" and f.verdict is Verdict.BLOCK
                   for f in got.findings)
    finally:
        led.close()


def test_mutation_findings_absent_at_pre_commit(tmp_path, monkeypatch):
    r = _mut_repo(tmp_path)
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT: []})
    cfg = config.load_config(r)
    cfg.mutation["mutation_block_armed"] = True
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        _seed_mut(led)
        got = pipeline.run_gate(r, Gate.PRE_COMMIT, "staged", cfg, led)
        assert not any(f.tool == "mutation" for f in got.findings)
    finally:
        led.close()


def test_all_mode_does_not_resolve_tracked_mutation(tmp_path, monkeypatch):
    # Guard (whole-branch review): mode=="all" must NOT resolve mutation
    # findings. scope_files under --all is the whole tracked tree, not a push
    # range, so resolving on it would durably clear every open mutation finding
    # on tracked source. The finding is seeded on a TRACKED file (src/real.py,
    # which _mut_repo creates) that IS in the all-mode scope_files.
    r = _mut_repo(tmp_path)
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})
    cfg = config.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        _seed_mut(led, fid="t" * 64, file="src/real.py")   # TRACKED source
        pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led)
        assert led.open_findings()["t" * 64]["status"] == "open"  # NOT resolved
    finally:
        led.close()


# ------------------------------------------------ auto_resolve_tdd (1a-F2) ---

def _seed_tdd(led, fid, file):
    # mirrors _seed_mut above, for tdd instead of mutation.
    f = Finding(id=fid, tool="tdd", rule="code-without-test", severity_raw="medium",
                severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file, line=0,
                message="code changed with no new test in this range", evidence="",
                gate=Gate.ALL, source=Source.DETERMINISTIC)
    led.record_run("r0", _MUT_NOW, "drain", set(), set(), [f])


def test_range_mode_without_upstream_does_not_resolve_tdd(tmp_path, monkeypatch):
    """The SHARP proof of guard 1 (pipeline.py's `if rng:` nest inside
    `if mode == "range":`). A brand-new repo with no upstream/origin resolves
    rng=None -> FULL_HISTORY_RNG (""), so scope_files is the WHOLE tracked
    tree, not the push's delta (mirrors
    test_mode_range_no_upstream_scans_full_tracked_set_not_empty_diff above)
    -- mode == "range" alone is not enough. Committing tests/test_a.py makes
    the real tdd producer return [] (a tracked test file is present, per
    tdd.py:47-52's has_new_test_lines), so no real tdd id enters present_ids
    and the present_ids guard cannot be why the seeded finding stays open --
    only guard 1 can be. Must FAIL if the `if rng:` nest is dropped."""
    root = _repo(tmp_path)
    assert gitutil.resolve_range(root) is None  # sanity: genuinely no upstream

    (root / "tests").mkdir()
    (root / "tests" / "test_a.py").write_text(
        "def test_a():\n    assert True\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-m", "add test_a")

    cfg = _cfg(root, tmp_path, monkeypatch)
    led = _ledger(tmp_path)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, [])
    fid = "t" * 64
    try:
        _seed_tdd(led, fid, "a.py")
        pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, led)
        assert led.open_findings()[fid]["status"] == "open"
    finally:
        led.close()


def test_range_mode_without_upstream_does_not_resolve_mutation(tmp_path, monkeypatch):
    """The mutation sibling of the guard-1 proof above. auto_resolve_mutation
    was the LAST resolver still guarded by `mode == "range"` alone, one nesting
    level outside `if rng:` -- so in this exact no-upstream repo it resolved on
    the WHOLE tracked tree and appended a durable (un-undoable) FINDING_RESOLVED
    for every open mutation finding on tracked source.

    Only ONE mechanism is under test here: `_repo` has no tests/ directory, so
    auto_resolve_mutation's `changed_test_stems` is empty and `test_added`
    cannot fire. `source_touched` is the only path that can resolve a.py, and
    only guard 1 stops it. Must FAIL if the call moves back out of `if rng:`."""
    root = _repo(tmp_path)
    assert gitutil.resolve_range(root) is None  # sanity: genuinely no upstream

    cfg = _cfg(root, tmp_path, monkeypatch)
    led = _ledger(tmp_path)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, [])
    fid = "m" * 64
    try:
        _seed_mut(led, fid=fid, file="a.py")   # TRACKED, and in the full-tree scope
        pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, led)
        assert led.open_findings()[fid]["status"] == "open"
    finally:
        led.close()


def _crf(led, idx, target, killed_s1, survived_s1, killed_fps=(), survivor_fps=()):
    # mirrors test_mutation_score_gate.py's _crf seeding pattern.
    led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", "t", payload={
        "consumer": "mutation", "item_id": "q",
        "mutation_scores": {"schema": 1, "targets": {target: {
            "generated": killed_s1 + survived_s1, "killed_s1": killed_s1,
            "survived_s1": survived_s1, "timeouts": 0, "errors": 0,
            "fully_mutated": True, "killed_fps": list(killed_fps),
            "survivor_fps": list(survivor_fps)}}}}))


def test_range_mode_without_upstream_does_not_suppress_score_regression(
        tmp_path, monkeypatch):
    """The EPHEMERAL sibling of the two guards above, on the same root cause.
    mutation_score_gate_findings takes changed_files under `mode == "range"`
    alone, and uses it ONLY to suppress a transition regression whose
    module-mapped test the push touched. With no upstream, scope_files is the
    WHOLE tracked tree, so every mapped test looks "just changed" and the
    suppression fires on a false premise -- the 2b gate goes silent on a real
    regression.

    Unlike its two siblings this writes NO ledger event, so the damage is one
    quiet run rather than a durable false resolve -- which is why it is fixed
    here separately rather than folded into the resolver guard.

    tests/test_a.py must exist and be COMMITTED: it is what puts stem "test_a"
    into the full-tree scope, and _module_tests("a") matching it is the exact
    thing that wrongly suppresses. Must FAIL (finding absent) without the
    `and rng` guard."""
    root = _repo(tmp_path)
    assert gitutil.resolve_range(root) is None  # sanity: genuinely no upstream

    (root / "tests").mkdir()
    (root / "tests" / "test_a.py").write_text(
        "def test_a():\n    assert True\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-m", "add test_a")

    cfg = _cfg(root, tmp_path, monkeypatch)
    led = _ledger(tmp_path)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, [])
    try:
        # baseline kills the fp; the current run has it as a confirmed survivor
        _crf(led, 0, "a.py::f", 2, 0, killed_fps=["deadbeef", "other"])
        _crf(led, 1, "a.py::f", 1, 2, killed_fps=["other"],
             survivor_fps=["deadbeef"])
        got = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, led)
        assert any(f.tool == "mutation-score" and f.rule == "transition"
                   for f in got.findings)
    finally:
        led.close()
