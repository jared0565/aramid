import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from aramid import config, gitutil, pipeline
from aramid.ledger import Ledger
from aramid.models import EventType, Finding, Gate, Severity, Source, Verdict
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
    # which is the scenario this test is actually about.
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
