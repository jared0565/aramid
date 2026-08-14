"""integration: `aramid check` -- the thin cmd_check wrapper over
aramid.pipeline.run_gate that the installed git hook shims invoke directly.

Runners are monkeypatched (pipeline.RUNNERS / pipeline.GATE_RUNNER_KEYS)
exactly as tests/unit/test_pipeline.py does -- no real gitleaks/semgrep/etc
binary is required.
"""
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import config as config_mod
from aramid import pipeline
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Source, Verdict
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name="r") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "a.py")
    _git(r, "commit", "-q", "-m", "initial")
    return r


def _no_user_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")


def _fake(run_result: RunnerResult, raws: list[RawFinding] | None = None):
    return SimpleNamespace(run=lambda ctx: run_result, parse=lambda result, ctx: raws or [])


# --------------------------------------------------- (a) seeded BLOCK -> 1 ---

def test_seeded_secret_repo_pre_commit_returns_1(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)

    raw = RawFinding(tool="gitleaks", rule="generic-api-key", severity_raw="high",
                      file="a.py", line=1, message="found a key", secret="AKIA1234567890AB")
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                         _fake(RunnerResult("gitleaks", ToolState.OK), raws=[raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["gitleaks"])

    rc = cmd_check(root, Gate.PRE_COMMIT, "staged")

    assert rc == 1
    out = capsys.readouterr().out
    assert "generic-api-key" in out


# ------------------------------------------------------------ (b) clean -> 0 -

def test_clean_repo_pre_commit_returns_0(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                         _fake(RunnerResult("gitleaks", ToolState.OK)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["gitleaks"])

    rc = cmd_check(root, Gate.PRE_COMMIT, "staged")

    assert rc == 0


# ---------------------------------- (c) fresh ledger, pre-push, WARN-only ---

def test_fresh_ledger_prepush_warn_only_finding_does_not_block(tmp_path, monkeypatch):
    """The no-new-warnings ratchet (pipeline's PRE_PUSH-only WARN->BLOCK
    escalation) keys off 'seen before', which is empty on a brand new
    ledger -- so a legacy WARN finding looks 'new' and would normally
    escalate to BLOCK on the very first run. cmd_check's fresh-clone rule
    must catch this and return 0 or 2, never 1."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    assert not Ledger(root / ".aramid" / "ledger.db").has_baseline()

    raw = RawFinding(tool="eslint", rule="no-unused-vars", severity_raw="1",
                      file="a.py", line=1, message="unused var")
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.OK), raws=[raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["fake"])

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc in (0, 2)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    assert ledger.has_baseline()
    ledger.close()


# ------------------------------- (d) fresh ledger, pre-push, genuine BLOCK --

def test_fresh_ledger_prepush_genuine_secret_still_blocks(tmp_path, monkeypatch):
    """The fresh-clone rule must NEVER downgrade a genuine BLOCK-tier
    finding (a real gitleaks secret) -- only the ratchet's own
    WARN->BLOCK escalation is suppressed on a fresh ledger. Without this,
    a real secret would sail through the first push of a new repo."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    assert not Ledger(root / ".aramid" / "ledger.db").has_baseline()

    raw = RawFinding(tool="gitleaks", rule="generic-api-key", severity_raw="high",
                      file="a.py", line=1, message="found a key", secret="AKIA1234567890AB")
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                         _fake(RunnerResult("gitleaks", ToolState.OK), raws=[raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["gitleaks"])

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 1


def test_an_override_made_while_disarmed_does_not_defeat_the_block_after_arming(
        tmp_path, monkeypatch, capsys):
    """END-TO-END guard for the property a downstream repo's 26 suppressions
    rest on, reported in interop round 84.

    That repo holds 26 ledger overrides, every one stored `verdict: "warn"`,
    with `semgrep_block_armed = true` today. It is not a repo that sits outside
    the stored-verdict defect -- it is precisely the population the defect
    describes. The only thing between it and 26 silently defeated blocks is
    that semgrep findings are freshly scanned every run and re-classified under
    the CURRENT config, so `policy.apply_overrides` sees a BLOCK and refuses to
    downgrade it.

    `test_override_does_not_downgrade_block_finding` pins that guard, but it is
    a unit test of `apply_overrides` -- it pins the guard's BEHAVIOUR and not
    that the guard is REACHED. Both would keep passing if a status filter were
    ever added ahead of it, which is exactly mutation's shape:
    `mutation_gate_findings` drops any record whose status is not "open", so an
    overridden mutation finding never reaches `apply_overrides` at all. The
    reporter's point was that their repo would go from clean to 26 defeated
    blocks with no change to semgrep whatsoever. This test is the thing that
    would go red.

    It also pins the known-open residual honestly: the override is NOT undone
    by arming. It survives, the row still reads `overridden`, and the block is
    held by the re-classification rather than by anything having reconsidered
    the suppression.
    """
    from aramid.commands.override import cmd_override

    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    cfg_path = root / "aramid.toml"

    raw = RawFinding(tool="semgrep", rule="owasp-top-ten.a03-injection.python-sqli-string-concat",
                      severity_raw="ERROR", file="a.py", line=1,
                      message="SQL built by concatenation")
    monkeypatch.setitem(pipeline.RUNNERS, "semgrep",
                         _fake(RunnerResult("semgrep", ToolState.OK), raws=[raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["semgrep"])

    # 1. Detect it while DISARMED. classify -> WARN, and that is what is stored.
    cfg_path.write_text("semgrep_block_armed = false\n", encoding="utf-8")
    cmd_check(root, Gate.PRE_PUSH, "range")

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
    finally:
        ledger.close()
    fid = next(iter(state))
    assert state[fid]["verdict"] == "warn", state[fid]

    # 2. Suppress it locally. Legitimate while disarmed -- it really is WARN-tier
    #    right now -- and this must SUCCEED, or the arms below prove nothing.
    assert cmd_override(root, fid, "noisy during the bake") == 0

    # 3. Arm. Arming is retroactive, so the same finding is now BLOCK-tier,
    #    while its ledger row still reads "warn" and still reads "overridden".
    cfg_path.write_text("semgrep_block_armed = true\n", encoding="utf-8")

    rc = cmd_check(root, Gate.PRE_PUSH, "range")
    err = capsys.readouterr().err

    assert rc == 1, "a stale override must not defeat a now-armed BLOCK"

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        after = ledger.open_findings()[fid]
    finally:
        ledger.close()
    # The residual this test used to pin -- `status` still reading "overridden"
    # after arming, the block held only by re-classification and nothing having
    # reconsidered the suppression -- is CLOSED as of the disarm mechanism
    # (interop rounds 84 §2, 87 §5, 89). The gate-start sweep now revokes it,
    # so the assertion is inverted deliberately rather than deleted: this is
    # the end-to-end proof that the sweep runs at gate start, on the same
    # fixture that demonstrated the hole.
    assert after["status"] == "open", after
    assert after["invalidated_cause"] == "recorded_disarmed", after
    # And the operator is told, with the count and the cause -- a bare notice
    # is the difference between re-adjudicating and hunting for a bug.
    assert "1 override" in err, err
    assert "re-adjudication" in err, err


def test_a_blocked_suite_names_a_log_that_exists_and_holds_the_failing_test(
        tmp_path, monkeypatch, capsys):
    """Reported from a downstream repo (interop round 92): the whole blocking
    line was

        [BLOCK] 0eb10e21... python.exe:tests-failed <test-suite>:0
                -- python.exe exited 1: test suite failed

    and there was nowhere to go from it. Every component is a constant for the
    repo -- tool, rule, the synthetic path, line 0, and a fixed message -- so
    the identifier answers "is the suite failing?" while the surrounding prose
    invites reading it as "has THIS failure recurred?". Which test failed
    existed only in `.aramid/logs/`, 15KB of pytest output that nothing in the
    blocked output mentioned. They found it on a hunch.

    This drives the whole path -- runner to log file to GateResult to rendered
    console -- because the two halves passing separately would not prove the
    pointer names anything real. The assertions are deliberately that the file
    EXISTS and CONTAINS the failing test name: a pointer to an absent path
    would be the same "points at nothing" defect in a new costume.
    """
    import re

    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    # The `tests` slot is only SELECTED where a suite is detected, so a repo
    # with one `a.py` never reaches the runner being faked below. Naming the
    # command explicitly is what puts the slot in scope.
    (root / "aramid.toml").write_text(
        '[tests]\ncommand = ["python", "-m", "pytest", "-q"]\n', encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_probe.py").write_text("def test_x():\n    pass\n",
                                                   encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "add suite")

    pytest_output = ("FAILED tests/test_probe.py::test_timeout_carries_output "
                     "- assert 0 > 0\n1 failed, 2925 passed")
    raw = RawFinding(tool="python.exe", rule="tests-failed", severity_raw="high",
                      file="<test-suite>", line=0,
                      message="python.exe exited 1: test suite failed")
    monkeypatch.setitem(pipeline.RUNNERS, "tests",
                         _fake(RunnerResult("python.exe", ToolState.OK,
                                            raw=pytest_output, returncode=1),
                               raws=[raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    rc = cmd_check(root, Gate.PRE_PUSH, "range")
    out = capsys.readouterr().out

    assert rc == 1, out
    match = re.search(r"full output: (\S+)", out)
    assert match, f"a finding located at a marker must name its log:\n{out}"

    named = root / match.group(1)
    assert named.exists(), f"the pointer names a path that does not exist: {named}"
    assert "test_timeout_carries_output" in named.read_text(encoding="utf-8"), \
        "the log must actually carry the discriminating information"


# --------------------------- (e) fresh ledger, pre-push, degraded BLOCK-tier -

def test_fresh_ledger_prepush_degraded_block_tier_still_blocks(tmp_path, monkeypatch):
    """`pipeline.run_gate` has a SECOND, finding-free route to exit_code==1:
    a BLOCK-tier tool (gitleaks/semgrep/tests -- pipeline.BLOCK_TIER_KEYS)
    that comes back MISSING/CRASHED/TIMEOUT at pre-push escalates via
    `policy.escalate_degraded`, with no Finding object produced at all (the
    tool never ran, so it never emitted anything to classify). The
    fresh-clone rule must not downgrade this case either -- a broken/absent
    secret scanner on a fresh clone's very first push must never silently
    pass. Repro of reviewer's CRITICAL-1 finding (task-7-review.md)."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    assert not Ledger(root / ".aramid" / "ledger.db").has_baseline()

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                         _fake(RunnerResult("gitleaks", ToolState.MISSING)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["gitleaks"])

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 1


# ------- (f) fresh ledger, pre-push, degraded BLOCK-tier, tool-name != key --

def test_fresh_ledger_prepush_degraded_block_tier_tool_name_diverges_from_key(
        tmp_path, monkeypatch):
    """`pipeline.run_gate`'s own `degraded_block_tier` computation keys off
    the RUNNERS *registry key* ("tests"), but a degraded `tests` runner's
    `RunnerResult.tool` can be a DIFFERENT string -- e.g. "pytest", set
    inside `run_pytest` -> `run_subprocess` when the pytest binary itself is
    missing (runners/tests.py). `GateResult.degraded` is built from
    `RunnerResult.tool` names, not registry keys, so naively intersecting
    `result.degraded` against `pipeline.BLOCK_TIER_KEYS` (registry keys)
    would MISS this case. The fix must reuse `result.degraded_block_tier`
    (pipeline's own already-computed flag), not re-derive it from tool
    names, to avoid exactly this divergence."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    (root / "tests").mkdir()  # makes "tests" applicable via detect_tests()
    # A bare dir is no longer a detect_tests() signal (Task 1) -- a real
    # test file is what keeps "tests" applicable.
    (root / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8")
    assert not Ledger(root / ".aramid" / "ledger.db").has_baseline()

    # Simulate: pytest detected as the test framework, but the pytest
    # BINARY itself is missing -- RunnerResult.tool ends up "pytest", not
    # "tests" (the registry key).
    monkeypatch.setitem(pipeline.RUNNERS, "tests",
                         _fake(RunnerResult("pytest", ToolState.MISSING)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["tests"])

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 1


# --- (g) fresh ledger, pre-push, armed+confirmed+critical LLM BLOCK finding -

def test_fresh_ledger_prepush_armed_confirmed_critical_llm_finding_still_blocks(
        tmp_path, monkeypatch):
    """task-13b HIGH gap (review of Phase 1's fresh-ledger exemption):
    `policy.classify("llm-review", ...)` ALWAYS returns WARN by deliberate
    Task 3 design -- the real BLOCK verdict for an LLM finding is computed
    only in `review.llm_gate_findings` from ledger state + [llm].llm_block_armed,
    never in policy.classify. `_has_genuine_block`'s `policy.classify`
    re-derivation therefore can NEVER see an LLM finding as genuine, even one
    whose verdict IS Verdict.BLOCK (which only happens when armed + confirmed
    + critical -- a deliberate, refute-confirmed block, not legacy onboarding
    debt; arming is meant to be retroactive). Without the fix, this silently
    downgrades to exit 0 on a fresh clone / CI runner / reset ledger (`.aramid/`
    is gitignored), defeating the LLM gate entirely."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    (root / "aramid.toml").write_text(
        'schema_version = 1\n\n[llm]\nllm_block_armed = true\n', encoding="utf-8")

    quote = "return db.get(order_id)"
    (root / "src").mkdir()
    (root / "src" / "auth.py").write_text(quote + "\n", encoding="utf-8")
    _git(root, "add", "src/auth.py")
    _git(root, "commit", "-q", "-m", "add auth")

    ledger = Ledger(root / ".aramid" / "ledger.db")
    assert not ledger.has_baseline()
    finding = Finding(
        id="f" * 64, tool="llm-review", rule="llm/a01", severity_raw="critical",
        severity=Severity.CRITICAL, verdict=Verdict.WARN, file="src/auth.py", line=1,
        message="IDOR: no ownership check", evidence=quote, gate=Gate.ALL,
        source=Source.LLM, confirmed=True)
    ledger.record_run("r0", "2026-01-01T00:00:00+00:00", "drain", set(), set(), [finding])
    ledger.close()

    # No deterministic runners at all this pre-push -- isolates the block to
    # the materialized LLM finding alone.
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, [])

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 1


# --------------------------------------------------------- --strict mapping -

def test_strict_maps_degraded_exit_2_to_1(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    # pre-baseline this repo so the fresh-clone rule doesn't interfere.
    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.write_baseline("seed", "2026-01-01T00:00:00+00:00", set())
    ledger.close()

    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.MISSING)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    rc_non_strict = cmd_check(root, Gate.PRE_COMMIT, "staged", strict=False)
    assert rc_non_strict == 2

    rc_strict = cmd_check(root, Gate.PRE_COMMIT, "staged", strict=True)
    assert rc_strict == 1


# ------------------------------------------- --strict --json exit-code sync -

def test_strict_json_reports_final_exit_code(tmp_path, monkeypatch):
    """`cmd_check` reassigns its local `exit_code` twice (fresh-clone
    downgrade, then --strict remap) but must render the FINAL value, not
    the pipeline's original, unmutated `result.exit_code` -- otherwise the
    JSON body's "exit_code" field can disagree with the process's actual
    return code (Important-1, task-7-review.md). Exercises exactly the
    invocation pattern check.py's own docstring calls out as the CI use
    case: `--strict --json` on a degraded (non-block-tier, pre-baselined)
    case, where non-strict would be 2 but --strict remaps to 1."""
    import contextlib
    import io
    import json

    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    # pre-baseline this repo so the fresh-clone rule doesn't interfere.
    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.write_baseline("seed", "2026-01-01T00:00:00+00:00", set())
    ledger.close()

    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.MISSING)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_check(root, Gate.PRE_COMMIT, "staged", strict=True, as_json=True)

    assert rc == 1
    parsed = json.loads(buf.getvalue())
    assert parsed["exit_code"] == 1
    assert parsed["exit_code"] == rc


# ----------------------------------------------------- --json output mode ---

def test_json_mode_emits_valid_json(tmp_path, monkeypatch):
    import json

    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.write_baseline("seed", "2026-01-01T00:00:00+00:00", set())
    ledger.close()

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                         _fake(RunnerResult("gitleaks", ToolState.OK)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["gitleaks"])

    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_check(root, Gate.PRE_COMMIT, "staged", as_json=True)

    assert rc == 0
    parsed = json.loads(buf.getvalue())
    assert parsed["exit_code"] == 0


# --------------------------------------------------- ARAMID_ACCEPT_DEGRADED -

def test_env_accept_degraded_is_read_when_flag_arg_absent(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.write_baseline("seed", "2026-01-01T00:00:00+00:00", set())
    ledger.close()

    (root / "tests").mkdir()  # keep "tests" applicable-by-detection irrelevant here;
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                         _fake(RunnerResult("fake", ToolState.MISSING)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["fake"])
    monkeypatch.setattr(pipeline, "BLOCK_TIER_KEYS", frozenset({"fake"}))
    monkeypatch.setenv("ARAMID_ACCEPT_DEGRADED", "ci has no fake binary")

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 2
    ledger = Ledger(root / ".aramid" / "ledger.db")
    events = [e for e in ledger.events() if e.type.value == "infrastructure_bypass"]
    assert len(events) == 1
    assert events[0].payload["reason"] == "ci has no fake binary"
    ledger.close()
