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
