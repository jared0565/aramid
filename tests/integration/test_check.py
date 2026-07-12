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
from aramid.models import Gate
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
