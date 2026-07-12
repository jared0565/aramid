import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import config, pipeline
from aramid.ledger import Ledger
from aramid.models import EventType, Gate, Verdict
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

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-f")

    assert result.exit_code == 1
    assert len(result.findings) == 1
    assert result.findings[0].verdict is Verdict.BLOCK
    assert result.findings[0].id in result.new_ids
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
