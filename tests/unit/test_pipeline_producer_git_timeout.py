"""FN-21: an ARMED tdd or red-proof producer whose git did not answer
degrades the pre-push gate as a BLOCK-tier tool, instead of reading as no
finding.

Both producers swallowed `GitTimeout` into "no finding" (fail-open, kept on
purpose by FN-17), so with `tdd_block_armed` or `red_proof_block_armed` a
git that hung past `gitutil.GIT_TIMEOUT_S` let the push through unchecked
by that producer. They now let the timeout go up, and `run_gate` decides by
arming -- the same `policy.classify` question the override refusal asks:
armed, the producer joins `degraded` and `degraded_block_tier`, so the push
is refused unless the operator accepts the degradation with a reason;
disarmed (the bake), it stays fail-open exactly as before.
"""
import subprocess
from pathlib import Path

from aramid import config, gitutil, pipeline
from aramid.ledger import Ledger
from aramid.models import EventType, Gate


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n")
    _git(r, "add", "a.py")
    _git(r, "commit", "-m", "initial")
    return r


def _setup(tmp_path, monkeypatch, *, hang):
    """A pre-push gate with no runners, whose `hang` producer's git never
    answers and whose other producer finds nothing."""
    root = _repo(tmp_path)
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    cfg = config.load_config(root)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, [])

    def hung(*a, **k):
        raise gitutil.GitTimeout("git diff did not answer")

    monkeypatch.setattr(pipeline.tdd, "scan", hung if hang == "tdd" else (lambda ctx, cfg: []))
    monkeypatch.setattr(pipeline.red_proof, "scan_scoped",
                        hung if hang == "red-proof" else (lambda ctx, cfg: ([], set())))
    return root, cfg, Ledger(tmp_path / "ledger.db")


def _degraded_on_the_row(ledger):
    finished = [e for e in ledger.events() if e.type is EventType.RUN_FINISHED][-1]
    return finished.payload["degraded"]


def test_an_armed_tdd_whose_git_hung_refuses_the_push(tmp_path, monkeypatch):
    root, cfg, ledger = _setup(tmp_path, monkeypatch, hang="tdd")
    cfg.tdd_block_armed = True
    try:
        result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-t")
        assert result.exit_code == 1
        assert result.degraded == ["tdd"]
        assert result.degraded_block_tier is True
        assert result.degraded_reasons == {"tdd": "git did not answer: git diff did not answer"}
        assert _degraded_on_the_row(ledger) == result.degraded_reasons
    finally:
        ledger.close()


def test_a_disarmed_tdd_whose_git_hung_stays_fail_open(tmp_path, monkeypatch):
    root, cfg, ledger = _setup(tmp_path, monkeypatch, hang="tdd")
    try:
        result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-t")
        assert result.exit_code == 0
        assert result.degraded == []
        assert result.degraded_block_tier is False
        assert _degraded_on_the_row(ledger) == {}
    finally:
        ledger.close()


def test_an_armed_red_proof_whose_git_hung_refuses_the_push(tmp_path, monkeypatch):
    root, cfg, ledger = _setup(tmp_path, monkeypatch, hang="red-proof")
    cfg.red_proof["red_proof_block_armed"] = True
    try:
        result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-r")
        assert result.exit_code == 1
        assert result.degraded == ["red-proof"]
        assert result.degraded_block_tier is True
        assert result.degraded_reasons == {
            "red-proof": "git did not answer: git diff did not answer"}
        assert _degraded_on_the_row(ledger) == result.degraded_reasons
    finally:
        ledger.close()


def test_a_disarmed_red_proof_whose_git_hung_stays_fail_open(tmp_path, monkeypatch):
    root, cfg, ledger = _setup(tmp_path, monkeypatch, hang="red-proof")
    try:
        result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-r")
        assert result.exit_code == 0
        assert result.degraded == []
        assert result.degraded_block_tier is False
    finally:
        ledger.close()


def test_arming_one_producer_does_not_arm_the_other(tmp_path, monkeypatch):
    # tdd hangs, only red-proof is armed: tdd is still the bake.
    root, cfg, ledger = _setup(tmp_path, monkeypatch, hang="tdd")
    cfg.red_proof["red_proof_block_armed"] = True
    try:
        result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-x")
        assert result.exit_code == 0
        assert result.degraded == []
    finally:
        ledger.close()


def test_an_accepted_degradation_lets_the_push_through_on_record(tmp_path, monkeypatch):
    # The documented escape hatch for a degraded BLOCK-tier tool covers the
    # producer too: exit 0, with the bypass row naming it.
    root, cfg, ledger = _setup(tmp_path, monkeypatch, hang="tdd")
    cfg.tdd_block_armed = True
    try:
        result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-a",
                                   accept_degraded="git server down, reviewed by hand")
        assert result.exit_code == 0
        (bypass,) = [e for e in ledger.events() if e.type is EventType.INFRASTRUCTURE_BYPASS]
        assert bypass.payload["degraded"] == ["tdd"]
    finally:
        ledger.close()


def test_only_the_pre_push_gate_runs_the_producers(tmp_path, monkeypatch):
    # The producers are pre-push only; a pre-commit never reaches them, so
    # an armed producer's hang cannot degrade it.
    root, cfg, ledger = _setup(tmp_path, monkeypatch, hang="tdd")
    cfg.tdd_block_armed = True
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, [])
    try:
        result = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-c")
        assert result.exit_code == 0
        assert result.degraded == []
    finally:
        ledger.close()
