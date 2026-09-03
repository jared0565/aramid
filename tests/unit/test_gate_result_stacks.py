"""The fleet health row asks 'should pip-audit have run here', which is a
question about the repo's STACK, not about which requirements files exist.
`run_gate` already detects the stacks for runner selection; the result has
to carry them so the row does not re-walk the tree at push time."""
import subprocess
from types import SimpleNamespace

from aramid import config, pipeline
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _python_repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "a.py")
    _git(r, "commit", "-q", "-m", "initial")
    return r


def test_run_gate_carries_the_detected_stacks(tmp_path, monkeypatch):
    root = _python_repo(tmp_path)
    cfg = config.load_config(root)
    ledger = Ledger(tmp_path / "ledger.db")
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                        SimpleNamespace(run=lambda ctx: RunnerResult("fake", ToolState.OK),
                                        parse=lambda result, ctx: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger)

    assert result.stacks == ("python",)
    ledger.close()


def test_stacks_defaults_empty_for_hand_built_results():
    r = pipeline.GateResult(exit_code=0, findings=[], degraded=[], new_ids=[],
                            stale_overrides=[], run_id="r")
    assert r.stacks == ()
