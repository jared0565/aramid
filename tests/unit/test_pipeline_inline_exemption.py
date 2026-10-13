"""The push ratchet exempts the inline pass's own findings (FN-38) by their
label AND their rule. A repo's own rule that happens to carry the inline
rule's id, `inline-suppressed-block`, is not one of them and is held to the
ratchet like any other. Pins `and` against `or` in `run_gate._escalates`,
which FN-39's edit to run_gate put in the drain's scope (the generator draws a
changed function whole)."""
import subprocess
from types import SimpleNamespace

from aramid import config, pipeline
from aramid.ledger import Ledger
from aramid.models import Gate, Verdict
from aramid.normalizer import RawFinding
from aramid.runners import inline
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *args):
    subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True)


def _only(monkeypatch, raws):
    """One runner double whose parse() yields `raws`; nothing else runs."""
    monkeypatch.setitem(pipeline.RUNNERS, "fake", SimpleNamespace(
        run=lambda ctx: RunnerResult("fake", ToolState.OK),
        parse=lambda result, ctx: list(raws)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["fake"])
    monkeypatch.setattr(pipeline.tdd, "scan", lambda ctx, cfg: [])
    monkeypatch.setattr(pipeline.red_proof, "scan_scoped", lambda ctx, cfg: ([], set()))


def _new_finding(tmp_path, monkeypatch, tool, severity_raw, subject=None):
    r = tmp_path / tool / "r"
    r.mkdir(parents=True)
    for args in (("init", "-b", "main"), ("config", "user.email", "t@t"),
                 ("config", "user.name", "t")):
        _git(r, *args)
    (r / "a.py").write_text("x = 1\n")
    _git(r, "add", "a.py")
    _git(r, "commit", "-m", "initial")
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    cfg = config.load_config(r)
    ledger = Ledger(tmp_path / tool / "ledger.db")
    _only(monkeypatch, [])
    pipeline.run_gate(r, Gate.PRE_PUSH, "range", cfg, ledger, run_id="baseline")
    _only(monkeypatch, [RawFinding(tool=tool, rule=inline.RULE, severity_raw=severity_raw,
                                   file="a.py", line=1, message="m", line_content="x = 1",
                                   subject=subject)])
    result = pipeline.run_gate(r, Gate.PRE_PUSH, "range", cfg, ledger, run_id="next")
    ledger.close()
    [finding] = result.findings
    assert finding.id in result.new_ids
    return finding, result


def test_a_repo_rule_named_like_the_inline_rule_is_held_to_the_ratchet(tmp_path, monkeypatch):
    finding, result = _new_finding(tmp_path, monkeypatch, "semgrep", "low")
    assert (finding.verdict, finding.id in result.ratchet_escalated, result.exit_code) == (
        Verdict.BLOCK, True, 1)


def test_control_the_inline_pass_own_finding_is_exempt(tmp_path, monkeypatch):
    """The inline pass's own shape, as `test_inline_markers` builds it: a marker
    hiding a BLOCK-tier rule."""
    finding, result = _new_finding(tmp_path, monkeypatch, inline.RUFF, "error",
                                   ("ruff", "S105"))
    assert (finding.verdict, finding.id in result.ratchet_escalated, result.exit_code) == (
        Verdict.WARN, False, 0)
