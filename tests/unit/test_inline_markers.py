"""unit: FN-38 -- a tool's own inline marker that hides a BLOCK-tier hit is
reported as a WARN finding of its own. Spec:
docs/superpowers/specs/2026-10-09-aramid-visible-inline-suppressions-design.md.

The finding is stamped with a per-tool LABEL (`ruff-inline`, `gitleaks-inline`,
`semgrep-inline`), never `aramid`: `ledger.record_run` resolves an open finding
only when its tool is the label of a runner result that ran OK, so a tool name
no runner reports could never resolve once its marker was removed.
"""
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import config, pipeline, policy
from aramid.fingerprint import compute_fingerprint
from aramid.ledger import Ledger
from aramid.models import Gate, Severity, Verdict
from aramid.normalizer import RawFinding, normalize
from aramid.runners import inline
from aramid.runners.base import RunnerResult, ToolState

_LINE = 'password = "hunter2hunter2"  # noqa: S105'


def _raw(tool, rule, subject=None, *, line_content=_LINE, file="creds.py", message="m"):
    return RawFinding(tool=tool, rule=rule, severity_raw="error", file=file, line=1,
                      message=message, line_content=line_content, subject=subject)


def _ids(raws):
    findings = normalize(raws, Path("."), lambda f: "HEAD", b"salt", Gate.PRE_PUSH,
                         lambda t, r, s, g: (Severity.HIGH, Verdict.WARN))
    return [f.id for f in findings]


# --------------------------------------------------------------- identity ---

def test_a_raw_without_a_subject_keeps_the_id_it_always_had():
    # Every existing producer leaves `subject` unset; their ids must not move,
    # or every suppression and override in every consumer stops binding.
    assert _ids([_raw("ruff", "S105")]) == [
        compute_fingerprint("ruff", "S105", "creds.py", _LINE, 0)]


def test_the_inline_finding_never_shares_the_underlying_findings_id():
    # A shared id would let a suppression written to accept the MARKER also
    # downgrade the real BLOCK once the marker is gone.
    real, hidden = _ids([_raw("ruff", "S105"),
                         _raw(inline.RUFF, inline.RULE, ("ruff", "S105"))])
    assert real != hidden


def test_two_hidden_rules_on_one_line_get_ids_that_do_not_depend_on_order():
    # Positional occurrence numbering alone would swap these two ids whenever
    # the tool reported the rules in the other order, and a reasoned
    # suppression entry would silently move to the other rule.
    s105 = _raw(inline.RUFF, inline.RULE, ("ruff", "S105"))
    s106 = _raw(inline.RUFF, inline.RULE, ("ruff", "S106"))
    forward = _ids([s105, s106])
    backward = _ids([s106, s105])
    assert forward[0] != forward[1]
    assert forward == list(reversed(backward))


# ---------------------------------------------------------------- verdict ---

def _promoting_cfg():
    """Every promotion path armed, and repo additions that would match the
    rule id if any branch ever compared it."""
    rules = policy.load_block_rules()
    rules["ruff"]["block"] = [*rules["ruff"]["block"], inline.RULE]
    rules["semgrep"]["block"] = [*rules["semgrep"]["block"], "*"]
    return SimpleNamespace(block_rules=rules, semgrep_block_armed=True,
                           tdd_block_armed=True, mutation={"mutation_block_armed": True},
                           red_proof={"red_proof_block_armed": True},
                           shadow={"shadow_block_armed": True},
                           pack={"pack_block_armed": True})


@pytest.mark.parametrize("label", sorted(inline.TOOLS))
@pytest.mark.parametrize("gate", [Gate.PRE_COMMIT, Gate.PRE_PUSH, Gate.ALL])
def test_an_inline_finding_is_warn_at_every_gate_whatever_block_rules_say(label, gate):
    _, verdict = policy.classify(label, inline.RULE, "high", gate, _promoting_cfg())
    assert verdict is Verdict.WARN


# ------------------------------------------------------- through the gate ---

def _git(root, *args):
    subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "creds.py").write_text(_LINE + "\n", encoding="utf-8")
    _git(r, "add", "creds.py")
    _git(r, "commit", "-m", "initial")
    return r


def _cfg(root, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    return config.load_config(root)


def _only(monkeypatch, gate, raws):
    """One runner double whose parse() yields `raws`; nothing else runs."""
    monkeypatch.setitem(pipeline.RUNNERS, "fake", SimpleNamespace(
        run=lambda ctx: RunnerResult("fake", ToolState.OK),
        parse=lambda result, ctx: list(raws)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, gate, ["fake"])
    monkeypatch.setattr(pipeline.tdd, "scan", lambda ctx, cfg: [])
    monkeypatch.setattr(pipeline.red_proof, "scan_scoped", lambda ctx, cfg: ([], set()))


def test_a_new_inline_finding_is_not_escalated_by_the_push_ratchet(tmp_path, monkeypatch):
    # The first push after upgrading meets every marker the repo already has
    # (25 in aramid's own tree). Escalated, that push would be refused for
    # markers nobody added in it. A baseline run first, so `new_ids` is the
    # ratchet's real input rather than "everything".
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = Ledger(tmp_path / "ledger.db")
    _only(monkeypatch, Gate.PRE_PUSH, [])
    pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="baseline")

    _only(monkeypatch, Gate.PRE_PUSH, [_raw(inline.RUFF, inline.RULE, ("ruff", "S105"))])
    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="next")

    [finding] = result.findings
    assert finding.id in result.new_ids
    assert finding.verdict is Verdict.WARN
    assert finding.id not in result.ratchet_escalated
    assert result.exit_code == 0
    ledger.close()


def test_a_marker_that_hides_a_warn_tier_rule_produces_nothing(tmp_path, monkeypatch):
    # F401 is not BLOCK-tier: silencing it inline is the repo's own business.
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = Ledger(tmp_path / "ledger.db")
    _only(monkeypatch, Gate.PRE_COMMIT, [
        _raw(inline.RUFF, inline.RULE, ("ruff", "F401"), message="hides F401"),
        _raw(inline.RUFF, inline.RULE, ("ruff", "S105"), message="hides S105")])

    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="r1")

    assert [f.message for f in result.findings] == ["hides S105"]
    ledger.close()


def test_semgrep_markers_count_only_while_semgrep_would_block(tmp_path, monkeypatch):
    # The one authority is `policy.classify` on the HIDDEN hit: a disarmed
    # semgrep (the bake) blocks nothing, so its markers hide nothing that
    # would have blocked.
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    hidden = _raw(inline.SEMGREP, inline.RULE,
                  ("semgrep", "owasp-top-ten.a03-injection.python-sqli-string-concat"))
    for armed, expected in ((False, 0), (True, 1)):
        cfg.semgrep_block_armed = armed
        ledger = Ledger(tmp_path / f"ledger-{armed}.db")
        _only(monkeypatch, Gate.PRE_COMMIT, [hidden])
        result = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger,
                                   run_id=f"r-{armed}")
        assert len(result.findings) == expected, armed
        ledger.close()


# ------------------------------------------------------------ the wiring ---

def test_the_gate_turns_the_inline_pass_on_with_the_resolved_ruff_block_list(
        tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    cfg.block_rules["ruff"]["block"] = [*cfg.block_rules["ruff"]["block"], "S324"]
    seen = []
    monkeypatch.setitem(pipeline.RUNNERS, "fake", SimpleNamespace(
        run=lambda ctx: seen.append(ctx) or RunnerResult("fake", ToolState.OK),
        parse=lambda result, ctx: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])
    ledger = Ledger(tmp_path / "ledger.db")

    pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="r1")

    [ctx] = seen
    assert ctx.inline_pass is True
    assert ctx.ruff_block_rules == tuple(cfg.block_rules["ruff"]["block"])
    assert "S324" in ctx.ruff_block_rules
    ledger.close()


# ------------------------------------------------------------- lifecycle ---
#
# A bundle as the real runners build it: the tool's own result plus its
# second pass, the second carrying what it examined. mode "all", so the
# committed file is in the gate's scope.

def _bundle_runner(monkeypatch, second: RunnerResult, raws):
    own = RunnerResult("fake", ToolState.OK, raw="[]")
    monkeypatch.setitem(pipeline.RUNNERS, "fake", SimpleNamespace(
        run=lambda ctx: inline.bundle(own, second),
        parse=lambda result, ctx: list(raws)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])


def _second(state=ToolState.OK):
    return RunnerResult(inline.RUFF, state, raw="[]",
                        examined=frozenset({"creds.py"}) if state is ToolState.OK else None)


def test_an_inline_finding_resolves_once_its_marker_is_gone(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = Ledger(tmp_path / "ledger.db")
    _bundle_runner(monkeypatch, _second(), [_raw(inline.RUFF, inline.RULE, ("ruff", "S105"))])
    [finding] = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger,
                                  run_id="r1").findings
    assert ledger.open_findings()[finding.id]["status"] == "open"

    _bundle_runner(monkeypatch, _second(), [])
    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="r2")

    assert inline.RUFF in result.tools_ran
    assert ledger.open_findings()[finding.id]["status"] == "fixed"
    ledger.close()


def test_a_degraded_second_pass_leaves_its_findings_open_and_says_so(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = Ledger(tmp_path / "ledger.db")
    _bundle_runner(monkeypatch, _second(), [_raw(inline.RUFF, inline.RULE, ("ruff", "S105"))])
    [finding] = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger,
                                  run_id="r1").findings

    _bundle_runner(monkeypatch, _second(ToolState.TIMEOUT), [])
    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="r2")

    assert ledger.open_findings()[finding.id]["status"] == "open"
    assert result.degraded == [inline.RUFF]
    assert "fake" in result.tools_ran
    assert result.exit_code == 2      # a WARN-tier degradation, as for any runner
    ledger.close()


def test_a_suppression_entry_accepts_the_marker_and_goes_stale_when_the_line_changes(
        tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = Ledger(tmp_path / "ledger.db")
    hidden = _raw(inline.RUFF, inline.RULE, ("ruff", "S105"))
    _bundle_runner(monkeypatch, _second(), [hidden])
    [finding] = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger,
                                  run_id="r1").findings
    (root / ".aramid-suppressions.toml").write_text(
        "[[suppress]]\n"
        f'tool = "{inline.RUFF}"\nrule = "{inline.RULE}"\npath = "creds.py"\n'
        f'id = "{finding.id}"\nreason = "fixture credential in a test helper"\n',
        encoding="utf-8")

    accepted = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="r2")
    assert [f.verdict for f in accepted.findings] == [Verdict.INFO]
    assert accepted.stale_overrides == []

    moved = _raw(inline.RUFF, inline.RULE, ("ruff", "S105"),
                 line_content='password = "a-different-fixture"  # noqa: S105')
    _bundle_runner(monkeypatch, _second(), [moved])
    changed = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="r3")
    assert [f.verdict for f in changed.findings] == [Verdict.WARN]
    assert [s.id for s in changed.stale_overrides] == [finding.id]
    ledger.close()


def test_a_degraded_second_pass_refuses_a_strict_run_like_any_degraded_runner(
        tmp_path, monkeypatch):
    # The decision, pinned: a second pass that did not run is UNGRADED, not
    # clean. Non-strict hooks let exit 2 through; `--strict` (CI, and
    # `[hooks].pre_push_match_ci`) refuses it, as it does any degraded runner.
    import contextlib
    import io
    import json
    from aramid.commands.check import cmd_check
    root = _repo(tmp_path)
    _cfg(root, tmp_path, monkeypatch)
    _bundle_runner(monkeypatch, _second(ToolState.TIMEOUT), [])
    for strict, expected in ((False, 2), (True, 1)):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cmd_check(root, Gate.PRE_COMMIT, "all", strict=strict, as_json=True)
        assert rc == expected, (strict, rc)
        assert json.loads(buf.getvalue())["degraded"] == [inline.RUFF]


# ---------------------------------------------------------- deadline guard ---

def test_a_second_pass_without_a_deadline_runs_on_the_calling_thread():
    import threading
    ran_on = []
    ctx = SimpleNamespace(gate_deadline=None)
    done = RunnerResult(inline.GITLEAKS, ToolState.OK, raw="[]")
    result = inline.within_deadline(ctx, inline.GITLEAKS,
                                    lambda: ran_on.append(threading.current_thread()) or done)
    assert result is done
    assert ran_on == [threading.current_thread()]


@pytest.mark.parametrize("deadline", [None, 60.0])
def test_a_second_pass_that_raises_is_crashed_under_its_label_never_an_exception(deadline):
    # Raised out of the runner, the gate would mark the WHOLE key crashed and
    # lose the tool's own finished result with it.
    import time

    def boom():
        raise ValueError("a value quoted from the report")

    ctx = SimpleNamespace(gate_deadline=None if deadline is None else time.monotonic() + deadline)
    result = inline.within_deadline(ctx, inline.GITLEAKS, boom)
    assert (result.tool, result.state) == (inline.GITLEAKS, ToolState.CRASHED)
    # The type and nothing the exception says: stderr always reaches the
    # label's log, and a secret only the second pass found is not among the
    # values the log scrubber is given (a crashed pass yields no findings).
    assert result.stderr == f"aramid: {inline.GITLEAKS} raised ValueError"


def test_a_second_pass_still_running_at_the_margin_is_abandoned_as_a_timeout():
    import threading
    import time
    release = threading.Event()
    ctx = SimpleNamespace(gate_deadline=time.monotonic() + inline.MARGIN_S + 0.5)
    started = time.monotonic()
    result = inline.within_deadline(ctx, inline.GITLEAKS, lambda: release.wait(30) and None)
    waited = time.monotonic() - started
    release.set()
    assert (result.tool, result.state) == (inline.GITLEAKS, ToolState.TIMEOUT)
    assert 0.3 < waited < 2.0, waited
    assert "abandoned" in result.stderr
