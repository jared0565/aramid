import json

from aramid import reporter
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Verdict
from aramid.pipeline import GateResult
from aramid.policy import OverrideRecord


def _f(fid, tool="ruff", rule="S102", verdict=Verdict.WARN, file="a.py", line=1):
    return Finding(fid, tool, rule, "high", Severity.HIGH, verdict,
                    file, line, "m", "e", Gate.PRE_PUSH)


# ---------------------------------------------- NEW-first + baseline collapse

def test_new_findings_render_before_collapsed_baseline(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    findings = [
        _f("base1", verdict=Verdict.WARN),
        _f("base2", verdict=Verdict.WARN, file="b.py"),
        _f("new1", verdict=Verdict.BLOCK, file="c.py"),
    ]
    result = GateResult(exit_code=1, findings=findings, degraded=[], new_ids=["new1"],
                         stale_overrides=[], run_id="r1")

    out = reporter.render_console(result, ledger)

    assert "new1" in out
    assert "(+2 baseline findings)" in out
    assert out.index("new1") < out.index("(+2 baseline findings)")
    ledger.close()


def test_blocking_baseline_finding_is_named_not_just_counted(tmp_path):
    """A BLOCK verdict is the REASON the gate fails, so it must be named even
    when it is not new.

    Before this, a blocking finding that was not first-seen-this-run got
    collapsed into `(+N baseline findings)`, so the gate exited 1 having
    printed nothing but a count -- `--json` was the only way to learn what
    blocked. Hit for real while pushing a release tag: the whole output was

        (+7 baseline findings)
        45 findings open in ledger
        error: failed to push some refs to '...'
    """
    ledger = Ledger(tmp_path / "l.db")
    findings = [
        _f("warn1", verdict=Verdict.WARN),
        _f("blk1", tool="tests", rule="tests-failed", verdict=Verdict.BLOCK,
           file="<test-suite>", line=0),
    ]
    result = GateResult(exit_code=1, findings=findings, degraded=[], new_ids=[],
                        stale_overrides=[], run_id="r1")

    out = reporter.render_console(result, ledger)

    assert "blk1" in out, f"the blocking finding was never named:\n{out}"
    assert "tests-failed" in out
    # the WARN one stays collapsed -- this is not a licence to print everything
    assert "warn1" not in out
    assert "(+1 baseline findings)" in out
    ledger.close()


def test_gate_that_blocks_never_renders_only_a_count(tmp_path):
    """The invariant behind the test above, stated directly: if anything in the
    result blocks, the rendered text must contain that finding's id. A future
    refactor that reintroduces the collapse fails here."""
    ledger = Ledger(tmp_path / "l.db")
    for new_ids in ([], ["blk1"]):          # blocking, new and not-new alike
        result = GateResult(exit_code=1, findings=[_f("blk1", verdict=Verdict.BLOCK)],
                            degraded=[], new_ids=new_ids, stale_overrides=[], run_id="r1")
        out = reporter.render_console(result, ledger)
        assert "blk1" in out, f"new_ids={new_ids} rendered no cause:\n{out}"
    ledger.close()


# ------------------------------------------------------- secret rotate line --

def test_secret_finding_shows_rotate_warning(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    findings = [_f("sec1", tool="gitleaks", rule="aws-key", verdict=Verdict.BLOCK)]
    result = GateResult(exit_code=1, findings=findings, degraded=[], new_ids=["sec1"],
                         stale_overrides=[], run_id="r1")

    out = reporter.render_console(result, ledger)

    assert "rotate the credential — deleting the line does not fix the leak" in out
    ledger.close()


def test_non_secret_finding_has_no_rotate_warning(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    findings = [_f("new1", tool="ruff", verdict=Verdict.BLOCK)]
    result = GateResult(exit_code=1, findings=findings, degraded=[], new_ids=["new1"],
                         stale_overrides=[], run_id="r1")

    out = reporter.render_console(result, ledger)

    assert "rotate the credential" not in out
    ledger.close()


# --------------------------------------------------------- stale overrides ---

def test_stale_override_renders_reaffirm_line(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    stale = [OverrideRecord(id="stale1", tool="ruff", rule="S102", path="a.py", reason="was fine")]
    result = GateResult(exit_code=0, findings=[], degraded=[], new_ids=[],
                         stale_overrides=stale, run_id="r1")

    out = reporter.render_console(result, ledger)

    # The tier tags this line used to carry -- "(WARN)" on the ledger route,
    # "(BLOCK)" on the file -- became wrong when the committed file went
    # tier-agnostic: the file is now the right answer at EITHER tier, and it
    # is the only one a teammate ever sees. The routes differ in reach, so
    # that is what the line names.
    assert ("stale override stale1 -- re-affirm it: `aramid override stale1 --reason` "
            "(WARN only, machine-local) or an entry in .aramid-suppressions.toml "
            "(any tier, committed)") in out
    ledger.close()


def test_no_stale_overrides_renders_no_reaffirm_line(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    result = GateResult(exit_code=0, findings=[], degraded=[], new_ids=[],
                         stale_overrides=[], run_id="r1")

    out = reporter.render_console(result, ledger)

    assert "stale override" not in out
    ledger.close()


# -------------------------------------------------------------- degraded ----

def test_degraded_tools_listed_as_skips(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    result = GateResult(exit_code=2, findings=[], degraded=["semgrep", "tests"], new_ids=[],
                         stale_overrides=[], run_id="r1")

    out = reporter.render_console(result, ledger)

    assert "semgrep" in out
    assert "tests" in out
    ledger.close()


# ---------------------------------------------------------------- aging -----

def test_open_count_line_reflects_ledger_state(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    ledger.record_run("r0", "t0", "pre-push", {"ruff"}, {"a.py", "b.py"},
                       [_f("id1"), _f("id2", file="b.py")])
    result = GateResult(exit_code=0, findings=[], degraded=[], new_ids=[],
                         stale_overrides=[], run_id="r1")

    out = reporter.render_console(result, ledger)

    assert "2 findings open" in out
    ledger.close()


# ------------------------------------------------------------- render_json --

def test_render_json_is_valid_and_shape_matches():
    findings = [_f("new1", tool="ruff", verdict=Verdict.BLOCK)]
    stale = [OverrideRecord(id="stale1", tool="ruff", rule="S102", path="a.py", reason="r")]
    result = GateResult(exit_code=1, findings=findings, degraded=["semgrep"], new_ids=["new1"],
                         stale_overrides=stale, run_id="r1")

    out = reporter.render_json(result)
    parsed = json.loads(out)

    assert parsed["exit_code"] == 1
    assert parsed["degraded"] == ["semgrep"]
    assert parsed["new_ids"] == ["new1"]
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["id"] == "new1"
    assert len(parsed["stale_overrides"]) == 1
    assert parsed["stale_overrides"][0]["id"] == "stale1"


def test_render_json_never_contains_raw_secret():
    # Finding.evidence is already-redacted (normalizer's job) -- reporter must
    # not reintroduce raw material; simulate a redacted evidence string and
    # prove the literal raw secret it stood for is nowhere in the JSON.
    raw_secret = "AKIA1234567890AB"
    redacted_evidence = f"AK{chr(0x2026)}AB"
    findings = [Finding("sec1", "gitleaks", "aws-key", "high", Severity.HIGH, Verdict.BLOCK,
                         "a.py", 1, "found a key", redacted_evidence, Gate.PRE_COMMIT)]
    result = GateResult(exit_code=1, findings=findings, degraded=[], new_ids=["sec1"],
                         stale_overrides=[], run_id="r1")

    out = reporter.render_json(result)

    assert raw_secret not in out
    # json.dumps escapes non-ASCII by default (ensure_ascii=True), so the
    # redacted evidence's "…" appears as a \uXXXX escape in the raw text --
    # assert on the round-tripped value, not a literal substring of `out`.
    parsed = json.loads(out)
    assert parsed["findings"][0]["evidence"] == redacted_evidence


# ------------------------- intrinsic BLOCK vs ratchet-escalated WARN (R69) ---
# A consumer scripting `check --json` read `verdict: block` for a rule we
# deliberately shipped as WARN, and came within one step of reporting that the
# tier decision had failed. Neither value was wrong: `pipeline.run_gate` calls
# `record_run` BEFORE the no-new-warnings ratchet and the ratchet then rebinds
# `findings`, so the ledger holds the intrinsic verdict and `--json` reports the
# effective one for this push. Both computed in the same run -- which is why the
# consumer measured the disagreement at FIRST detection, where staleness cannot
# reach.
#
# The defect is that one word covers two conditions demanding opposite
# responses: an intrinsic BLOCK means fix the security issue; a ratchet
# escalation means you added a new warning, and it stops escalating once the
# finding is no longer new. aramid knew this -- it is written down in
# tests/integration/test_gates_end_to_end.py as "an artifact of the ratchet" --
# but only ever in a place no consumer would read.

def test_json_marks_a_ratchet_escalated_finding_as_such():
    findings = [_f("newwarn", verdict=Verdict.BLOCK)]
    result = GateResult(exit_code=1, findings=findings, degraded=[],
                         new_ids=["newwarn"], stale_overrides=[], run_id="r1",
                         ratchet_escalated=("newwarn",))

    parsed = json.loads(reporter.render_json(result))
    f = parsed["findings"][0]

    assert f["verdict"] == "block", "the effective verdict for this push is unchanged"
    assert f["escalated_by_ratchet"] is True
    assert f["verdict_before_ratchet"] == "warn", \
        "the intrinsic verdict must be recoverable without knowing the ratchet rule"


def test_json_does_not_mark_an_intrinsic_block():
    """The control, and the whole point. If every BLOCK were labelled, the
    label would carry no information -- a consumer still could not tell a
    security finding from a new-warning escalation."""
    findings = [_f("realblock", verdict=Verdict.BLOCK)]
    result = GateResult(exit_code=1, findings=findings, degraded=[],
                         new_ids=["realblock"], stale_overrides=[], run_id="r1",
                         ratchet_escalated=())

    f = json.loads(reporter.render_json(result))["findings"][0]

    assert f["verdict"] == "block"
    assert f["escalated_by_ratchet"] is False
    assert f["verdict_before_ratchet"] == "block"


def test_json_ratchet_field_is_present_even_when_nothing_escalated():
    """Absent-vs-empty, the distinction this whole exchange has been about. A
    missing key means an aramid too old to record it; `false` means it looked
    and this finding was not escalated."""
    result = GateResult(exit_code=0, findings=[_f("w", verdict=Verdict.WARN)],
                         degraded=[], new_ids=[], stale_overrides=[], run_id="r1")

    f = json.loads(reporter.render_json(result))["findings"][0]

    assert "escalated_by_ratchet" in f
    assert f["escalated_by_ratchet"] is False
