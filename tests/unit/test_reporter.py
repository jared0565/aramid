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

    assert ("stale override stale1 — re-affirm with `aramid override stale1 --reason` "
            "(WARN) or update .aramid-suppressions.toml (BLOCK)") in out
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
