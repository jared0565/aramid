"""integration: `aramid override <id> --reason` -- WARN-only local
suppression (design doc section 6). A BLOCK-tier finding must error and
direct the user to .aramid-suppressions.toml instead.
"""
from pathlib import Path

from aramid.commands.override import cmd_override
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Source, Verdict


def _f(fid, tool="ruff", rule="F401", verdict=Verdict.WARN, file="a.py"):
    return Finding(fid, tool, rule, "medium", Severity.MEDIUM, verdict, file, 1, "m", "e",
                    Gate.PRE_PUSH)


def _llm_finding(fid, severity=Severity.CRITICAL, confirmed=True, verdict=Verdict.WARN):
    """Mirrors tests/unit/test_llm_gate.py's _llm_finding: the ledger always
    stores verdict='warn' for an LLM finding -- policy.classify("llm-review",
    ...) always returns WARN at drain time; the real BLOCK verdict for a
    confirmed-critical LLM finding is computed only at gate time in
    review.llm_gate_findings and is never persisted to the ledger."""
    return Finding(fid, "llm-review", "llm/a01", str(severity), severity, verdict,
                    "src/auth.py", 2, "IDOR: no ownership check", "evidence text",
                    Gate.ALL, source=Source.LLM, confirmed=confirmed)


def _ledger(root) -> Ledger:
    return Ledger(root / ".aramid" / "ledger.db")


def test_warn_id_is_overridden_and_recorded(tmp_path):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("warn1")])
    ledger.close()

    rc = cmd_override(root, "warn1", "known false positive, tracked in JIRA-123")

    assert rc == 0
    ledger = _ledger(root)
    try:
        state = ledger.open_findings()
        assert state["warn1"]["status"] == "overridden"
        events = [e for e in ledger.events() if e.type.value == "finding_overridden"]
        assert len(events) == 1
        assert events[0].finding_id == "warn1"
    finally:
        ledger.close()


def test_block_id_errors_and_directs_to_suppressions_file(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"gitleaks"}, {"a.py"},
                       [_f("block1", tool="gitleaks", rule="aws-key", verdict=Verdict.BLOCK)])
    ledger.close()

    rc = cmd_override(root, "block1", "please just let me push")
    err = capsys.readouterr().err

    assert rc == 3
    assert ".aramid-suppressions.toml" in err

    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["block1"]["status"] == "open"
    finally:
        ledger.close()


def _snippet_from(err: str) -> str:
    assert "[[suppress]]" in err, f"no TOML snippet in refusal:\n{err}"
    return err[err.index("[[suppress]]"):]


def test_the_refusal_emits_a_snippet_that_actually_suppresses_the_finding(tmp_path, capsys):
    """The refusal tells the user to add an entry to .aramid-suppressions.toml
    but historically left them to hand-assemble it from `aramid status`
    output -- and the `id` is an opaque content fingerprint, the one field
    nobody can retype from memory.

    Asserted by ROUND-TRIP, not by substring. A snippet can contain every
    expected word and still be unusable: wrong key names, an unquoted
    fingerprint, a missing `reason` (which load_suppressions drops, silently
    suppressing nothing). So this writes the emitted text to the real file,
    loads it through the real loader, and requires a record that matches the
    finding -- the same path the gate takes.
    """
    import tomllib

    from aramid import config as config_mod

    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"gitleaks"}, {"src/db.py"},
                       [_f("fp-abc123", tool="gitleaks", rule="aws-key",
                           verdict=Verdict.BLOCK, file="src/db.py")])
    ledger.close()

    rc = cmd_override(root, "fp-abc123", "test fixture credential, rotated 2026-08-01")
    snippet = _snippet_from(capsys.readouterr().err)

    assert rc == 3
    tomllib.loads(snippet)  # parses standalone, before any file surgery
    (root / ".aramid-suppressions.toml").write_text(snippet, encoding="utf-8")
    records, warnings = config_mod.load_suppressions(root)

    assert warnings == []  # a reasonless entry would land here instead
    assert len(records) == 1
    rec = records[0]
    assert rec.id == "fp-abc123"
    assert rec.tool == "gitleaks"
    assert rec.rule == "aws-key"
    assert rec.path == "src/db.py"
    assert "rotated 2026-08-01" in rec.reason


def test_the_emitted_snippet_survives_a_reason_containing_toml_metacharacters(tmp_path):
    """`--reason` is free user text interpolated into generated TOML. A
    double quote or a backslash (Windows paths in a justification are
    ordinary) would otherwise produce a snippet that fails to parse, or --
    worse -- one that parses into something other than what was typed.
    """
    import tomllib

    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"gitleaks"}, {"a.py"},
                       [_f("b1", tool="gitleaks", rule="aws-key", verdict=Verdict.BLOCK)])
    ledger.close()

    nasty = 'sample key from "vendor docs" at C:\\refs\\keys.md\tnot live'
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        cmd_override(root, "b1", nasty)
    snippet = _snippet_from(buf.getvalue())

    parsed = tomllib.loads(snippet)
    assert parsed["suppress"][0]["reason"] == nasty


def test_unknown_id_errors(tmp_path, capsys):
    root: Path = tmp_path
    rc = cmd_override(root, "nope", "some reason")
    err = capsys.readouterr().err

    assert rc == 3
    assert "nope" in err


def test_llm_confirmed_critical_is_refused_regardless_of_armed_state(tmp_path, capsys):
    """Task 13b's classify-blindness gap, mirrored for override.py (the
    parallel fix check.py's _has_genuine_block already got). The ledger's
    STORED verdict for an LLM finding is ALWAYS "warn" -- policy.classify
    ("llm-review", ...) always returns WARN at drain time, and the real BLOCK
    verdict for a confirmed-critical LLM finding is computed only at gate
    time in review.llm_gate_findings, never persisted. So checking
    rec["verdict"] == "block" alone can never catch an LLM finding. This test
    seeds NO [llm].llm_block_armed state at all (arming lives in config, not
    the ledger) -- the refusal must fire independent of armed state, because
    arming is retroactive by design: if the refusal only fired while armed,
    an operator could override the finding while disarmed (gate only WARNs,
    so no refusal), then arm later -- the finding is already "overridden" and
    the gate skips it, permanently and silently defeating the block with no
    reviewable artifact (.aramid/ is gitignored)."""
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "drain", set(), set(),
                       [_llm_finding("llmcrit1")])
    ledger.close()

    rc = cmd_override(root, "llmcrit1", "let me push anyway")
    err = capsys.readouterr().err

    assert rc == 3
    assert ".aramid-suppressions.toml" in err

    ledger = _ledger(root)
    try:
        state = ledger.open_findings()
        assert state["llmcrit1"]["status"] == "open"
        events = [e for e in ledger.events() if e.type.value == "finding_overridden"]
        assert events == []
    finally:
        ledger.close()


def test_llm_unconfirmed_or_noncritical_keeps_light_override_path(tmp_path):
    """Only a CONFIRMED + CRITICAL LLM finding is BLOCK-tier for override
    purposes. A WARN-tier LLM finding -- unconfirmed, or confirmed but below
    critical severity -- must keep using the legitimate light override path;
    the fix must not over-refuse."""
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "drain", set(), set(), [
        _llm_finding("llm-unconfirmed", confirmed=False),
        _llm_finding("llm-high", severity=Severity.HIGH, confirmed=True),
    ])
    ledger.close()

    rc1 = cmd_override(root, "llm-unconfirmed", "false positive")
    rc2 = cmd_override(root, "llm-high", "tracked in JIRA-456")

    assert rc1 == 0
    assert rc2 == 0
    ledger = _ledger(root)
    try:
        state = ledger.open_findings()
        assert state["llm-unconfirmed"]["status"] == "overridden"
        assert state["llm-high"]["status"] == "overridden"
    finally:
        ledger.close()


def test_missing_reason_errors(tmp_path, capsys):
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("warn1")])
    ledger.close()

    rc = cmd_override(root, "warn1", "")
    err = capsys.readouterr().err

    assert rc == 3
    assert "reason" in err.lower()


def test_unreachable_finding_is_refused(tmp_path, capsys):
    from aramid.models import Event, EventType
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("f1", tool="ruff")])
    ledger.append(Event(EventType.FINDING_UNREACHABLE, "r2", "t2",
                        finding_id="f1", payload={"reason": "ruff not selected"}))
    ledger.close()

    rc = cmd_override(root, "f1", "let me override it anyway")
    err = capsys.readouterr().err

    assert rc == 3
    assert "unreachable" in err
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["f1"]["status"] == "unreachable"
        events = [e for e in ledger.events() if e.type.value == "finding_overridden"]
        assert events == []
    finally:
        ledger.close()
