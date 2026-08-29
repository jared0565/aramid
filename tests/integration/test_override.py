"""integration: `aramid override <id> --reason` -- WARN-only local
suppression (design doc section 6). A BLOCK-tier finding must error and
direct the user to .aramid-suppressions.toml instead.
"""
import tomllib
from pathlib import Path

import pytest

from aramid import config as config_mod
from aramid import policy
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


def _mutation_finding(fid, verdict=Verdict.WARN):
    """A drain-written surviving-mutant row. The drain stores the verdict
    policy.classify computed AT DRAIN TIME -- WARN while
    [mutation].mutation_block_armed is false. Arming later promotes the same
    finding to BLOCK (classify's tool=="mutation" branch, mirrored in
    mutation_gate.mutation_gate_findings) but never rewrites the stored row:
    the ledger is append-only, so `verdict` stays frozen at "warn" forever."""
    return Finding(fid, "mutation", "survived", "medium", Severity.MEDIUM, verdict,
                    "src/pay.py", 7, "surviving mutant", "evidence text",
                    Gate.PRE_PUSH, source=Source.DETERMINISTIC)


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


def test_a_stored_block_stays_refused_even_when_its_rule_no_longer_blocks(
        tmp_path, capsys):
    """THE RATCHET, pinned. Written before `_is_block_tier_now` was re-expressed
    on top of `tier.verdict_now`, so it is a refactor guard rather than a
    red-first test: it passed before the change and must pass after.

    `tier.verdict_now` reports TRUTH and is free to answer WARN for a finding
    whose stored verdict is `block` -- a rule demoted, a tool disarmed. This
    command must NOT follow it down. Widening what a machine-local, gitignored
    suppression may hide is the one direction it must never move, and the
    obvious "simplification" of replacing the whole composite with
    `verdict_now(...) is BLOCK` does exactly that. This test is what walks that
    edit into a red.
    """
    root: Path = tmp_path
    # Stored BLOCK, under a config where semgrep no longer blocks anything.
    (root / "aramid.toml").write_text("semgrep_block_armed = false\n", encoding="utf-8")
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"semgrep"}, {"a.py"},
                       [_f("stale1", tool="semgrep",
                           rule="owasp-top-ten.a03-injection.python-sqli-string-concat",
                           verdict=Verdict.BLOCK)])
    ledger.close()

    # Precondition: the recompute really does answer WARN here, or the arm
    # below would be refused by the recompute rather than by the ratchet and
    # would prove nothing about the ratchet at all.
    from aramid import tier
    cfg = config_mod.load_config(root)
    state_rec = _ledger(root).open_findings()["stale1"]
    assert tier.verdict_now(cfg, state_rec) is Verdict.WARN

    rc = cmd_override(root, "stale1", "the rule was demoted, let me hide it")
    err = capsys.readouterr().err

    assert rc == 3, "a stored BLOCK must stay unoverridable after a demotion"
    assert ".aramid-suppressions.toml" in err


def test_override_records_the_arming_state_it_assumed(tmp_path):
    """An override is a decision made UNDER a config, and the ledger has never
    recorded which one. Without that, a later sweep cannot tell "suppressed
    while this class was disarmed" from "suppressed by a version that never
    asked" -- and those two want different words in front of an operator
    (interop round 89: cause `recorded_disarmed` vs `arming_state_unrecorded`).

    Two arms, because a test that only asserts the key EXISTS would pass
    against a hardcoded empty dict. The recorded value has to track the config
    that was actually in force.
    """
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"},
                       [_f("warn1"), _f("warn2")])
    ledger.close()

    assert cmd_override(root, "warn1", "false positive, disarmed") == 0

    # Arm semgrep and override a second time. The finding is a ruff finding, so
    # arming semgrep does not make it BLOCK-tier -- the override still succeeds
    # and the only thing that moves is the recorded state.
    (root / "aramid.toml").write_text("semgrep_block_armed = true\n", encoding="utf-8")
    assert cmd_override(root, "warn2", "false positive, armed") == 0

    ledger = _ledger(root)
    try:
        by_id = {e.finding_id: e.payload
                 for e in ledger.events() if e.type.value == "finding_overridden"}
        assert "arming_state" in by_id["warn1"], "override recorded no arming state"
        assert by_id["warn1"]["arming_state"]["semgrep_block_armed"] is False
        assert by_id["warn2"]["arming_state"]["semgrep_block_armed"] is True
    finally:
        ledger.close()


def test_recorded_arming_state_covers_every_armable_flag_not_a_hand_kept_list(tmp_path):
    """Collected by walking the config for `*_armed`, never from a literal list
    of today's tools. A hand-kept list is the failure mode this repo has now
    paid for twice: whoever adds the next armable tool does not know this
    record exists, the flag silently goes unrecorded, and its overrides join
    the legacy population without anyone choosing that.

    Asserts the nested-dict flags are present too -- they live in `llm`,
    `mutation` and `red_proof` sub-tables, so a walk that only looked at
    top-level bool fields would capture two flags out of six and still pass a
    test that checked `semgrep_block_armed` alone.
    """
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("warn1")])
    ledger.close()

    assert cmd_override(root, "warn1", "false positive") == 0

    ledger = _ledger(root)
    try:
        ev = [e for e in ledger.events() if e.type.value == "finding_overridden"][0]
        recorded = ev.payload["arming_state"]
    finally:
        ledger.close()

    for flag in ("semgrep_block_armed", "tdd_block_armed", "llm_block_armed",
                 "mutation_block_armed", "score_block_armed", "red_proof_block_armed"):
        assert flag in recorded, f"{flag} not captured in the recorded arming state"


def test_armed_mutation_finding_is_refused_though_the_ledger_froze_its_verdict_at_warn(
        tmp_path, capsys):
    """The stored verdict is a snapshot of one config, and this command trusted
    it. `rec["verdict"] == "block"` reads a value classify computed at DRAIN
    time; for a mutation finding drained while [mutation].mutation_block_armed
    was false that value is "warn", and the append-only ledger never rewrites
    it. Arming afterwards makes the finding BLOCK-tier everywhere that
    recomputes -- classify, mutation_gate.mutation_gate_findings,
    check._has_genuine_block -- while this command still reads "warn" and
    permits the suppression.

    That is the exact defeat
    test_llm_confirmed_critical_is_refused_regardless_of_armed_state was
    written to prevent, reachable through a different door: the override flips
    status to "overridden", mutation_gate_findings skips any rec whose status
    is not "open", and the armed BLOCK is silently and permanently gone with
    no reviewable artifact (`.aramid/` is gitignored). LLM findings got a
    dedicated is_confirmed_critical_llm guard because their stored verdict is
    always "warn"; mutation has no such guard and the stored verdict is its
    ONLY signal, so nothing catches this.
    """
    root: Path = tmp_path
    (root / "aramid.toml").write_text(
        "[mutation]\nmutation_block_armed = true\n", encoding="utf-8")

    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, set(),
                       [_mutation_finding("mut1")])
    ledger.close()

    # Preconditions. Without all three the refusal below could pass for the
    # wrong reason -- an over-refusal that rejects every mutation override, or
    # a row that was never WARN-in-store to begin with, would both look green.
    cfg = config_mod.load_config(root)
    assert cfg.mutation.get("mutation_block_armed") is True
    assert policy.classify("mutation", "survived", "medium",
                            Gate.PRE_PUSH, cfg)[1] is Verdict.BLOCK
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["mut1"]["verdict"] == "warn"
    finally:
        ledger.close()

    rc = cmd_override(root, "mut1", "mutation testing is noisy, ignore")
    err = capsys.readouterr().err

    assert rc == 3
    assert ".aramid-suppressions.toml" in err
    # ...and specifically the BLOCK-tier refusal for THIS record. Every refusal
    # path in cmd_override returns 3, so rc alone does not say which one fired.
    assert 'tool = "mutation"' in err

    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["mut1"]["status"] == "open"
        events = [e for e in ledger.events() if e.type.value == "finding_overridden"]
        assert events == []
    finally:
        ledger.close()


def test_an_unreadable_config_refuses_rather_than_falling_back_to_the_stored_verdict(
        tmp_path, capsys):
    """The BLOCK-tier check needs the config in force, so failing to read the
    config must not degrade to trusting the stored verdict. `aramid.toml` is an
    ordinary writable repo file: if a malformed one sent this command back to
    `rec["verdict"] == "block"`, anyone wanting to suppress an armed mutation
    BLOCK could get it by breaking one line of TOML. The refusal must name the
    config, not the suppressions file -- this is not "you picked the wrong
    channel", it is "I could not answer the question".
    """
    root: Path = tmp_path
    (root / "aramid.toml").write_text(
        "[mutation]\nmutation_block_armed = = true\n", encoding="utf-8")

    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"mutation"}, set(),
                       [_mutation_finding("mut1")])
    ledger.close()

    # Precondition: the config really is unreadable, and the stored verdict
    # really is the permissive "warn" -- otherwise the refusal proves nothing.
    with pytest.raises(tomllib.TOMLDecodeError):
        config_mod.load_config(root)
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["mut1"]["verdict"] == "warn"
    finally:
        ledger.close()

    rc = cmd_override(root, "mut1", "let me push")
    err = capsys.readouterr().err

    assert rc == 3
    assert "config" in err.lower()

    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["mut1"]["status"] == "open"
        assert [e for e in ledger.events() if e.type.value == "finding_overridden"] == []
    finally:
        ledger.close()


def test_a_superseded_finding_is_refused_and_points_at_its_successor(tmp_path, capsys):
    """Same shape as the unreachable refusal (T-8 section 7.1), same cost if
    allowed: overriding the OLD id of a rewritten line grants nothing -- the
    sibling that replaced it is still open -- and would stop a revert of the
    rewrite from re-detecting, because overridden findings never resurrect.
    Round 135 s3."""
    root: Path = tmp_path
    ledger = _ledger(root)
    ledger.record_run("r1", "t1", "pre-push", {"ruff"}, {"a.py"}, [_f("old", tool="ruff")])
    ledger.record_run("r2", "t2", "pre-push", {"ruff"}, {"a.py"}, [_f("new", tool="ruff")])
    ledger.close()

    rc = cmd_override(root, "old", "let me override it anyway")
    err = capsys.readouterr().err

    assert rc == 3
    assert "superseded" in err and "new" in err
    ledger = _ledger(root)
    try:
        assert ledger.open_findings()["old"]["status"] == "superseded"
        assert [e for e in ledger.events() if e.type.value == "finding_overridden"] == []
    finally:
        ledger.close()
