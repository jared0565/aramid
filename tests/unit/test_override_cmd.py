"""`commands.override` at unit scope: the WARN-only local suppression, its
BLOCK-tier refusal with the ready-to-paste snippet, the gate-start sweep
that revokes overrides arming moved out from under, and the two renderers
-- every refusal line and every appended Event asserted whole.

The drain confirms a mutant against the unit suite alone, and until this
file `cmd_override` was executed by tests/integration/test_override.py and
the sweep by test_override_invalidation.py, which the drain never runs:
25 of the module's 31 generator mutants sat on lines no unit test reached
-- `or` -> `and` on the tier composite (which would let a stored WARN that
blocks today be overridden locally), every refusal's `return 3` -> 4, the
TOML escaper's control-character bounds, the sweep's status and tier
guards, the last-sweep-wins selection. `.aramid/` is gitignored, so a
wrong answer here is a machine-local, unreviewable suppression.

Seams: a real tmp ledger; the repo's own aramid.toml for arming; the event
clock and run id injected so each Event is asserted byte for byte."""
from types import SimpleNamespace

import pytest

from aramid import config as config_mod
from aramid.commands import override as ov
from aramid.commands.override import (
    _sweep_context,
    _toml_str,
    cmd_override,
    invalidate_stale_overrides,
    render_invalidations,
    render_sweep_reason,
)
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Source, Verdict

AT = "2026-09-14T12:00:00+00:00"
RUN = "e" * 32
ARMED = "[mutation]\nmutation_block_armed = true\n"


def _f(fid, tool="ruff", rule="F401", verdict=Verdict.WARN, file="a.py", severity=Severity.MEDIUM):
    return Finding(fid, tool, rule, severity.value, severity, verdict, file, 1, "m", "e",
                   Gate.PRE_PUSH)


def _mutation(fid):
    """A drain-written surviving mutant: stored WARN while disarmed; arming
    promotes it to BLOCK without rewriting the row."""
    return Finding(fid, "mutation", "survived", "medium", Severity.MEDIUM, Verdict.WARN,
                   "src/pay.py", 7, "surviving mutant", "e", Gate.PRE_PUSH)


def _llm(fid, severity=Severity.CRITICAL, confirmed=True):
    return Finding(fid, "llm-review", "llm/a01", severity.value, severity, Verdict.WARN,
                   "src/auth.py", 2, "IDOR", "e", Gate.ALL, source=Source.LLM,
                   confirmed=confirmed)


def _ledger(root):
    return Ledger(root / ".aramid" / "ledger.db")


def _seed(root, *findings, events=()):
    led = _ledger(root)
    try:
        led.record_run("r1", "2026-09-14T00:00:00+00:00", "pre-push",
                       {f.tool for f in findings}, {f.file for f in findings}, list(findings))
        for e in events:
            led.append(e)
    finally:
        led.close()


def _state(root):
    led = _ledger(root)
    try:
        return led.open_findings(), led.events()
    finally:
        led.close()


def _appended(root, kind, run=RUN):
    _, events = _state(root)
    return [e for e in events if e.type is kind and e.run_id == run]


@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(ov, "_now", lambda: AT)
    monkeypatch.setattr(ov, "uuid", SimpleNamespace(uuid4=lambda: SimpleNamespace(hex=RUN)))


def _resolved(fid, **payload):
    return Event(EventType.FINDING_RESOLVED, "r2", AT, finding_id=fid, payload=payload)


SNIPPET_F1 = ('[[suppress]]\nid = "f1"\ntool = "ruff"\nrule = "S102"\npath = "a.py"\n'
              'reason = "why"\n')


# ------------------------------------------------------------ cmd_override --

def test_a_warn_finding_is_overridden_with_the_arming_state_it_assumed(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1"))

    assert cmd_override(tmp_path, "f1", "  accepted as a warn  ") == 0

    assert capsys.readouterr() == ("aramid: override: f1 overridden (accepted as a warn)\n", "")
    state, _ = _state(tmp_path)
    assert state["f1"]["status"] == "overridden"
    assert state["f1"]["reason"] == "accepted as a warn"
    events = _appended(tmp_path, EventType.FINDING_OVERRIDDEN)
    expected_arming = config_mod.arming_state(config_mod.load_config(tmp_path))
    assert events == [Event(EventType.FINDING_OVERRIDDEN, RUN, AT, finding_id="f1",
                            payload={"reason": "accepted as a warn",
                                     "arming_state": expected_arming})]
    # the walk, not a hand-kept list: every `*_armed` flag in force, as bools
    # (a bare repo arms only the pack, `pack_block_armed = true` in defaults.toml)
    assert expected_arming["mutation_block_armed"] is False
    assert expected_arming["pack_block_armed"] is True
    assert all(isinstance(v, bool) for v in expected_arming.values())


@pytest.mark.parametrize("reason", ["", "   ", None])
def test_a_reason_is_required_before_the_ledger_is_opened(tmp_path, capsys, reason):
    assert cmd_override(tmp_path, "f1", reason) == 3
    assert capsys.readouterr() == ("", "aramid: override: --reason is required\n")
    assert not (tmp_path / ".aramid" / "ledger.db").exists()


def test_unknown_id(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1"))

    assert cmd_override(tmp_path, "nope", "why") == 3
    assert capsys.readouterr() == ("", "aramid: override: unknown finding id nope\n")


def test_an_unreachable_finding_is_refused(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1"), events=[Event(EventType.FINDING_UNREACHABLE, "r2", AT,
                                             finding_id="f1", payload={"reason": "gone"})])

    assert cmd_override(tmp_path, "f1", "why") == 3
    assert capsys.readouterr() == (
        "", "aramid: override: f1 is unreachable -- its tool does not run in this repo, so "
            "there is nothing to override\n")
    assert _appended(tmp_path, EventType.FINDING_OVERRIDDEN) == []


def test_an_out_of_scope_finding_is_refused_naming_its_file(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1", file="ci.yml"),
          events=[Event(EventType.FINDING_OUT_OF_SCOPE, "r2", AT, finding_id="f1",
                        payload={"reason": "scoped", "tool": "ruff", "file": "ci.yml"})])

    assert cmd_override(tmp_path, "f1", "why") == 3
    assert capsys.readouterr() == (
        "", "aramid: override: f1 is resolved as out of scope -- its runner no longer "
            "examines ci.yml, so there is nothing to override\n")


def test_a_superseded_finding_is_refused_pointing_at_its_successor(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1"), events=[_resolved("f1", superseded_by="sib1")])

    assert cmd_override(tmp_path, "f1", "why") == 3
    assert capsys.readouterr() == (
        "", "aramid: override: f1 is superseded -- rewritten -- superseded by sib1; decide on "
            "that finding instead\n")


def test_an_unreadable_config_refuses_rather_than_trusting_the_stored_verdict(
        tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1"))
    (tmp_path / "aramid.toml").write_text("[mutation]\nmutation_block_armed = = true\n",
                                          encoding="utf-8")

    assert cmd_override(tmp_path, "f1", "why") == 3
    err = capsys.readouterr().err
    assert err.startswith("aramid: override: cannot read the config (")
    assert err.endswith(") -- refusing. Whether f1 is BLOCK-tier depends on the config in "
                        "force, and its stored verdict is not proof of that. Fix aramid.toml "
                        "and retry.\n")
    assert _appended(tmp_path, EventType.FINDING_OVERRIDDEN) == []


def test_a_stored_block_is_refused_with_the_ready_to_paste_entry(tmp_path, capsys, clock):
    _seed(tmp_path, _f("f1", rule="S102", verdict=Verdict.BLOCK, severity=Severity.HIGH))

    assert cmd_override(tmp_path, "f1", "why") == 3
    assert capsys.readouterr() == (
        "", "aramid: override: f1 is a BLOCK-tier finding -- a local override is not "
            "permitted; add a reasoned entry to .aramid-suppressions.toml instead (design "
            "doc section 6).\n"
            "Append this, review it, and commit it:\n\n"
            + SNIPPET_F1 + "\n")
    assert _state(tmp_path)[0]["f1"]["status"] == "open"


def test_a_stored_warn_that_blocks_under_todays_config_is_refused(tmp_path, capsys, clock):
    """The ratchet's first half: the stored row says warn, arming says block,
    and the composite must OR them (`or` -> `and` here is a gitignored file
    gaining the power to hide an armed BLOCK)."""
    (tmp_path / "aramid.toml").write_text(ARMED, encoding="utf-8")
    _seed(tmp_path, _mutation("mut1"))

    assert cmd_override(tmp_path, "mut1", "why") == 3
    assert capsys.readouterr().err.startswith(
        "aramid: override: mut1 is a BLOCK-tier finding -- a local override is not "
        "permitted; add a reasoned entry to .aramid-suppressions.toml instead")
    assert _state(tmp_path)[0]["mut1"]["status"] == "open"


def test_a_stored_block_stays_refused_when_its_rule_no_longer_blocks(tmp_path, capsys, clock):
    """The ratchet's second half: the recompute answers WARN for a demoted
    rule and the command must not follow it down."""
    (tmp_path / "aramid.toml").write_text("semgrep_block_armed = false\n", encoding="utf-8")
    _seed(tmp_path, _f("stale1", tool="semgrep",
                       rule="owasp-top-ten.a03-injection.python-sqli-string-concat",
                       verdict=Verdict.BLOCK))
    from aramid import tier
    assert tier.verdict_now(config_mod.load_config(tmp_path),
                            _state(tmp_path)[0]["stale1"]) is Verdict.WARN

    assert cmd_override(tmp_path, "stale1", "the rule was demoted") == 3
    assert ".aramid-suppressions.toml" in capsys.readouterr().err


def test_an_llm_confirmed_critical_is_refused_and_a_lesser_llm_finding_is_not(
        tmp_path, capsys, clock):
    _seed(tmp_path, _llm("crit"), _llm("minor", severity=Severity.HIGH),
          _llm("unconfirmed", confirmed=False))

    assert cmd_override(tmp_path, "crit", "why") == 3
    assert "crit is a BLOCK-tier finding" in capsys.readouterr().err
    assert cmd_override(tmp_path, "minor", "why") == 0
    assert cmd_override(tmp_path, "unconfirmed", "why") == 0
    assert [e.finding_id for e in _appended(tmp_path, EventType.FINDING_OVERRIDDEN)] == \
        ["minor", "unconfirmed"]


def test_the_refusal_names_the_sweep_that_reopened_the_finding_and_its_batch(
        tmp_path, capsys, clock):
    _seed(tmp_path, _mutation("mut1"), _mutation("mut2"), _mutation("mut3"))
    for fid in ("mut1", "mut2", "mut3"):
        assert cmd_override(tmp_path, fid, "accepted as a warn") == 0
    (tmp_path / "aramid.toml").write_text(ARMED, encoding="utf-8")
    led = _ledger(tmp_path)
    try:
        swept = invalidate_stale_overrides(led, config_mod.load_config(tmp_path),
                                           run_id="r-sweep", at=AT)
    finally:
        led.close()
    assert swept == [{"id": "mut1", "cause": "recorded_disarmed"},
                     {"id": "mut2", "cause": "recorded_disarmed"},
                     {"id": "mut3", "cause": "recorded_disarmed"}]
    capsys.readouterr()

    assert cmd_override(tmp_path, "mut2", "still fine by me") == 3
    assert capsys.readouterr().err == (
        "aramid: override: mut2 is a BLOCK-tier finding -- a local override is not "
        "permitted; add a reasoned entry to .aramid-suppressions.toml instead (design doc "
        "section 6).\n"
        "aramid: override: it is back because a gate-start sweep revoked your earlier "
        "override of it -- recorded as made while the class was disarmed. Arming is "
        "retroactive, so that judgement is due again in the committed file.\n"
        "aramid: override: the same sweep reopened 3 findings -- a run of these refusals "
        "is one re-adjudication, not 3 unrelated denials.\n"
        "Append this, review it, and commit it:\n\n"
        '[[suppress]]\nid = "mut2"\ntool = "mutation"\nrule = "survived"\n'
        'path = "src/pay.py"\nreason = "still fine by me"\n\n')


# ---------------------------------------------------------------- _toml_str --

@pytest.mark.parametrize("value, expected", [
    ("plain words", '"plain words"'),
    ('say "hi" C:\\tmp', '"say \\"hi\\" C:\\\\tmp"'),
    ("tab\tnl\ncr\rff\fbs\b", '"tab\\tnl\\ncr\\rff\\fbs\\b"'),
    ("\x01\x1f", '"\\u0001\\u001f"'),
    ("\x7f", '"\\u007f"'),
    (" \x21 caf\u00e9", '" \x21 caf\u00e9"'),      # the bounds: space and DEL's neighbours stay
])
def test_toml_str_escapes_exactly_what_a_basic_string_cannot_carry(value, expected):
    assert _toml_str(value) == expected


# ---------------------------------------------------- render_invalidations --

def test_render_invalidations_counts_by_cause_and_is_silent_when_empty():
    assert render_invalidations([]) == ""
    assert render_invalidations([
        {"id": "a", "cause": "recorded_disarmed"},
        {"id": "b", "cause": "arming_state_unrecorded"},
        {"id": "c", "cause": "recorded_disarmed"},
        {"id": "d", "cause": "novel_cause"},
    ]) == (
        "aramid: check: 4 override(s) invalidated by arming -- reopened for re-adjudication:\n"
        "aramid: check:   1 -- arming state was not recorded when they were made\n"
        "aramid: check:   1 -- novel_cause\n"
        "aramid: check:   2 -- recorded as made while the class was disarmed")


# ------------------------------------------------ invalidate_stale_overrides --

def _sweep(root, run_id="r-sweep"):
    led = _ledger(root)
    try:
        return invalidate_stale_overrides(led, config_mod.load_config(root), run_id=run_id, at=AT)
    finally:
        led.close()


def test_the_sweep_revokes_an_override_arming_moved_out_from_under(tmp_path, clock):
    _seed(tmp_path, _mutation("mut1"))
    assert cmd_override(tmp_path, "mut1", "accepted as a warn") == 0
    (tmp_path / "aramid.toml").write_text(ARMED, encoding="utf-8")

    assert _sweep(tmp_path) == [{"id": "mut1", "cause": "recorded_disarmed"}]
    state, _ = _state(tmp_path)
    assert state["mut1"]["status"] == "open"
    assert _appended(tmp_path, EventType.FINDING_OVERRIDE_INVALIDATED, run="r-sweep") == [
        Event(EventType.FINDING_OVERRIDE_INVALIDATED, "r-sweep", AT, finding_id="mut1",
              payload={"cause": "recorded_disarmed"})]
    assert _sweep(tmp_path) == [], "a revoked row is open, so a second sweep sees nothing"


def test_a_legacy_override_without_a_recorded_arming_state_gets_its_own_cause(tmp_path):
    _seed(tmp_path, _mutation("mut1"),
          events=[Event(EventType.FINDING_OVERRIDDEN, "old", AT, finding_id="mut1",
                        payload={"reason": "legacy"})])
    (tmp_path / "aramid.toml").write_text(ARMED, encoding="utf-8")

    assert _sweep(tmp_path) == [{"id": "mut1", "cause": "arming_state_unrecorded"}]


def test_the_sweep_leaves_a_still_warn_override_and_every_non_overridden_row_alone(
        tmp_path, clock):
    _seed(tmp_path, _mutation("mut1"), _f("f1"),
          _f("b1", rule="S102", verdict=Verdict.BLOCK, severity=Severity.HIGH))
    assert cmd_override(tmp_path, "mut1", "accepted as a warn") == 0
    assert cmd_override(tmp_path, "f1", "accepted as a warn") == 0
    # no aramid.toml: mutation stays disarmed; b1 is BLOCK but was never overridden

    assert _sweep(tmp_path) == []
    state, _ = _state(tmp_path)
    assert [state[f]["status"] for f in ("mut1", "f1", "b1")] == ["overridden", "overridden", "open"]
    assert _appended(tmp_path, EventType.FINDING_OVERRIDE_INVALIDATED, run="r-sweep") == []


def test_the_sweep_revokes_a_stored_block_even_when_its_rule_no_longer_blocks(tmp_path):
    """Same ratchet as the refusal: the stored verdict is ORed in, so a
    demoted rule cannot keep an override of a BLOCK row alive."""
    (tmp_path / "aramid.toml").write_text("semgrep_block_armed = false\n", encoding="utf-8")
    _seed(tmp_path, _f("stale1", tool="semgrep",
                       rule="owasp-top-ten.a03-injection.python-sqli-string-concat",
                       verdict=Verdict.BLOCK),
          events=[Event(EventType.FINDING_OVERRIDDEN, "old", AT, finding_id="stale1",
                        payload={"reason": "legacy"})])

    assert _sweep(tmp_path) == [{"id": "stale1", "cause": "arming_state_unrecorded"}]


# ------------------------------------------------------------ _sweep_context --

def _invalidated(run, fid, cause):
    return Event(EventType.FINDING_OVERRIDE_INVALIDATED, run, AT, finding_id=fid,
                 payload={"cause": cause})


def test_sweep_context_is_none_without_a_sweep_and_the_last_sweep_wins_with_its_batch(tmp_path):
    _seed(tmp_path, _mutation("mut1"), _mutation("mut2"), _mutation("mut3"),
          events=[Event(EventType.FINDING_OVERRIDDEN, "old", AT, finding_id="mut1",
                        payload={"reason": "legacy"}),
                  _invalidated("sweep-a", "mut1", "recorded_disarmed"),
                  _invalidated("sweep-a", "mut2", "recorded_disarmed"),
                  _invalidated("sweep-b", "mut1", "arming_state_unrecorded")])
    led = _ledger(tmp_path)
    try:
        assert _sweep_context(led, "mut3") is None
        assert _sweep_context(led, "mut2") == ("recorded_disarmed", 2)
        assert _sweep_context(led, "mut1") == ("arming_state_unrecorded", 1)
    finally:
        led.close()


# -------------------------------------------------------- render_sweep_reason --

def test_render_sweep_reason_adds_the_batch_line_only_past_one():
    single = ("aramid: override: it is back because a gate-start sweep revoked your earlier "
              "override of it -- recorded as made while the class was disarmed. Arming is "
              "retroactive, so that judgement is due again in the committed file.")
    assert render_sweep_reason("recorded_disarmed", 1) == single
    assert render_sweep_reason("recorded_disarmed", 2) == single + (
        "\naramid: override: the same sweep reopened 2 findings -- a run of these refusals "
        "is one re-adjudication, not 2 unrelated denials.")
    assert render_sweep_reason("novel_cause", 1) == (
        "aramid: override: it is back because a gate-start sweep revoked your earlier "
        "override of it -- novel_cause. Arming is retroactive, so that judgement is due "
        "again in the committed file.")
