from aramid import mutation_score
from aramid.models import Event, EventType


def _crf(idx, target, killed_s1, survived_s1, fully,
         killed_fps=(), survivor_fps=(), killed_s2=None):
    t = {"generated": killed_s1 + survived_s1 + (killed_s2 or 0),
         "killed_s1": killed_s1, "survived_s1": survived_s1,
         "timeouts": 0, "errors": 0,
         "fully_mutated": fully, "killed_fps": list(killed_fps),
         "survivor_fps": list(survivor_fps)}
    if killed_s2 is not None:      # rows written before the key existed omit it
        t["killed_s2"] = killed_s2
    return Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", "t", payload={
        "consumer": "mutation", "item_id": "q",
        "mutation_scores": {"schema": 1, "targets": {target: t}}})


# --- verdict-based rate (interop round 174, Q3) ------------------------------
#
# `survived_s1` used to mean "passed stage 1", and stayed set when the
# full-suite confirm timed out, errored, or killed the mutant -- so a mutant
# that never reached a verdict read as a survivor, and one the full suite
# killed read as BOTH killed and survived. The consumer now moves those out of
# `survived_s1` (timeouts/errors/unconfirmed) or into `killed_s2`, and the
# rate counts kills of either stage over mutants with a verdict.

def test_rate_counts_a_full_suite_kill_as_a_kill():
    events = [_crf(0, "f.py::g", 1, 1, True, killed_s2=2)]
    s = mutation_score.iter_target_scores(events)[0]
    assert s.killed_s2 == 2
    assert s.rate == 3 / 4


def test_rows_without_killed_s2_keep_the_old_rate():
    events = [_crf(0, "f.py::g", 2, 1, True)]
    s = mutation_score.iter_target_scores(events)[0]
    assert s.killed_s2 == 0
    assert s.rate == 2 / 3


def test_iter_target_scores_parses_and_indexes():
    events = [_crf(0, "f.py::g", 2, 1, True, killed_fps=["a", "b"])]
    scores = mutation_score.iter_target_scores(events)
    assert len(scores) == 1
    s = scores[0]
    assert s.target == "f.py::g"
    assert s.killed_s1 == 2 and s.survived_s1 == 1
    assert s.rate == 2 / 3
    assert s.run_index == 0
    assert s.killed_fps == frozenset({"a", "b"})


def test_run_index_is_event_stream_position():
    """2a-c: the run-id label ("r7") and the CRF's own ordinal count (this is
    the only CRF in the stream) are BOTH deliberately made to disagree with
    the true stream position (1, since `other` occupies position 0) -- a
    single assertion now discriminates against two wrong implementations at
    once: run_index derived from int(run_id label) (would read 7) and
    run_index derived from counting CONSUMER_RUN_FINISHED events seen so far
    (would read 0). Only enumerate()'s stream-position idx (mutation_score.py
    :35,49) gives 1. The prior version (_crf(1, ...) at actual position 1)
    could not distinguish stream-position from run-id-label, since both gave
    the same answer."""
    other = Event(EventType.RUN_FINISHED, "r", "t", payload={})
    events = [other, _crf(7, "f.py::g", 1, 0, True)]
    scores = mutation_score.iter_target_scores(events)
    assert scores[0].run_index == 1   # stream position wins, not "r7"'s int(7)


def test_iter_skips_target_missing_subscripted_key():
    """2a-b: killed_s1/survived_s1/fully_mutated are read via subscript at
    mutation_score.py:50-52 -- missing any one of the three raises inside the
    try, caught by the except (KeyError, TypeError, ValueError) at :55-56.
    killed_fps/survivor_fps are .get(..., [])-defaulted at :53-54 and CANNOT
    trigger it: dropping either of those instead yields a fully-constructed
    TargetScore with an empty frozenset, covering nothing (that gap is
    exactly why this test targets killed_s1 specifically, not one of the fps
    lists). test_iter_skips_malformed_and_wrong_schema above covers
    wrong-schema / no-scores / non-dict-target but never a missing
    subscripted key on an otherwise well-formed target dict."""
    e = Event(EventType.CONSUMER_RUN_FINISHED, "r", "t", payload={
        "mutation_scores": {"schema": 1, "targets": {"f.py::g": {
            "survived_s1": 1, "fully_mutated": True}}}})   # killed_s1 missing
    assert mutation_score.iter_target_scores([e]) == []


def test_rate_none_when_no_verdicts():
    events = [_crf(0, "f.py::g", 0, 0, False)]
    assert mutation_score.iter_target_scores(events)[0].rate is None


def test_iter_skips_malformed_and_wrong_schema():
    bad_schema = Event(EventType.CONSUMER_RUN_FINISHED, "r", "t",
                       payload={"mutation_scores": {"schema": 99, "targets": {}}})
    no_scores = Event(EventType.CONSUMER_RUN_FINISHED, "r", "t", payload={})
    bad_target = Event(EventType.CONSUMER_RUN_FINISHED, "r", "t", payload={
        "mutation_scores": {"schema": 1, "targets": {"x::y": "not-a-dict"}}})
    assert mutation_score.iter_target_scores([bad_schema, no_scores, bad_target]) == []


def test_transition_fires_when_killed_mutant_now_survives():
    FP = "deadbeef"
    events = [
        _crf(0, "calc.py::is_adult", 2, 0, True, killed_fps=[FP, "other"]),
        _crf(1, "calc.py::is_adult", 1, 2, True, killed_fps=["other"],
             survivor_fps=[FP, "fresh"]),   # "fresh" was never killed in baseline
    ]
    regs = mutation_score.latest_regressions(events)
    trans = [r for r in regs if r.kind == "transition"]
    assert len(trans) == 1
    # Exact intersection pins the extra x extra JOIN, not a single operand:
    # FP was killed-then-survives; "other" was killed in BOTH runs (not a
    # current survivor); "fresh" survives now but was never killed. Only FP.
    assert trans[0].transition_fps == frozenset({FP})
    assert trans[0].baseline_index == 0 and trans[0].current_index == 1


def test_transition_fires_against_partial_current_run():
    # a survivor in a truncated current run still transitions vs a full baseline
    FP = "cafe"
    events = [
        _crf(0, "m.py::f", 2, 0, True, killed_fps=[FP]),
        _crf(1, "m.py::f", 0, 1, False, survivor_fps=[FP]),   # partial current
    ]
    regs = mutation_score.latest_regressions(events)
    assert any(r.kind == "transition" for r in regs)
    assert not any(r.kind == "rate" for r in regs)   # rate skipped: current partial


def test_rate_regression_full_to_partial_kill():
    events = [
        _crf(0, "m.py::f", 3, 0, True),   # rate 1.00
        _crf(1, "m.py::f", 1, 2, True),   # rate 0.33
    ]
    regs = [r for r in mutation_score.latest_regressions(events) if r.kind == "rate"]
    assert len(regs) == 1
    assert regs[0].detail == "1.00 -> 0.33"


def test_partial_current_no_rate_regression():
    events = [
        _crf(0, "m.py::f", 3, 0, True),
        _crf(1, "m.py::f", 1, 2, False),   # partial
    ]
    assert [r for r in mutation_score.latest_regressions(events)
            if r.kind == "rate"] == []


def test_baseline_is_most_recent_prior_fully_mutated():
    events = [
        _crf(0, "m.py::f", 3, 0, True),    # older full, rate 1.00
        _crf(1, "m.py::f", 0, 3, False),   # partial - never a baseline
        _crf(2, "m.py::f", 1, 2, True),    # current, rate 0.33
    ]
    regs = [r for r in mutation_score.latest_regressions(events) if r.kind == "rate"]
    assert len(regs) == 1
    assert regs[0].baseline_index == 0


def test_no_baseline_no_regression():
    events = [_crf(0, "m.py::f", 1, 2, True)]
    assert mutation_score.latest_regressions(events) == []


def test_rate_improvement_is_not_a_regression():
    events = [
        _crf(0, "m.py::f", 1, 2, True),    # rate 0.33
        _crf(1, "m.py::f", 3, 0, True),    # rate 1.00 (better)
    ]
    assert [r for r in mutation_score.latest_regressions(events)
            if r.kind == "rate"] == []


def test_latest_by_target_picks_highest_run_index():
    events = [_crf(0, "a::f", 1, 0, True), _crf(1, "a::f", 0, 1, True),
              _crf(2, "b::g", 1, 0, True)]
    latest = mutation_score.latest_by_target(
        mutation_score.iter_target_scores(events))
    assert latest["a::f"].run_index == 1   # stream position, not the run_id label
    assert latest["b::g"].run_index == 2
