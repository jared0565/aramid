from aramid import mutation_score
from aramid.models import Event, EventType


def _crf(idx, target, killed_s1, survived_s1, fully,
         killed_fps=(), survivor_fps=()):
    return Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", "t", payload={
        "consumer": "mutation", "item_id": "q",
        "mutation_scores": {"schema": 1, "targets": {target: {
            "generated": killed_s1 + survived_s1, "killed_s1": killed_s1,
            "survived_s1": survived_s1, "timeouts": 0, "errors": 0,
            "fully_mutated": fully, "killed_fps": list(killed_fps),
            "survivor_fps": list(survivor_fps)}}}})


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
    other = Event(EventType.RUN_FINISHED, "r", "t", payload={})
    events = [other, _crf(1, "f.py::g", 1, 0, True)]
    scores = mutation_score.iter_target_scores(events)
    assert scores[0].run_index == 1   # position in the stream, not the CRF count


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
