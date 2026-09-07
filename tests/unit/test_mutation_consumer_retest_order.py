"""Unit-scope pins for the ORDER of the mutation consumer's re-test
candidates (`consumers.mutation._retest_candidates`). A hand-built ledger,
no repo, no subprocess."""
from aramid.consumers import mutation as mut_consumer
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict


def _survivor(fid: str, line: int) -> Finding:
    return Finding(id=fid, tool="mutation", rule="int-bound", severity_raw="medium",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file="calc.py",
                   line=line, message="mutant survived", evidence="", gate=Gate.ALL)


def _ledger(tmp_path, retested_runs):
    """Three recorded survivors A, B, C (oldest first), then one mutation
    consumer row per entry of `retested_runs`, each naming the ids that run
    re-tested -- the shape `drain._consume_item` writes from the consumer's
    extra."""
    (tmp_path / ".aramid").mkdir(parents=True)
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    led.record_run("r1", "2026-09-01T00:00:00+00:00", "drain", {"mutation"}, {"calc.py"},
                   [_survivor("a" * 64, 2), _survivor("b" * 64, 3), _survivor("c" * 64, 4)])
    for i, ids in enumerate(retested_runs):
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"d{i}",
                         f"2026-09-0{i + 2}T00:00:00+00:00",
                         payload={"consumer": "mutation", "item_id": f"q{i}",
                                  "state": "ok", "note": "", "retested_ids": list(ids)}))
    return led


def _order(led, tmp_path):
    try:
        return [fid[0] for fid, _, _ in mut_consumer._retest_candidates(led, tmp_path)]
    finally:
        led.close()


def test_never_retested_survivors_come_first_oldest_first(tmp_path):
    assert _order(_ledger(tmp_path, []), tmp_path) == ["a", "b", "c"]


def test_a_survivor_retested_last_drain_goes_to_the_back(tmp_path):
    """The 2026-09-07 14:00Z drain re-tested 3 of 12 -- the three OLDEST --
    and a re-confirmed survivor keeps its place at the head, so with
    `retest_cap` 3 the same three run every drain and the other nine never
    get a turn: a second starvation, of the pile by its own front. Least
    recently re-tested first; never re-tested before any of those."""
    assert _order(_ledger(tmp_path, [["a" * 64]]), tmp_path) == ["b", "c", "a"]


def test_the_rotation_reads_every_prior_run_not_only_the_last(tmp_path):
    # run 1 re-tested a and b; run 2 re-tested c: c is the most recent, then
    # a and b (same run, oldest-first tie-break), and nothing is untested.
    r1, r2 = tmp_path / "one", tmp_path / "two"
    assert _order(_ledger(r1, [["a" * 64, "b" * 64], ["c" * 64]]), r1) == ["a", "b", "c"]
    # run 1 re-tested c; run 2 re-tested a: b never, then c, then a.
    assert _order(_ledger(r2, [["c" * 64], ["a" * 64]]), r2) == ["b", "c", "a"]
