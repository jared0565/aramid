"""Unit-scope pins for the EMPTY-QUEUE re-test item.

Consumers run only on a popped queue item, so a repo with nothing queued
never re-tested its `pending_retest` mutation survivors: the gate had said
"a push addressed this gap", and with no further commit nothing ever
verified it (2026-09-10, this repo: three rows sat pending after the
22:00Z drain, closed only by a hand-run `triage HEAD` + `drain --repo .`).

The drain now synthesizes one item per such repo -- base == head == HEAD,
one reason carrying the `pending-retest:` marker -- and the mutation
consumer re-tests exactly the pending rows on it. Hand-built ledgers; git
only for a HEAD sha."""
import subprocess
from types import SimpleNamespace

from aramid import queue
from aramid.commands import drain as drain_mod
from aramid.consumers import mutation as mut_consumer
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict

A, B, C = "a" * 64, "b" * 64, "c" * 64


def _survivor(fid, line):
    return Finding(id=fid, tool="mutation", rule="int-bound", severity_raw="medium",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file="calc.py",
                   line=line, message="mutant survived", evidence="", gate=Gate.ALL)


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "base"], cwd=r, check=True)
    (r / ".aramid").mkdir()
    return r


def _head(r):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, check=True,
                          capture_output=True, text=True).stdout.strip()


def _ledger(r, *, pending=(), open_=()):
    led = Ledger(r / ".aramid" / "ledger.db")
    led.record_run("r1", "2026-09-01T00:00:00+00:00", "drain", {"mutation"}, {"calc.py"},
                   [_survivor(f, i + 2) for i, f in enumerate([*pending, *open_])])
    for n, fid in enumerate(pending):
        led.append(Event(EventType.FINDING_RESOLVED, "gate", f"2026-09-01T00:01:{n:02d}+00:00",
                         finding_id=fid,
                         payload={"auto_resolved": "gap_addressed", "pending_retest": True}))
    return led


def _cfg(**mutation):
    return SimpleNamespace(mutation={"enabled": True, **mutation}, triage={"min_score": 40})


def _item(*reasons):
    return queue.QueueItem(id="q", base="x", head="x", score=40, reasons=tuple(reasons),
                           state="queued", created_at="t", updated_at="t")


KNOBS_ON = {"retest_open_survivors": True}
KNOBS_OFF = {"retest_open_survivors": False}
A_TEST_CHANGED = {"tests/test_calc.py": {3}}


# ------------------------------------------------ the marker, one constant --

def test_the_marker_reason_round_trips_through_the_queue():
    assert queue.is_pending_retest_item(_item(queue.pending_retest_reason(2)))
    assert "2 " in queue.pending_retest_reason(2)
    assert not queue.is_pending_retest_item(_item("survivor-retest: 1 module(s)"))
    assert not queue.is_pending_retest_item(_item())


# ------------------------------------------- the consumer's population rule --

def test_a_changed_test_re_tests_open_and_pending_rows():
    assert mut_consumer._retest_statuses(KNOBS_ON, A_TEST_CHANGED, _item("t")) \
        == ("open", "pending_retest")


def test_an_empty_queue_item_re_tests_pending_rows_only():
    # No changed test, so no claimed pass and no rotation through OPEN
    # survivors: those are findings awaiting a fix, and re-testing them four
    # times a day on an idle repo costs a full-suite run each and proves
    # nothing new. Pending rows are the ones that exist only to be verified.
    assert mut_consumer._retest_statuses(KNOBS_ON, {}, _item(queue.pending_retest_reason(1))) \
        == ("pending_retest",)


def test_a_plain_item_with_no_changed_test_re_tests_nothing():
    assert mut_consumer._retest_statuses(KNOBS_ON, {}, _item("t")) == ()
    assert mut_consumer._retest_statuses(KNOBS_ON, {"calc.py": {1}}, _item("t")) == ()


def test_the_knob_turns_both_re_test_paths_off():
    assert mut_consumer._retest_statuses(KNOBS_OFF, A_TEST_CHANGED, _item("t")) == ()
    assert mut_consumer._retest_statuses(KNOBS_OFF, {}, _item(queue.pending_retest_reason(1))) == ()


def test_candidates_can_be_narrowed_to_pending_rows(tmp_path):
    r = _repo(tmp_path)
    led = _ledger(r, pending=(A,), open_=(B,))
    try:
        both = [c[0] for c in mut_consumer._retest_candidates(led, r)]
        pending = [c[0] for c in mut_consumer.pending_retests(led, r)]
    finally:
        led.close()
    assert sorted(both) == [A, B]
    assert pending == [A]


# ------------------------------------------------ the drain's decision --

def test_the_drain_enqueues_one_re_test_item_for_a_repo_with_pending_rows(tmp_path):
    r = _repo(tmp_path)
    led = _ledger(r, pending=(A, B), open_=(C,))
    try:
        item = drain_mod._pending_retest_item(r, _cfg(), led, "2026-09-02T00:00:00+00:00")
        queued = queue.queued_item(queue.materialize_queue(led.events()))
    finally:
        led.close()
    assert item is not None and queued is not None and queued.id == item.id
    assert item.base == item.head == _head(r), "an empty range: no fresh mutants, only re-tests"
    assert item.score == 40, "exactly min_score, so the drain's own filter admits it"
    assert queue.is_pending_retest_item(item)
    assert "2 " in item.reasons[0], "counts the PENDING rows, not the open one"


def test_open_survivors_alone_never_trigger_an_item(tmp_path):
    r = _repo(tmp_path)
    led = _ledger(r, open_=(A, B))
    try:
        assert drain_mod._pending_retest_item(r, _cfg(), led, "t") is None
        assert queue.queued_item(queue.materialize_queue(led.events())) is None
    finally:
        led.close()


def test_a_suppressed_pending_row_does_not_count(tmp_path):
    # Same eligibility as the consumer: an `equivalent mutant` entry says
    # unkillable, and an item for it would cut a worktree to re-test nothing.
    r = _repo(tmp_path)
    (r / ".aramid-suppressions.toml").write_text(
        '[[suppress]]\nid = "' + A + '"\ntool = "mutation"\nrule = "int-bound"\n'
        'path = "calc.py"\nreason = "equivalent mutant"\n', encoding="utf-8")
    led = _ledger(r, pending=(A,))
    try:
        assert drain_mod._pending_retest_item(r, _cfg(), led, "t") is None
    finally:
        led.close()


def test_a_stood_down_mutation_consumer_is_not_poked(tmp_path):
    # A consumer that gave up (persistent baseline failure, timeouts, no test
    # command) returns `ok` with a give-up note and would do so again every
    # drain: an item for it is a row of noise every four hours, forever.
    r = _repo(tmp_path)
    led = _ledger(r, pending=(A,))
    led.append(Event(EventType.CONSUMER_RUN_FINISHED, "d1", "2026-09-01T06:00:00+00:00",
                     payload={"consumer": "mutation", "item_id": "q0", "state": "ok",
                              "note": "giving up: baseline failing @ deadbeef x3",
                              "duration_s": 1.0}))
    try:
        assert drain_mod._pending_retest_item(r, _cfg(), led, "t") is None
    finally:
        led.close()


def test_mutation_disabled_or_re_tests_off_means_no_item(tmp_path):
    r = _repo(tmp_path)
    led = _ledger(r, pending=(A,))
    try:
        assert drain_mod._pending_retest_item(r, _cfg(enabled=False), led, "t") is None
        assert drain_mod._pending_retest_item(r, _cfg(retest_open_survivors=False), led, "t") is None
        assert queue.queued_item(queue.materialize_queue(led.events())) is None
    finally:
        led.close()
