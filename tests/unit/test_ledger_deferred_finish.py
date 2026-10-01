"""FN-24: a ledger with `defer_finish` set holds each run's RUN_FINISHED back so
the caller that decides the exit code can write the count that actually
blocked (`finish_run`), and a run that dies before then still gets its row
(`finish_pending`, with the count known when it was recorded).

`record_run` counted `blocking` from the verdicts it was handed, and the
pre-push ratchet escalates a new WARN to BLOCK only after it -- it needs the
`new_ids` record_run returns -- so `status` read a ratchet-refused push as
`0 blocking`. Nothing here changes the default: every ledger that does not
ask still gets its RUN_FINISHED from record_run itself, at once. A flag on
the ledger rather than a parameter, so neither record_run's nor run_gate's
signature moves: `cmd_check` owns the ledger it sets it on.
"""
from aramid.ledger import Ledger
from aramid.models import EventType, Finding, Gate, Severity, Verdict


def _finding(fid, verdict):
    return Finding(fid, "eslint", "no-unused-vars", "1", Severity.LOW, verdict,
                   "a.py", 1, "m", "e", Gate.PRE_PUSH)


def _finished(led):
    return [e for e in led.events() if e.type is EventType.RUN_FINISHED]


def test_by_default_record_run_finishes_the_run_at_once(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        led.record_run("r1", "t", "pre-push", {"eslint"}, set(),
                       [_finding("a", Verdict.BLOCK)], finished_at="t2")
        (row,) = _finished(led)
        assert row.run_id == "r1"
        assert row.payload == {"blocking": 1, "finished_at": "t2"}
    finally:
        led.close()


def test_a_deferred_run_has_no_row_until_it_is_finished(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        led.defer_finish = True
        new_ids = led.record_run("r1", "t", "pre-push", {"eslint"}, set(),
                                 [_finding("a", Verdict.WARN)], finished_at="t2",
                                 degraded={"semgrep": "not found"})
        assert new_ids == ["a"]                 # recording itself is unchanged
        assert _finished(led) == []

        assert led.finish_run("r1", blocking=1) is True

        (row,) = _finished(led)
        assert (row.run_id, row.at) == ("r1", "t")
        # The count is the caller's; everything else is what record_run saw.
        assert row.payload == {"blocking": 1, "finished_at": "t2",
                               "degraded": {"semgrep": "not found"}}
    finally:
        led.close()


def test_a_run_is_finished_once(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        led.defer_finish = True
        led.record_run("r1", "t", "pre-push", {"eslint"}, set(), [])
        assert led.finish_run("r1", blocking=0) is True
        assert led.finish_run("r1", blocking=5) is False
        assert led.finish_pending() == 0
        assert [e.payload["blocking"] for e in _finished(led)] == [0]
    finally:
        led.close()


def test_finishing_an_unknown_run_writes_nothing(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        assert led.finish_run("never-recorded", blocking=1) is False
        assert _finished(led) == []
    finally:
        led.close()


def test_a_run_left_unfinished_is_flushed_with_its_recorded_count(tmp_path):
    # The crash path: whatever died between record_run and finish_run, the
    # run still gets its row, counted as record_run counted it.
    led = Ledger(tmp_path / "l.db")
    try:
        led.defer_finish = True
        led.record_run("r1", "t", "pre-push", {"eslint"}, set(),
                       [_finding("a", Verdict.BLOCK), _finding("b", Verdict.WARN)])
        led.record_run("r2", "u", "pre-push", {"eslint"}, set(), [])

        assert led.finish_pending() == 2

        rows = {e.run_id: e.payload["blocking"] for e in _finished(led)}
        assert rows == {"r1": 1, "r2": 0}
        assert led.finish_pending() == 0
    finally:
        led.close()


def test_finishing_without_a_count_keeps_the_recorded_one(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        led.defer_finish = True
        led.record_run("r1", "t", "pre-push", {"eslint"}, set(),
                       [_finding("a", Verdict.BLOCK)])
        assert led.finish_run("r1") is True
        assert [e.payload["blocking"] for e in _finished(led)] == [1]
    finally:
        led.close()
