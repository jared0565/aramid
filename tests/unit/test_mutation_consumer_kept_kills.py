"""FN-43: a recorded survivor gets a re-test it can count on.

Both halves were reproduced in a scratch repo before this was written
(2026-10-12), each with a control that fired:

- THE TIME WALL. A survivor id names every line with the same content, and a
  claim needs every occurrence killed. Each kill of a recorded survivor costs a
  full-suite confirm, and the wall clock starts before the baseline, so a
  three-occurrence survivor can fit the item's run count (min(max_mutants,
  confirm_cap)) and still not its clock. Every drain then killed the first two,
  stopped before the third, threw both kills away and claimed nothing --
  4307f4ee on this repo, about 47 minutes a drain at `wall_budget_s` 2500.
- THE OPEN SURVIVOR NOBODY NAMES. An item that changed a test re-tests every
  recorded survivor, but in the hygiene pass, last, on what the range left. A
  push that changes source and tests together spends that first, and the
  drain's empty-queue item re-tests `pending_retest` rows only, so an open row
  whose killing test is already in history waited for a quieter push that may
  never come (59bcbe17, dee97bcb).

KEPT KILLS. A re-test's confirmed kills are written on the consumer row
(`retest_partial`), keyed on the head the item tested and the suite that
confirmed them. A later re-test under the same key runs only the occurrences
still owed a kill, and claims once every occurrence has one. A new head or a
new suite starts over; a surviving occurrence re-reports the id and drops them.

OWED RE-TESTS. What an item that changed a test did not settle -- no claim and
no re-report -- is written on its row (`retest_owed`). The drain's empty-queue
item re-tests those rows, open ones included, until each has a verdict. The
cost is the one the hygiene pass was already meant to pay.

Harness as in test_mutation_consumer_consume.py: a real tmp git repo and
worktree, a real ledger, and `run_subprocess` replaced by an oracle that reads
which mutant is applied and answers from a script."""
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from aramid import config as config_mod
from aramid import mutation, queue
from aramid.commands import drain as drain_mod
from aramid.consumers import mutation as mut_consumer
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict
from aramid.queue import QueueItem
from aramid.runners.base import RunnerResult, ToolState

# f1, f1_b and f1_c hold the same line, so one survivor id names all three.
SRC = ("def f1(x):\n    return x + 1\n\n\n"
       "def f1_b(x):\n    return x + 1\n\n\n"
       "def f1_c(x):\n    return x + 1\n\n\n"
       "def f2(x):\n    return x + 2\n")
LINES = SRC.splitlines()
MUTANTS = mutation.generate_mutants(SRC, set(range(1, len(LINES) + 1)))
assert [m.func for m in MUTANTS] == ["f1", "f1_b", "f1_c", "f2"]
TOML = ("schema_version = 1\n[mutation]\nmax_mutants = 20\nconfirm_cap = 3\n"
        "wall_budget_s = 600\nmutant_timeout_s = 120\nbaseline_timeout_s = 480\n"
        "retest_cap = 3\n")
TEST = "from calc import f1\ndef test_one():\n    assert isinstance(f1(1), int)\n"


def fp(func):
    m = next(x for x in MUTANTS if x.func == func)
    return mut_consumer._mutant_fp("calc.py", m.op, m.line, LINES)


TRIPLE = fp("f1")
assert fp("f1_b") == fp("f1_c") == TRIPLE
assert len(mut_consumer._survivor_mutants("calc.py", TRIPLE, SRC, MUTANTS[0].op)) == 3


def _git(root, *a):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a],
                   cwd=root, check=True, capture_output=True, text=True)


def _sha(root):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


def _repo(tmp_path, toml=TOML):
    """calc.py empty at base, SRC at head."""
    r = tmp_path / "r"
    (r / "tests").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    (r / "aramid.toml").write_text(toml, encoding="utf-8")
    (r / "conftest.py").write_text("", encoding="utf-8")
    (r / "tests" / "test_calc.py").write_text(TEST, encoding="utf-8")
    (r / "calc.py").write_text("", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "calc.py").write_text(SRC, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "head")
    return r, base, _sha(r)


def _commit(r, rel, body):
    (r / rel).parent.mkdir(parents=True, exist_ok=True)
    (r / rel).write_text(body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", rel)
    return _sha(r)


def _knob(r, old, new):
    """Edit aramid.toml in the WORKING TREE, as an operator would: the drain
    reads it from there, and the head does not move."""
    p = r / "aramid.toml"
    text = p.read_text(encoding="utf-8")
    assert old in text, old
    p.write_text(text.replace(old, new), encoding="utf-8")


def _record(r, survivors, *, pending=()):
    """`survivors` (func names whose recorded id is `fp(func)`) open on the
    books, in that order; `pending` of them flipped by the gate."""
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("seed", "2026-09-01T00:00:00+00:00", "drain", {"mutation"}, {"calc.py"},
                       [Finding(id=fp(f), tool="mutation", rule=MUTANTS[0].op,
                                severity_raw="medium", severity=Severity.MEDIUM,
                                verdict=Verdict.WARN, file="calc.py",
                                line=next(m.line for m in MUTANTS if m.func == f),
                                message="mutant survived", evidence="", gate=Gate.ALL)
                        for f in survivors])
        for k, f in enumerate(pending):
            led.append(Event(EventType.FINDING_RESOLVED, "gate", f"2026-09-01T00:01:{k:02d}+00:00",
                             finding_id=fp(f),
                             payload={"auto_resolved": "gap_addressed", "pending_retest": True}))
    finally:
        led.close()


@dataclass
class Out:
    rc: int = 0
    state: ToolState = ToolState.OK


KILL, PASS, TIMEOUT = Out(rc=1), Out(rc=0), Out(state=ToolState.TIMEOUT)


class Oracle:
    """Answers a run by the mutant applied to the worktree's calc.py: kind
    "full" (the baseline and every confirm) or "s1", label "BASE" or the
    mutated function's name. The first run is the baseline, unmutated, so
    it names the source every later run is compared against."""

    def __init__(self, full_argv, outcomes, default):
        self.full = list(full_argv)
        self.outcomes = dict(outcomes)
        self.default = default
        self.original = None
        self.by_source = {}
        self.calls = []

    def __call__(self, argv, cwd, timeout_s, env=None, **kw):
        src = (Path(cwd) / "calc.py").read_text(encoding="utf-8")
        if self.original is None:
            self.original = src
            lines = src.splitlines()
            self.by_source = {m.source: m.func for m in
                              mutation.generate_mutants(src, set(range(1, len(lines) + 1)))}
        label = "BASE" if src == self.original else self.by_source.get(src, "?")
        kind = "full" if list(argv) == self.full else "s1"
        self.calls.append((kind, label))
        spec = self.outcomes.get((kind, label), PASS if label == "BASE" else self.default)
        return RunnerResult(tool=str(argv[0]), state=spec.state, duration_s=0.5,
                            returncode=spec.rc)


def _clock(monkeypatch, *ticks):
    """`time.monotonic` as a script: the item's start, then one reading per
    mutant before it runs; the last tick repeats."""
    seq = list(ticks)

    def monotonic():
        return seq.pop(0) if len(seq) > 1 else seq[0]
    monkeypatch.setattr(mut_consumer, "time", SimpleNamespace(monotonic=monotonic))


def _empty_queue_item(head, n=1):
    return QueueItem(id=f"e-{head[:6]}", base=head, head=head, score=40,
                     reasons=(queue.pending_retest_reason(n),), state="queued",
                     created_at="t", updated_at="t")


def _item(base, head, item_id="q"):
    return QueueItem(id=item_id, base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")


_TICK = iter(range(10_000))


def _drain(r, item, monkeypatch, outcomes=None, default=KILL):
    """One drain's consumer run on `item`, recorded the way the drain records
    it (`_record_consumer_run`), so the next run reads what production
    reads."""
    cfg = config_mod.load_config(r)
    oracle = Oracle(mut_consumer._full_argv(cfg, r), outcomes or {}, default)
    monkeypatch.setattr(mut_consumer, "run_subprocess", oracle)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        res = mut_consumer.consume(item, DrainContext(root=r, cfg=cfg, ledger=led,
                                                      clock=lambda: "t"))
        drain_mod._record_consumer_run(
            led, f"run{next(_TICK)}", lambda: f"2026-09-02T00:{next(_TICK) % 60:02d}:00+00:00",
            mut_consumer.NAME, item, res, [], 1.0)
    finally:
        led.close()
    return res, [lab for _k, lab in oracle.calls]


def _suite(r):
    return mut_consumer._suite_label(mut_consumer._full_argv(config_mod.load_config(r), r))


def _pending(r):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        return [c[0] for c in mut_consumer.pending_retests(led, r)]
    finally:
        led.close()


def _status(r, fid):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        return led.open_findings().get(fid, {}).get("status")
    finally:
        led.close()


def _stats(res, **expect):
    zero = {"generated": 0, "tested": 0, "killed_s1": 0, "killed_s2": 0, "survived": 0,
            "confirmed": 0, "timeouts": 0, "errors": 0, "unconfirmed_kills": 0,
            "capped_kills": 0, "unselected_s1": 0, "truncated": False,
            "retest_candidates": 0, "retested": 0, "retest_killed": 0,
            "retest_truncated": False, "retest_skipped": 0, "claimed": 0,
            "claimed_retested": 0, "retested_ids": []}
    want = {**zero, **expect}
    got = {k: res.extra[k] for k in want}
    assert got == want, {k: (got[k], want[k]) for k in want if got[k] != want[k]}


CUT_BEFORE_THE_THIRD = (0.0, 0.0, 0.0, 600.001)     # start, f1, f1_b, then past 600


# ------------------------------------------------------------- kept kills --

def test_the_kills_a_cut_re_test_bought_are_kept_and_the_next_drain_claims(tmp_path, monkeypatch):
    r, _base, head = _repo(tmp_path)
    _record(r, ["f1"], pending=["f1"])
    _clock(monkeypatch, *CUT_BEFORE_THE_THIRD)

    res, calls = _drain(r, _empty_queue_item(head), monkeypatch)

    assert calls == ["BASE", "f1", "f1", "f1_b", "f1_b"], "two occurrences, each killed and confirmed"
    _stats(res, tested=2, killed_s1=2, truncated=True, retest_truncated=True,
           retest_candidates=1, retested=1, retested_ids=[TRIPLE])
    assert res.repaired is not None and res.repaired.ids == (), "two of three is not a claim"
    assert res.extra["retest_partial"] == {
        TRIPLE: {"head": head, "suite": _suite(r), "of": 3, "killed": [0, 1]}}
    assert res.note == ("0 confirmed survivor(s) of 2 mutant(s) tested (truncated: budget/cap"
                        " hit, remainder dropped); re-tested 1 of 1 open survivor(s), 0 killed;"
                        " 1 survivor(s) part-killed, kills kept for a re-test at this head")
    assert _status(r, TRIPLE) == "pending_retest"

    _clock(monkeypatch, 0.0)
    res, calls = _drain(r, _empty_queue_item(head), monkeypatch)

    assert calls == ["BASE", "f1_c", "f1_c"], "only the occurrence still owed a kill"
    _stats(res, tested=1, killed_s1=1, retest_candidates=1, retested=1, retest_killed=1,
           retested_ids=[TRIPLE])
    assert res.repaired is not None and res.repaired.ids == (TRIPLE,)
    assert res.extra["retest_partial"] == {}
    assert _status(r, TRIPLE) == "fixed"


def test_a_kept_kill_counts_only_at_the_head_it_was_made_at(tmp_path, monkeypatch):
    r, _base, head = _repo(tmp_path)
    _record(r, ["f1"], pending=["f1"])
    _clock(monkeypatch, *CUT_BEFORE_THE_THIRD)
    _drain(r, _empty_queue_item(head), monkeypatch)
    head2 = _commit(r, "README.md", "a new head: the source or its tests may differ\n")

    _clock(monkeypatch, *CUT_BEFORE_THE_THIRD)
    res, calls = _drain(r, _empty_queue_item(head2), monkeypatch)

    assert calls == ["BASE", "f1", "f1", "f1_b", "f1_b"], "started over at the new head"
    assert res.repaired is not None and res.repaired.ids == ()
    assert res.extra["retest_partial"] == {
        TRIPLE: {"head": head2, "suite": _suite(r), "of": 3, "killed": [0, 1]}}


def test_a_kept_kill_counts_only_under_the_suite_that_confirmed_it(tmp_path, monkeypatch):
    # The drain reads aramid.toml from the working tree, so the suite can
    # change while the head stands still; a claim made of two suites' kills
    # rests on neither.
    r, _base, head = _repo(tmp_path)
    _record(r, ["f1"], pending=["f1"])
    _clock(monkeypatch, *CUT_BEFORE_THE_THIRD)
    _drain(r, _empty_queue_item(head), monkeypatch)
    before = _suite(r)
    _knob(r, "[mutation]\n", '[mutation]\ntest_command = ["python", "-m", "pytest", "-q", "tests"]\n')
    assert _suite(r) != before

    _clock(monkeypatch, 0.0)
    res, calls = _drain(r, _empty_queue_item(head), monkeypatch)

    assert calls == ["BASE", "f1", "f1", "f1_b", "f1_b", "f1_c", "f1_c"]
    assert res.repaired is not None and res.repaired.ids == (TRIPLE,)


def test_a_surviving_occurrence_re_reports_the_id_and_drops_the_kept_kills(tmp_path, monkeypatch):
    r, _base, head = _repo(tmp_path)
    _record(r, ["f1"], pending=["f1"])
    _clock(monkeypatch, *CUT_BEFORE_THE_THIRD)
    _drain(r, _empty_queue_item(head), monkeypatch)

    _clock(monkeypatch, 0.0)
    res, calls = _drain(r, _empty_queue_item(head), monkeypatch,
                        {("s1", "f1_c"): PASS, ("full", "f1_c"): PASS})

    assert calls == ["BASE", "f1_c", "f1_c"]
    assert res.repaired is not None and res.repaired.ids == ()
    assert [f.file for f in res.findings] == ["calc.py"], "the id is re-reported"
    assert res.extra["retest_partial"] == {}, "a survivor cannot be claimed; its kills go"

    _clock(monkeypatch, *CUT_BEFORE_THE_THIRD)
    _, calls = _drain(r, _empty_queue_item(head), monkeypatch)
    assert calls == ["BASE", "f1", "f1", "f1_b", "f1_b"], "nothing kept to resume from"


def test_kept_kills_for_a_different_number_of_occurrences_are_ignored(tmp_path, monkeypatch):
    # The index of an occurrence means something only against the same
    # regeneration; a row that disagrees on the count is not resumed from.
    r, _base, head = _repo(tmp_path)
    _record(r, ["f1"], pending=["f1"])
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, "old", "2026-09-01T12:00:00+00:00",
                         payload={"consumer": "mutation", "item_id": "x", "state": "ok",
                                  "retested_ids": [TRIPLE],
                                  "retest_partial": {TRIPLE: {"head": head, "suite": _suite(r),
                                                              "of": 2, "killed": [0, 1]}}}))
    finally:
        led.close()

    _clock(monkeypatch, 0.0)
    _, calls = _drain(r, _empty_queue_item(head), monkeypatch)

    assert calls == ["BASE", "f1", "f1", "f1_b", "f1_b", "f1_c", "f1_c"]


def test_a_kept_index_that_names_no_occurrence_counts_for_nothing(tmp_path, monkeypatch):
    # The claim is "every occurrence has a kill": an index the regeneration
    # does not have must neither stand in for one nor block the claim.
    r, _base, head = _repo(tmp_path)
    _record(r, ["f1"], pending=["f1"])
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, "old", "2026-09-01T12:00:00+00:00",
                         payload={"consumer": "mutation", "item_id": "x", "state": "ok",
                                  "retested_ids": [TRIPLE],
                                  "retest_partial": {TRIPLE: {"head": head, "suite": _suite(r),
                                                              "of": 3, "killed": [0, 1, 7]}}}))
    finally:
        led.close()

    _clock(monkeypatch, 0.0)
    res, calls = _drain(r, _empty_queue_item(head), monkeypatch)

    assert calls == ["BASE", "f1_c", "f1_c"]
    assert res.repaired is not None and res.repaired.ids == (TRIPLE,)


def test_kept_kills_that_cover_every_occurrence_are_no_kills_at_all(tmp_path, monkeypatch):
    # The consumer never keeps a full set: a re-test that killed every
    # occurrence claims instead. So a row that lists them all is forged or
    # corrupt, and taking it would claim with no run in this process --
    # `mutant_killed` on a survivor nothing re-tested (llm-review 961336fe).
    # It counts for nothing, and the survivor is re-tested from scratch.
    r, _base, head = _repo(tmp_path)
    _record(r, ["f1"], pending=["f1"])
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, "old", "2026-09-01T12:00:00+00:00",
                         payload={"consumer": "mutation", "item_id": "x", "state": "ok",
                                  "retested_ids": [TRIPLE],
                                  "retest_partial": {TRIPLE: {"head": head, "suite": _suite(r),
                                                              "of": 3, "killed": [0, 1, 2]}}}))
    finally:
        led.close()

    _clock(monkeypatch, 0.0)
    res, calls = _drain(r, _empty_queue_item(head), monkeypatch)

    assert calls == ["BASE", "f1", "f1", "f1_b", "f1_b", "f1_c", "f1_c"]
    assert res.repaired is not None and res.repaired.ids == (TRIPLE,)


def test_only_the_mutation_consumers_own_rows_are_its_memory(tmp_path, monkeypatch):
    # Another consumer's row that happens to carry the same keys says
    # nothing about this consumer's re-tests: it neither wipes kept kills nor
    # pays a debt.
    r, _base, head = _repo(tmp_path)
    _record(r, ["f1"], pending=["f1"])
    _clock(monkeypatch, *CUT_BEFORE_THE_THIRD)
    _drain(r, _empty_queue_item(head), monkeypatch)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, "js", "2026-09-03T00:00:00+00:00",
                         payload={"consumer": "js_mutation", "item_id": "x", "state": "ok",
                                  "retested_ids": [TRIPLE], "retest_owed": []}))
    finally:
        led.close()

    _clock(monkeypatch, 0.0)
    _, calls = _drain(r, _empty_queue_item(head), monkeypatch)

    assert calls == ["BASE", "f1_c", "f1_c"], "the kills this consumer kept still stand"


def test_another_consumers_row_does_not_pay_the_debt(tmp_path, monkeypatch):
    r, _head2, _, _ = _owing_push(tmp_path, monkeypatch)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, "js", "2026-09-03T00:00:00+00:00",
                         payload={"consumer": "js_mutation", "item_id": "x", "state": "ok",
                                  "retest_owed": []}))
        led.append(Event(EventType.FINDING_DETECTED, "x", "2026-09-03T00:00:01+00:00",
                         finding_id="f" * 64,
                         payload={"consumer": "mutation", "retest_owed": [],
                                  "tool": "other", "file": "x.py", "line": 1}))
    finally:
        led.close()

    assert _pending(r) == [TRIPLE]


def test_the_budget_check_counts_only_the_occurrences_still_owed_a_kill(tmp_path, monkeypatch):
    r, _base, head = _repo(tmp_path, TOML.replace("confirm_cap = 3", "confirm_cap = 1"))
    _record(r, ["f1"], pending=["f1"])

    # Control: one confirm slot, three occurrences, nothing kept -- skipped
    # unspent, as the atomic claim has always required.
    _clock(monkeypatch, 0.0)
    res, calls = _drain(r, _empty_queue_item(head), monkeypatch)
    assert calls == ["BASE"] and res.extra["retest_skipped"] == 1

    _knob(r, "confirm_cap = 1", "confirm_cap = 3")
    _clock(monkeypatch, *CUT_BEFORE_THE_THIRD)
    _drain(r, _empty_queue_item(head), monkeypatch)
    _knob(r, "confirm_cap = 3", "confirm_cap = 1")

    _clock(monkeypatch, 0.0)
    res, calls = _drain(r, _empty_queue_item(head), monkeypatch)

    assert calls == ["BASE", "f1_c", "f1_c"], "one occurrence owed, one slot: it fits"
    assert res.repaired is not None and res.repaired.ids == (TRIPLE,)


def test_a_re_test_left_alone_this_run_keeps_its_kills_for_later(tmp_path, monkeypatch):
    # The memory is the NEWEST row that re-tested the id. A run that never
    # reached it (here: confirm_cap 0, so it is skipped unspent) is not that
    # row, and does not wipe what an earlier one kept.
    r, _base, head = _repo(tmp_path)
    _record(r, ["f1"], pending=["f1"])
    _clock(monkeypatch, *CUT_BEFORE_THE_THIRD)
    _drain(r, _empty_queue_item(head), monkeypatch)
    _knob(r, "confirm_cap = 3", "confirm_cap = 0")
    _clock(monkeypatch, 0.0)
    _, calls = _drain(r, _empty_queue_item(head), monkeypatch)
    assert calls == ["BASE"]
    _knob(r, "confirm_cap = 0", "confirm_cap = 3")

    _, calls = _drain(r, _empty_queue_item(head), monkeypatch)

    assert calls == ["BASE", "f1_c", "f1_c"]


# ------------------------------------------------------- what the note says --

def test_a_survivor_skipped_because_the_range_spent_the_slots_is_said_so(tmp_path, monkeypatch):
    # Before: "occurrences exceed the remaining re-test budget" for a survivor
    # with ONE occurrence, when the range had simply spent every slot. The
    # range here is one new function (f3) and max_mutants is 1.
    r, _base, head = _repo(tmp_path, TOML.replace("max_mutants = 20", "max_mutants = 1"))
    _record(r, ["f2"])
    _commit(r, "calc.py", SRC + "\n\ndef f3(x):\n    return x + 3\n")
    head3 = _commit(r, "tests/test_other.py", "def test_x():\n    assert True\n")
    _clock(monkeypatch, 0.0)

    res, calls = _drain(r, _item(head, head3), monkeypatch)

    assert calls == ["BASE", "f3"], "the range's one mutant, killed at stage 1, then nothing"
    assert res.extra["retest_skipped"] == 1
    assert res.note.endswith("; 1 survivor(s) not re-tested: no re-test slot was left for them"), \
        res.note


def test_a_survivor_with_more_occurrences_than_the_slots_left_is_said_so(tmp_path, monkeypatch):
    r, _base, head = _repo(tmp_path, TOML.replace("confirm_cap = 3", "confirm_cap = 2"))
    _record(r, ["f1"], pending=["f1"])
    _clock(monkeypatch, 0.0)

    res, _ = _drain(r, _empty_queue_item(head), monkeypatch)

    assert res.note.endswith("; 1 survivor(s) not re-tested: more occurrences than the re-test"
                             " slots left"), res.note


# ------------------------------------------------------------- owed re-tests --

def _owing_push(tmp_path, monkeypatch):
    """f2 then TRIPLE open on the books; a push changes a test that names
    neither, with retest_cap 1: the hygiene pass settles f2 and never reaches
    TRIPLE."""
    r, _base, head = _repo(tmp_path, TOML.replace("retest_cap = 3", "retest_cap = 1"))
    _record(r, ["f2", "f1"])
    head2 = _commit(r, "tests/test_other.py", "def test_x():\n    assert True\n")
    _clock(monkeypatch, 0.0)
    res, calls = _drain(r, _item(head, head2), monkeypatch)
    return r, head2, res, calls


def test_an_item_that_changed_a_test_owes_what_its_passes_did_not_settle(tmp_path, monkeypatch):
    r, head2, res, calls = _owing_push(tmp_path, monkeypatch)

    assert calls == ["BASE", "f2", "f2"]
    assert res.repaired is not None and res.repaired.ids == (fp("f2"),)
    assert res.extra["retest_truncated"] is True
    assert res.extra["retest_owed"] == [TRIPLE], "settled rows are not owed; unreached ones are"
    assert _status(r, TRIPLE) == "open"
    assert _pending(r) == [TRIPLE], "the empty-queue item's population now includes it"


def test_the_empty_queue_item_re_tests_an_owed_open_row_and_pays_the_debt(tmp_path, monkeypatch):
    r, head2, _, _ = _owing_push(tmp_path, monkeypatch)

    res, calls = _drain(r, _empty_queue_item(head2), monkeypatch)

    assert calls == ["BASE", "f1", "f1", "f1_b", "f1_b", "f1_c", "f1_c"]
    assert res.repaired is not None and res.repaired.ids == (TRIPLE,)
    assert res.extra["retest_owed"] == []
    assert _status(r, TRIPLE) == "fixed"
    assert _pending(r) == []


def test_a_re_report_pays_the_debt_too(tmp_path, monkeypatch):
    r, head2, _, _ = _owing_push(tmp_path, monkeypatch)

    res, _ = _drain(r, _empty_queue_item(head2), monkeypatch,
                    {("s1", "f1"): PASS, ("full", "f1"): PASS})

    assert res.repaired is not None and res.repaired.ids == ()
    assert res.extra["retest_owed"] == [], "a verdict, if not the hoped-for one"
    assert _pending(r) == [], "an open row with no debt is not the empty-queue item's"


def test_an_unsettled_owed_row_stays_owed(tmp_path, monkeypatch):
    r, head2, _, _ = _owing_push(tmp_path, monkeypatch)

    res, _ = _drain(r, _empty_queue_item(head2), monkeypatch, default=TIMEOUT)

    assert res.repaired is not None and res.repaired.ids == ()
    assert res.extra["retest_owed"] == [TRIPLE]
    assert _pending(r) == [TRIPLE]


def test_an_item_that_re_tests_nothing_leaves_the_debt_where_it_was(tmp_path, monkeypatch):
    # A plain push (source only, no changed test) re-tests no survivor, so
    # its row says nothing about the debt: the newest row that does still
    # stands.
    r, head2, _, _ = _owing_push(tmp_path, monkeypatch)
    head3 = _commit(r, "calc.py", SRC + "\n\ndef f3(x):\n    return x + 3\n")

    res, _ = _drain(r, _item(head2, head3), monkeypatch, default=KILL)

    assert "retest_owed" not in res.extra
    assert _pending(r) == [TRIPLE]


def test_an_owed_row_that_regenerates_nothing_is_settled_by_one_visit(tmp_path, monkeypatch):
    # Its line was rewritten: a re-test can neither kill nor re-report it,
    # and the pre-push gate is what closes it (`line_departed`). Left owed,
    # every drain would cut an item and pay a baseline to test nothing.
    r, _head2, _, _ = _owing_push(tmp_path, monkeypatch)
    head3 = _commit(r, "calc.py", SRC.replace("x + 1\n", "x + 10\n"))
    assert _pending(r) == [TRIPLE]

    res, calls = _drain(r, _empty_queue_item(head3), monkeypatch)

    assert calls == ["BASE"], "nothing regenerates, so nothing runs"
    assert res.extra["retest_owed"] == []
    assert _pending(r) == []


def test_an_owed_row_that_is_settled_elsewhere_is_no_longer_re_tested(tmp_path, monkeypatch):
    # The debt names ids; whether each is still worth a re-test is the
    # ledger's answer today (open or pending, unsuppressed), not the row's.
    r, _head2, _, _ = _owing_push(tmp_path, monkeypatch)
    assert _pending(r) == [TRIPLE]
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.FINDING_RESOLVED, "op", "2026-09-03T00:00:00+00:00",
                         finding_id=TRIPLE, payload={"auto_resolved": "elsewhere"}))
    finally:
        led.close()

    assert _status(r, TRIPLE) == "fixed"
    assert _pending(r) == []
