# Drain Aging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An item the drain left behind on its budget is recorded as deferred in its own repo's ledger, is visible in `drain --dry-run` and `status`, and is opened FIRST by the next drain regardless of score; `drain --help` names the exit codes.

**Architecture:** One new ledger event (`QUEUE_ITEM_DEFERRED`) written by `cmd_drain` for every candidate left when the loop stops; `queue.materialize_queue` replays it into `QueueItem.deferred` / `deferred_reason`; `cmd_drain` sorts candidates by `(-deferred, -score)`; `ledger.compact` keeps the type for queued items; `status` and the dry-run line render it.

**Tech Stack:** Python stdlib; pytest with the `seam` + fake-consumer fixtures of `tests/integration/test_drain.py`; a scripted `monotonic` for deterministic budget stops.

**Spec:** `docs/superpowers/specs/2026-09-04-aramid-drain-aging-design.md`

## Global Constraints

1. The drain never raises out of the deferral write: a ledger that cannot take the row prints to stderr and sets `degraded`, like every other per-repo failure in `cmd_drain`.
2. The budget stays drain-wide and between-items (spec 2.3). No preemption.
3. Tests: `python -m pytest <path> -q -p no:cacheprovider`; never `pip install -e .`.
4. Every commit: `python -P -m aramid check --staged`, then `python -P -m aramid ledger filter --status open`; `git commit -F`, trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` + `Claude-Session: https://claude.ai/code/session_01Swr1yPAqMtUnH36YVhune9`; never `--no-verify`.
5. Heredocs mangle backslashes: Write/Edit tools for source.

---

### Task 1: the event and the queue

**Files:** Modify `src/aramid/models.py` (`EventType.QUEUE_ITEM_DEFERRED = "queue_item_deferred"`), `src/aramid/queue.py` (`QueueItem.deferred: int = 0`, `deferred_reason: str | None = None`; `materialize_queue` branch; `mark_deferred(ledger, item_id, run_id, at, *, reason, after, elapsed_s, budget_s)`), `src/aramid/ledger.py` (`queue_types` in `compact` gains the value); Test `tests/unit/test_queue.py`, `tests/unit/test_ledger_compact.py`.

- [ ] Step 1: tests.
```python
def test_deferred_event_type_exists():
    assert EventType.QUEUE_ITEM_DEFERRED.value == "queue_item_deferred"


def test_deferral_counts_survives_coalesce_and_ends_on_drain(tmp_path):
    led = Ledger(tmp_path / "l.db")
    item = queue.enqueue(led, _iso(NOW), "aaa1111", "bbb2222", 45, ["r"])
    assert queue.materialize_queue(led.events())[item.id].deferred == 0
    queue.mark_deferred(led, item.id, "run1", _iso(NOW + timedelta(hours=4)),
                        reason="drain budget", after=["F:/other"], elapsed_s=1723, budget_s=600.0)
    got = queue.materialize_queue(led.events())[item.id]
    assert (got.deferred, got.deferred_reason, got.state) == (1, "drain budget", "queued")
    assert got.updated_at == _iso(NOW + timedelta(hours=4))
    ev = [e for e in led.events() if e.type is EventType.QUEUE_ITEM_DEFERRED][0]
    assert ev.finding_id == item.id
    assert ev.payload == {"reason": "drain budget", "after": ["F:/other"],
                          "elapsed_s": 1723, "budget_s": 600.0}
    queue.enqueue(led, _iso(NOW + timedelta(hours=5)), "bbb2222", "ccc3333", 90, ["r2"])
    assert queue.materialize_queue(led.events())[item.id].deferred == 1   # coalesce keeps it
    queue.mark_drained(led, item.id, "run2", _iso(NOW + timedelta(hours=8)))
    assert queue.materialize_queue(led.events())[item.id].state == "drained"
    led.close()
```
And in `test_ledger_compact.py`: enqueue, `mark_deferred`, `compact()`, materialize -> `deferred == 1`.
- [ ] Step 2: red (`AttributeError: QUEUE_ITEM_DEFERRED`). Step 3: implement. Step 4: green + `tests/unit/test_queue*.py tests/unit/test_ledger_compact.py tests/integration/test_drain.py`. Gate, commit `feat(queue): a deferred item remembers it -- QUEUE_ITEM_DEFERRED, replayed into QueueItem.deferred`.

### Task 2: the drain defers, orders, and shows

**Files:** Modify `src/aramid/commands/drain.py` (deferral write on the stop; sort key; dry-run line), `src/aramid/commands/status.py` (`_queue_lines`), `src/aramid/cli.py` (drain parser `description`/`epilog` with exit codes); Test `tests/integration/test_drain.py`, `tests/integration/test_status.py`, `tests/unit/test_cli*.py` (whichever builds the parser).

- [ ] Step 1: tests (test_drain.py):
```python
def _ticks(*values):
    """A scripted clock for `cmd_drain(monotonic=...)` (already a keyword
    parameter): `started`, then one value per between-items check."""
    it = iter(values)
    return lambda: next(it)
# and every call below passes it: cmd_drain([], dry_run=False, monotonic=_ticks(0.0, 0.0, 10_000.0))
# The `--help` test: `with pytest.raises(SystemExit): cli.main(["drain", "--help"])` then
# `assert "exit codes" in capsys.readouterr().out`.


def _head(r):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, check=True,
                          capture_output=True, text=True).stdout.strip()


def test_budget_stop_defers_the_left_items_in_their_own_ledgers(tmp_path, seam, fake_consumer, monkeypatch):
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")
    _ticks(monkeypatch, 0.0, 0.0, 10_000.0)      # started; r1 opens; r2 sees the budget gone

    assert cmd_drain([], dry_run=False) == 0

    assert [c.head for c in fake_consumer.calls] == [_head(r1)]     # equal scores, registry order
    led = Ledger(r2 / ".aramid" / "ledger.db")
    try:
        ev = [e for e in led.events() if e.type is EventType.QUEUE_ITEM_DEFERRED]
        item = queue.queued_item(queue.materialize_queue(led.events()))
    finally:
        led.close()
    assert len(ev) == 1 and ev[0].finding_id == item.id
    assert ev[0].payload["reason"] == "drain budget"
    assert ev[0].payload["after"] == [normalize_path(str(r1))]
    assert ev[0].payload["budget_s"] == 600.0 and ev[0].payload["elapsed_s"] == 10000
    assert item.deferred == 1
    led1 = Ledger(r1 / ".aramid" / "ledger.db")
    try:
        assert not any(e.type is EventType.QUEUE_ITEM_DEFERRED for e in led1.events())
    finally:
        led1.close()


def test_a_deferred_item_is_opened_first_next_time(tmp_path, seam, fake_consumer, monkeypatch):
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")
    _ticks(monkeypatch, 0.0, 0.0, 10_000.0)
    cmd_drain([], dry_run=False)                       # r1 drained, r2 deferred
    _commit(r1, "src/auth_login2.py", "def g(x):\n    exec(x)\n", "risky again")   # r1 re-queues at >= r2's score
    fake_consumer.calls = []
    monkeypatch.setattr(drain_mod, "monotonic", lambda: 0.0)

    cmd_drain([], dry_run=False)

    assert [c.head for c in fake_consumer.calls][0] == _head(r2), "the deferred item goes first"
    assert len(fake_consumer.calls) == 2


def test_item_limit_defers_with_its_own_reason(tmp_path, seam, fake_consumer):
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")
    cmd_drain([], dry_run=False, max_items=1)
    led = Ledger(r2 / ".aramid" / "ledger.db")
    try:
        ev = [e for e in led.events() if e.type is EventType.QUEUE_ITEM_DEFERRED]
    finally:
        led.close()
    assert ev and ev[0].payload["reason"] == "item limit"


def test_dry_run_names_the_deferral(tmp_path, seam, fake_consumer, monkeypatch, capsys):
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")
    _ticks(monkeypatch, 0.0, 0.0, 10_000.0)
    cmd_drain([], dry_run=False)
    capsys.readouterr()
    cmd_drain([], dry_run=True)
    out = capsys.readouterr().out
    assert "queued=45 deferred=1" in out or "deferred=1" in out, out
```
(status: in `tests/integration/test_status.py`, enqueue + `mark_deferred` on a scratch repo, `cmd_status` output contains `deferred 1x: drain budget`. CLI: the parser's `drain --help` text contains `exit codes` -- locate the parser builder in `src/aramid/cli.py` and the existing CLI tests' pattern first.)
- [ ] Step 2: red. Step 3: implement:
  - `drain.py`: keep `run_id = uuid.uuid4().hex` per drain and `drained_roots: list[str]`; replace the `break` block with: record the stop reason (`"item limit"` if `drained >= limit` else `"drain budget"`), then for each remaining candidate `queue.mark_deferred(Ledger(...), item.id, run_id, clock(), reason=..., after=drained_roots, elapsed_s=int(elapsed), budget_s=budget_s)` inside try/except -> stderr + `degraded = True`; `candidates.sort(key=lambda c: (-c[2].deferred, -c[0]))`; dry-run print appends ` deferred={item.deferred}` when > 0; `drained_roots.append(normalize_path(str(root)))` after each consume.
  - `status.py`: `f"queue: {n} queued (score {q.score}, {age_h}h old{', deferred ' + str(q.deferred) + 'x: ' + q.deferred_reason if q.deferred else ''}) | ..."`.
  - `cli.py`: `sub.add_parser("drain", help=..., description="...", epilog="exit codes: 0 every popped item fully consumed; 2 a consumer degraded or raised, or a repo could not be probed (the rest completed); 3 engine error -- another drain holds the lock, or the registry is unusable.")`.
- [ ] Step 4: green + `tests/integration/test_drain*.py tests/integration/test_status.py tests/unit/test_cli*.py`. Gate, commit `feat(drain): an item left behind on the budget is deferred in its own ledger and opened first next time (round 177)`.

### Task 3: docs

- [ ] `docs/user-guide.md` section 7 "The scheduled drain": the budget is drain-wide and between items; deferral, ordering, the dry-run/status surfaces, exit codes. `CHANGELOG.md` Unreleased: Added (deferral + ordering + help) / Fixed (starvation). Gate, commit `docs: drain aging`.
