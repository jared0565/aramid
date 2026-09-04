# aramid drain: an item left behind by the budget goes first next time

**Date:** 2026-09-04
**Status:** accepted (interop rounds 177/178; committed to graphite-agent in 178)
**Scope:** `commands.drain.cmd_drain`, `queue`, `models.EventType`, `commands.status`, `ledger.compact`, the `drain` CLI help

## 1. The finding

`drain --all` takes one queued item per registered repo, sorts them by score
descending (stable), and pops them in order under ONE drain-wide wall budget
(`max` of the candidates' `[drain].wall_clock_budget_s`, default 600 s) that
is checked only BETWEEN items. An item's consumers carry their own budgets
(mutation alone can run ~25 min), so the first item can spend the whole
drain, and every later item is left queued with a line on a stdout the
scheduler discards.

2026-09-04 10:00Z: aramid's item (score 45, added 09:57Z) tied graphite's
(score 45, added 09:13Z); the stable sort kept registry order (aramid first);
aramid's item took 28.7 min; graphite's was never opened and nothing anywhere
said why (round 177). By 14:00Z aramid's item had coalesced to score 100, so
the same thing would happen again, indefinitely: an active repo starves a
quieter one.

## 2. Design

### 2.1 A deferral is recorded where it happened

When the loop stops on the budget or the item limit, every remaining
candidate gets a `QUEUE_ITEM_DEFERRED` event in ITS OWN repo's ledger:

    Event(QUEUE_ITEM_DEFERRED, run_id, at, finding_id=item.id, payload={
        "reason": "drain budget" | "item limit",
        "after": ["<normalized root of each repo drained this run>"],
        "elapsed_s": <int>, "budget_s": <float>})

The drain already writes to every registered repo's ledger (sweep, expiry,
consumer rows); this is one more row of the same kind. It is written by the
drain process, never by the repo's own gate.

### 2.2 The queue replays it

`QueueItem` gains `deferred: int = 0`. `materialize_queue` counts
`QUEUE_ITEM_DEFERRED` for a queued item (`updated_at` moves too); DRAINED and
EXPIRED end the item as today; COALESCED keeps the count -- the starvation
does not reset because the item absorbed a new head. `ledger.compact` keeps
the new type alongside the other queue types for still-queued items.

### 2.3 Deferred items go first

`candidates.sort(key=lambda c: (-c[2].deferred, -c[0]))`: most-deferred
first, then score as today, still stable. One deferral therefore guarantees
an item is opened by the second scheduled drain after it was queued, unless
two or more repos are starving each other -- then the most-deferred wins,
which is the fair order.

Not done: preempting a running item (a killed mutation run is a wasted
25 minutes and a `degraded` row) or splitting the budget per repo (a 150 s
share cannot run any baseline). The budget stays drain-wide and
between-items; what changes is who gets it next time.

### 2.4 It shows

- `drain --dry-run`: `aramid drain (dry-run): <root> queued=<score>
  deferred=<n>` when `n > 0`.
- `status`'s queue line: `queue: 1 queued (score 45, 3h old, deferred 1x:
  drain budget) | ...` when deferred.
- `drain --help` epilog names the exit codes: 0 every popped item fully
  consumed; 2 a consumer degraded or raised, or a repo could not be probed
  (the rest completed); 3 engine error -- lock held, registry unusable.
  Round 177 asked because `drain --help` said nothing.

## 3. Testing

- Unit (`tests/unit/test_queue.py` or the file that holds
  `materialize_queue` tests): DEFERRED increments `deferred` and moves
  `updated_at`; COALESCED keeps it; DRAINED ends the item.
- Integration (`tests/integration/test_drain.py`, the `seam` +
  `fake_consumer` fixtures): two registered repos with equal-score items and
  `wall_clock_budget_s = 0`; the fake consumer takes long enough that the
  budget is spent after the first item -> the second repo's ledger has a
  DEFERRED row with `reason == "drain budget"` and `after == [first root]`;
  `--dry-run` prints `deferred=1`; a second `cmd_drain` opens the deferred
  repo FIRST (the fake consumer's call order) despite the lower score. Item
  limit (`--max-items 1`) records `"item limit"`.
- Compaction: a DEFERRED row on a queued item survives `compact`.
- CLI: `aramid drain --help` output contains `exit codes`, `2`, `3`.

## 4. Rollout

Ships in the next release (with round 174's three fixes and round 176's
certification). Until then the scheduled drain starves a tied or lower-scored
repo behind an active one; a by-hand `aramid drain --repo .` in the starved
repo pops its item (the singleton lock makes an overlapping scheduled drain
exit 3, so do not overlap the 4-hourly run).
