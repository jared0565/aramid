"""queue -- risk-scored review queue, materialized from ledger events.

Same event-sourcing discipline as Phase 1: events are appended, never
mutated; queue state is replayed by materialize_queue(). Queue events
reuse the ledger's finding_id column to carry the queue item id (it is
a plain indexed TEXT column). Invariant (spec section 4): at most one
"queued" item exists per repo ledger at any time -- enqueue() coalesces
into it (base kept, head advances, score = max, reasons union).
"""
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from aramid.ledger import Ledger
from aramid.models import Event, EventType

QUEUED = "queued"
DRAINED = "drained"
EXPIRED = "expired"

# The reason prefix of an item the DRAIN synthesizes for a repo whose queue is
# empty while `pending_retest` mutation survivors wait: the drain writes it,
# the mutation consumer reads it (`is_pending_retest_item`), nothing else
# parses it. One constant, so the two sides cannot drift apart.
PENDING_RETEST_REASON = "pending-retest"


def pending_retest_reason(pending: int) -> str:
    return (f"{PENDING_RETEST_REASON}: {pending} mutation survivor(s) awaiting a "
            "verified re-test; the queue was empty")


def is_pending_retest_item(item) -> bool:
    """True for an item the drain synthesized to re-test pending survivors:
    its range is empty (base == head) and only the re-test pass has work."""
    return any(str(r).startswith(PENDING_RETEST_REASON + ":")
               for r in (getattr(item, "reasons", None) or ()))


@dataclass(frozen=True)
class QueueItem:
    id: str
    base: str | None
    head: str
    score: int
    reasons: tuple[str, ...]
    state: str
    created_at: str
    updated_at: str
    # How many drains stopped with this item still queued, and why the last
    # one did ("drain budget" / "item limit"). A coalesce keeps the count --
    # absorbing a new head does not end the starvation -- and the next drain
    # opens the most-deferred item FIRST, regardless of score (round 177:
    # an active repo's item spent the drain-wide budget and a tied, quieter
    # repo's item was never opened, with nothing anywhere saying why).
    deferred: int = 0
    deferred_reason: str | None = None

    @property
    def range_str(self) -> str:
        return f"{self.base}..{self.head}" if self.base else self.head


def materialize_queue(events: list[Event]) -> dict[str, QueueItem]:
    items: dict[str, QueueItem] = {}
    for e in events:
        if e.type is EventType.QUEUE_ITEM_ADDED:
            items[e.finding_id] = QueueItem(
                id=e.finding_id, base=e.payload.get("base"), head=e.payload["head"],
                score=e.payload["score"], reasons=tuple(e.payload.get("reasons", [])),
                state=QUEUED, created_at=e.at, updated_at=e.at)
        elif e.type is EventType.QUEUE_ITEM_COALESCED and e.finding_id in items:
            prev = items[e.finding_id]
            items[e.finding_id] = QueueItem(
                id=prev.id, base=e.payload.get("base"), head=e.payload["head"],
                score=e.payload["score"], reasons=tuple(e.payload.get("reasons", [])),
                state=prev.state, created_at=prev.created_at, updated_at=e.at,
                deferred=prev.deferred, deferred_reason=prev.deferred_reason)
        elif e.type is EventType.QUEUE_ITEM_DEFERRED and e.finding_id in items:
            prev = items[e.finding_id]
            items[e.finding_id] = QueueItem(
                id=prev.id, base=prev.base, head=prev.head, score=prev.score,
                reasons=prev.reasons, state=prev.state,
                created_at=prev.created_at, updated_at=e.at,
                deferred=prev.deferred + 1,
                deferred_reason=e.payload.get("reason") or prev.deferred_reason)
        elif e.type is EventType.QUEUE_ITEM_DRAINED and e.finding_id in items:
            prev = items[e.finding_id]
            consumed = e.payload.get("head")
            if consumed is not None and consumed != prev.head:
                # The drain popped this item at `consumed` and ran for a
                # while; a commit made meanwhile coalesced into the SAME id
                # (base kept, head advanced). Marking the id drained used to
                # swallow that absorbed range -- never graded, and the
                # catch-up sweep, anchored past it, never re-triaged it
                # (2026-09-06). What the drain did not consume stays queued
                # as its own remainder, freshly so: no drain passed it over.
                items[e.finding_id] = QueueItem(
                    id=prev.id, base=consumed, head=prev.head, score=prev.score,
                    reasons=prev.reasons, state=QUEUED,
                    created_at=prev.created_at, updated_at=e.at)
                continue
            items[e.finding_id] = QueueItem(
                id=prev.id, base=prev.base, head=prev.head, score=prev.score,
                reasons=prev.reasons, state=DRAINED,
                created_at=prev.created_at, updated_at=e.at,
                deferred=prev.deferred, deferred_reason=prev.deferred_reason)
        elif e.type is EventType.QUEUE_ITEM_EXPIRED and e.finding_id in items:
            prev = items[e.finding_id]
            items[e.finding_id] = QueueItem(
                id=prev.id, base=prev.base, head=prev.head, score=prev.score,
                reasons=prev.reasons, state=EXPIRED,
                created_at=prev.created_at, updated_at=e.at,
                deferred=prev.deferred, deferred_reason=prev.deferred_reason)
    return items


def queued_item(items: dict[str, QueueItem]) -> QueueItem | None:
    for item in items.values():
        if item.state == QUEUED:
            return item
    return None


def enqueue(ledger: Ledger, at: str, base: str | None, head: str,
            score: int, reasons: list[str]) -> QueueItem:
    existing = queued_item(materialize_queue(ledger.events()))
    if existing is not None:
        merged_reasons = sorted(set(existing.reasons) | set(reasons))
        payload = {"absorbed": f"{base}..{head}" if base else head,
                   "base": existing.base, "head": head,
                   "score": max(existing.score, score), "reasons": merged_reasons}
        ledger.append(Event(EventType.QUEUE_ITEM_COALESCED, uuid.uuid4().hex, at,
                            finding_id=existing.id, payload=payload))
        return QueueItem(id=existing.id, base=existing.base, head=head,
                         score=max(existing.score, score),
                         reasons=tuple(merged_reasons), state=QUEUED,
                         created_at=existing.created_at, updated_at=at)
    item_id = uuid.uuid4().hex
    payload = {"base": base, "head": head, "score": score,
               "reasons": sorted(set(reasons))}
    ledger.append(Event(EventType.QUEUE_ITEM_ADDED, uuid.uuid4().hex, at,
                        finding_id=item_id, payload=payload))
    return QueueItem(id=item_id, base=base, head=head, score=score,
                     reasons=tuple(sorted(set(reasons))), state=QUEUED,
                     created_at=at, updated_at=at)


def mark_drained(ledger: Ledger, item_id: str, run_id: str, at: str, *,
                 head: str | None = None) -> None:
    """`head` is the head the drain actually consumed. A coalesce that landed
    while it ran advanced the item past it; `materialize_queue` keeps that
    remainder queued. Without `head` (older rows, tests) the whole item is
    drained, whatever it holds."""
    payload = {"head": head} if head is not None else {}
    ledger.append(Event(EventType.QUEUE_ITEM_DRAINED, run_id, at, finding_id=item_id,
                        payload=payload))


def mark_deferred(ledger: Ledger, item_id: str, run_id: str, at: str, *,
                  reason: str, after: list, elapsed_s: int, budget_s: float) -> None:
    """Record that a drain stopped with this item still queued.

    Written by the drain (`run_id` is the drain's) into THIS repo's ledger:
    `reason` is "drain budget" or "item limit", `after` the normalized roots
    the drain did open this run, `elapsed_s` / `budget_s` the numbers that
    stopped it. `status` and `drain --dry-run` render it; the next drain
    orders on `QueueItem.deferred` first (round 177)."""
    ledger.append(Event(EventType.QUEUE_ITEM_DEFERRED, run_id, at, finding_id=item_id,
                        payload={"reason": reason, "after": list(after),
                                 "elapsed_s": int(elapsed_s), "budget_s": float(budget_s)}))


def expire_stale(ledger: Ledger, now_iso: str, expiry_days: int) -> list[str]:
    now = datetime.fromisoformat(now_iso)
    expired: list[str] = []
    for item in materialize_queue(ledger.events()).values():
        if item.state != QUEUED:
            continue
        created = datetime.fromisoformat(item.created_at)
        if now - created > timedelta(days=expiry_days):
            age = (now - created).days
            ledger.append(Event(EventType.QUEUE_ITEM_EXPIRED, uuid.uuid4().hex, now_iso,
                                finding_id=item.id, payload={"age_days": age}))
            expired.append(item.id)
    return expired


def record_triage(ledger: Ledger, at: str, base: str | None, head: str,
                  score: int, queued: bool, paths: list[str]) -> None:
    ledger.append(Event(EventType.TRIAGE_RECORDED, uuid.uuid4().hex, at,
                        payload={"base": base, "head": head, "score": score,
                                 "queued": queued, "paths": sorted(paths)}))


def last_triaged_head(ledger: Ledger) -> str | None:
    head = None
    for e in ledger.events():
        if e.type is EventType.TRIAGE_RECORDED:
            head = e.payload.get("head")
    return head


def triaged_heads_newest_first(ledger: Ledger, limit: int = 50) -> list[str]:
    """The heads of the newest `limit` triage rows, newest first, for the
    drain sweep's ancestry-aware anchor (commands.drain._sweep_anchor)."""
    heads: list[str] = []
    for e in reversed(ledger.events()):
        if e.type is EventType.TRIAGE_RECORDED and e.payload.get("head"):
            heads.append(e.payload["head"])
            if len(heads) >= limit:
                break
    return heads


def triaged_paths(ledger: Ledger) -> set[str]:
    seen: set[str] = set()
    for e in ledger.events():
        if e.type is EventType.TRIAGE_RECORDED:
            seen.update(e.payload.get("paths", []))
    return seen
