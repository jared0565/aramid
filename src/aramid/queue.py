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
                state=prev.state, created_at=prev.created_at, updated_at=e.at)
        elif e.type is EventType.QUEUE_ITEM_DRAINED and e.finding_id in items:
            prev = items[e.finding_id]
            items[e.finding_id] = QueueItem(
                id=prev.id, base=prev.base, head=prev.head, score=prev.score,
                reasons=prev.reasons, state=DRAINED,
                created_at=prev.created_at, updated_at=e.at)
        elif e.type is EventType.QUEUE_ITEM_EXPIRED and e.finding_id in items:
            prev = items[e.finding_id]
            items[e.finding_id] = QueueItem(
                id=prev.id, base=prev.base, head=prev.head, score=prev.score,
                reasons=prev.reasons, state=EXPIRED,
                created_at=prev.created_at, updated_at=e.at)
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


def mark_drained(ledger: Ledger, item_id: str, run_id: str, at: str) -> None:
    ledger.append(Event(EventType.QUEUE_ITEM_DRAINED, run_id, at, finding_id=item_id))


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


def triaged_paths(ledger: Ledger) -> set[str]:
    seen: set[str] = set()
    for e in ledger.events():
        if e.type is EventType.TRIAGE_RECORDED:
            seen.update(e.payload.get("paths", []))
    return seen
