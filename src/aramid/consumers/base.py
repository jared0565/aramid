"""Consumer protocol (spec section 2): a consumer is a module exposing
NAME: str and consume(item: QueueItem, ctx: DrainContext) -> ConsumerResult.
Mirrors runners/: the drain iterates CONSUMERS like the pipeline iterates
RUNNERS. ConsumerResult.cost is the Phase 4 metering slot -- every 2a
consumer writes 0.0 (zero tokens by construction)."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from aramid.models import EventType

OK = "ok"
DEGRADED = "degraded"
ERROR = "error"


@dataclass
class DrainContext:
    root: Path
    cfg: object
    ledger: object
    clock: Callable[[], str]


@dataclass
class Repaired:
    """A producer's POSITIVE claim that specific finding identities are fixed.

    Not "I ran and didn't re-report it" -- the drain refuses that inference on
    purpose (`_consume_item` passes empty scopes, because a narrow ruleset
    re-reporting nothing proves nothing). This is the other direction: the
    consumer re-derived these exact fingerprints and DISPROVED them. Mutation
    re-mutates the same line with the same operator and the suite kills it.

    `tool` is the string the FINDINGS carry, which is not always the consumer's
    NAME -- `js_mutation` emits `tool="js-mutation"`. Getting that wrong makes
    the claim a silent no-op, so it is stated rather than inferred.
    `reason` lands in the ledger as `auto_resolved`, so it must read as a cause
    ("mutant_killed"), not as a restatement of the outcome.
    """
    tool: str
    reason: str
    ids: tuple = ()


@dataclass
class ConsumerResult:
    consumer: str
    state: str
    findings: list = field(default_factory=list)
    duration_s: float = 0.0
    cost: float = 0.0
    note: str = ""
    # Absent by default: a consumer that says nothing resolves nothing, which
    # is what keeps this opt-in per producer rather than a global rule.
    repaired: Repaired | None = None
    # Auto-learn (autolearn spec section 6): structured payload merged into
    # the CONSUMER_RUN_FINISHED event by the drain (setdefault -- core keys
    # always win). llm_review puts its `selection` telemetry dict here.
    extra: dict = field(default_factory=dict)


CONSUMERS: dict[str, object] = {}  # populated by consumer modules (Task 16)


def open_findings_for(ledger, tool: str) -> dict:
    """This producer's currently-OPEN findings, keyed by id.

    Read for one reason: to know which of a run's conclusions are
    LOAD-BEARING. A producer re-deriving an identity that matches nothing open
    changes no state, so it needs no confirmation and costs nothing -- which is
    almost every identity, and is what keeps repair-proving affordable.

    `tool` is the string the FINDINGS carry, which is not always the consumer's
    NAME: `js_mutation` emits `tool="js-mutation"`. Passing NAME here would
    silently match nothing and report success doing it, so every caller states
    it.

    Never raises: an unreadable ledger yields an empty map -- no claims, which
    is the safe direction.
    """
    try:
        return {fid: rec for fid, rec in ledger.open_findings().items()
                if rec.get("tool") == tool and rec.get("status") == "open"}
    except Exception:
        return {}


def prior_note_count(ledger, consumer: str, item_id: str, prefix: str) -> int:
    """How many CONSUMER_RUN_FINISHED events this consumer has already
    recorded for this queue item with a note starting with `prefix`.
    Give-up counters (llm_review malformed, mutation baseline-failing) key
    on this -- the note strings involved are load-bearing."""
    n = 0
    for e in ledger.events():
        if (e.type is EventType.CONSUMER_RUN_FINISHED
                and e.payload.get("consumer") == consumer
                and e.payload.get("item_id") == item_id
                and str(e.payload.get("note", "")).startswith(prefix)):
            n += 1
    return n


def note_count_any_item(ledger, consumer: str, prefix: str) -> int:
    """Like `prior_note_count`, but across EVERY queue item.

    For conditions that belong to the REPOSITORY rather than to a commit
    range. `prior_note_count` cannot express one: it filters on `item_id`, and
    a give-up that returns `ok` lets the drain mark the item drained -- so the
    next drain arrives with a fresh id and a count of zero. Combined with a
    prefix carrying `item.head`, a per-item counter has two independent reset
    paths and latches only by coincidence. Measured downstream: one give-up
    event recorded, then the same ~8-minute run resumed every 4 hours for
    three days.

    A caller using this is asserting the condition cannot be fixed by new
    commits, so it MUST put its own release valve in the prefix -- mutation
    keys on (suite command, budget), the two things an operator can change.
    Without that this is a one-way door.
    """
    n = 0
    for e in ledger.events():
        if (e.type is EventType.CONSUMER_RUN_FINISHED
                and e.payload.get("consumer") == consumer
                and str(e.payload.get("note", "")).startswith(prefix)):
            n += 1
    return n
