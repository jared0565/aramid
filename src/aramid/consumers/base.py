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
