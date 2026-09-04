from dataclasses import dataclass, field
from enum import StrEnum

class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
class Verdict(StrEnum):
    BLOCK = "block"
    WARN = "warn"
    INFO = "info"
class Status(StrEnum):
    OPEN = "open"
    FIXED = "fixed"
    OVERRIDDEN = "overridden"
    HISTORICAL = "historical"
    ROTATED = "rotated"
    # S105 justification: this is a StrEnum member name/value for a
    # ledger status, not a credential -- ruff's hardcoded-password heuristic
    # matches the substring "SECRET" in the identifier, nothing else.
    NOT_A_SECRET = "not_a_secret"  # noqa: S105
    UNREACHABLE = "unreachable"
    # The line was REWRITTEN, not repaired: ids hash content, so a rewrite
    # is a new id, and the old one vanishes in the same run a sibling of the
    # same tool/rule/file appears nearby. `fixed` is what this used to read
    # -- at exactly the moment the call was being rewritten (round 135 s3).
    SUPERSEDED = "superseded"
    # Its runner still runs here but no longer EXAMINES this path (a runner
    # whose file scope narrowed -- typecheck to .py/.pyi, round 139), so no
    # run can ever resolve it and `mark-unreachable` rightly refuses. Set
    # only by `ledger resolve --out-of-scope`, which records WHY as its own
    # event kind and refuses while the runner can still examine the path.
    OUT_OF_SCOPE = "out_of_scope"
    # A mutation survivor the gate resolved on INTENT (the push touched its
    # module or a mapped test) and nothing has yet re-tested. Not `fixed`:
    # measured on aramid's own ledger, 21 such resolves and 20 never
    # re-examined, because range-mode mutation only regenerates changed
    # lines and the re-test read `open` rows only. Does not gate; the
    # verified re-test (`mutant_killed`) closes it, a re-detect re-opens it.
    PENDING_RETEST = "pending_retest"
class Gate(StrEnum):
    PRE_COMMIT = "pre-commit"
    PRE_PUSH = "pre-push"
    ALL = "all"
class Source(StrEnum):
    DETERMINISTIC = "deterministic"
    LLM = "llm"
class EventType(StrEnum):
    RUN_STARTED = "run_started"
    RUN_FINISHED = "run_finished"
    FINDING_DETECTED = "finding_detected"
    FINDING_RESOLVED = "finding_resolved"
    FINDING_OVERRIDDEN = "finding_overridden"
    FINDING_ROTATED = "finding_rotated"
    # S105 justification: same as Status.NOT_A_SECRET above -- an
    # EventType member name/value, not a credential.
    FINDING_NOT_A_SECRET = "finding_not_a_secret"  # noqa: S105
    FINDING_UNREACHABLE = "finding_unreachable"
    # A resolution by hand for a path the finding's runner no longer
    # examines. Its own kind rather than a FINDING_RESOLVED with a note:
    # the ledger must be able to tell "a run examined the file and it was
    # clean" from "a person said no run ever will" without reading payloads.
    FINDING_OUT_OF_SCOPE = "finding_out_of_scope"
    # The same finding, at a new line. Its own event type rather than a
    # re-issued FINDING_DETECTED because `_materialize` rebuilds a finding's
    # WHOLE record from a detect payload and resets `status` to open -- so
    # re-detecting on a move would silently un-override every triaged finding
    # whose code shifted. This one touches `line` and nothing else.
    FINDING_MOVED = "finding_moved"
    # An override stopped binding because arming moved its finding to
    # BLOCK tier. Its own event type, and RECORDED rather than computed from
    # config at read time: computed, disarming would silently restore the
    # suppression, because the predicate simply flips back. As an event, the
    # append-only log makes revocation one-way for free -- nothing about
    # disarming emits a counter-event, so re-suppressing costs a NEW decision
    # that the operator has to make and that leaves an artifact.
    FINDING_OVERRIDE_INVALIDATED = "finding_override_invalidated"
    INFRASTRUCTURE_BYPASS = "infrastructure_bypass"
    BASELINE_SNAPSHOT = "baseline_snapshot"

    # --- Phase 2a: triage/queue/drain events (spec section 4) ---
    TRIAGE_RECORDED = "triage_recorded"
    QUEUE_ITEM_ADDED = "queue_item_added"
    QUEUE_ITEM_COALESCED = "queue_item_coalesced"
    QUEUE_ITEM_DRAINED = "queue_item_drained"
    QUEUE_ITEM_EXPIRED = "queue_item_expired"
    # A drain stopped (budget or item limit) with this item still queued.
    # Written by the DRAIN into the starved repo's own ledger; replayed onto
    # `QueueItem.deferred`, which the next drain orders on first (round 177).
    QUEUE_ITEM_DEFERRED = "queue_item_deferred"
    CONSUMER_RUN_FINISHED = "consumer_run_finished"

    # What a resolver SAW, not only what it cleared. Emitted once per
    # invocation -- including the early returns -- so that no event at all
    # means "was never called", which is the only signal that catches a
    # resolver silently switched off upstream. See `ledger.note_yield`.
    RESOLVER_YIELD = "resolver_yield"

@dataclass(frozen=True)
class Finding:
    id: str
    tool: str
    rule: str
    severity_raw: str
    severity: Severity
    verdict: Verdict
    file: str
    line: int
    message: str
    evidence: str
    gate: Gate
    source: Source = Source.DETERMINISTIC
    historical: bool = False
    # Phase 2b: refute-survivor flag (spec section 3). Only ever True for
    # source=LLM findings whose CRITICAL severity survived the refute pass;
    # the pre-push ledger gate blocks on nothing else.
    confirmed: bool = False
    # Auto-learn (autolearn spec section 6): structured refute outcome --
    # True iff apply_refute demoted this finding (critical -> high). The
    # gate reads `confirmed`, never this.
    refuted: bool = False

@dataclass(frozen=True)
class Event:
    type: EventType
    run_id: str
    at: str
    finding_id: str | None = None
    payload: dict = field(default_factory=dict)
