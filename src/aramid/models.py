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
    INFRASTRUCTURE_BYPASS = "infrastructure_bypass"
    BASELINE_SNAPSHOT = "baseline_snapshot"

    # --- Phase 2a: triage/queue/drain events (spec section 4) ---
    TRIAGE_RECORDED = "triage_recorded"
    QUEUE_ITEM_ADDED = "queue_item_added"
    QUEUE_ITEM_COALESCED = "queue_item_coalesced"
    QUEUE_ITEM_DRAINED = "queue_item_drained"
    QUEUE_ITEM_EXPIRED = "queue_item_expired"
    CONSUMER_RUN_FINISHED = "consumer_run_finished"

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

@dataclass(frozen=True)
class Event:
    type: EventType
    run_id: str
    at: str
    finding_id: str | None = None
    payload: dict = field(default_factory=dict)
