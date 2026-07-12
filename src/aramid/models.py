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

@dataclass(frozen=True)
class Event:
    type: EventType
    run_id: str
    at: str
    finding_id: str | None = None
    payload: dict = field(default_factory=dict)
