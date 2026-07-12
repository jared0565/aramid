"""override -- ledger-logged WARN suppression (design doc section 6, "two
tiers"). A BLOCK-tier finding cannot be suppressed here at all: enforcement
requires a reviewed, committed entry in `.aramid-suppressions.toml`
instead, visible in diff review with a reason -- this command actively
refuses and says so rather than silently no-op'ing.

KNOWN GAP (pre-existing, already flagged in .superpowers/sdd/progress.md's
Task 5.3 cross-task note; out of scope for this milestone):
`Ledger._materialize` does not fold a `finding_overridden` event's payload
(including this command's `--reason`) back into materialized state, so
`aramid.pipeline._overrides_from_ledger` currently always reads `reason=""`
for a ledger-sourced override regardless of what was passed here. The
reason IS durably recorded in the raw event stream (`aramid ledger show
<id>` surfaces it via the payload) -- only the *materialized* convenience
view drops it. Not fixed here: ledger.py/pipeline.py are already-built and
tested (M3/M5) modules outside M7's "thin CLI wrapper" scope.
"""
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def cmd_override(root, finding_id: str, reason: str) -> int:
    root = Path(root)
    reason = (reason or "").strip()
    if not reason:
        print("aramid: override: --reason is required", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: override: unknown finding id {finding_id}", file=sys.stderr)
            return 3

        if rec.get("verdict") == "block":
            print(f"aramid: override: {finding_id} is a BLOCK-tier finding -- a local "
                  f"override is not permitted; add a reasoned entry to "
                  f".aramid-suppressions.toml instead (design doc section 6)", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: override: {finding_id} overridden ({reason})")
        return 0
    finally:
        ledger.close()
