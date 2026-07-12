"""ledger_cmd -- query the findings ledger (`aramid ledger list|show|filter|
mark-rotated`). `mark-rotated` is the only mutating subcommand: it appends a
`finding_rotated` event and requires the target finding's materialized
status be `historical` (design doc section 6 -- rotation only ever applies
to init's full-history secret scan hits; anything else errors rather than
silently no-op'ing)."""
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _render_row(finding_id: str, rec: dict) -> str:
    return (f"[{rec.get('status')}] {finding_id} {rec.get('tool')}:{rec.get('rule')} "
            f"{rec.get('file')}:{rec.get('line')} — {rec.get('message')}")


# ------------------------------------------------------------------- list ---

def cmd_ledger_list(root) -> int:
    root = Path(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        if not state:
            print("aramid: ledger: no findings recorded")
            return 0
        for finding_id, rec in state.items():
            print(_render_row(finding_id, rec))
        return 0
    finally:
        ledger.close()


# ------------------------------------------------------------------- show ---

def cmd_ledger_show(root, finding_id: str) -> int:
    root = Path(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: ledger show: unknown finding id {finding_id}", file=sys.stderr)
            return 3

        print(f"id:       {finding_id}")
        for key in ("tool", "rule", "file", "line", "severity", "verdict", "message",
                    "evidence", "historical", "status"):
            print(f"{key}: {rec.get(key)}")

        print("events:")
        for e in ledger.events():
            if e.finding_id == finding_id:
                print(f"  {e.at}  {e.type.value}  run={e.run_id}")
        return 0
    finally:
        ledger.close()


# ----------------------------------------------------------------- filter ---

def cmd_ledger_filter(root, tool: str | None = None, rule: str | None = None,
                       status: str | None = None, severity: str | None = None) -> int:
    root = Path(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        matched = {
            finding_id: rec for finding_id, rec in state.items()
            if (tool is None or rec.get("tool") == tool)
            and (rule is None or rec.get("rule") == rule)
            and (status is None or rec.get("status") == status)
            and (severity is None or rec.get("severity") == severity)
        }
        if not matched:
            print("aramid: ledger filter: no matching findings")
            return 0
        for finding_id, rec in matched.items():
            print(_render_row(finding_id, rec))
        return 0
    finally:
        ledger.close()


# ----------------------------------------------------------- mark-rotated ---

def cmd_ledger_mark_rotated(root, finding_id: str, reason: str) -> int:
    root = Path(root)
    reason = (reason or "").strip()
    if not reason:
        print("aramid: ledger mark-rotated: --reason is required", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: ledger mark-rotated: unknown finding id {finding_id}",
                  file=sys.stderr)
            return 3
        if rec.get("status") != "historical":
            print(f"aramid: ledger mark-rotated: {finding_id} is not a historical finding "
                  f"(status={rec.get('status')}) -- mark-rotated only applies to historical "
                  f"secrets from init's full-history scan", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_ROTATED, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: ledger: {finding_id} marked rotated ({reason})")
        return 0
    finally:
        ledger.close()
