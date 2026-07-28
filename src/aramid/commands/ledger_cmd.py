"""ledger_cmd -- query the findings ledger (`aramid ledger list|show|filter|
mark-rotated|mark-not-a-secret|mark-unreachable`). `mark-rotated`,
`mark-not-a-secret`, and `mark-unreachable` are the three mutating
subcommands: `mark-rotated` appends a `finding_rotated` event and requires
the target finding's materialized status be `historical` OR `not_a_secret`
(design doc section 6 -- rotation applies to init's full-history secret
scan hits, and also to a finding previously marked not-a-secret that
turned out to be a real credential after all). `mark-not-a-secret` appends
a `finding_not_a_secret` event and requires status be EXACTLY `historical`
-- a live (`open`) finding has its own suppression paths, and a `rotated`
finding is a safety assertion that is never downgraded. `mark-unreachable`
(T-8) appends a `finding_unreachable` event and requires status be EXACTLY
`open` AND the finding's tool be in `aramid.toolset.RUNNER_TOOL_NAMES` but
NOT in `aramid.toolset.selected_tool_names(root, cfg)` -- a finding whose
tool has left this repo's live selection (de-selected, disabled, or
genuinely removed), so no future run can ever resolve it the normal way.
All three guards error rather than silently no-op'ing; transitions only
ever move toward more caution, and there is no un-mark."""
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import toolset
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
                    "evidence", "historical", "status", "reason"):
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
        status = rec.get("status")
        if status not in ("historical", "not_a_secret"):
            print(f"aramid: ledger mark-rotated: {finding_id} is not a historical or "
                  f"not-a-secret finding (status={status}) -- mark-rotated only applies "
                  f"to historical secrets from init's full-history scan, or to a finding "
                  f"already marked not-a-secret", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_ROTATED, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: ledger: {finding_id} marked rotated ({reason})")
        return 0
    finally:
        ledger.close()


# --------------------------------------------------- mark-not-a-secret ---

def cmd_ledger_mark_not_a_secret(root, finding_id: str, reason: str) -> int:
    root = Path(root)
    reason = (reason or "").strip()
    if not reason:
        print("aramid: ledger mark-not-a-secret: --reason is required", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: ledger mark-not-a-secret: unknown finding id {finding_id}",
                  file=sys.stderr)
            return 3
        status = rec.get("status")
        if status != "historical":
            if status == "open":
                tail = ("mark-not-a-secret only applies to historical secrets from "
                         "init's full-history scan. For a live BLOCK finding use a "
                         "committed .aramid-suppressions.toml entry; for a WARN use "
                         "`aramid override`.")
            elif status == "not_a_secret":
                tail = "already marked not-a-secret."
            elif status == "rotated":
                tail = ("already retired by rotation. A rotated finding is never "
                         "downgraded to not-a-secret.")
            else:
                tail = ("mark-not-a-secret only applies to historical secrets from "
                         "init's full-history scan.")
            print(f"aramid: ledger mark-not-a-secret: {finding_id} is not a historical "
                  f"finding (status={status}) -- {tail}", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_NOT_A_SECRET, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: ledger: {finding_id} marked not-a-secret ({reason})")
        return 0
    finally:
        ledger.close()


# ------------------------------------------------------- mark-unreachable ---

def cmd_ledger_mark_unreachable(root, finding_id: str, reason: str) -> int:
    root = Path(root)
    reason = (reason or "").strip()
    if not reason:
        print("aramid: ledger mark-unreachable: --reason is required", file=sys.stderr)
        return 3

    try:
        cfg = config_mod.load_config(root)
    except Exception as exc:
        print(f"aramid: ledger mark-unreachable: engine error: {exc}", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: ledger mark-unreachable: unknown finding id {finding_id}",
                  file=sys.stderr)
            return 3

        tool = rec.get("tool")
        if tool not in toolset.RUNNER_TOOL_NAMES:
            print(f"aramid: ledger mark-unreachable: {finding_id} is a {tool!r} finding "
                  f"-- producer/consumer findings (tdd, red-proof, mutation, "
                  f"mutation-score, llm-review, js-mutation, fuzz, dast) resolve "
                  f"through their own producer's mechanism, never by hand",
                  file=sys.stderr)
            return 3

        status = rec.get("status")
        if status != "open":
            tails = {
                "unreachable": "already marked unreachable.",
                "fixed": "already fixed -- nothing to retire.",
                "historical": "a historical secret -- use `aramid ledger mark-rotated` "
                              "or `mark-not-a-secret` instead.",
                "overridden": "already overridden.",
                "rotated": "already retired by rotation.",
                "not_a_secret": "already marked not-a-secret.",
            }
            tail = tails.get(status, "mark-unreachable only applies to an open finding.")
            print(f"aramid: ledger mark-unreachable: {finding_id} is not open "
                  f"(status={status}) -- {tail}", file=sys.stderr)
            return 3

        selected = toolset.selected_tool_names(root, cfg)
        if tool in selected:
            print(f"aramid: ledger mark-unreachable: {finding_id}'s tool ({tool}) still "
                  f"runs in this repo -- not a ghost. If it fails every run, that is "
                  f"`aramid doctor`'s problem, not mark-unreachable's", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_UNREACHABLE, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: ledger: {finding_id} marked unreachable ({reason})")
        return 0
    finally:
        ledger.close()
