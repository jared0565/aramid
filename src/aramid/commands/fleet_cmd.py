"""fleet / notices -- the operator's view of the machine-level fleet store
(fleet-readiness spec section 8). `fleet` is a report: exit 0 always, it
has nothing to block. `notices` lists, shows and acks aramid's own notices;
exit 3 only for an id the channel has never seen, with the pending ids
listed so the typo is one line away from the fix.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from aramid import fleet, notices


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def cmd_fleet(as_json: bool = False) -> int:
    """Exit 0 always (spec section 8): a report has nothing to block, so an
    internal failure -- a corrupt verdict, an unreadable policy -- costs one
    stderr line rather than a traceback."""
    try:
        verdict = fleet.read_verdict()
        if as_json:
            print(json.dumps(verdict, indent=2, sort_keys=True))
            return 0
        print(fleet.render_report(verdict, fleet.load_policy(), now=_now()))
        return 0
    except Exception as exc:
        print(f"aramid: fleet: report failed ({exc})", file=sys.stderr)
        return 0


def _unknown(notice_id) -> int:
    ids = ", ".join(n["id"] for n in notices.pending()) or "none"
    print(f"aramid: notices: unknown id {notice_id!r}; pending: {ids}", file=sys.stderr)
    return 3


def cmd_notices(action: str, notice_id: str | None, root) -> int:
    """Exit 0, or 3 for an id the channel has never seen (spec section 8).
    An internal failure -- a corrupt channel, an unreadable registry --
    costs one stderr line and the same exit 3 rather than a traceback."""
    try:
        action = action or "list"
        if action == "list":
            pend = notices.pending()
            if not pend:
                print("no pending fleet notices")
            for n in pend:
                print(f"{n['id']} {n['notice_kind']} {n['title']}")
            return 0
        if action == "show":
            rec = notices.materialize(notices.read_events()).get(notice_id or "")
            if rec is None:
                return _unknown(notice_id)
            n = rec["notice"]
            state = "acked" if rec["acked"] else "cleared" if rec["cleared"] else "pending"
            print(f"{n['id']} {n['notice_kind']} ({n['at']})")
            print(n["title"])
            print()
            print(n["body"])
            print()
            print(f"state: {state}")
            print("evidence: " + json.dumps(n.get("evidence", {}), sort_keys=True))
            return 0
        if action == "ack":
            if notices.ack(notice_id or "", repo=fleet.repo_key(Path(root)), now=_now()):
                print(f"acked {notice_id}")
                return 0
            return _unknown(notice_id)
        print("aramid: notices: a subcommand is required (list|show|ack)", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"aramid: notices: command failed ({exc})", file=sys.stderr)
        return 3
