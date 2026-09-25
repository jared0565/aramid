"""fleet / notices -- the operator's view of the machine-level fleet store
(fleet-readiness spec section 8). `fleet` is a report: exit 0 always, it
has nothing to block. `fleet deregister` removes one repo from the fleet:
exit 0, or 3 when the target names no repo or more than one. `notices`
lists, shows and acks aramid's own notices; exit 3 only for an id the
channel has never seen, with the pending ids listed so the typo is one line
away from the fix.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from aramid import __version__, fleet, notices, registry
from aramid.fingerprint import normalize_path


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


def _matches(entries: list[dict], target: str) -> list[dict]:
    """By path first (as typed, then resolved against the cwd), then by the
    directory name ignoring case -- the name is what `aramid fleet` prints,
    and for a repo that has left the disk it is all there is left to type."""
    wanted = {normalize_path(target), normalize_path(str(Path(target).expanduser().resolve()))}
    by_path = [e for e in entries if normalize_path(e["path"]) in wanted]
    if by_path:
        return by_path
    return [e for e in entries if Path(e["path"]).name.casefold() == target.casefold()]


def cmd_fleet_deregister(target: str) -> int:
    """Remove ONE repo from the fleet (1.0 blocker FN-1). Exit 0 once it is
    gone; 3 when `target` names no registered repo or more than one, or the
    registry cannot be rewritten. Touches only `~/.aramid/repos.toml` -- the
    repo's hooks, aramid.toml and ledger stay, which is what separates this
    from `aramid uninstall` and why it works on a path that no longer
    exists. Keeps the file it rewrote, and re-judges at once so `aramid
    fleet` reads the new membership now rather than after the next drain."""
    try:
        entries = registry.load_registry()
        hits = _matches(entries, target)
        if not hits:
            names = ", ".join(sorted((Path(e["path"]).name for e in entries),
                                     key=str.casefold)) or "none"
            print(f"aramid: fleet deregister: {target!r} is not registered; "
                  f"registered: {names}", file=sys.stderr)
            return 3
        if len(hits) > 1:
            paths = "; ".join(e["path"] for e in hits)
            print(f"aramid: fleet deregister: {target!r} names {len(hits)} registered "
                  f"repos ({paths}) -- pass the full path", file=sys.stderr)
            return 3
        entry = hits[0]
        now = _now()
        stamp = datetime.fromisoformat(now).strftime("%Y%m%dT%H%M%SZ")
        kept = registry.backup(f"{stamp}-deregister")
        registry.remove(entry["path"])
        print(f"aramid fleet: deregistered {Path(entry['path']).name} ({entry['path']})")
        print(f"aramid fleet: previous registry kept at {kept}")
        print("aramid fleet: its hooks, aramid.toml and ledger are untouched "
              "-- `aramid uninstall <path>` reverses onboarding")
        verdict = fleet.run_judgement(now, aramid_version=__version__)
        if verdict is not None:
            print(fleet.readiness_line(verdict, now=now))
        return 0
    except Exception as exc:
        print(f"aramid: fleet deregister: failed ({exc})", file=sys.stderr)
        return 3


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
