"""notices -- aramid's own channel to the operator (fleet-readiness spec
sections 3.3 and 7). Machine-level, under the fleet store, append-only.

Event-sourced like the ledger: `notice`, `shown`, `ack` and `cleared` events
are only ever appended, and "pending" is materialised from them. A notice's
id is derived from its kind and key, so a condition that is judged again
maps to the SAME id and is deduplicated by construction, and an `ack` in one
repo silences it in every repo -- it followed you; you answered it.
"""
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aramid import fleet

SCHEMA_VERSION = fleet.SCHEMA_VERSION
NOTICES_FILE = "notices.jsonl"
KINDS = ("readiness-reached", "readiness-broken", "fleet-defect")


def notices_path() -> Path:
    return fleet.store_dir() / NOTICES_FILE


def notice_id(kind: str, key: str) -> str:
    return hashlib.sha256(f"{kind}:{key}".encode("utf-8")).hexdigest()[:12]


def _parse(at) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(at))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def read_events(path: Path | None = None) -> list[dict]:
    return fleet._read_jsonl(path if path is not None else notices_path(),
                             required=("kind", "id", "at"))


def append_event(event: dict, path: Path | None = None) -> None:
    fleet.append_line(path if path is not None else notices_path(), event)


def materialize(events: list[dict]) -> dict[str, dict]:
    """id -> {"notice", "acked", "cleared", "shown": {repo: at}}. A `notice`
    event for a known id is a RE-POST (only ever written after a `cleared`,
    see `post`) and starts the record over. Events for unknown ids are
    ignored rather than fatal."""
    out: dict[str, dict] = {}
    for e in events:
        kind, nid = e.get("kind"), str(e.get("id"))
        if kind == "notice":
            out[nid] = {"notice": e, "acked": False, "cleared": False, "shown": {}}
            continue
        rec = out.get(nid)
        if rec is None:
            continue
        if kind == "shown":
            rec["shown"][str(e.get("repo", ""))] = str(e.get("at", ""))
        elif kind == "ack":
            rec["acked"] = True
        elif kind == "cleared":
            rec["cleared"] = True
    return out


def _is_pending(rec: dict) -> bool:
    return not rec["acked"] and not rec["cleared"]


def pending(events: list[dict] | None = None) -> list[dict]:
    recs = materialize(read_events() if events is None else events)
    return sorted((r["notice"] for r in recs.values() if _is_pending(r)),
                  key=lambda n: str(n.get("at", "")))


def pending_count() -> int | None:
    """None when the store cannot be read -- the gate's JSON key has to be
    able to say 'unknown' rather than 'none'."""
    try:
        return len(pending())
    except Exception:
        return None


def post(kind: str, key: str, *, title: str, body: str, evidence: dict,
         now: str) -> str | None:
    """Append a notice unless one with this id is pending OR acked: an ack
    means 'I know', and a condition that persists past it must not nag
    again. Only a `cleared` notice (the condition went away) may re-post,
    because then the condition has genuinely come back."""
    nid = notice_id(kind, key)
    rec = materialize(read_events()).get(nid)
    if rec is not None and not rec["cleared"]:
        return None
    append_event({"schema_version": SCHEMA_VERSION, "kind": "notice", "id": nid,
                  "notice_kind": kind, "key": key, "at": now, "title": title,
                  "body": body, "evidence": evidence})
    return nid


def clear(nid: str, *, reason: str, now: str) -> bool:
    rec = materialize(read_events()).get(nid)
    if rec is None or rec["cleared"]:
        return False
    append_event({"schema_version": SCHEMA_VERSION, "kind": "cleared", "id": nid,
                  "at": now, "reason": reason})
    return True


def ack(nid: str, *, repo: str, now: str) -> bool:
    """Idempotent. False only for an id the channel has never seen."""
    rec = materialize(read_events()).get(nid)
    if rec is None:
        return False
    if not rec["acked"]:
        append_event({"schema_version": SCHEMA_VERSION, "kind": "ack", "id": nid,
                      "at": now, "repo": repo})
    return True


def mark_shown(nid: str, *, repo: str, surface: str, now: str) -> None:
    append_event({"schema_version": SCHEMA_VERSION, "kind": "shown", "id": nid,
                  "at": now, "repo": repo, "surface": surface})


def due(repo: str, now: str, repeat_hours: int, events: list[dict] | None = None) -> list[dict]:
    """Pending notices not shown in `repo` within the last `repeat_hours`."""
    recs = materialize(read_events() if events is None else events)
    now_dt = _parse(now)
    out = []
    for rec in recs.values():
        if not _is_pending(rec):
            continue
        last_dt = _parse(rec["shown"].get(repo)) if repo in rec["shown"] else None
        if (last_dt is not None and now_dt is not None
                and now_dt - last_dt < timedelta(hours=repeat_hours)):
            continue
        out.append(rec["notice"])
    return sorted(out, key=lambda n: str(n.get("at", "")))


def render_line(n: dict) -> str:
    return (f"NOTICE {n['id']} {n['notice_kind']}: {n['title']}"
            f" -- ack: aramid notices ack {n['id']}")
