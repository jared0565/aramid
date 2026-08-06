import json
import sqlite3
from pathlib import Path
from aramid.models import Event, EventType, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL, run_id TEXT NOT NULL, at TEXT NOT NULL,
  finding_id TEXT, payload TEXT NOT NULL DEFAULT '{}');
"""


def _departed(root: Path | None, file: str | None) -> bool:
    """True when `file` is no longer present in the repo at all.

    OPT-IN BY DESIGN: `root` is None for every caller except the gate, so this
    returns False and behaviour is unchanged for them. That is not tidiness,
    it is a safety requirement -- `commands/init._scan_history` records
    HISTORICAL gitleaks findings from `git log --all`, whose paths are those of
    OLD commits and routinely do not exist at HEAD. Resolving on absence there
    would clear every historical secret the instant it was recorded.

    A path that cannot even be tested (the `<test-suite>` marker is not a legal
    Windows filename) is reported as present, i.e. NOT departed: the gate has
    a dedicated resolver for those, and the safe default here is to leave a
    finding open rather than clear one we could not check.

    CONTAINMENT. `root / file` does not keep you inside root. Measured:

        Path(r'F:\\Projects\\aramid') / 'C:/Windows/win.ini' -> C:\\Windows\\win.ini
        Path(r'F:\\Projects\\aramid') / '/etc/passwd'        -> F:\\etc\\passwd

    An absolute `file` discards root outright and `..` is never normalized
    away, so the check lands on some unrelated path that almost never exists --
    reporting "departed" and silently RESOLVING the finding. A path that was
    never inside the repository cannot have departed it, so an escape returns
    False, which is also the safe direction: the finding stays open.
    """
    if root is None or not file:
        return False
    try:
        base = root.resolve()
        target = (base / file).resolve()
        if not target.is_relative_to(base):
            return False
        return not target.exists()
    except (OSError, ValueError):
        return False


def _detect_payload(f: Finding) -> dict:
    return {"tool": f.tool, "file": f.file, "rule": f.rule, "verdict": str(f.verdict),
            "severity": str(f.severity), "line": f.line, "message": f.message,
            "evidence": f.evidence, "historical": f.historical,
            "source": str(f.source), "confirmed": f.confirmed,
            "refuted": f.refuted}


def _materialize(events):
    state: dict[str, dict] = {}
    seen: set[str] = set()
    for e in events:
        if e.type.value == "finding_detected":
            seen.add(e.finding_id)
            state[e.finding_id] = {**e.payload,
                                   "status": "historical" if e.payload.get("historical") else "open"}
        elif e.type.value == "finding_resolved":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "fixed"
        elif e.type.value == "finding_overridden":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "overridden"
                state[e.finding_id]["reason"] = e.payload.get("reason", "")
        elif e.type.value == "finding_rotated":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "rotated"
        elif e.type.value == "finding_not_a_secret":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "not_a_secret"
                state[e.finding_id]["reason"] = e.payload.get("reason", "")
        elif e.type.value == "finding_unreachable":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "unreachable"
                state[e.finding_id]["reason"] = e.payload.get("reason", "")
    return state, seen


class Ledger:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._c = sqlite3.connect(str(db_path))
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.executescript(_SCHEMA)
        self._c.commit()

    def append(self, event: Event) -> None:
        self._c.execute(
            "INSERT INTO events(type,run_id,at,finding_id,payload) VALUES(?,?,?,?,?)",
            (str(event.type), event.run_id, event.at, event.finding_id,
             json.dumps(event.payload)))
        self._c.commit()

    def events(self) -> list[Event]:
        rows = self._c.execute(
            "SELECT type,run_id,at,finding_id,payload FROM events ORDER BY seq").fetchall()
        return [Event(EventType(t), r, a, fid, json.loads(p)) for t, r, a, fid, p in rows]

    def close(self): self._c.close()

    def open_findings(self) -> dict:
        state, _ = _materialize(self.events())
        return state

    def record_run(self, run_id, at, gate, scope_tools, scope_files, findings, *,
                   selected_tools: set[str] | None = None,
                   root: Path | None = None,
                   examined_by_tool: dict[str, set[str]] | None = None):
        state, seen = _materialize(self.events())
        present = {f.id for f in findings}
        payload = {"gate": gate, "tools": sorted(scope_tools)}
        if selected_tools is not None:
            payload["selected"] = sorted(selected_tools)
        self.append(Event(EventType.RUN_STARTED, run_id, at, payload=payload))
        new_ids = []
        for f in findings:
            if f.id not in state or state[f.id]["status"] in ("fixed", "unreachable"):
                self.append(Event(EventType.FINDING_DETECTED, run_id, at,
                                  finding_id=f.id, payload=_detect_payload(f)))
            if f.id not in seen:
                new_ids.append(f.id)
        for fid, rec in state.items():
            if rec["status"] != "open" or fid in present:
                continue
            if rec.get("tool") not in scope_tools:
                continue
            # `file in <what the tool examined>` is the ordinary route. The
            # second clause exists because every discovery path filters
            # `--diff-filter=ACMR` (gitutil) -- Deleted is excluded, since a
            # gone file cannot be linted -- so a deleted file is NEVER in
            # scope_files and its findings could never resolve. `git rm` a
            # file and its findings stayed open forever; repos accumulated one
            # immortal entry per file they ever deleted. It has to stay ahead
            # of the examination check too: nothing can examine a file that no
            # longer exists, so requiring examination would re-create exactly
            # that bug.
            #
            # EXAMINATION, not mere presence in the run's file set. A runner
            # reports `examined` for the files it can vouch for; absent from
            # the map means "could not report" and falls back to scope_files,
            # which is the pre-2026-08-06 behaviour. An EMPTY set is a
            # positive claim that nothing was looked at, and resolves nothing.
            # Without this, a runner whose own config excluded a file still
            # exited 0, landed in scope_tools, and its findings there were
            # recorded as FIXED -- a false repair written into an append-only
            # audit trail. Measured on ruff `--force-exclude`; the same shape
            # applies to .eslintignore and clippy exclusions.
            tool_scope = (examined_by_tool or {}).get(rec.get("tool"))
            in_scope = (rec.get("file") in scope_files if tool_scope is None
                        else rec.get("file") in tool_scope)
            if in_scope or _departed(root, rec.get("file")):
                self.append(Event(EventType.FINDING_RESOLVED, run_id, at, finding_id=fid))
        self.append(Event(EventType.RUN_FINISHED, run_id, at,
                          payload={"blocking": sum(1 for f in findings if str(f.verdict)=="block")}))
        return new_ids

    def has_baseline(self) -> bool:
        return any(e.type == EventType.BASELINE_SNAPSHOT for e in self.events())

    def write_baseline(self, run_id, at, fingerprints: set[str]) -> None:
        self.append(Event(EventType.BASELINE_SNAPSHOT, run_id, at,
                          payload={"ids": sorted(fingerprints)}))

    def baseline_ids(self) -> set[str]:
        ids: set[str] = set()
        for e in self.events():
            if e.type == EventType.BASELINE_SNAPSHOT:
                ids = set(e.payload.get("ids", []))
        return ids

    def is_new(self, finding_id: str) -> bool:
        _, seen = _materialize(self.events())
        return finding_id not in self.baseline_ids() and finding_id not in seen

    def compact(self) -> int:
        # LANDMINE -- compact() is currently DEAD CODE (no src/ call sites).
        # Wiring it into a command must still coordinate one integration:
        # (1) autolearn.rollup cursors are event COUNTS: compacting shrinks
        #     the list below a stored cursor. rollup now SKIPS the fold on a
        #     shrunk ledger (no double-count) -- but its posteriors are then
        #     stale, so any wiring must rebuild the autolearn state
        #     (`aramid autolearn --rebuild`, cross-repo) in the same operation.
        # (2) give-up history is now preserved: every per-(consumer,item)
        #     CONSUMER_RUN_FINISHED row is kept (below), so
        #     consumers.base.prior_note_count (llm malformed / mutation
        #     baseline-failing counters) survives a compaction intact.
        rows = self._c.execute(
            "SELECT seq,type,finding_id,payload FROM events ORDER BY seq").fetchall()

        # Latest FINDING_DETECTED seq per finding — carries the tool/file/payload
        # that _materialize needs to resurrect the finding.
        last_detect: dict[str, int] = {}
        for seq, type_, finding_id, _payload in rows:
            if type_ == EventType.FINDING_DETECTED.value and finding_id:
                last_detect[finding_id] = seq

        # Latest terminal transition per finding, but only one that occurred
        # AFTER that finding's latest detect — anything before it would have
        # been overwritten by the re-detect and is redundant.
        terminal_types = {EventType.FINDING_RESOLVED.value,
                           EventType.FINDING_OVERRIDDEN.value,
                           EventType.FINDING_ROTATED.value,
                           EventType.FINDING_NOT_A_SECRET.value,
                           EventType.FINDING_UNREACHABLE.value}
        last_terminal: dict[str, int] = {}
        for seq, type_, finding_id, _payload in rows:
            if type_ in terminal_types and finding_id and finding_id in last_detect \
               and seq > last_detect[finding_id]:
                if finding_id not in last_terminal or seq > last_terminal[finding_id]:
                    last_terminal[finding_id] = seq

        keep = set(last_detect.values()) | set(last_terminal.values())
        for seq, type_, finding_id, _payload in rows:
            if type_ == EventType.BASELINE_SNAPSHOT.value:
                keep.add(seq)

        # --- Phase 2a events (spec section 4). Local import: queue.py already
        # imports Ledger from this module; importing at module scope would be
        # circular.
        from aramid.queue import QUEUED, materialize_queue

        full_events = self.events()
        queued_ids = {item.id for item in materialize_queue(full_events).values()
                      if item.state == QUEUED}
        queue_types = {EventType.QUEUE_ITEM_ADDED.value,
                       EventType.QUEUE_ITEM_COALESCED.value,
                       EventType.QUEUE_ITEM_DRAINED.value,
                       EventType.QUEUE_ITEM_EXPIRED.value}
        latest_singleton: dict[str, int] = {}  # type -> newest seq
        for seq, type_, finding_id, _payload in rows:
            if type_ in queue_types and finding_id in queued_ids:
                keep.add(seq)
            if type_ in (EventType.TRIAGE_RECORDED.value,
                         EventType.CONSUMER_RUN_FINISHED.value,
                         EventType.RUN_FINISHED.value):
                latest_singleton[type_] = seq
            if type_ == EventType.CONSUMER_RUN_FINISHED.value:
                # Give-up counters (consumers.base.prior_note_count) read every
                # per-(consumer,item) row, not just the newest -- preserve them
                # all, else llm/mutation give-up history silently resets.
                try:
                    pl = json.loads(_payload)
                except (ValueError, TypeError):
                    pl = {}
                if pl.get("consumer") and pl.get("item_id"):
                    keep.add(seq)
        keep.update(latest_singleton.values())

        to_delete = [seq for seq, _, _, _ in rows if seq not in keep]
        if to_delete:
            self._c.executemany("DELETE FROM events WHERE seq=?", [(s,) for s in to_delete])
            self._c.commit()
        return len(to_delete)
