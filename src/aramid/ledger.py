import json, sqlite3
from pathlib import Path
from aramid.models import Event, EventType, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL, run_id TEXT NOT NULL, at TEXT NOT NULL,
  finding_id TEXT, payload TEXT NOT NULL DEFAULT '{}');
"""


def _detect_payload(f: Finding) -> dict:
    return {"tool": f.tool, "file": f.file, "rule": f.rule, "verdict": str(f.verdict),
            "severity": str(f.severity), "line": f.line, "message": f.message,
            "evidence": f.evidence, "historical": f.historical}


def _materialize(events):
    state: dict[str, dict] = {}
    seen: set[str] = set()
    for e in events:
        if e.type.value == "finding_detected":
            seen.add(e.finding_id)
            state[e.finding_id] = {**e.payload,
                                   "status": "historical" if e.payload.get("historical") else "open"}
        elif e.type.value == "finding_resolved":
            if e.finding_id in state: state[e.finding_id]["status"] = "fixed"
        elif e.type.value == "finding_overridden":
            if e.finding_id in state: state[e.finding_id]["status"] = "overridden"
        elif e.type.value == "finding_rotated":
            if e.finding_id in state: state[e.finding_id]["status"] = "rotated"
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

    def record_run(self, run_id, at, gate, scope_tools, scope_files, findings):
        state, seen = _materialize(self.events())
        present = {f.id for f in findings}
        self.append(Event(EventType.RUN_STARTED, run_id, at,
                          payload={"gate": gate, "tools": sorted(scope_tools)}))
        new_ids = []
        for f in findings:
            if f.id not in state or state[f.id]["status"] in ("fixed",):
                self.append(Event(EventType.FINDING_DETECTED, run_id, at,
                                  finding_id=f.id, payload=_detect_payload(f)))
            if f.id not in seen: new_ids.append(f.id)
        for fid, rec in state.items():
            if rec["status"] == "open" and fid not in present \
               and rec.get("tool") in scope_tools and rec.get("file") in scope_files:
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
        rows = self._c.execute(
            "SELECT seq,type,finding_id FROM events ORDER BY seq").fetchall()

        # Latest FINDING_DETECTED seq per finding — carries the tool/file/payload
        # that _materialize needs to resurrect the finding.
        last_detect: dict[str, int] = {}
        for seq, type_, finding_id in rows:
            if type_ == EventType.FINDING_DETECTED.value and finding_id:
                last_detect[finding_id] = seq

        # Latest terminal transition per finding, but only one that occurred
        # AFTER that finding's latest detect — anything before it would have
        # been overwritten by the re-detect and is redundant.
        terminal_types = {EventType.FINDING_RESOLVED.value,
                           EventType.FINDING_OVERRIDDEN.value,
                           EventType.FINDING_ROTATED.value}
        last_terminal: dict[str, int] = {}
        for seq, type_, finding_id in rows:
            if type_ in terminal_types and finding_id and finding_id in last_detect \
               and seq > last_detect[finding_id]:
                if finding_id not in last_terminal or seq > last_terminal[finding_id]:
                    last_terminal[finding_id] = seq

        keep = set(last_detect.values()) | set(last_terminal.values())
        for seq, type_, finding_id in rows:
            if type_ == EventType.BASELINE_SNAPSHOT.value:
                keep.add(seq)

        to_delete = [seq for seq, _, _ in rows if seq not in keep]
        if to_delete:
            self._c.executemany("DELETE FROM events WHERE seq=?", [(s,) for s in to_delete])
            self._c.commit()
        return len(to_delete)
