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
