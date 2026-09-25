"""resolvers -- grade every auto-resolver on what it SAW, not only on what it
cleared. Read-only: never mutates the ledger, never runs a gate.

Exit codes follow `status`'s contract rather than `check`'s: 0 whether or not
a defect is reported, 3 on an engine error. A dead resolver is a diagnostic
about the gate itself, not a verdict on the code under test, and wiring it to
a non-zero exit would put it on the blocking path -- where a false flag stops
a push and the honest fix is to delete the report. Reports that can block get
disabled; this one has to survive being wrong.
"""
import sys
from pathlib import Path

from aramid import yield_report
from aramid.ledger import Ledger


# The shape version of `resolvers --json` (1.0 blocker API-3).
# Bumped only by a change an existing reader could trip on -- a key removed,
# renamed or retyped; adding a key is not one. Each `--json` document is
# versioned on its own, so one command's change never moves another's.
JSON_SCHEMA_VERSION = 1


def cmd_resolvers(root, as_json: bool = False) -> int:
    root = Path(root)
    try:
        ledger = Ledger(root / ".aramid" / "ledger.db")
    except Exception as exc:
        print(f"aramid: resolvers: engine error: {exc}", file=sys.stderr)
        return 3

    try:
        rows = yield_report.collect(ledger)
        if as_json:
            import json
            # An object, not a bare list (0.19.0): a list has nowhere to
            # carry its own version.
            print(json.dumps({"schema_version": JSON_SCHEMA_VERSION, "resolvers": [
                {"resolver": r.resolver, "tool": r.tool,
                 "runs": r.runs, "considered": r.considered,
                 "resolved": r.resolved, "volume": r.volume,
                 "open_now": r.open_now, "verdict": r.verdict,
                 "flagged": r.flagged} for r in rows]}, indent=2))
        else:
            print(yield_report.render(rows))
        return 0
    except Exception as exc:
        print(f"aramid: resolvers: engine error: {exc}", file=sys.stderr)
        return 3
    finally:
        ledger.close()
