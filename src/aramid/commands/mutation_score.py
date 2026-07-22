"""mutation-score -- read-only advisory report of per-function mutation
scores and detected regressions (2a). Never mutates the ledger, never runs a
gate. Exit 0 on a readable ledger, 3 on engine error."""
import json
import sys
from pathlib import Path

from aramid import mutation_score as analyzer
from aramid.ledger import Ledger


def cmd_mutation_score(root, *, as_json: bool = False) -> int:
    root = Path(root)
    try:
        ledger = Ledger(root / ".aramid" / "ledger.db")
    except Exception as exc:
        print(f"aramid: mutation-score: engine error: {exc}", file=sys.stderr)
        return 3
    try:
        events = ledger.events()
        scores = analyzer.iter_target_scores(events)
        latest = analyzer.latest_by_target(scores)   # current per-target (spec §6)
        regressions = analyzer.latest_regressions(events)
        if as_json:
            print(json.dumps({
                "targets": [
                    {"target": s.target, "run_index": s.run_index,
                     "killed_s1": s.killed_s1, "survived_s1": s.survived_s1,
                     "rate": s.rate, "fully_mutated": s.fully_mutated}
                    for s in (latest[k] for k in sorted(latest))],
                "regressions": [
                    {"target": r.target, "kind": r.kind, "detail": r.detail,
                     "baseline_index": r.baseline_index,
                     "current_index": r.current_index}
                    for r in regressions]}, indent=2))
            return 0
        if not latest:
            print("aramid mutation-score: no mutation scores recorded")
            return 0
        lines = ["aramid mutation-score:"]
        for target in sorted(latest):
            s = latest[target]
            rate = f"{s.rate:.2f}" if s.rate is not None else "n/a"
            fm = "" if s.fully_mutated else " (partial)"
            lines.append(f"  {target}: kill-rate {rate} "
                         f"({s.killed_s1}/{s.killed_s1 + s.survived_s1}){fm}")
        if regressions:
            lines.append("  regressions:")
            for r in sorted(regressions, key=lambda r: (r.target, r.kind)):
                lines.append(f"    {r.target} [{r.kind}]: {r.detail}")
        else:
            lines.append("  regressions: none")
        print("\n".join(lines))
        return 0
    except Exception as exc:
        print(f"aramid: mutation-score: engine error: {exc}", file=sys.stderr)
        return 3
    finally:
        ledger.close()
