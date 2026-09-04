"""mutation-score -- read-only advisory report of per-function mutation
scores and detected regressions (2a). Never mutates the ledger, never runs a
gate. Exit 0 on a readable ledger, 3 on engine error."""
import json
import sys
from pathlib import Path

from aramid import config as config_mod
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
                     "killed_s1": s.killed_s1, "killed_s2": s.killed_s2,
                     "survived_s1": s.survived_s1,
                     "rate": s.rate, "fully_mutated": s.fully_mutated}
                    for s in (latest[k] for k in sorted(latest))],
                "regressions": [
                    {"target": r.target, "kind": r.kind, "detail": r.detail,
                     "baseline_index": r.baseline_index,
                     "current_index": r.current_index}
                    for r in regressions]}, indent=2))
            return 0
        armed = bool(config_mod.load_config(root)
                     .mutation.get("score_block_armed", False))
        arm_line = ("  transition regressions: BLOCK (armed)" if armed
                    else "  transition regressions: WARN (baking)")
        if not latest:
            print("aramid mutation-score: no mutation scores recorded")
            print(arm_line)
            return 0
        lines = ["aramid mutation-score:", arm_line]
        # AN ABSENT MEASUREMENT IS NOT A BAD ONE. `rate` is None exactly when no
        # mutant was tested for a target, and this used to render as
        # `kill-rate n/a (0/0) (partial)` -- which sits in a column of real
        # rates and reads as "coverage is poor". A consumer repo read it that
        # way, and the truth was the opposite: nothing had been measured at all,
        # because their mutation baseline could never finish.
        #
        # The two demand opposite responses -- write tests, versus fix the
        # engine -- so they must not share a rendering. A genuine 0.00 (mutants
        # tested, none killed) is a real finding about the tests and is
        # deliberately left loud.
        if not any(latest[t].rate is not None for t in latest):
            lines.append("  no target has been measured -- mutation recorded scores "
                         "but tested no mutants. This is an ABSENT measurement, not "
                         "a low one; `aramid status` reports why (look for a degraded "
                         "or stood-down mutation consumer).")
        for target in sorted(latest):
            s = latest[target]
            if s.rate is None:
                # No rate, and no `(partial)` either: partial-vs-complete is a
                # statement about a measurement that happened.
                lines.append(f"  {target}: not measured (0 mutants tested)")
                continue
            fm = "" if s.fully_mutated else " (partial)"
            # Kills of either stage over mutants with a verdict -- the same
            # two terms `rate` is computed from, so the fraction and the
            # rate cannot disagree.
            killed = s.killed_s1 + s.killed_s2
            lines.append(f"  {target}: kill-rate {s.rate:.2f} "
                         f"({killed}/{killed + s.survived_s1}){fm}")
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
