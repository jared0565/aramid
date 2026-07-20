"""`aramid rebaseline`: re-snapshot the current findings as the accepted
ratchet baseline. First-release recovery for fingerprint churn -- when an
aramid upgrade changes rule/path normalization, grandfathered findings
re-fingerprint and the ratchet re-escalates them as new BLOCKs; rebaseline
re-accepts the current set. Destructive to grandfathering, so it refuses
without an explicit --yes (no interactive prompt: safe in hooks/CI).

--yes runs a full ALL-gate, so it appends the normal RUN_STARTED /
FINDING_DETECTED / FINDING_RESOLVED / RUN_FINISHED events too, not just the
BASELINE_SNAPSHOT. One consequence: a finding that merely re-fingerprinted
(old id vanished, new id appeared) is recorded as "fixed" in the ledger's
materialized state -- expected, but it means `aramid status` / `ledger list`
may show a re-fingerprinted finding as resolved after a churn-driven
rebaseline."""
import datetime as _dt
from pathlib import Path

from aramid import config as config_mod
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.pipeline import run_gate


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def cmd_rebaseline(root: Path, *, yes: bool = False) -> int:
    cfg = config_mod.load_config(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        old = len(ledger.baseline_ids())
        if not yes:
            print(f"aramid: rebaseline: would discard the current baseline "
                  f"({old} grandfathered finding(s)) and re-snapshot the current "
                  f"gate result. This drops ratchet grandfathering. Re-run with "
                  f"--yes to proceed.")
            return 3
        result = run_gate(root, Gate.ALL, "all", cfg, ledger)
        new_ids = {f.id for f in result.findings}
        ledger.write_baseline(result.run_id, _now(), new_ids)
        print(f"aramid: rebaseline: baseline rewritten ({old} -> {len(new_ids)} "
              f"finding(s) accepted).")
        return 0
    finally:
        ledger.close()
