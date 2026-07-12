"""check -- thin wrapper over aramid.pipeline.run_gate: load config, open the
ledger, run the gate, render, and translate the result into a process exit
code. This is what the installed git hook shims invoke directly
(`<interp> -m aramid check --gate <gate>`) and what CI calls with
`--strict --json`.

Fresh-clone rule (design doc section 3, "Fresh clone / empty ledger"): the
no-new-warnings ratchet (aramid.pipeline's PRE_PUSH-only WARN->BLOCK
escalation, `run_gate`'s `if gate is Gate.PRE_PUSH: findings = [...]` step)
keys off `Ledger.record_run`'s "seen before" set, which -- on a literal
empty ledger -- is empty for every single finding, so EVERY WARN finding
looks "new" and gets escalated to BLOCK on the very first run. Unhandled,
that would block the first push of any freshly cloned repo on legacy
findings it never introduced. This module is where that gap is closed (not
aramid.pipeline, which is an already-built/tested M5 module out of this
milestone's scope): when `not ledger.has_baseline()` at gate=pre-push, this
writes a baseline from the findings just computed and, if the ONLY reason
`exit_code` came back 1 is the ratchet's own escalation (no finding is
independently BLOCK per `policy.classify`, the same pure classifier
`run_gate` itself uses), downgrades to 0/2. A genuine BLOCK-tier finding
(gitleaks secret, armed semgrep, failing tests, critical CVE) is NEVER
downgraded -- `_has_genuine_block` re-derives each still-BLOCK finding's
pre-ratchet verdict and only ever suppresses the ratchet's own contribution.

Deliberately scoped to gate=pre-push only, matching the design doc's own
wording ("the first PRE-PUSH run auto-baselines"): pre-commit has no
ratchet escalation at all (only PRE_PUSH triggers it in run_gate), so a
fresh ledger's pre-commit exit code is already correct as computed by
run_gate -- and writing a narrow staged-only baseline from a pre-commit run
would corrupt the LATER pre-push's own fresh-clone handling (that pre-push
scan would then see its own legacy findings as "not in that narrow
baseline" and re-trigger a false block).
"""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import policy
from aramid import reporter
from aramid.ledger import Ledger
from aramid.models import Gate, Verdict
from aramid.pipeline import run_gate


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _has_genuine_block(findings, cfg) -> bool:
    """True iff at least one still-BLOCK finding is BLOCK independent of the
    ratchet's own WARN->BLOCK escalation -- i.e. `policy.classify` (the same
    pure, ratchet-agnostic classifier aramid.pipeline.run_gate itself calls)
    would call it BLOCK on its own. A finding already downgraded to INFO by
    an override/suppression is excluded by the `f.verdict is Verdict.BLOCK`
    check (apply_overrides runs before the ratchet in run_gate, so a
    suppressed BLOCK is never still BLOCK by the time findings reach here)."""
    return any(
        f.verdict is Verdict.BLOCK
        and policy.classify(f.tool, f.rule, f.severity_raw, f.gate, cfg)[1] is Verdict.BLOCK
        for f in findings
    )


def cmd_check(root, gate: Gate, mode: str, strict: bool = False, as_json: bool = False,
              accept_degraded: str | None = None) -> int:
    root = Path(root)

    try:
        cfg = config_mod.load_config(root)
        ledger = Ledger(root / ".aramid" / "ledger.db")
    except Exception as exc:  # engine/config error -> exit 3, never a silent 0.
        print(f"aramid: check: engine error: {exc}", file=sys.stderr)
        return 3

    try:
        if accept_degraded is None:
            accept_degraded = os.environ.get("ARAMID_ACCEPT_DEGRADED")

        fresh = gate is Gate.PRE_PUSH and not ledger.has_baseline()

        result = run_gate(root, gate, mode, cfg, ledger, accept_degraded=accept_degraded)

        exit_code = result.exit_code
        if fresh:
            ledger.write_baseline(result.run_id, _now(), {f.id for f in result.findings})
            if exit_code == 1 and not _has_genuine_block(result.findings, cfg):
                print("aramid: check: fresh ledger -- baseline written; legacy findings do "
                      "not block the first pre-push run", file=sys.stderr)
                exit_code = 2 if result.degraded else 0

        if strict and exit_code in (2, 3):
            exit_code = 1

        output = reporter.render_json(result) if as_json else reporter.render_console(result, ledger)
        print(output)
        return exit_code
    except Exception as exc:  # engine error mid-run -> exit 3, never a silent 0.
        print(f"aramid: check: engine error: {exc}", file=sys.stderr)
        return 3
    finally:
        ledger.close()
