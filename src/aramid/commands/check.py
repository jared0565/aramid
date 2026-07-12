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
findings it never introduced. This module is where that gap-closing DECISION
lives (aramid.pipeline, an already-built/tested M5 module, stays behavior-
neutral here -- it only gained one additive, read-only `GateResult` field,
`degraded_block_tier`, so this module could reuse its own computation
verbatim instead of re-deriving a divergent copy; see (b) below): when
`not ledger.has_baseline()` at gate=pre-push, this writes a baseline from
the findings just computed and, if the ONLY reason `exit_code` came back 1
is the ratchet's own escalation, downgrades to 0/2.

`run_gate` has TWO independent routes to `exit_code == 1` (pipeline.py's
`block_findings` branch vs. its `policy.escalate_degraded` branch), so
"the ratchet's own escalation was the only reason" requires checking BOTH:
  (a) a genuine BLOCK-tier finding (gitleaks secret, armed semgrep, failing
      tests, critical CVE) -- `_has_genuine_block` re-derives each
      still-BLOCK finding's pre-ratchet verdict via `policy.classify`, the
      same pure classifier `run_gate` itself uses.
  (b) a degraded BLOCK-tier tool (gitleaks/semgrep/tests -- `run_gate`'s own
      `degraded_block_tier` local, now exposed on `GateResult` and read back
      here verbatim via `result.degraded_block_tier`) at pre-push. This
      route produces zero Finding objects (the tool never ran, so it never
      emitted anything to classify) -- it would be invisible to a
      findings-only check. Deliberately NOT re-derived from
      `result.degraded` (tool NAMES, from `RunnerResult.tool`) intersected
      against `pipeline.BLOCK_TIER_KEYS` (registry KEYS): those two can
      diverge -- e.g. the "tests" registry key can produce a RunnerResult
      with `.tool == "pytest"` when the pytest binary itself is missing
      (runners/tests.py's `run_pytest` -> `run_subprocess`), which would
      never name-match "tests" in BLOCK_TIER_KEYS even though it IS the
      BLOCK-tier "tests" slot degrading -- reading the already-computed
      boolean straight off `GateResult` sidesteps that divergence entirely.
      It can only have produced exit_code==1 without `accept_degraded`,
      because `run_gate` takes its `accept_degraded` branch instead whenever
      `accept_degraded` is supplied (that branch never returns 1) -- so no
      separate accept_degraded check is needed here.
EITHER (a) or (b) is treated as a genuine block and is NEVER downgraded --
only suppresses the ratchet's own WARN->BLOCK contribution.

Deliberately scoped to gate=pre-push only, matching the design doc's own
wording ("the first PRE-PUSH run auto-baselines"): pre-commit has no
ratchet escalation at all (only PRE_PUSH triggers it in run_gate), so a
fresh ledger's pre-commit exit code is already correct as computed by
run_gate -- and writing a narrow staged-only baseline from a pre-commit run
would corrupt the LATER pre-push's own fresh-clone handling (that pre-push
scan would then see its own legacy findings as "not in that narrow
baseline" and re-trigger a false block).
"""
import dataclasses
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import pipeline
from aramid import policy
from aramid import reporter
from aramid.ledger import Ledger
from aramid.models import Gate, Verdict


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _has_genuine_block(result, cfg) -> bool:
    """True iff `exit_code == 1` was NOT solely the ratchet's own doing --
    i.e. at least one of `run_gate`'s two independent routes to exit_code 1
    fired for a reason other than the fresh-ledger ratchet:
      (a) a still-BLOCK finding that is BLOCK independent of the ratchet's
          own WARN->BLOCK escalation (`policy.classify`, the same pure,
          ratchet-agnostic classifier `run_gate` itself calls). A finding
          already downgraded to INFO by an override/suppression is excluded
          by the `f.verdict is Verdict.BLOCK` check (apply_overrides runs
          before the ratchet in run_gate, so a suppressed BLOCK is never
          still BLOCK by the time findings reach here).
      (b) `result.degraded_block_tier` -- `run_gate`'s own already-computed
          BLOCK-tier-degradation flag, read back verbatim (see module
          docstring for why this must NOT be re-derived from `result.degraded`
          tool names against `pipeline.BLOCK_TIER_KEYS` registry keys).
    """
    genuine_finding = any(
        f.verdict is Verdict.BLOCK
        and policy.classify(f.tool, f.rule, f.severity_raw, f.gate, cfg)[1] is Verdict.BLOCK
        for f in result.findings
    )
    return genuine_finding or result.degraded_block_tier


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

        result = pipeline.run_gate(root, gate, mode, cfg, ledger, accept_degraded=accept_degraded)

        exit_code = result.exit_code
        if fresh:
            ledger.write_baseline(result.run_id, _now(), {f.id for f in result.findings})
            if exit_code == 1 and not _has_genuine_block(result, cfg):
                print("aramid: check: fresh ledger -- baseline written; legacy findings do "
                      "not block the first pre-push run", file=sys.stderr)
                exit_code = 2 if result.degraded else 0

        if strict and exit_code in (2, 3):
            exit_code = 1

        # Render the FINAL exit code (post fresh-clone downgrade, post
        # --strict remap), not the pipeline's original `result.exit_code` --
        # otherwise the JSON body's "exit_code" field can disagree with the
        # process's actual return code (Important-1, task-7-review.md).
        if exit_code != result.exit_code:
            result = dataclasses.replace(result, exit_code=exit_code)

        output = reporter.render_json(result) if as_json else reporter.render_console(result, ledger)
        print(output)
        return exit_code
    except Exception as exc:  # engine error mid-run -> exit 3, never a silent 0.
        print(f"aramid: check: engine error: {exc}", file=sys.stderr)
        return 3
    finally:
        ledger.close()
