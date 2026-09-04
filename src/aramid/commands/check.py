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
      tests, critical CVE, armed+confirmed+critical LLM finding) --
      `_has_genuine_block` re-derives each still-BLOCK finding's pre-ratchet
      verdict via `policy.classify`, the same pure classifier `run_gate`
      itself uses -- EXCEPT source=LLM findings, which are genuine-by-source
      directly, bypassing classify (which always returns WARN for
      "llm-review" by design, so it structurally can't see an LLM BLOCK;
      see `_has_genuine_block`'s own docstring, task-13b).
  (b) a degraded BLOCK-tier tool (gitleaks/semgrep/tests -- `run_gate`'s own
      `degraded_block_tier` local, now exposed on `GateResult` and read back
      here verbatim via `result.degraded_block_tier`) at pre-push. This
      route USUALLY produces zero Finding objects (the tool never ran, so
      it never emitted anything to classify) -- it would be invisible to a
      findings-only check on its own. [Updated, MUST FIX 2 whole-branch
      review] Not always, though: a dual-suite `tests-tool-missing`
      finding (runners/tests.py) CAN reach exit_code==1 via this same
      route despite being a real Finding, because `run_gate`'s BLOCK-
      gating check excludes that one rule by name (it only ever explains
      a degradation `degraded_block_tier` already carries). Harmless
      either way for the logic below: (a) above's own `classify()`
      re-check independently also calls that finding genuine (policy.py's
      dedicated `tests-tool-missing` branch is an unconditional BLOCK), so
      (a) and (b) agree on the outcome even in the case where both are
      technically true at once. Deliberately NOT re-derived from
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
import uuid
from datetime import datetime, timezone
from pathlib import Path

from aramid import __version__
from aramid import config as config_mod
from aramid import fleet
from aramid import pipeline
from aramid import policy
from aramid import pushrefs
from aramid import reporter
from aramid.commands import override as override_cmd
from aramid.ledger import Ledger
from aramid.models import Gate, Source, Verdict


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
          Exception: an LLM finding (`f.source is Source.LLM`) is treated as
          genuine directly, WITHOUT going through `policy.classify` -- by
          deliberate Task 3 design, `policy.classify("llm-review", ...)`
          ALWAYS returns WARN (the real BLOCK verdict for an LLM finding is
          computed only in `review.llm_gate_findings`, from ledger state +
          [llm].llm_block_armed, never in policy.classify), so classify
          structurally can never see an LLM finding as genuine. An LLM
          finding only ever carries `verdict is Verdict.BLOCK` when it is
          armed + confirmed + critical (llm_gate_findings sets BLOCK only in
          that case) -- a deliberate, refute-confirmed, armed block, not
          legacy onboarding debt (arming is meant to be retroactive) -- so
          it must never be downgraded on a fresh ledger (task-13b-review.md
          HIGH: this gap silently defeated the LLM gate on any fresh clone /
          CI runner / reset ledger, since `.aramid/` is gitignored).
      (b) `result.degraded_block_tier` -- `run_gate`'s own already-computed
          BLOCK-tier-degradation flag, read back verbatim (see module
          docstring for why this must NOT be re-derived from `result.degraded`
          tool names against `pipeline.BLOCK_TIER_KEYS` registry keys).
    """
    genuine_finding = any(
        f.verdict is Verdict.BLOCK
        and (f.source is Source.LLM
             or policy.classify(f.tool, f.rule, f.severity_raw, f.gate, cfg)[1] is Verdict.BLOCK)
        for f in result.findings
    )
    return genuine_finding or result.degraded_block_tier


def _ledger_snapshot(root: Path) -> Ledger:
    """A throwaway copy of the repo's ledger, so a `--no-record` run answers
    exactly as a recording run would -- the ratchet, `new_ids` and the
    fresh-ledger rule all read history -- while nothing it appends reaches
    `.aramid/ledger.db`. Copied through sqlite's backup API rather than the
    file: the ledger runs in WAL mode, and a plain file copy can miss the
    write-ahead log. A repo with no ledger yet gets an empty snapshot and
    still ends the run with no ledger."""
    import shutil
    import sqlite3
    import tempfile
    tmp_dir = Path(tempfile.mkdtemp(prefix="aramid-no-record-"))
    dst = tmp_dir / "ledger.db"
    src_path = root / ".aramid" / "ledger.db"
    if src_path.exists():
        src = sqlite3.connect(str(src_path))
        try:
            dst_conn = sqlite3.connect(str(dst))
            try:
                src.backup(dst_conn)
            finally:
                dst_conn.close()
        finally:
            src.close()
    ledger = Ledger(dst)
    ledger._no_record_dir = tmp_dir           # reaped in cmd_check's finally
    ledger._no_record_rmtree = shutil.rmtree
    return ledger


def cmd_check(root, gate: Gate, mode: str, strict: bool = False, as_json: bool = False,
              accept_degraded: str | None = None, record: bool = True) -> int:
    root = Path(root)

    try:
        cfg = config_mod.load_config(root)
        # `record=False` (interop round 149 c): a whole-tree measurement used
        # to write every finding it saw into the ledger -- 683 rows for one
        # consumer's look. The gate now runs against a snapshot instead.
        ledger = Ledger(root / ".aramid" / "ledger.db") if record else _ledger_snapshot(root)
        if not record:
            print("aramid: check: no-record -- running against a snapshot of the ledger; "
                  "nothing from this run is written to .aramid/ledger.db", file=sys.stderr)
    except Exception as exc:  # engine/config error -> exit 3, never a silent 0.
        print(f"aramid: check: engine error: {exc}", file=sys.stderr)
        return 3

    try:
        if accept_degraded is None:
            accept_degraded = os.environ.get("ARAMID_ACCEPT_DEGRADED")

        fresh = gate is Gate.PRE_PUSH and not ledger.has_baseline()

        # What this run certifies (pre-push only; interop round 176). Over
        # smart HTTP git ships the tip as of hook EXIT, so the refs git named
        # on the hook's stdin are pinned here, BEFORE anything runs, and
        # re-resolved by run_gate after the last runner returns.
        certified = None
        if gate is Gate.PRE_PUSH:
            hook_text = pushrefs.read_hook_stdin()      # None unless ARAMID_HOOK is set
            refs = pushrefs.parse_push_lines(hook_text or "")
            if hook_text is not None and not refs:
                # git's "Everything up-to-date", or a push that only deletes:
                # nothing ships, so there is nothing to certify -- and no run
                # row, because a row with no tools reads as a skip and would
                # start a skip streak for a push that shipped nothing.
                print("aramid: pre-push: nothing to push -- git handed the hook an "
                      "empty ref list; gate not run", file=sys.stderr)
                return 0
            certified = pushrefs.certify(root, refs, hook=hook_text is not None)

        # Gate START, before anything detects. Deliberately not on the
        # detection path: every armed tool's gate skips records whose status
        # is not "open" (mutation's is the sharpest), so an invalidation that
        # waited for the finding to re-fire would be eaten by the very filter
        # that makes a defeated block permanent -- suppressed, therefore never
        # re-detected, therefore never re-opened.
        invalidated = override_cmd.invalidate_stale_overrides(
            ledger, cfg, run_id=uuid.uuid4().hex, at=_now())
        if invalidated:
            print(override_cmd.render_invalidations(invalidated), file=sys.stderr)

        result = pipeline.run_gate(root, gate, mode, cfg, ledger, accept_degraded=accept_degraded,
                                   certified=certified)
        result = dataclasses.replace(result, recorded=record)

        exit_code = result.exit_code
        if fresh:
            ledger.write_baseline(result.run_id, _now(), {f.id for f in result.findings})
            result = dataclasses.replace(result, fresh_ledger_baseline=True)
            if exit_code == 1 and not _has_genuine_block(result, cfg):
                # Said in the JSON as well as on stderr: a CI step reads the
                # report, and `exit_code: 0` beside block-tier findings has to
                # explain itself there (interop rounds 149 s3 / 150).
                result = dataclasses.replace(
                    result, grandfathered=tuple(getattr(result, "ratchet_escalated", ()) or ()))
                print("aramid: check: fresh ledger -- baseline written; legacy findings do "
                      "not block the first pre-push run", file=sys.stderr)
                exit_code = 2 if result.degraded else 0

        if result.refs_moved:
            # A certified ref moved while the gate ran: the certification is
            # void and git will not say so (over smart HTTP it ships the
            # moved tip while printing the pre-hook range). Fail, not warn --
            # and AFTER the fresh-ledger downgrade above, which grandfathers
            # legacy findings, never a moved branch.
            print("aramid: pre-push: " + pushrefs.render(result.refs_moved), file=sys.stderr)
            exit_code = 1

        if strict and exit_code in (2, 3):
            exit_code = 1

        # Render the FINAL exit code (post fresh-clone downgrade, post
        # --strict remap), not the pipeline's original `result.exit_code` --
        # otherwise the JSON body's "exit_code" field can disagree with the
        # process's actual return code (Important-1, task-7-review.md).
        if exit_code != result.exit_code:
            result = dataclasses.replace(result, exit_code=exit_code)

        # The notice COUNT rides the report (fleet-readiness spec section 8);
        # read here, not in the reporter, which touches no filesystem.
        from aramid import notices as notices_mod
        try:
            trailer = fleet.load_policy().gate_trailer
        except Exception:  # fail-open: policy trouble never changes the gate's answer
            trailer = fleet.Policy().gate_trailer
        result = dataclasses.replace(result, fleet_notices_pending=notices_mod.pending_count(),
                                     fleet_trailer=trailer)

        output = reporter.render_json(result) if as_json else reporter.render_console(result, ledger)
        print(output)
        # Fleet health row (fleet-readiness spec section 5): this repo's own
        # signals, appended to the machine-level store AFTER the report is
        # printed, so a slow or broken store can never delay or hide the
        # verdict. Fail-open inside `record_health`. A `--no-record` run is a
        # snapshot, not evidence, and writes nothing.
        if record:
            fleet.record_health(root, cfg, ledger, result, gate=gate,
                                aramid_version=__version__, now=_now())
        return exit_code
    except Exception as exc:  # engine error mid-run -> exit 3, never a silent 0.
        print(f"aramid: check: engine error: {exc}", file=sys.stderr)
        # The row says the gate died: criteria all red, audit unknown. The
        # ledger may be the thing that broke; `record_health` tolerates that.
        if record:
            fleet.record_health(root, cfg, ledger, None, gate=gate,
                                aramid_version=__version__, now=_now(), engine_error=True)
        return 3
    finally:
        ledger.close()
        tmp_dir = getattr(ledger, "_no_record_dir", None)
        if tmp_dir is not None:
            ledger._no_record_rmtree(tmp_dir, ignore_errors=True)
