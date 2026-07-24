"""mutation_score_gate -- the zero-persistence pre-push seam for 2a's
mutation-score regressions (sub-project 2b). mutation_score.py detects two
advisory signals over CONSUMER_RUN_FINISHED history (per-mutant transition;
per-function stage-1 rate-delta); nothing surfaces them at the gate. This
module is mutation_gate.py's twin for DERIVED state: recompute
latest_regressions fresh each PRE_PUSH and materialize the results as
findings under the distinct tool "mutation-score" -- auto_resolve_mutation
and mutation_gate_findings both filter tool == "mutation", so neither ever
touches these; nothing is written to the ledger, so there is no stored
record to wrongly resolve ("only a re-drain truly clears it" holds by
construction -- the 2a spec s12 caveat, closed).

The verdict is computed HERE from [mutation].score_block_armed -- the SAME
rule policy.classify's tool == "mutation-score" branch encodes (BLOCK iff
armed AND rule == "transition"); the two one-line rules must agree.

Ephemeral test-mapped suppression (transitions only -- WARNs need no escape
valve): a push whose changed_files touch the module-mapped test
(test_<module>/<module>_test, per mutation_gate._module_tests) drops the
transition for THIS gate run only. No ledger write; a bare source-touch
never suppresses -- that is exactly the 1b auto-resolve hole 2b closes.
changed_files is the push's scope ONLY under mode "range"; pipeline passes
None otherwise (under "all"/"staged" the scope is the whole tree/staged set
and suppressing against it would suppress everything).

Fail-open contract identical to mutation_gate: NEVER raises into run_gate.
Documented limitations (spec s10): the fingerprint pins occurrence to 0, so
two same-op mutants on one identical line share an fp and a transition may
conflate them; findings are ephemeral (invisible to aramid status and to
apply_overrides -- escape = mapped test or disarm); a function rewritten
without its mapped test blocks until a re-drain re-measures, which is why
[mutation].enabled = false disables the seam entirely (engine off = no
re-drain backstop = an armed stale regression could never clear).
Detection reads only killed_s1/survived_s1/fully_mutated/fps -- never the
under-counted, write-only errors/timeouts buckets (spec s10 NEW-1, honored
by construction).
"""
from pathlib import Path

from aramid import gitutil, mutation_score
from aramid.fingerprint import compute_fingerprint
from aramid.models import Finding, Gate, Severity, Source, Verdict
from aramid.mutation_gate import _module_tests

TOOL = "mutation-score"


def mutation_score_gate_findings(cfg, ledger, gate: Gate,
                                 changed_files=None) -> list[Finding]:
    """Materialize current mutation-score regressions as gate findings.
    PRE_PUSH only; [] when [mutation].enabled is false. Never raises."""
    if gate is not Gate.PRE_PUSH:
        return []
    try:
        mcfg = getattr(cfg, "mutation", None) or {}
        if not mcfg.get("enabled", True):
            return []
        armed = bool(mcfg.get("score_block_armed", False))
        regressions = mutation_score.latest_regressions(ledger.events())
    except Exception:
        return []
    changed_test_stems = set()
    if changed_files:
        try:
            changed_test_stems = {Path(c).stem for c in changed_files
                                  if gitutil.is_test_file(c)}
        except Exception:
            changed_test_stems = set()
    out = []
    for r in regressions:
        try:
            rel, sep, func = r.target.partition("::")
            if not sep or not func:
                continue                    # malformed target key: skip
            if r.kind == "transition":
                if _module_tests(Path(rel).stem) & changed_test_stems:
                    continue    # ephemeral suppression, this gate run only
                verdict = Verdict.BLOCK if armed else Verdict.WARN
                severity_raw, severity = "high", Severity.HIGH
                message = (f"mutation-score regression in {func}: "
                           f"{len(r.transition_fps)} previously-killed "
                           f"mutant(s) now survive")
                evidence = ", ".join(sorted(r.transition_fps))
            elif r.kind == "rate":
                verdict = Verdict.WARN
                severity_raw, severity = "low", Severity.LOW
                message = (f"mutation-score rate regression in {func}: "
                           f"{r.detail}")
                evidence = ""
            else:
                continue
            out.append(Finding(
                id=compute_fingerprint(TOOL, r.kind, rel, func, 0),
                tool=TOOL, rule=r.kind, severity_raw=severity_raw,
                severity=severity, verdict=verdict, file=rel, line=0,
                message=message, evidence=evidence, gate=gate,
                source=Source.DETERMINISTIC))
        except Exception:
            continue
    return out
