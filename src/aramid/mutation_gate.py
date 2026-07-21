"""mutation_gate -- the zero-token pre-push seam for the drain's surviving-
mutant findings (sub-project 1b). consumers/mutation.py writes stage-2
full-suite-CONFIRMED survivors to the ledger, but nothing surfaces them at the
gate (only LLM findings are, via review.llm_gate_findings). This module is
their twin: materialize still-open mutation findings at pre-push
(mutation_gate_findings) and optimistically resolve them when the push
addresses the gap (auto_resolve_mutation), mirroring review's llm helpers.

Both functions are pure ledger/git-fact computation and NEVER raise into
run_gate (fail-open: a broken seam must never block a push or crash the gate).
The verdict is computed inline from [mutation].mutation_block_armed -- the SAME
rule policy.classify's tool=="mutation" branch encodes (which is what makes
_has_genuine_block treat an armed mutation BLOCK as genuine on a fresh clone);
the two one-line rules must agree.
"""
from aramid.models import Finding, Gate, Severity, Source, Verdict

TOOL = "mutation"


def mutation_gate_findings(cfg, ledger, gate: Gate) -> list[Finding]:
    """Materialize still-open mutation findings as gate findings (spec 1b).
    PRE_PUSH only. Verdict computed HERE from [mutation].mutation_block_armed
    -- never read from the stored record -- so arming applies retroactively:
    BLOCK when armed, WARN while baking."""
    if gate is not Gate.PRE_PUSH:
        return []
    armed = bool(cfg.mutation.get("mutation_block_armed", False))
    verdict = Verdict.BLOCK if armed else Verdict.WARN
    out = []
    for fid, rec in sorted(ledger.open_findings().items()):
        if rec.get("tool") != TOOL or rec.get("status") != "open":
            continue
        # Per-record guard (fail-safe): a MALFORMED rec (e.g. line stored as
        # null so int(rec.get("line", 0)) raises TypeError) is SKIPPED -- never
        # crash the gate. A skipped rec stays open, forcing manual triage, the
        # safe outcome for a block gate. Mirrors review.llm_gate_findings.
        try:
            try:
                severity = Severity(rec.get("severity", "medium"))
            except ValueError:
                severity = Severity.MEDIUM
            out.append(Finding(
                id=fid, tool=TOOL, rule=rec.get("rule", ""),
                severity_raw=rec.get("severity", ""), severity=severity,
                verdict=verdict, file=rec.get("file", ""),
                line=int(rec.get("line", 0)), message=rec.get("message", ""),
                evidence=rec.get("evidence", ""), gate=gate,
                source=Source.DETERMINISTIC))
        except Exception:
            continue
    return out
