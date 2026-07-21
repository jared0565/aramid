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
from pathlib import Path

from aramid import gitutil
from aramid.fingerprint import normalize_path
from aramid.models import Event, EventType, Finding, Gate, Severity, Source, Verdict

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


def _module_tests(module: str) -> set[str]:
    """Mapped-test basenames for a source module stem, per the
    consumers/mutation.py::_stage1_argv convention (test_<module>.py)."""
    return {f"test_{module}", f"{module}_test"}


def auto_resolve_mutation(ledger, run_id: str, at: str, changed_files) -> list[str]:
    """Optimistically resolve open mutation findings the push addresses, BEFORE
    the block check (mirrors review.auto_resolve_llm's call site), so a dev who
    added a test is not blocked by a stale finding. Module-mapped (spec 1b §4):
    resolve a finding on x.py iff the push changed x.py OR added/modified a test
    whose basename stem is test_<x>/<x>_test. Liberal by design -- a wrong
    resolve only lets a test-gap slip until the re-drain re-reports it (never a
    security hole); the async re-drain is the authoritative backstop. Two source
    files sharing a module stem are resolved together by one mapped test -- an
    accepted, low-stakes consequence of module-mapping."""
    changed_norm = {normalize_path(c) for c in changed_files}
    changed_test_stems = {Path(c).stem for c in changed_files
                          if gitutil.is_test_file(c)}
    resolved = []
    for fid, rec in ledger.open_findings().items():
        if rec.get("tool") != TOOL or rec.get("status") != "open":
            continue
        try:
            path = rec.get("file", "")
            if not path:
                continue                            # malformed: no file -> skip
            module = Path(path).stem
            source_touched = normalize_path(path) in changed_norm
            test_added = bool(_module_tests(module) & changed_test_stems)
            if source_touched or test_added:
                ledger.append(Event(EventType.FINDING_RESOLVED, run_id, at,
                                    finding_id=fid,
                                    payload={"auto_resolved": "gap_addressed"}))
                resolved.append(fid)
        except Exception:
            continue
    return resolved
