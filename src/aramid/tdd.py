"""tdd -- synchronous 'code-without-test' producer for the pre-push gate
(design 1a sections 3-4). Pure git-diff analysis: one WARN-tier RawFinding per
changed production .py file when the range adds no new test lines. No
subprocess; never raises into run_gate (fail-open); the block rests only on
git facts. The graph note is an inert no-op stub that lights up once Graphite
is decision-grade."""
from pathlib import Path

from aramid import gitutil
from aramid.fingerprint import normalize_path
from aramid.models import Event, EventType
from aramid.normalizer import RawFinding

RULE = "code-without-test"
_TOOL = "tdd"
_MESSAGE = "code changed with no new test in this range"


def _split_range(rng):
    """Derive (base, head) for gitutil.diff_new_lines from run_gate's `rng`.
    `rng` is a truthy git range string like '@{u}..HEAD'; callers must handle
    the FULL_HISTORY_RNG sentinel (empty string / None, new-repo first push)
    themselves before calling this (see scan())."""
    base, sep, head = rng.partition("..")
    if not sep:
        return None, "HEAD"
    return (base or None), (head or "HEAD")


def _graph_advisory_note(root: Path, rel: str) -> str:
    """No-op advisory stub (design 1a section 9). Returns "" today; a future
    sub-project promotes this to a fail-open read of graph-out/graph.json once
    Graphite resolution is decision-grade. Must never raise and never affect a
    verdict."""
    return ""


def scan(ctx, cfg) -> list[RawFinding]:
    """Return code-without-test RawFindings for the pre-push range. `ctx.files`
    is the already-changed, already-ignore-filtered file set. Fail-open: any
    error yields no findings (never blocks a push, never crashes the gate)."""
    try:
        if not getattr(cfg, "tdd", {}).get("enabled", True):
            return []
        prod = [f for f in ctx.files
                if f.endswith(".py") and not gitutil.is_test_file(f)]
        if not prod:
            return []
        if not ctx.rng:
            # First push (FULL_HISTORY_RNG / no upstream): ctx.files is the whole
            # tracked tree, so "the change" is the entire repo. It is tested iff
            # any tracked file is a test file -- a diff over "all history" is not
            # a meaningful notion of "new test lines" (every line is an addition).
            has_new_test_lines = any(gitutil.is_test_file(f) for f in ctx.files)
        else:
            base, head = _split_range(ctx.rng)
            new_lines = gitutil.diff_new_lines(ctx.root, base, head)
            has_new_test_lines = any(
                lines and gitutil.is_test_file(path)
                for path, lines in new_lines.items())
        if has_new_test_lines:
            return []
        out = []
        for rel in prod:
            note = _graph_advisory_note(ctx.root, rel)
            message = f"{_MESSAGE} ({note})" if note else _MESSAGE
            out.append(RawFinding(tool=_TOOL, rule=RULE, severity_raw="medium",
                                  file=rel, line=0, message=message))
        return out
    except Exception:
        return []


def auto_resolve_tdd(ledger, run_id: str, at: str, changed_files, present_ids) -> list[str]:
    """Resolve open code-without-test findings the push addresses (mirrors
    mutation_gate.auto_resolve_mutation, which mirrors review.auto_resolve_llm).
    Module-mapped: resolve a finding on x.py iff the range changed x.py OR
    added/modified a test whose basename stem is test_<x>/<x>_test -- the
    common fix is adding tests/test_x.py WITHOUT touching x.py, which is
    exactly what the ledger's own tool/file scope cannot express.

    present_ids (NOT needed by the two precedents, which resolve only
    drain-produced findings) skips anything this run's producer re-fired:
    auto_resolve runs AFTER record_run, so a still-broken file is already
    re-detected/open by now and must not be resolved out from under itself.

    Liberal by design and self-healing: the fingerprint is tool+rule+path
    (line=0), so a wrong resolve re-fires identically on the next push that
    touches the file without a test. Never raises into run_gate."""
    changed_norm = {normalize_path(c) for c in changed_files}
    changed_test_stems = {Path(c).stem for c in changed_files
                          if gitutil.is_test_file(c)}
    resolved = []
    for fid, rec in ledger.open_findings().items():
        if rec.get("tool") != _TOOL or rec.get("status") != "open" \
           or fid in present_ids:
            continue
        try:
            path = rec.get("file", "")
            if not path:
                continue                            # malformed: no file -> skip
            module = Path(path).stem
            source_touched = normalize_path(path) in changed_norm
            test_added = bool({f"test_{module}", f"{module}_test"} & changed_test_stems)
            if source_touched or test_added:
                ledger.append(Event(EventType.FINDING_RESOLVED, run_id, at,
                                    finding_id=fid,
                                    payload={"auto_resolved": "test_added"}))
                resolved.append(fid)
        except Exception:
            continue
    return resolved
