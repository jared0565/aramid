"""tdd -- synchronous 'code-without-test' producer for the pre-push gate
(design 1a sections 3-4). Pure git-diff analysis: one WARN-tier RawFinding per
changed production .py file when the range adds no new test lines. No
subprocess; never raises into run_gate (fail-open); the block rests only on
git facts. The graph note is an inert no-op stub that lights up once Graphite
is decision-grade."""
from pathlib import Path

from aramid import gitutil
from aramid.normalizer import RawFinding

RULE = "code-without-test"
_TOOL = "tdd"
_MESSAGE = "code changed with no new test in this range"


def _split_range(rng):
    """Derive (base, head) for gitutil.diff_new_lines from run_gate's `rng`.
    `rng` is a git range string like '@{u}..HEAD'; the FULL_HISTORY_RNG
    sentinel (empty string / None, new-repo first push) maps to (None, 'HEAD'),
    which diff_new_lines reads via its base=None `git show` path."""
    if not rng:
        return None, "HEAD"
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
