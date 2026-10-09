"""FN-38: a tool's own inline marker that hides a BLOCK-tier hit, made visible.

aramid runs ruff, gitleaks and semgrep with the target repo's own markers in
force, so a committed `# noqa: S105`, a ruff `per-file-ignores` entry, a
`# gitleaks:allow` or a `# nosemgrep` removes a BLOCK finding with no
`.aramid-suppressions.toml` entry, no reason and no ledger row. Each of those
three runners now runs a second pass with the markers off (`semgrep` needs no
second process: `--disable-nosem` reports what it would have hidden) and
reports every BLOCK-tier hit only the markers were hiding as a WARN finding
of its own. The marker still silences the tool's own BLOCK, so nothing that
passed before starts failing. Spec:
docs/superpowers/specs/2026-10-09-aramid-visible-inline-suppressions-design.md.

THE TOOL NAME IS A PER-TOOL LABEL, NOT `aramid`. `ledger.record_run` resolves
an open finding only when its `tool` is the label of a runner result that ran
OK this run (`scope_tools`), against that result's `examined` set. Each second
pass is therefore a real `RunnerResult` carried in its parent's
`.sub_results` (the deps/tests precedent), and its findings carry its label.
A finding stamped with a name no runner reports could never resolve once its
marker was removed. A degraded second pass is a degraded runner under its own
label: it resolves nothing, and it never degrades the tool's own result.
"""
import dataclasses
import time

from aramid.models import Verdict
from aramid.runners.base import RunnerResult, ToolState

# The rule every inline finding carries, whatever it hides. Never fold the
# hidden rule into it: classify's semgrep globs are substring patterns
# (`*sqli*`), and a rule id carrying `...python-sqli-string-concat` would
# match one. The hidden tool and rule travel on `RawFinding.subject`.
RULE = "inline-suppressed-block"

RUFF = "ruff-inline"
GITLEAKS = "gitleaks-inline"
SEMGREP = "semgrep-inline"

# Underlying runner NAME -> the label its second pass reports under.
LABELS = {"ruff": RUFF, "gitleaks": GITLEAKS, "semgrep": SEMGREP}
TOOLS = frozenset(LABELS.values())


# The gate abandons a whole registry key at its budget (pipeline._run_selected)
# and replaces it with a bare TIMEOUT. A second pass that ran past the deadline
# would therefore throw away the tool's OWN finished result -- a BLOCK-tier
# gitleaks among them. So a second pass leaves MARGIN_S unspent for the runner
# to parse and return, and is not started at all with less than MIN_S to run.
MARGIN_S = 1.0
MIN_S = 1.0


def second_pass_timeout(ctx, cap: float) -> float | None:
    """The timeout a second pass may use, or None when the gate's budget has
    too little left to start one. No deadline (a ctx built outside run_gate)
    means unbounded by it, never expired."""
    deadline = getattr(ctx, "gate_deadline", None)
    if deadline is None:
        return cap
    left = deadline - time.monotonic() - MARGIN_S
    return min(cap, left) if left >= MIN_S else None


def skipped(label: str) -> RunnerResult:
    """A second pass not started for lack of budget: degraded under its own
    label, never an empty OK that would read as "no markers"."""
    return RunnerResult(label, ToolState.TIMEOUT, stderr=(
        f"aramid: {label} not started: less than {MARGIN_S + MIN_S:g} s of the "
        f"gate's budget was left after the tool's own run"))


def bundle(own: RunnerResult, second: RunnerResult) -> RunnerResult:
    """The tool's own result, carrying both passes as `.sub_results` so the
    pipeline's `_flatten` gives each its own degraded flag, log, scope entry
    and examined set. The top level keeps the tool's own state: a failed
    second pass never degrades the BLOCK-tier result it sits beside."""
    combined = dataclasses.replace(own)
    combined.sub_results = (own, second)
    return combined


def message(tool: str, rule: str, marker: str, detail: str) -> str:
    return (f"{marker} hides {tool} {rule} here ({detail}). Remove the marker, or "
            f"accept it with a reasoned .aramid-suppressions.toml entry for this "
            f"finding's id")


def block_tier_only(raws: list, verdict_of) -> list:
    """Drop every inline raw whose HIDDEN hit would not have blocked.

    `verdict_of(tool, rule, severity_raw)` is `policy.classify` for the gate
    being run, so the one authority is the question the marker actually
    answers: would this hit have refused the commit or push without it? A
    WARN-tier rule silenced inline is the repo's own business, and so is a
    semgrep hit during the bake, which blocks nothing either way. Every other
    raw passes through untouched. An inline raw with no subject names nothing
    it hid, and is dropped rather than guessed at.
    """
    return [r for r in raws
            if r.tool not in TOOLS
            or (r.subject is not None
                and verdict_of(*r.subject, r.severity_raw) is Verdict.BLOCK)]
