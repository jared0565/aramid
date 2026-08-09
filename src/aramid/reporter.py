"""reporter -- pure formatting of a `GateResult` into console text and JSON.

No side effects and no re-running of tools: everything rendered here comes
from the `GateResult` passed in (already produced by `pipeline.run_gate`)
and from read-only `Ledger` queries. In particular this module never reads
the wall clock -- see `_open_count_line` below for why the "aging" line is
a simple open-finding count rather than an "open > 30 days" figure.
"""
import dataclasses
import json

from aramid.ledger import Ledger
from aramid.models import Finding, Verdict
from aramid.pipeline import GateResult

ROTATE_WARNING = "rotate the credential — deleting the line does not fix the leak"


def _render_finding(f: Finding) -> str:
    line = f"  [{f.verdict.value.upper()}] {f.id} {f.tool}:{f.rule} {f.file}:{f.line} — {f.message}"
    if f.tool == "gitleaks":
        line += f"\n      {ROTATE_WARNING}"
    return line


def _open_count_line(ledger: Ledger) -> str:
    # "Aging" per the brief would ideally be "N findings open > 30 days",
    # but that needs a detection timestamp compared against the current
    # wall clock. `Ledger.open_findings()` materializes finding state
    # (status, tool, file, ...) but does not carry the original
    # `finding_detected` event's `at` -- and `render_console` is deliberately
    # not handed a clock (pure formatting, spec-mandated no side effects).
    # Rather than reach for `datetime.now()` inside a module that must stay
    # deterministic given fixed inputs, we fall back to the brief's
    # documented alternative: a simple open-finding count.
    open_count = sum(1 for rec in ledger.open_findings().values() if rec.get("status") == "open")
    return f"{open_count} findings open in ledger"


def render_console(result: GateResult, ledger: Ledger) -> str:
    lines: list[str] = []

    new_findings = [f for f in result.findings if f.id in result.new_ids]
    baseline_findings = [f for f in result.findings if f.id not in result.new_ids]

    # A BLOCK verdict is the REASON the gate fails, so it is always named --
    # being un-new is not a reason to hide it. Collapsing these into
    # "(+N baseline findings)" meant a blocked push printed a count and
    # nothing else, leaving `--json` as the only way to learn the cause:
    #
    #     (+7 baseline findings)
    #     45 findings open in ledger
    #     error: failed to push some refs to '...'
    #
    # The WARN half stays collapsed; the point is the cause of the failure,
    # not printing everything.
    still_blocking = [f for f in baseline_findings if f.verdict is Verdict.BLOCK]
    quiet_baseline = [f for f in baseline_findings if f.verdict is not Verdict.BLOCK]

    if new_findings:
        lines.append(f"NEW findings ({len(new_findings)}):")
        for f in new_findings:
            lines.append(_render_finding(f))
    if still_blocking:
        lines.append(f"STILL BLOCKING ({len(still_blocking)}) — seen before, "
                     "and still failing this gate:")
        for f in still_blocking:
            lines.append(_render_finding(f))
    if quiet_baseline:
        lines.append(f"(+{len(quiet_baseline)} baseline findings)")
    if not result.findings:
        lines.append("no findings")

    if result.degraded:
        lines.append("skipped (degraded tools):")
        for tool in result.degraded:
            lines.append(f"  - {tool}")

    lines.append(_open_count_line(ledger))

    for record in result.stale_overrides:
        # Named by REACH, not by tier. These used to read "(WARN)" and
        # "(BLOCK)", which stopped being true when the committed file went
        # tier-agnostic (design doc section 6 amendment, 2026-08-09) -- the
        # file is now the correct answer at either tier, and it is the only
        # one of the two a teammate ever sees.
        lines.append(
            f"stale override {record.id} — re-affirm it: `aramid override {record.id} --reason` "
            "(WARN only, machine-local) or an entry in .aramid-suppressions.toml "
            "(any tier, committed)"
        )

    return "\n".join(lines)


def render_json(result: GateResult) -> str:
    # Finding.evidence is already redacted by the normalizer -- this is pure
    # dataclass->dict serialization, nothing here adds raw material back in.
    payload = {
        "exit_code": result.exit_code,
        "findings": [dataclasses.asdict(f) for f in result.findings],
        "degraded": list(result.degraded),
        "new_ids": list(result.new_ids),
        "stale_overrides": [dataclasses.asdict(s) for s in result.stale_overrides],
    }
    return json.dumps(payload, indent=2)
