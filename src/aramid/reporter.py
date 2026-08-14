"""reporter -- pure formatting of a `GateResult` into console text and JSON.

No side effects and no re-running of tools: everything rendered here comes
from the `GateResult` passed in (already produced by `pipeline.run_gate`)
and from read-only `Ledger` queries. In particular this module never reads
the wall clock -- see `_open_count_line` below for why the "aging" line is
a simple open-finding count rather than an "open > 30 days" figure.
"""
import dataclasses
import json

from aramid.ledger import Ledger, _is_synthetic_path
from aramid.models import Finding, Verdict
from aramid.pipeline import GateResult

ROTATE_WARNING = "rotate the credential — deleting the line does not fix the leak"


def _render_finding(f: Finding, log_paths: dict | None = None) -> str:
    # ASCII `--`, for the reason `ledger_cmd._render_row` is: a literal U+2014
    # goes out as the single byte 0x97 under a redirected stdout on Windows,
    # which is not valid UTF-8. `cli.main` now reconfigures the stream so this
    # is belt-and-braces rather than the fix, but there is no reason for a
    # separator to be non-ASCII and every other rendered line here already
    # uses `--`.
    line = f"  [{f.verdict.value.upper()}] {f.id} {f.tool}:{f.rule} {f.file}:{f.line} -- {f.message}"
    if f.tool == "gitleaks":
        line += f"\n      {ROTATE_WARNING}"
    # A `<...>` marker is not a location -- it is a label standing in for a
    # finding that has no file (`ledger._is_synthetic_path`, reused rather than
    # re-matched because its own docstring asks new consumers to inherit the
    # guard so a second marker never needs a second fix). For those, every
    # component of the printed line is a constant for the repo, so the line
    # discriminates nothing: which test failed lives only in the run log.
    #
    # Gated on a log this run actually wrote, never on a constructed path.
    # Consumer-produced findings (mutation, llm) have no RunnerResult and no
    # log, and naming a file that is not there would be the same defect this
    # fixes wearing a different costume.
    log = (log_paths or {}).get(f.tool)
    if log and _is_synthetic_path(f.file):
        line += f"\n      full output: {log}"
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

    # FIRST, above the findings. A reader who meets twenty blocking findings
    # before learning the scope changed spends that time hunting a regression
    # that did not happen -- which is exactly what it cost the repo that
    # reported this, mid-release, with the tag already cut.
    if getattr(result, "scope_widened", None):
        lines.append(f"note: {result.scope_widened}")

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
            lines.append(_render_finding(f, result.log_paths))
    if still_blocking:
        lines.append(f"STILL BLOCKING ({len(still_blocking)}) -- seen before, "
                     "and still failing this gate:")
        for f in still_blocking:
            lines.append(_render_finding(f, result.log_paths))
    if quiet_baseline:
        lines.append(f"(+{len(quiet_baseline)} baseline findings)")
    if not result.findings:
        lines.append("no findings")

    if result.degraded:
        lines.append("skipped (degraded tools):")
        for tool in result.degraded:
            lines.append(f"  - {tool}")

    # The rule id printed above is aramid's CANONICAL one -- deliberately
    # stripped of semgrep's config-path prefix so it is identical in every
    # checkout. That is what makes it safe to commit in block_rules.toml and a
    # suppressions file, and also what makes it useless to paste into
    # semgrep's own `# nosemgrep:`, which matches the un-stripped id. A repo
    # wrote 20 markers with the printed id and every one silently did nothing.
    if any(f.tool == "semgrep" for f in result.findings):
        lines.append(
            "to suppress a semgrep finding: add it to "
            ".aramid-suppressions.toml (reviewed, committed, binds by finding "
            "id, identical in every clone).")
        lines.append(
            "  `# nosemgrep: <the rule id above>` will NOT match -- semgrep "
            "namespaces ids by config path and this ruleset ships inside the "
            "installed package, so the id it matches contains an absolute "
            "path. A bare `# nosemgrep` does work, but silences every rule "
            "on that line.")

    lines.append(_open_count_line(ledger))

    for record in result.stale_overrides:
        # Named by REACH, not by tier. These used to read "(WARN)" and
        # "(BLOCK)", which stopped being true when the committed file went
        # tier-agnostic (design doc section 6 amendment, 2026-08-09) -- the
        # file is now the correct answer at either tier, and it is the only
        # one of the two a teammate ever sees.
        lines.append(
            f"stale override {record.id} -- re-affirm it: `aramid override {record.id} --reason` "
            "(WARN only, machine-local) or an entry in .aramid-suppressions.toml "
            "(any tier, committed)"
        )

    return "\n".join(lines)


def render_json(result: GateResult) -> str:
    # Finding.evidence is already redacted by the normalizer -- this is pure
    # dataclass->dict serialization, nothing here adds raw material back in.
    # WHY a finding is BLOCK, not only that it is. The no-new-warnings ratchet
    # escalates a brand-new WARN to BLOCK, so `verdict` alone covers two
    # conditions with opposite remedies: an intrinsic BLOCK is a security
    # finding to fix, a ratchet escalation is a new warning that stops
    # escalating once the finding is no longer new. A consumer scripting this
    # output read the second as the first and nearly reported that a deliberate
    # WARN-tier rule decision had failed.
    #
    # `new_ids` was already here and is NOT sufficient to derive this: a
    # brand-new finding can be BLOCK on its own merits, and telling the two
    # apart otherwise means reimplementing the ratchet's exemption list.
    #
    # Both keys are always present. An absent key means an aramid too old to
    # record provenance; `false` means it looked -- the same absent-vs-empty
    # contract as `tools` below.
    escalated = set(getattr(result, "ratchet_escalated", ()) or ())

    def _finding(f) -> dict:
        d = dataclasses.asdict(f)
        was = f.id in escalated
        d["escalated_by_ratchet"] = was
        d["verdict_before_ratchet"] = "warn" if was else d.get("verdict")
        return d

    payload = {
        "exit_code": result.exit_code,
        "findings": [_finding(f) for f in result.findings],
        "degraded": list(result.degraded),
        "new_ids": list(result.new_ids),
        "stale_overrides": [dataclasses.asdict(s) for s in result.stale_overrides],
        # Always present, even when empty: an ABSENT key means an aramid old
        # enough not to record provenance, an EMPTY one means it looked and
        # found nothing. A consumer diffing two runs has to tell those apart.
        "tools": dict(getattr(result, "tool_provenance", {}) or {}),
        # WHAT RAN, as opposed to `tools` above, which is WHICH BINARY backed
        # the keys that have one. They are not the same question and the
        # provenance map is not a superset: the `tests` slot has no executable
        # named `tests`, so it never appears there however well it ran.
        #
        # Added because a consumer read `tools` as the answer to "did the suite
        # run in this gate?", got two entries where the ledger recorded three,
        # and reasoned from an undercount. Additive on purpose -- renaming
        # `tools` would break anyone already reading the provenance map.
        "tools_ran": sorted(getattr(result, "tools_ran", ()) or ()),
        # null on an ordinary delta scan; a sentence when this run covered more
        # than the delta. A consumer diffing finding counts between two runs
        # cannot otherwise tell a regression from a scope change.
        "scope_widened": getattr(result, "scope_widened", None),
    }
    return json.dumps(payload, indent=2)
