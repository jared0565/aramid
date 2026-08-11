"""resolvers -- read-only report on what each auto-resolver SAW, not only on
what it cleared. Never mutates the ledger, never runs a gate.

WHY THIS EXISTS. A resolution writes itself into the ledger; a non-resolution
writes nothing. So a resolver that examined a hundred candidates and declined
them all leaves exactly the same trace as one that was never called -- none --
and those two want opposite responses from whoever is reading. Four times in
this repo the second wore the first's clothes, and every one of them was found
by hand, once, by someone who happened to count:

  * `gap_addressed` at ZERO lifetime fires with eleven open mutation findings.
    `[hooks].pre_push_match_ci` runs the shim with `--all`, `--all` means mode
    "all", and every range-scoped resolver sat behind `if mode == "range"`.
    The CI-parity opt-in was a silent off-switch for all auto-resolution.
  * `.aramid-suppressions.toml` binding nothing for three synthesized
    producers, and not reporting itself stale in either direction.
  * The module-mapped test rule reaching no subpackage module.
  * `js-mutation`, `fuzz` and `dast` with no resolver of any kind, so a
    genuine repair cleared nothing at all.

`ledger.note_yield` records the missing half. This module grades it.

THE GRADING IS THE PRODUCT, not the counting. Two rows in this repo's own
ledger both read zero:

    mutant_killed  0 fires   <- no js-mutation findings exist here
    gap_addressed  0 fires   <- eleven candidates walked past it

Print those the same and the report is noise, nobody reads it, and the
detector for silent no-ops is one. Each row is therefore graded against what
was AVAILABLE to it -- see `_grade`.
"""
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

from aramid.ledger import Ledger
from aramid.models import EventType
from aramid.tests_gate import SUITE_MARKER

# Grades. Upper-case is a defect; lower-case is a state a healthy repo sits
# in routinely. Keeping the two visually separable is not cosmetic -- a report
# that flags normality gets muted, and a muted report detects nothing.
NO_DATA = "no data"
NO_OPPORTUNITY = "no opportunity"
NO_CLEARS = "no clears yet"
LIVE = "live"
NOT_INSTRUMENTED = "not instrumented"
NEVER_RAN = "NEVER RAN"
BLIND = "BLIND"

# ONLY MECHANISM FAULTS ARE DEFECTS. `NEVER RAN` and `BLIND` both say the
# resolver could not have worked -- it was not called, or its filter matches
# nothing. "Saw candidates and cleared none" is an OUTCOME, and outcomes are
# confounded: overwhelmingly it means the findings have not been fixed, which
# is not a fault in the gate.
#
# That is measured, not argued. Replaying one real gate's worth of yields over
# a copy of this repo's live ledger graded three rows as defects on a healthy
# tree -- two of them `.aramid-suppressions.toml` entries carrying proof that
# their mutants are already dead. A suppression binds by ID at report time and
# does NOT flip ledger status, so those findings stay open and no resolver
# will ever clear them, by design. Flagging that is a permanent false alarm on
# the tool's own repository, and a report that cries wolf on day one is a
# report nobody reads -- the exact failure this module exists to end.
_DEFECTS = frozenset({NEVER_RAN, BLIND})


def _by_tool(name: str) -> Callable[[dict], bool]:
    return lambda rec: rec.get("tool") == name


def _by_file(marker: str) -> Callable[[dict], bool]:
    return lambda rec: rec.get("file") == marker


@dataclass(frozen=True)
class _Spec:
    resolver: str          # the `auto_resolved` reason literal it writes
    tool: str              # the producer whose findings it clears
    match: Callable[[dict], bool]   # how to find that producer's findings


# THE REGISTRY DECIDES WHICH ROWS EXIST, not the observed events. A resolver
# that stops emitting must still get a row -- that silence IS the signal, and
# a report built from what it happened to see could never show it.
#
# Keyed on (resolver, tool) rather than resolver alone because two of these
# are emitted once per opted-in producer: `file_departed` runs for each name
# in `pipeline.run_gate`'s tuple, and `resolve_repaired` carries whichever
# producer claimed the repair. Collapsing them would average a dead pairing
# into a live one.
_SPECS = (
    _Spec("gap_addressed", "mutation", _by_tool("mutation")),
    _Spec("test_added", "tdd", _by_tool("tdd")),
    _Spec("red_proven", "red-proof", _by_tool("red-proof")),
    _Spec("evidence_gone", "llm-review", _by_tool("llm-review")),
    # Keyed on the runner SLOT and joined through the marker, because a suite
    # finding's tool is the test command's argv[0] -- "python" in this repo,
    # anything at all in another. Joining on the label would grade this row
    # `no data` everywhere, permanently, which is the failure mode the whole
    # module is about.
    _Spec("suite_completed_clean", "tests", _by_file(SUITE_MARKER)),
    _Spec("file_departed", "mutation", _by_tool("mutation")),
    _Spec("file_departed", "tdd", _by_tool("tdd")),
    _Spec("file_departed", "red-proof", _by_tool("red-proof")),
    _Spec("mutant_killed", "js-mutation", _by_tool("js-mutation")),
    _Spec("crash_not_reproduced", "fuzz", _by_tool("fuzz")),
    _Spec("endpoint_reprobed", "dast", _by_tool("dast")),
)

EXPECTED = tuple((s.resolver, s.tool) for s in _SPECS)


@dataclass(frozen=True)
class Row:
    resolver: str
    tool: str
    runs: int          # yield events seen -- 0 means the resolver never ran
    considered: int    # candidates it walked, summed over those runs
    resolved: int      # of those, how many it cleared
    volume: int        # findings this producer has EVER filed
    open_now: int      # ...and how many are open at report time
    verdict: str

    @property
    def flagged(self) -> bool:
        return self.verdict in _DEFECTS


def _grade(runs: int, considered: int, resolved: int,
           volume: int, open_now: int) -> str:
    """Six answers, and the two joins that keep them apart.

    `volume` (lifetime) answers NEVER RAN: has this producer ever filed
    anything for the resolver to have missed? `open_now` answers BLIND: is
    there anything here RIGHT NOW that it should have seen? They are
    deliberately different questions. Using lifetime volume for BLIND would
    flag every producer whose findings were all legitimately fixed; using the
    open count for NEVER RAN would miss a resolver that was dead for months
    and whose backlog someone has since cleared by hand.

    BLIND is a grade of its own because counting clears structurally cannot
    catch a filter that matches nothing: no candidates means `resolved == 0`
    is never even reached. A resolver keyed on tool "llm" against findings
    labelled "llm-review" would run forever, consider nothing, and look
    healthy.
    """
    if runs == 0:
        return NEVER_RAN if volume > 0 else NO_DATA
    if considered == 0:
        return BLIND if open_now > 0 else NO_OPPORTUNITY
    return NO_CLEARS if resolved == 0 else LIVE


def collect(ledger: Ledger) -> list[Row]:
    """One row per registered (resolver, producer) pair, in registry order."""
    seen: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0])
    for e in ledger.events():
        if e.type is not EventType.RESOLVER_YIELD:
            continue
        key = (e.payload.get("resolver", ""), e.payload.get("tool", ""))
        acc = seen[key]
        acc[0] += 1
        acc[1] += int(e.payload.get("considered", 0) or 0)
        acc[2] += int(e.payload.get("resolved", 0) or 0)

    # A LEDGER PREDATING THE INSTRUMENTATION IS NOT A REPO WITH ELEVEN DEAD
    # RESOLVERS. Measured on this repo's own ledger the day it shipped: eight
    # rows graded NEVER RAN, `evidence_gone` among them -- and that same
    # ledger records `evidence_gone` firing twelve times. The grades were
    # right about the events and wrong about the world.
    #
    # Zero yield events of ANY kind is the discriminator, and it is safe only
    # because the instrumentation is all-or-nothing: a single gate run emits
    # several, from resolvers that do not know about each other. So this
    # amnesty ends at the first gate run and cannot mask a resolver that dies
    # later -- it forgives an un-instrumented LEDGER, never an
    # un-instrumented RESOLVER. A report whose first output is eleven false
    # alarms is a report that gets muted on day one, and a muted detector
    # detects nothing.
    instrumented = bool(seen)

    state = ledger.open_findings()
    rows = []
    for spec in _SPECS:
        runs, considered, resolved = seen[(spec.resolver, spec.tool)]
        matched = [rec for rec in state.values() if spec.match(rec)]
        volume = len(matched)
        open_now = sum(1 for rec in matched if rec.get("status") == "open")
        verdict = (_grade(runs, considered, resolved, volume, open_now)
                   if instrumented else NOT_INSTRUMENTED)
        rows.append(Row(spec.resolver, spec.tool, runs, considered, resolved,
                        volume, open_now, verdict))
    return rows


def _line(row: Row) -> str:
    detail = f"{row.runs} run{'' if row.runs == 1 else 's'}"
    if row.runs:
        detail += f", {row.considered} considered, {row.resolved} resolved"
    if row.volume:
        detail += f"   [{row.open_now} open, {row.volume} ever]"
    return f"  {row.verdict:<14} {row.resolver:<21} {row.tool:<12} {detail}"


def render(rows: list[Row]) -> str:
    """Defects first and in full. A flagged row without the numbers behind it
    is an accusation the reader cannot check, and the healthy rows are printed
    too so that "this resolver is fine" is a visible answer rather than an
    absence."""
    flagged = [r for r in rows if r.flagged]
    out = ["resolver yield -- what each auto-resolver saw, not only what it cleared",
           ""]
    out += [_line(r) for r in flagged]
    if flagged:
        out.append("")
    out += [_line(r) for r in rows if not r.flagged]
    out.append("")
    if rows and all(r.verdict == NOT_INSTRUMENTED for r in rows):
        out.append("no yield data recorded yet -- every grade above is pending "
                   "the next gate run, which is what records it.")
    elif flagged:
        out.append(f"{len(flagged)} of {len(rows)} resolvers flagged. "
                   "NEVER RAN = no yield events while its producer has findings; "
                   "BLIND = ran but matched nothing while findings are open. "
                   "`no clears yet` is not a defect -- it usually means the "
                   "findings have not been fixed.")
    else:
        out.append(f"no resolver defects ({len(rows)} resolvers graded).")
    return "\n".join(out)
