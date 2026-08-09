"""tests_gate -- ledger-side resolution for the `tests` runner's whole-suite
findings.

WHY IT IS NEEDED. `ledger.record_run` resolves an open finding only when
`rec["tool"] in scope_tools and rec["file"] in scope_files`. The file clause is
correct for its purpose -- at pre-commit `scope_files` is the staged set, and
without it a finding in an unstaged file would resolve merely for not having
been re-scanned. But the tests runner reports every whole-suite finding against
the synthetic marker `<test-suite>` (runners/tests.py), which is not a path and
so can never appear in any scope_files. Those findings were IMMORTAL: once the
suite failed or timed out even once, the finding stayed open forever, across
any number of subsequent green runs. Seen in aramid's own ledger -- detected
2026-07-12, still open weeks later with the suite passing throughout. `tests`
is BLOCK-tier, so that is not a cosmetic wart.

AND THIS RESOLVER WAS BEING UNDERCUT BY A SECOND ROUTE (fixed 2026-08-09).
`record_run` has a third resolve path the sentence above omits: a file that has
LEFT the repo resolves regardless of scope_files. `ledger._departed` judged the
`<test-suite>` marker by asking whether a file of that name exists -- it does
not -- so whenever the tool clause let a suite finding through, `record_run`
cleared it there, several lines before this function was called and WITHOUT the
`suite_completed` evidence below.

Measured rather than argued: the two routes write different payloads, and in
aramid's own ledger 3 of the 4 historical whole-suite resolutions carry an
EMPTY payload (record_run) against 1 carrying `auto_resolved:
suite_completed_clean`. This module was beaten to its own job three times out
of four. The outcomes coincided only by accident of labelling (see the final
paragraph: aramid's own `[tests].command` makes `argv[0]` "python", so "tests
ran OK" and "python in scope_tools" happen to be the same condition); where
they diverge, a suite finding cleared on a run whose suite never executed.
`_departed` now refuses synthetic `<...>` markers outright, so this module is
once again the ONLY thing that can resolve a suite finding.

WHY IT IS A SEPARATE MODULE. Every other producer resolves its own stale
findings from its own domain module (`review.auto_resolve_llm`,
`mutation_gate.auto_resolve_mutation`, `tdd.auto_resolve_tdd`,
`red_proof.auto_resolve_red_proof`). The `tests` producer is a RUNNER -- a pure
subprocess adapter -- and no runner imports the ledger. Putting resolution
there would make it the first to do so, so it lives here instead, mirroring
`mutation_gate.py`.

WHY IT MATCHES ON THE FILE MARKER RATHER THAN ON `tool`. `RunnerResult.tool` is
`Path(argv[0]).name` (runners/base.py), so a genuine failure carries "pytest",
"npm", or -- under a configured `[tests].command` such as aramid's own
`["python", "-m", "pytest", ...]` -- "python". The label "tests" shows up only
where a degraded result was relabelled to the registry name. The marker is the
single stable property shared by exactly the set of findings this exists to
rescue, so matching on it is both narrower and more robust than a tool list
that would silently miss the next spelling.
"""
from aramid.models import Event, EventType
from aramid.runners.tests import _SUITE_FILE_MARKER

SUITE_MARKER = _SUITE_FILE_MARKER


def auto_resolve_tests(ledger, run_id: str, at: str, present_ids,
                       *, suite_completed: bool) -> list[str]:
    """Resolve open whole-suite findings that did not re-fire this run.

    `suite_completed` is load-bearing and deliberately a required keyword: it
    must be True only when the `tests` slot reached ToolState.OK, i.e. the
    suite actually ran to a verdict. runners/tests.py emits `tests-failed` on
    TIMEOUT and CRASHED as well as on a non-zero exit, so "no suite finding in
    this run" on its own does NOT mean the suite passed -- it covers equally
    the case where the runner never got to say. Resolving there would clear a
    BLOCK-tier finding on a run whose suite hung, which is worse than leaving
    it open. The caller derives it from the runner registry key rather than
    from a result's `.tool` label, which varies (see module docstring).

    `present_ids` carries the ids produced by THIS run: a still-failing suite
    re-emits the same id (the marker's line_content is "" either way, so the
    two hash identically), so it is what separates "fixed" from "still broken".

    No blanket try/except here, unlike `auto_resolve_llm`: that one parses
    stored evidence and must survive a malformed record, whereas this reads
    only two plain string fields with `.get`, and swallowing an exception
    would just hide a real ledger fault.
    """
    if not suite_completed:
        return []
    resolved = []
    for fid, rec in ledger.open_findings().items():
        if rec.get("status") != "open" or rec.get("file") != SUITE_MARKER:
            continue
        if fid in present_ids:
            continue
        ledger.append(Event(EventType.FINDING_RESOLVED, run_id, at,
                            finding_id=fid,
                            payload={"auto_resolved": "suite_completed_clean"}))
        resolved.append(fid)
    return resolved
