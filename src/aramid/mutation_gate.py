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
from typing import Callable

from aramid import diagnostics, gitutil
from aramid.fingerprint import normalize_path
from aramid.ledger import _resolved_root, note_yield
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
    skipped = 0
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
            skipped += 1
            continue
    diagnostics.note_skipped("mutation-gate", skipped)
    return out


def _maps_to_module(test_stem: str, module_path: str) -> bool:
    """Is `test_stem` a test file basename for the source module at
    `module_path`? Three anchored forms, in the order they were needed:

        test_<module> / <module>_test        the original pair
        test_<parent>_<module>               a module inside a SUBPACKAGE
        test_<module>_<anything>             a test scoped to one aspect

    The last two are not embellishment. `test_<module>.py` alone cannot name a
    test for `consumers/base.py` without colliding with `runners/base.py`, so
    real repos qualify by package -- and a module big enough to mutate usually
    has more than one test file. Measured 2026-08-10 on aramid itself: FOUR of
    five open findings were mutants that the repo's own tests provably kill,
    left open because nothing mapped `test_consumers_base.py` back to
    `consumers/base.py` or `test_doctor_version_parsing.py` back to
    `commands/doctor.py`.

    ANCHORING IS THE WHOLE DESIGN, not a detail. The obvious wider rule --
    "the module name appears as a token of the test name" -- resolves
    `consumers/base.py` from `test_runners_base.py`, because `base` is a stem
    THREE source files share here. Qualifying on the module's own parent
    directory keeps them apart, and prefix-anchoring the suffix form stops
    `test_predoctor_helpers` mapping to `doctor`.

    TWO RESIDUALS, both accepted, both narrower than what they replaced. State
    them rather than discover them:

    1. `test_<stem>_*` cannot tell three `base.py` files apart, so a
       `test_base_*.py` would map to all of them. No such file exists here.
    2. A module whose name is a PREFIX of another module's absorbs the longer
       one's tests. Live in this repo today: `test_mutation_gate.py` maps to
       `mutation.py` as well as to `mutation_gate.py`, and
       `test_mutation_score_gate.py` maps to `mutation_score.py`. Pinned by
       `test_a_longer_modules_test_also_maps_to_the_shorter_prefix_module` so
       it reads as a known cost rather than a surprise.

    Both are the liberal direction this resolver's own docstring licenses: a
    wrong resolve lets a test-gap slip until the re-drain re-reports it. The
    alternative -- full dotted-path matching -- would break the plain
    `test_<module>.py` form that most repos actually use.

    The mapping's other blind spot -- a test whose stem maps to NOTHING
    (`test_runner_shadow.py` for `runners/shadow.py`) -- is not patched here
    with another naming rule. The mutation consumer covers it from the proof
    side: when a test file changes, it regenerates each open survivor from its
    fingerprint and re-runs it, claiming `mutant_killed` only on a confirmed
    kill (`consumers/mutation.py`, `_retest_candidates`). A name is a guess;
    the suite is the answer.
    """
    p = Path(module_path)
    module, parent = p.stem, p.parent.name
    if test_stem in (f"test_{module}", f"{module}_test"):
        return True
    if parent and test_stem == f"test_{parent}_{module}":
        return True
    return test_stem.startswith(f"test_{module}_")


def _has_mapped_test(module_path: str, test_stems) -> bool:
    """Did any of these changed test basenames map to this source module?"""
    return any(_maps_to_module(s, module_path) for s in test_stems)


def auto_resolve_mutation(ledger, run_id: str, at: str, changed_files, *,
                          suppressed=frozenset(),
                          changed_since: Callable[[str], set | None] | None = None
                          ) -> list[str]:
    """Optimistically resolve open mutation findings the push addresses, BEFORE
    the block check (mirrors review.auto_resolve_llm's call site), so a dev who
    added a test is not blocked by a stale finding. Module-mapped (spec 1b §4):
    resolve a finding on x.py iff the push changed x.py OR added/modified a test
    whose basename stem is test_<x>/<x>_test. Liberal by design -- a wrong
    resolve only lets a test-gap slip (never a security hole). Two source
    files sharing a module stem are resolved together by one mapped test -- an
    accepted, low-stakes consequence of module-mapping.

    WHAT THE RESOLVE RECORDS, corrected 2026-08-30. It used to write a bare
    FINDING_RESOLVED, which materializes as `fixed`, on the docstring's
    promise that "the async re-drain is the authoritative backstop". Measured
    on aramid's own ledger: 21 such resolves, 20 never re-examined. The
    backstop was structurally void -- range-mode mutation regenerates only
    mutants on CHANGED lines and the id is content-keyed, so an old id can
    only return through the survivor re-test (consumers/mutation.py,
    `_retest_candidates`), which read `open` rows only. The resolve now
    carries `pending_retest`, which materializes as that status: it does not
    gate (only `open` does), the re-test considers it, a confirmed kill
    closes it as `fixed`, and a re-detect re-opens it. The unblock is kept;
    the false `fixed` is not.

    `suppressed` -- ids bound by the tracked suppressions file. An
    `equivalent mutant` entry says "unkillable, adjudicated": there is no gap
    to address and any resolve for it is a false claim (c5326a9c, written
    `fixed` twice by this function on pushes that touched cli.py). The
    re-test already skips these; the gate now agrees.

    `changed_since` -- ONLY CHANGES AFTER THE GRADED HEAD COUNT, corrected
    2026-09-06. A drain grades an item at its head and records that head on
    each finding (`ledger.record_run(head=...)`). The 14:00Z drain that day
    graded a head carrying a test edit and reported three survivors ON it;
    two seconds into the push of that same head, this function resolved all
    three as gap_addressed, on the strength of the test edit the drain had
    already run against. `changed_since(head)` returns the files changed
    between that head and the push head, or None when it cannot say (the
    head is unknown, not an ancestor, or git failed) -- None, and a record
    with no head at all, keep the liberal rule over the whole push. The
    resolve is still optimistic: it only stops crediting changes the drain
    had already seen."""
    changed_norm = {normalize_path(c) for c in changed_files}
    changed_test_stems = {Path(c).stem for c in changed_files
                          if gitutil.is_test_file(c)}
    resolved = []
    skipped = 0
    considered = 0
    for fid, rec in ledger.open_findings().items():
        if rec.get("tool") != TOOL or rec.get("status") != "open":
            continue
        if fid in suppressed:
            continue
        considered += 1
        try:
            path = rec.get("file", "")
            if not path:
                continue                            # malformed: no file -> skip
            norm, stems = changed_norm, changed_test_stems
            graded = rec.get("head")
            if graded and changed_since is not None:
                delta = changed_since(graded)
                if delta is not None:
                    norm = {normalize_path(c) for c in delta}
                    stems = {Path(c).stem for c in delta if gitutil.is_test_file(c)}
            source_touched = normalize_path(path) in norm
            test_added = _has_mapped_test(path, stems)
            if source_touched or test_added:
                ledger.append(Event(EventType.FINDING_RESOLVED, run_id, at,
                                    finding_id=fid,
                                    payload={"auto_resolved": "gap_addressed",
                                             "pending_retest": True}))
                resolved.append(fid)
        except Exception:
            skipped += 1
            continue
    diagnostics.note_skipped("mutation-resolve", skipped)
    note_yield(ledger, run_id, at, resolver="gap_addressed", tool=TOOL,
               considered=considered, resolved=len(resolved))
    return resolved


def auto_resolve_line_departed(ledger, run_id: str, at: str, *, root) -> list[str]:
    """Resolve mutation survivors whose LINE has left the file: nothing in
    the file at `root` fingerprints to the id any more.

    THE HOLE THIS CLOSES. A survivor's id is (op, path, line content), and
    the drain's re-test regenerates it from that -- every occurrence, from
    the file at the item's head. Content that no longer exists in the file
    regenerates nothing, so the re-test can neither kill the survivor nor
    re-report it, and no other resolver reaches it: `gap_addressed` only
    moves it to `pending_retest` when the push touches the source (which a
    rewrite does), and `file_departed` needs the whole file gone. Two live
    instances on this repo's ledger, 2026-09-07 -- 4031dcd0 and f1c1930d,
    both on a `range(1, ...)` line an edit replaced with `enumerate` --
    `pending_retest` forever, re-tested to nothing every drain. The
    rewritten line's own mutants are graded fresh, under new ids, by the
    drain over the range that rewrote it; the old id carries nothing that
    grading will not re-derive.

    NOT OPTIMISTIC. `gap_addressed` credits a fix it has not seen; this
    reads the file and asks the re-test's own question -- is there a line
    this id could be regenerated from (`_survivor_lines`, the re-test's
    own prefilter) -- which is why it may write a bare `fixed` where
    gap_addressed may only write `pending_retest`. Both `open` and
    `pending_retest` rows are candidates -- the stranded state IS
    pending_retest. Suppressed ids are not skipped: an adjudicated
    equivalent mutant on a line that is gone is gone.

    THE FILE AT HEAD, NOT ON DISK (llm-review 88a4fab2, 2026-09-07). The
    first cut read the working tree, so a survivor's line rewritten on
    disk and never committed cleared a finding -- permanently, `fixed` --
    at pre-push; with `mutation_block_armed` that is a gate bypass (edit,
    push, revert), and the accidental form is a push carrying an unrelated
    uncommitted edit. HEAD is the revision being pushed: what is not
    committed is not there, an untracked file is never read, and a
    COMMITTED rewrite later reverted is re-detected under the same
    content-keyed id by the drain over the revert.

    BY THE HASHES ALONE (llm-review ea21b2a8, same day). Departure is a
    statement about the line's CONTENT. The first cut asked
    `_survivor_mutants`, which reaches `generate_mutants`, which swallows
    SyntaxError and returns [] -- so a file that did not parse (conflict
    markers, a mid-edit save) regenerated nothing and read as departed,
    and EVERY survivor in it was written `fixed` at once. The hashes need
    no parse: a line that is there but cannot be regenerated is left
    alone, like an unknown op.

    SAFE DIRECTION. `root` None is a no-op; a path git has no blob for at
    HEAD -- absent, untracked, or escaping the tree -- is skipped (an
    absent file is `file_departed`'s case, and "no file" is not "no
    line"); a malformed record keeps the finding open. Never raises.

    AN OP THE MUTATOR CANNOT EMIT IS NOT A CANDIDATE. The id is hashed with
    the op NAME. A survivor recorded under a name `mutation.OPS` lacks --
    renamed, retired, or never real -- can be regenerated by nobody, so
    "nothing in the file fingerprints to it" says nothing about the file;
    resolving on it would write `fixed` for every survivor of a renamed op
    at the next push, silently. Left open and not counted as considered.

    COST. One read per distinct file, and `_survivor_mutants` with the
    recorded op hashes the lines before generating anything: a present line
    costs its function's mutants, a departed one costs the hashes alone
    (6 ms on this repo's largest module). Yield is recorded so `aramid
    resolvers` grades it."""
    base = _resolved_root(root)
    if base is None:
        return []
    from aramid.consumers.mutation import _survivor_lines     # circular at module level
    from aramid.mutation import OPS
    resolved: list[str] = []
    considered = 0
    skipped = 0
    sources: dict[str, str | None] = {}
    try:
        state = ledger.open_findings()
    except Exception:
        state = {}
    for fid, rec in state.items():
        try:
            if rec.get("tool") != TOOL or rec.get("status") not in ("open", "pending_retest"):
                continue
            rel = str(rec.get("file") or "")
            op = str(rec.get("rule") or "")
            if not rel or op not in OPS:
                continue
            if rel not in sources:
                sources[rel] = gitutil.blob_at(base, "HEAD", rel)
            source = sources[rel]
            if source is None:
                continue                       # not at HEAD: absent, untracked, or escaped
            considered += 1
            if _survivor_lines(rel, fid, source.splitlines(), op):
                continue                       # still there, somewhere in the file
            ledger.append(Event(EventType.FINDING_RESOLVED, run_id, at, finding_id=fid,
                                payload={"auto_resolved": "line_departed"}))
            resolved.append(fid)
        except Exception:
            skipped += 1
            continue
    diagnostics.note_skipped("line-departed", skipped)
    note_yield(ledger, run_id, at, resolver="line_departed", tool=TOOL,
               considered=considered, resolved=len(resolved))
    return resolved


