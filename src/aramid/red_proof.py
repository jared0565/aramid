"""red_proof -- synchronous red-first-proof producer for the pre-push gate
(sub-project 3, spec sections 3-4). The range's changed test files (head
version) are run against a throwaway worktree at the range BASE: a file
whose tests all pass on the pre-change tree was never red, so it proves
nothing about the change -- one WARN-tier RawFinding per such file (tool
"red-proof", rule "test-not-red", line=0 so the fingerprint is stable per
tool+rule+path, the 1a trick).

Per-file verdict (pytest rc on the base tree): 0 -> never-red FINDING;
1/2 -> red proven, feeds proven_red for auto-resolution of any open
red-proof finding on that file (a collection error IS red -- a test
importing a brand-new module fails on base; documented lenient, spec
s10.2-3);
5 -> nothing collected, nothing to prove; timeout/other -> unattributable,
nothing. The whole scan is bounded by [red_proof].wall_budget_s and each
file by test_timeout_s; budget exhaustion skips the remainder silently.

ctx.rng falsy (first-push FULL_HISTORY_RNG, or modes staged/all which pass
rng None) -> no meaningful base -> silent skip. Zero cost when the range
adds no test lines: [] before any worktree or subprocess (that push is
tdd.scan's business, 1a). Head content is materialized via git show
(gitutil.read_blob) -- exact even under a dirty working tree.

Never raises into run_gate (fail-open, the whole-file discipline);
worktree cleanup in finally with the consumers/mutation.py leak-warning
fallback. Limitations (spec s10): whole-file verdict, decided by one pytest
run over the whole file -- an old test in a changed file failing on base
masks a never-red new test, and a fired finding cannot say which test
definition in the file was the one that never went red (recall/attribution
loss, not by itself a false positive); only subject files are materialized
at head, so a new test depending on head changes to non-test files it
imports usually collection-errors -> counts as red; single run, no flake
retries. A separate content gate (T-4, see _new_test_def_lines) requires at
least one changed line to itself be a test-definition line before a subject
is scanned at all (a pure reformat of an already-existing def line counts,
same as a freshly added one -- "changed", not "new") -- before this gate,
subject selection had no content check, so any edit to an already-green
test file (a fixture repair, a comment, a docstring) still triggered a full
base rerun and could produce a genuine false alarm; the gate closes that at
the cost of no longer scanning edits that only strengthen an existing
test's body (a new parametrize case, a tightened assertion) -- recall
traded for soundness, this producer's actual contract, not a compromise of
it.
The base run inherits the repo's own pytest config -- an addopts gate
(coverage thresholds, warnings-as-errors) can force a single-file base run
non-zero regardless of test outcomes, reading as red. As a detector this
stays harmless -- still never a false never-red FINDING -- but as a
resolver it is not: rc 1/2 feeds proven_red, so auto_resolve_red_proof
durably resolves any open red-proof finding on the file (FINDING_RESOLVED),
already true during the disarmed/WARN-only bake, not only once armed.
Unlike tdd's liberal-resolve (self-heals: ledger.py:76 re-detects once a
finding's status is 'fixed'), this does NOT self-heal -- rc 0 is
unreachable under such a gate, so the producer can never re-fire the
fingerprint to reopen the finding.
The base run's import path is forced to the base worktree by
runners.base.worktree_import_env; without it the run imports the INSTALLED
package, which under a pip editable install is the live source the push is
changing -- see that helper for why this inverted the producer rather than
merely adding noise. It was a private `_base_import_env` here until
2026-08-10, with one caller and no tests, which is how consumers/mutation.py
came to carry the identical bug unfixed."""
import ast
import shutil
import sys
import tempfile
import time
from pathlib import Path

from aramid import diagnostics, gitutil
from aramid.fingerprint import normalize_path
from aramid.ledger import note_yield
from aramid.models import Event, EventType
from aramid.normalizer import RawFinding
from aramid.runners.base import ToolState, run_subprocess, worktree_import_env
from aramid.tdd import _split_range

RULE = "test-not-red"
_TOOL = "red-proof"
_MESSAGE = "a changed test-definition line passes against the pre-change tree (never red)"


def _new_test_def_lines(content: str) -> set[int]:
    """T-4 content gate: line numbers of `def`/`async def` NAME lines for
    functions whose name starts with "test", found by walking the real
    `ast` -- never text/regex matching. A regex naively matching a
    `def test_`-shaped line also matches a STRING LITERAL that merely
    CONTAINS that text: T-4's motivating false alarm was a fixture-repair
    commit whose only change was a `write_text(...)` call passing
    '"def test_x():\\n    assert True\\n"' as a plain str argument. A regex
    fires on that; an AST walk cannot, because it only ever yields real
    ast.FunctionDef/AsyncFunctionDef nodes -- a Constant/Str node holding
    that text is never one, no matter what characters it contains, and the
    same goes for a triple-quoted docstring/comment block that merely
    contains def-shaped text.

    node.lineno on a decorated function is the `def` line itself, not the
    decorator's line (true since Python 3.8) -- so a diff that adds a new
    decorator over an already-existing, unchanged def does NOT satisfy this
    gate (the def line itself is untouched context, not a changed line),
    while a diff that adds both a new decorator and the def it decorates
    does, because then the def line is itself newly added.

    Fail-open by construction: unparsable content (SyntaxError, or any
    other parse failure) yields an empty set, i.e. "no test-definition line
    at all" -- the same silent-skip fate as an unreadable blob, never an
    exception escaping into scan_scoped's subject loop. A BOM-prefixed file
    lands here too (a UTF-8 BOM makes ast.parse raise SyntaxError), so a
    legitimately changed test in such a file is silently never scanned --
    correct fail-open behavior, real recall cost (README, Red-first proof
    limitation 8)."""
    try:
        tree = ast.parse(content)
    except Exception:
        return set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
           and node.name.startswith("test"):
            lines.add(node.lineno)
    return lines


def scan_scoped(ctx, cfg) -> tuple[list[RawFinding], set[str]]:
    """Red-first proof for the pre-push range (PRE_PUSH caller-gated, like
    tdd.scan), scoped: returns (findings, proven_red) so callers can
    auto-resolve open red-proof findings on definitively-red files without
    re-running the scan. Fail-open: any error yields no findings -- a broken
    producer must never block a push or crash the gate.

    proven_red contains ONLY files whose base-tree pytest run exited rc 1/2
    (see the loop below). rc 5 (nothing collected), a wall-budget break, and
    a per-file timeout are all deliberately excluded: none of them prove
    anything about the file, they mean "we couldn't tell", not "it's red" --
    resolving an open finding on an inconclusive verdict would silently
    clear a real gap. rc 1/2 is red EXCEPT under an addopts gate, which can
    force it regardless of test outcomes (module docstring) -- the one
    inconclusive case this scoping cannot filter out.

    A subject with no test-*definition* line among its changed lines
    (the T-4 content gate, _new_test_def_lines) never reaches the pytest run
    at all, so it lands in neither out nor proven_red -- from this
    function's return value alone that is indistinguishable from a file the
    wall budget skipped. Both mean only "not scanned this run", never
    "clean"; a push that merely strengthens an existing test's assertion or
    adds a `@pytest.mark.parametrize` case can no longer auto-resolve an
    open red-proof finding on that file this way -- only a push that changes
    a test-definition line can."""
    try:
        rcfg = getattr(cfg, "red_proof", None) or {}
        if not rcfg.get("enabled", True):
            return [], set()
        if not ctx.rng:
            return [], set()       # no meaningful base: first push / staged / all
        wall_budget = float(rcfg.get("wall_budget_s", 120))
        test_timeout = float(rcfg.get("test_timeout_s", 60))
        base, head = _split_range(ctx.rng)
        if base is None:
            return [], set()       # rangeless rng: no base tree to prove against
        in_scope = set(ctx.files)
        new_lines = gitutil.diff_new_lines(ctx.root, base, head)
        subjects = sorted(
            path for path, lines in new_lines.items()
            if lines and gitutil.is_test_file(path) and path in in_scope)
        if not subjects:
            return [], set()       # zero-cost guard: no worktree, no subprocess
        started = time.monotonic()
        out: list[RawFinding] = []
        proven_red: set[str] = set()
        tmp = Path(tempfile.mkdtemp(prefix="aramid-red-"))
        wt = tmp / "wt"
        try:
            cp = gitutil._run(ctx.root, "worktree", "add", "--detach",
                              str(wt), base)
            if cp.returncode != 0:
                return [], set()
            for rel in subjects:
                if time.monotonic() - started > wall_budget:
                    break   # budget exhausted: skip remainder silently
                content = gitutil.read_blob(ctx.root, head, rel)
                if not content:
                    continue        # unreadable/empty head blob: fail-open
                if not (_new_test_def_lines(content) & new_lines[rel]):
                    # T-4 content gate: no test *definition* line among this
                    # subject's changed lines (a pure reformat of an
                    # existing def line counts as "changed" too, same as a
                    # freshly added one) -- skip before the
                    # worktree write/subprocess entirely (fail-open: an
                    # unparsable blob lands here too, via the empty set
                    # _new_test_def_lines returns on SyntaxError). Before
                    # this gate, subject selection had no content check at
                    # all (gitutil.is_test_file matches on path only), so a
                    # fixture repair, a comment, or any other non-test-
                    # adding edit to an already-green test file still
                    # triggered a full whole-file base rerun and could
                    # produce a genuine false alarm -- the bug this gate
                    # closes (T-4). The trade: a new
                    # @pytest.mark.parametrize case on an existing function,
                    # or a strengthened assertion in an existing test, is no
                    # longer scanned either -- not an oversight, but this
                    # producer's own contract (recall loss only, never a
                    # false positive) enforced one layer earlier, before a
                    # subprocess is even spent on it. One resolution-side
                    # consequence follows: such a file can no longer land in
                    # proven_red from this kind of edit, so it can no longer
                    # auto-resolve an open red-proof finding on that file --
                    # only a push that changes a test-definition line can.
                    continue
                dest = wt / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
                res = run_subprocess(
                    [sys.executable, "-m", "pytest", "-q", rel],
                    wt, test_timeout, env=worktree_import_env(wt))
                if res.state is ToolState.OK and res.returncode == 0:
                    out.append(RawFinding(
                        tool=_TOOL, rule=RULE, severity_raw="medium",
                        file=rel, line=0, message=_MESSAGE))
                elif res.state is ToolState.OK and res.returncode in (1, 2):
                    proven_red.add(rel)
                # rc 5: nothing collected. timeout / other rc: unattributable.
                # Neither -> out nor proven_red for those (spec s3.6).
        finally:
            try:
                gitutil._run(ctx.root, "worktree", "remove", "--force", str(wt))
                gitutil._run(ctx.root, "worktree", "prune")
                shutil.rmtree(tmp, ignore_errors=True)
            except Exception:
                print(f"aramid: red-proof: worktree cleanup leaked at {wt}",
                      file=sys.stderr)
        return out, proven_red
    except Exception:
        return [], set()


def scan(ctx, cfg) -> list[RawFinding]:
    """Findings-only view of scan_scoped, preserving the original entry point
    (unit tests and any caller that does not need the resolution scope)."""
    return scan_scoped(ctx, cfg)[0]


def auto_resolve_red_proof(ledger, run_id: str, at: str, proven_red, present_ids) -> list[str]:
    """Resolve open red-proof findings whose file the push definitively
    proved red (mirrors mutation_gate.auto_resolve_mutation and
    tdd.auto_resolve_tdd). proven_red (from scan_scoped) contains ONLY files
    whose base-tree run exited rc 1/2 -- budget-break, rc 5, timeout, and
    (T-4) a subject the content gate skipped before ever running pytest are
    all deliberately excluded there (an inconclusive verdict must never
    silently clear a real gap), so nothing here re-checks the rc taxonomy. That is
    NOT the same as "certainly red": under a repo addopts gate an rc 1/2 can
    be infrastructure rather than a test outcome, and this function then
    durably resolves a still-never-red finding, irreversibly (module
    docstring). Do not add a resolve path that leans on presence in
    proven_red meaning more than "the base run exited rc 1/2".

    present_ids skips anything this run's producer re-fired -- same
    requirement and reason as tdd.auto_resolve_tdd (auto_resolve runs AFTER
    record_run, so a still-never-red file is already re-detected/open by now
    and must not be resolved out from under itself). Never raises into
    run_gate."""
    proven_norm = {normalize_path(p) for p in proven_red}
    resolved = []
    skipped = 0
    considered = 0
    for fid, rec in ledger.open_findings().items():
        if rec.get("tool") != _TOOL or rec.get("status") != "open" \
           or fid in present_ids:
            continue
        considered += 1
        try:
            if normalize_path(rec.get("file", "")) in proven_norm:
                ledger.append(Event(EventType.FINDING_RESOLVED, run_id, at,
                                    finding_id=fid,
                                    payload={"auto_resolved": "red_proven"}))
                resolved.append(fid)
        except Exception:
            skipped += 1
            continue
    diagnostics.note_skipped("red-proof-resolve", skipped)
    note_yield(ledger, run_id, at, resolver="red_proven", tool=_TOOL,
               considered=considered, resolved=len(resolved))
    return resolved
