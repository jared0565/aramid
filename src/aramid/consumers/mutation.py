"""Drain-time mutation consumer (Phase 2c-1 spec section 3): mutate the
functions the queue item's commits touched, inside a throwaway git worktree
at the item's head, and report mutants the repo's FULL test suite cannot
kill as WARN-tier test-gap findings.

Two-stage execution (spec decisions table): a targeted pytest kill-run per
mutant (tests/**/test_<module>.py, else -k <module>), then a full-suite
confirmation capped per item -- a survivor is only REPORTED if the full
suite passes on it, so narrow stage-1 selection can never manufacture a
false test-gap finding. pytest runs as [sys.executable, -m, pytest]: the
drain must be PATH-independent (deliberate deviation from runners/tests.py's
bare "pytest" argv). Timeouts are unattributable -- counted, never reported.
Zero tokens; cost stays 0.0 (CPU only, bounded by [mutation] budgets)."""
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

from aramid import config as config_mod
from aramid import detectors, gitutil, mutation
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.fingerprint import compute_fingerprint
from aramid.normalizer import RawFinding
from aramid.runners import tests as tests_runner
from aramid.runners.base import ToolState, run_subprocess, worktree_import_env

NAME = "mutation"
_BASELINE_GIVE_UP = 3   # mirrors llm_review._MALFORMED_GIVE_UP
_TIMEOUT_GIVE_UP = 3    # same threshold, deliberately a DIFFERENT counter
_MISSING_GIVE_UP = 3    # repo-scoped like the timeout family: no commit fixes a path
_LOG_TAIL_LINES = 60    # of stdout and of stderr, in the baseline log


def timeout_note_prefix(budget: float, suite: str) -> str:
    """The note family for "this suite does not fit this budget".

    Public because it is a CONTRACT, not an implementation detail: the
    repo-scoped give-up counter matches notes by this prefix, so the string
    and its inputs are load-bearing in the same way `failing_note_prefix`'s
    are, and the tests assert against it rather than re-typing it.

    Keyed on (suite command, budget) and NOT on the head, which is the entire
    point. A red suite is a property of a commit and a new commit deserves a
    fresh attempt -- that is why the failing-baseline give-up is head-scoped.
    A suite that overruns its budget is a property of the repo's config: no
    commit changes it, so head-scoping that counter means it never latches.

    Those two inputs are also the release valve. The give-up below is
    permanent for as long as the note matches, so it has to stop matching when
    the operator does something about it: raise `baseline_timeout_s`, or point
    `test_command` at a narrower suite, and the prefix changes, the count
    falls to zero, and mutation tries again on the next drain.
    """
    return f"baseline timeout: {suite} did not finish within the {budget:.0f}s budget"


def failing_note_prefix(head: str) -> str:
    """The note family for "the baseline suite is RED at this commit".

    Returns the COMPLETE note rather than a stem, and both the give-up counter
    and the emit site use it verbatim -- so there is no spelling of this note
    that the counter cannot match. That is a deliberate difference from
    `timeout_note_prefix`, whose callers append their own `(last seen @ ...)`;
    that convention predates this one and works, and changing it would be
    unrelated churn on a live contract. Two conventions in one module is worth
    one docstring saying which is which.

    Head-scoped, and load-bearing: a red suite is a property of a commit, so a
    new commit deserves a fresh attempt. Contrast the timeout family, which is
    repo-scoped because no commit ever changes a budget.

    On the grammar -- `(last seen @ <sha>)`, not `@ <sha>`: the sha is honest
    here, this really is a head at which the suite was red. But this note sits
    in the same `status` column as the timeout family directly beneath it, and
    a reader learns the column's grammar from whichever note they meet first.
    A bare `@ <sha>` teaches them to read the sha as causal, which is exactly
    the misreading the timeout reword removed. One grammar down the column.
    """
    return f"baseline failing (last seen @ {head[:12]})"


def missing_note_prefix(argv0: str) -> str:
    """The note family for "the baseline command could not be resolved".

    Distinct from `failing_note_prefix` because the two demand opposite
    responses: a red suite is fixed at a commit, a command that does not
    resolve is fixed in `aramid.toml`. They shared one note for three weeks
    (interop round 174: 43 rows of `baseline failing` in 2-7 s, none of
    which started a process) and the reader was sent looking for a broken
    test that did not exist.

    Repo-scoped, like the timeout family and for the same reason: a path is
    a property of the config and no commit ever resolves one. argv[0] is in
    the prefix as the release valve -- change the command and the count
    falls to zero. The emit site appends the cwd it was resolved from and
    the remedy; the counter matches on this prefix.
    """
    return f"baseline command not found: {argv0}"


_SAFE_STEM = re.compile(r"^[A-Za-z0-9_]+$")
_K_KEYWORDS = {"not", "and", "or"}   # pytest -k expression keywords

# pytest exits 5 for "no tests were collected" -- mirrors
# runners/tests.py's _PYTEST_NO_TESTS_RC. On the BASELINE run (the full-suite
# check at the top of the try block below) this is PERMANENT structural
# absence, the same condition the detect_tests() skip earlier in consume()
# exists for: a repo that has committed to pytest (e.g. a root conftest.py,
# one of Task 1's three positive detect_tests signals) but has no tests to
# run AT THIS HEAD. It is never a transiently failing baseline, so it must
# not share the `failing_note_prefix` note family -- that string is what
# base.prior_note_count's give-up counter matches (see the give-up
# check above the worktree try block), and this rc is not a failure at all.
_PYTEST_NO_TESTS_RC = 5

# M5: batches are budget-truncated (variable membership across drains), so
# the drain normalizes them with occurrence_index pinned to 0 -- one finding
# per (tool, rule, file, line-content), truncation-stable fingerprints.
PIN_OCCURRENCE = True


def _mutant_fp(rel: str, op: str, line: int, lines: list[str]) -> str:
    lc = lines[line - 1] if 0 <= line - 1 < len(lines) else ""
    return compute_fingerprint("mutation", op, rel, lc, 0)


def _recorded_survivor_ids(ledger) -> set:
    """Every recorded survivor this run could prove -- open, or
    `pending_retest` (the gate's optimistic resolve waiting for exactly this
    proof). Reported as `Repaired.examined` on EVERY completed run, claimed
    or not, so the ledger can tell "looked, proved 0" from "never ran"
    (interop round 180).

    Also the set that decides which stage-1 kills are LOAD-BEARING: a kill
    matching none of these changes no state, so it needs no confirmation
    and costs nothing -- almost every kill, which is what keeps confirmation
    affordable. It used to be a separate open-only set, and a survivor the
    gate had moved to `pending_retest` was then the one state a re-test
    could not claim (interop round 188). Never raises: an unreadable ledger
    reads as nothing examined and nothing claimable, the safe direction."""
    try:
        return {fid for fid, rec in ledger.open_findings().items()
                if rec.get("tool") == "mutation"
                and rec.get("status") in ("open", "pending_retest")}
    except Exception:
        return set()


def _new_target() -> dict:
    # `survived_s1` is "survived stage 1 AND the full suite passed on it":
    # the confirm moves a mutant OUT of it on any other outcome (killed_s2,
    # timeouts, errors, unconfirmed), so `killed_s1 + killed_s2 + survived_s1`
    # is exactly the mutants with a verdict (interop round 174, Q3). Keys are
    # additive on `mutation_scores` schema 1; the reader defaults them to 0.
    return {"generated": 0, "killed_s1": 0, "killed_s2": 0, "survived_s1": 0,
            "unconfirmed": 0, "timeouts": 0, "errors": 0,
            "killed_fps": [], "survivor_fps": []}


def _tgt(scores: dict, rel: str, func: str) -> dict:
    key = f"{rel}::{func}"
    t = scores.get(key)
    if t is None:
        t = _new_target()
        scores[key] = t
    return t


def _finalize_scores(scores: dict) -> dict:
    for t in scores.values():
        # Every generated mutant reached a verdict: killed at either stage,
        # or survived the full suite. Timeouts, errors and unconfirmed
        # mutants are the gap that makes a target `(partial)`.
        t["fully_mutated"] = (t["killed_s1"] + t["killed_s2"] + t["survived_s1"]
                              == t["generated"])
    return {"schema": 1, "targets": scores}


def _last_line(res) -> str:
    """The last non-empty line of stderr, else of stdout, else a marker.
    pytest puts its summary on stdout, so stderr alone is often empty;
    a crash before collection puts the traceback on stderr, so stderr
    wins when it has anything."""
    for text in (res.stderr or "", res.raw or ""):
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if lines:
            return lines[-1][:160]
    return "(no output)"


def _tail_log(root: Path, item_id: str, head: str, res) -> None:
    """The last `_LOG_TAIL_LINES` of stdout and of stderr, under
    `.aramid/logs/` beside the gate's own logs, named by item and head so a
    re-run at the same head overwrites rather than accumulates. Best
    effort: a log that cannot be written costs nothing but the log (spec
    section 9, fail-open) -- but says so on stderr, the way the worktree
    cleanup does, rather than vanishing. Only OSError is caught: that is
    the failure this function can legitimately have (a read-only tree, a
    full disk); anything else is a bug and should surface."""
    logs = root / ".aramid" / "logs"
    out = "\n".join((res.raw or "").splitlines()[-_LOG_TAIL_LINES:])
    err = "\n".join((res.stderr or "").splitlines()[-_LOG_TAIL_LINES:])
    body = (f"--- stdout (last {_LOG_TAIL_LINES} lines) ---\n{out}\n"
            f"--- stderr (last {_LOG_TAIL_LINES} lines) ---\n{err}\n")
    try:
        logs.mkdir(parents=True, exist_ok=True)
        (logs / f"mutation-baseline-{item_id}-{head[:12]}.log").write_text(
            body, encoding="utf-8")
    except OSError as exc:
        print(f"aramid: mutation: baseline log not written under {logs}: {exc}",
              file=sys.stderr)


def _is_test_file(rel: str) -> bool:
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if p.startswith("tests/") or "/tests/" in p:
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _stage1_argv(wt: Path, rel: str, cfg=None, root: Path | None = None) -> list[str]:
    module = Path(rel).stem
    tests_dir = wt / "tests"
    if tests_dir.exists():
        hits = sorted(tests_dir.rglob(f"test_{module}.py"))
        if hits:
            return [sys.executable, "-m", "pytest", "-q",
                    *(str(p.relative_to(wt)) for p in hits)]
    if _SAFE_STEM.match(module) and module.lower() not in _K_KEYWORDS:
        return [sys.executable, "-m", "pytest", "-q", "-k", module]
    # Unsafe -k token (pytest keyword / expression-breaking chars): pytest
    # would exit 4 (usage error) and the suite would never run. Full suite
    # is always correct, just slower.
    return _full_argv(cfg, root)


def _suite_label(argv) -> str:
    """How the confirmation suite reads inside a finding's message.

    A survivor is only ever "survived THE SUITE THAT RAN", and that suite is
    `[mutation].test_command`, which is deliberately NOT the whole tree -- the
    baseline is budgeted at `mutant_timeout_s * 4` and this repo's full suite
    does not fit. So a mutant killed only by a test outside that scope is
    reported as surviving, truthfully for the run and misleadingly for the
    reader: "mutant survived" reads as "you have a test gap" when it can also
    mean "the engine never ran your test".

    Measured 2026-08-11: two mutants in `pipeline._resolution_scope` were
    reported as survivors while `tests/integration/test_resolution_scope.py`
    kills both -- the scope is `tests/unit`. Naming the scope in the message is
    what lets a reader tell the two cases apart without re-deriving it.

    Drops the interpreter path and `-m`: they are constant noise, and the
    interpreter is an absolute path that would differ per machine and per
    worktree, making otherwise-identical findings read as different ones.
    """
    return " ".join(p for p in argv[1:] if p != "-m") or "the configured suite"


def _full_argv(cfg=None, root: Path | None = None) -> list[str]:
    """Mutation's whole-suite command: `[mutation].test_command` if the repo
    declares one, else `[tests].command`, else a bare `pytest -q`.

    THE TWO ARE DIFFERENT QUESTIONS and must be separable. `[tests].command`
    answers "what does the gate run before letting a push through", and the
    right answer there is whatever CI runs -- the whole tree. Mutation's
    baseline is bounded: it runs the suite once to establish green, then once
    per stage-2 confirm, all inside `mutant_timeout_s * 4`. Aiming that at a
    ~19-minute tree reproduces the original defect exactly -- 44 drains, zero
    findings, every one reporting "baseline failing" when the truth was "we
    never let it finish".

    This used to hardcode a bare `pytest -q`, ignoring `[tests].command`
    outright, and that single line is why mutation testing never ran on this
    repo: aramid scopes its own suite to `tests/unit` precisely because the
    full tree takes ~1141 s, and the baseline below is budgeted at
    `mutant_timeout_s * 4` = 480 s. The baseline timed out on every attempt --
    38 degraded runs out of 44, zero findings ever -- and reported
    "baseline failing", which reads as "your tests are red" rather than
    "we never let them finish". Honouring the configured command brings it to
    ~305 s, inside the budget with room to spare.

    `runners.tests._argv` is reused rather than reimplemented: it already
    handles the list-or-string form and the POSIX splitting, and a second
    copy of that logic is how the two would drift. `root` is the repo root
    (NOT the worktree): a repo-relative argv[0] is anchored there and
    launched absolute, so it resolves from whatever cwd the drain happens
    to have and inside the throwaway worktree alike (interop round 174).
    """
    if cfg is not None:
        for section, key in (("mutation", "test_command"), ("tests", "command")):
            command = (getattr(cfg, section, None) or {}).get(key)
            if command:
                argv = tests_runner._argv(command, root)
                if argv:
                    return argv
    return [sys.executable, "-m", "pytest", "-q"]


def _survivor_mutant(rel: str, line: int, fid: str, original: str):
    """Regenerate the recorded survivor `fid` from `original` (the file at
    the item's head), or None when nothing at `line` fingerprints to it any
    more -- the line's content moved or changed, which is `gap_addressed` /
    `file_departed`'s case, not this one. Generation is deterministic and
    the fingerprint is keyed on the line's CONTENT, so a match is the same
    mutant an earlier drain tested, not a lookalike."""
    lines = original.splitlines()
    for m in mutation.generate_mutants(original, {line}):
        if _mutant_fp(rel, m.op, m.line, lines) == fid:
            return m
    return None


def _retest_candidates(ledger, root: Path) -> list[tuple[str, str, int]]:
    """(id, file, line) of every mutation survivor worth re-testing -- open,
    or `pending_retest` (the gate's optimistic resolve, waiting for exactly
    this proof) -- oldest first.

    WHY RE-TEST AT ALL. `consume` mutates the python SOURCE in an item's
    range, so a survivor recorded at head N is re-tested only when its own
    module changes again. The ordinary way a survivor dies is that someone
    writes the test -- a change in a TEST file, on a module the range never
    touches -- and that event reached no resolver: `mutant_killed` never got
    a run, and the gate's `gap_addressed` needs a test-stem mapping that
    plain test names do not satisfy (`test_runner_shadow.py` never maps to
    `runners/shadow.py`; killed by perturbation on 2026-08-28, unclosable).
    The suite is the mapping: regenerate the mutant and ask.

    Skips survivors bound by the tracked suppressions file -- an
    `equivalent mutant` entry says "unkillable", and re-testing it would
    spend a full-suite run per drain forever -- and rows without a file and
    line to regenerate from. Never raises: an unreadable ledger yields no
    candidates and an unreadable suppressions file yields no suppressions,
    the permissive answer in each direction, and neither can write a false
    claim -- only spend time.
    """
    try:
        state = ledger.open_findings()
    except Exception:
        return []
    try:
        suppressed = {r.id for r in config_mod.load_suppressions(root)[0]}
    except Exception:
        suppressed = set()
    out: list[tuple[str, str, int]] = []
    for fid, rec in state.items():
        if rec.get("tool") != "mutation" or rec.get("status") not in ("open", "pending_retest"):
            continue
        if fid in suppressed or not rec.get("file") or not rec.get("line"):
            continue
        out.append((fid, str(rec["file"]), int(rec["line"])))
    return out


def consume(item, ctx: DrainContext) -> ConsumerResult:
    mcfg = getattr(ctx.cfg, "mutation", None) or {}
    if not mcfg.get("enabled", True):
        return ConsumerResult(consumer=NAME, state="ok", note="disabled")
    max_mutants = int(mcfg.get("max_mutants", 20))
    wall_budget = float(mcfg.get("wall_budget_s", 600))
    mutant_timeout = float(mcfg.get("mutant_timeout_s", 120))
    confirm_cap = int(mcfg.get("confirm_cap", 3))

    changed = gitutil.diff_new_lines(ctx.root, item.base, item.head)
    files = sorted(f for f in changed
                   if f.endswith(".py") and not _is_test_file(f))
    if ctx.cfg is not None:
        files = config_mod.filter_paths(files, ctx.cfg)
    # A changed TEST is the one event that can newly kill a recorded survivor
    # on a module this range never touched -- see `_retest_candidates`. Only
    # then is an item with no python source in range worth a worktree.
    retest_cap = int(mcfg.get("retest_cap", 3))
    retests = (_retest_candidates(ctx.ledger, ctx.root)
               if mcfg.get("retest_open_survivors", True)
               and any(_is_test_file(f) for f in changed) else [])
    if not files and not retests:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="no python files in range")
    if "pytest" not in detectors.detect_tests(ctx.root):
        # PERMANENT structural absence -> OK with a loud note, NOT degraded:
        # the drain refuses to mark an item drained while any consumer is
        # degraded (2a whole-branch fix), so a JS-only repo would otherwise
        # pin its queue items forever and re-run every consumer each drain.
        # Mirrors llm_review's no-providers-installed skip. (2c-1b seam.)
        return ConsumerResult(consumer=NAME, state="ok",
                              note="no python test stack (mutation skipped)")
    # Hoisted above the worktree: both give-up checks need the suite command
    # and the budget, and neither needs a checkout. `_full_argv` reads config
    # only.
    full_argv = _full_argv(ctx.cfg, ctx.root)
    suite = _suite_label(full_argv)
    # A per-mutant timeout pressed into service as a whole-suite budget is a
    # guess, and for any repo whose suite is genuinely long it is the wrong
    # one. `mutant_timeout_s * 4` stays the default so nothing changes for
    # repos it already fits; `baseline_timeout_s` is the number an operator
    # sets when it doesn't, and the timeout note names it.
    baseline_budget = float(mcfg.get("baseline_timeout_s", mutant_timeout * 4))

    if base.note_count_any_item(
            ctx.ledger, NAME,
            timeout_note_prefix(baseline_budget, suite)) >= _TIMEOUT_GIVE_UP:
        # REPO-scoped and permanent until the config changes -- see
        # `timeout_note_prefix`. Stays `ok` for the same reason the
        # failing-baseline give-up does: `degraded` stops the drain marking the
        # item drained, which would pin the queue and re-run every other
        # consumer on it forever. Loud in `status`, not in the drain state.
        return ConsumerResult(
            consumer=NAME, state="ok",
            note=(f"mutation giving up: {suite} does not fit the "
                  f"{baseline_budget:.0f}s baseline budget after "
                  f"{_TIMEOUT_GIVE_UP} attempts -- raise "
                  f"[mutation].baseline_timeout_s, or point "
                  f"[mutation].test_command at a narrower suite"))

    if base.note_count_any_item(
            ctx.ledger, NAME, missing_note_prefix(full_argv[0])) >= _MISSING_GIVE_UP:
        # Repo-scoped, permanent until the command changes -- the prefix
        # carries argv[0], so editing the config is what releases it. `ok`
        # for the same reason as the two give-ups around it.
        return ConsumerResult(
            consumer=NAME, state="ok",
            note=(f"mutation giving up: {full_argv[0]} not found after "
                  f"{_MISSING_GIVE_UP} attempts -- fix [mutation].test_command "
                  f"or [tests].command"))

    if base.prior_note_count(ctx.ledger, NAME, item.id,
                             failing_note_prefix(item.head)) >= _BASELINE_GIVE_UP:
        # A permanently-red suite must stop pinning the queue item: after 3
        # honest DEGRADED retries AT THIS HEAD this becomes a permanent-skip.
        # Head-scoped (review I2): queue coalescing advances item.head under
        # a stable item.id, and new commits always deserve a fresh baseline
        # try -- only the same code state failing 3x gives up. Keys on the
        # literal note below -- both strings load-bearing.
        return ConsumerResult(consumer=NAME, state="ok",
                              note="mutation giving up: baseline persistently failing")

    started = time.monotonic()
    stats = {"generated": 0, "tested": 0, "killed_s1": 0, "killed_s2": 0,
             "survived": 0, "confirmed": 0, "timeouts": 0, "errors": 0,
             "unconfirmed_kills": 0, "truncated": False,
             "retest_candidates": len(retests), "retested": 0,
             "retest_killed": 0, "retest_truncated": False}
    scores: dict[str, dict] = {}
    examined = _recorded_survivor_ids(ctx.ledger)
    repaired_ids: set = set()
    findings: list[RawFinding] = []
    tmp = Path(tempfile.mkdtemp(prefix="aramid-mut-"))
    wt = tmp / "wt"
    try:
        cp = gitutil._run(ctx.root, "worktree", "add", "--detach", str(wt), item.head)
        if cp.returncode != 0:
            return ConsumerResult(consumer=NAME, state="error",
                                  note=f"worktree add failed: {(cp.stderr or '').strip()[:200]}")

        # A run of the WHOLE configured command gets the whole-command
        # budget; only a TARGETED run gets the per-mutant one. Pointing the
        # confirm below at a ~305 s command inside `mutant_timeout` (120 s)
        # would move the timeout from the baseline to stage 2, where it is
        # counted as an unattributable timeout and emits NO finding -- so
        # mutation would report `ok` with permanently zero findings instead
        # of `degraded`. Healthy-looking and silent is worse than broken
        # and loud, and is the exact failure class this tool exists to stop.
        full_timeout = baseline_budget
        base_res = run_subprocess(full_argv, wt, full_timeout,
                                  env=worktree_import_env(wt))
        if base_res.state is ToolState.MISSING:
            # Nothing ran. Not a red suite (head-scoped, retried per commit)
            # and not a slow one (budget-scoped): a path that does not
            # resolve, which only an `aramid.toml` edit fixes. Names the cwd
            # it was resolved from because that is the variable the reader
            # cannot see -- the scheduled drain's cwd is whatever the
            # scheduler gave it (interop round 174).
            return ConsumerResult(
                consumer=NAME, state="degraded",
                note=(f"{missing_note_prefix(full_argv[0])} (resolved from "
                      f"{Path.cwd()}; set [mutation].test_command or "
                      f"[tests].command to a name on PATH, an absolute path, "
                      f"or a repo-relative path)"),
                duration_s=time.monotonic() - started)
        if base_res.state is ToolState.OK and base_res.returncode == _PYTEST_NO_TESTS_RC:
            # Permanent structural absence, not a failing baseline: the note
            # deliberately keeps the "no python test stack" wording used by
            # the detect_tests() skip above (and is retained by the E2E test
            # asserting on it) even though detect_tests DID find a pytest
            # signal here (e.g. a root conftest.py) -- rc 5 means the suite
            # it detected has nothing to run AT THIS HEAD, which is the same
            # species of absence, just discovered one step later. Accepted
            # trade (per the sub-project 3 brief): a stale `[tests].command`
            # selector or `addopts` that matches nothing would also exit 5
            # here and read as permanent absence rather than misconfigured --
            # cheaper than 3 rounds of worktree churn misdiagnosing it as a
            # red baseline, per the give-up guard's own accepted bound.
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="no python test stack (mutation skipped: "
                                       "pytest collected no tests at this head)",
                                  duration_s=time.monotonic() - started)
        if base_res.state is ToolState.TIMEOUT:
            # A TIMEOUT IS NOT A FAILURE, and merging them is what made this
            # invisible downstream for three days: 11 runs clustered inside 1%
            # of each other -- the signature of a budget, not of a red suite --
            # all reporting "baseline failing", which sends the reader looking
            # for a broken test that does not exist.
            #
            # The two demand opposite responses. A failure is fixed by fixing a
            # test, at a particular commit, so it is head-scoped and retried. A
            # timeout is fixed by changing the budget or the command, is a
            # property of the repo, and no commit will ever clear it -- so it
            # gets its own repo-scoped counter above.
            #
            # The budget is named; the elapsed time deliberately is not. The
            # process was killed AT the budget, so "elapsed" here would just be
            # the budget restated -- a number that looks measured and is not.
            # The real measurement is recorded on the runs that finish, below.
            return ConsumerResult(
                consumer=NAME, state="degraded",
                note=(f"{timeout_note_prefix(baseline_budget, suite)}"
                      f" (last seen @ {item.head[:12]})"),
                duration_s=time.monotonic() - started)
        if base_res.state is not ToolState.OK or base_res.returncode != 0:
            # Note text is load-bearing: the give-up counter above matches it
            # by PREFIX. Both ends call failing_note_prefix so they cannot
            # drift apart, and the suffix is free to say what the counter
            # never needed: the exit code and the last line of output. The
            # tails go to a log beside the gate's own (round 174: three weeks
            # of `baseline failing` with nothing anywhere saying what failed).
            _tail_log(ctx.root, item.id, item.head, base_res)
            return ConsumerResult(
                consumer=NAME, state="degraded",
                note=(f"{failing_note_prefix(item.head)} -- rc "
                      f"{base_res.returncode}: {_last_line(base_res)}"),
                duration_s=time.monotonic() - started)
        # The one run that can actually MEASURE the suite is one that finished.
        # A timeout only ever yields the budget you set, so recording "elapsed"
        # there would be circular; this is the number that tells an operator
        # what to set the budget to.
        baseline_s = float(getattr(base_res, "duration_s", 0.0) or 0.0)

        confirms_used = 0
        done = False
        tested_fps: set[str] = set()

        def _mutate(rel: str, target_lines: set[int], survivor: str | None = None):
            """Generate and test the mutants of `rel` at `target_lines` --
            or, with `survivor`, re-test that ONE recorded survivor,
            regenerated by fingerprint. A re-test walks the identical
            stage-1 / confirm / claim path below; what differs is bookkeeping:
            it is counted as `retested`, never as `generated`, and it leaves
            the range's per-target mutation scores alone (a score is a
            statement about THIS range's mutants, and a survivor from an
            untouched module is not one of them)."""
            nonlocal done, confirms_used
            src_path = wt / rel
            if not src_path.exists():
                return
            try:
                original = src_path.read_text(encoding="utf-8")
            except OSError:
                stats["errors"] += 1
                return
            lines = original.splitlines()
            if survivor is None:
                muts = mutation.generate_mutants(original, target_lines)
                stats["generated"] += len(muts)

                def t_of(func):
                    return _tgt(scores, rel, func)
                for m in muts:
                    t_of(m.func)["generated"] += 1
            else:
                m = _survivor_mutant(rel, next(iter(target_lines)), survivor, original)
                muts = [m] if m is not None else []

                def t_of(func):
                    return _new_target()      # a throwaway: scores untouched
            for m in muts:
                if stats["tested"] >= max_mutants \
                        or time.monotonic() - started > wall_budget:
                    stats["truncated"] = True
                    done = True
                    break
                stats["tested"] += 1
                if survivor is not None:
                    stats["retested"] += 1
                tested_fps.add(_mutant_fp(rel, m.op, m.line, lines))
                try:
                    src_path.write_text(m.source, encoding="utf-8")
                    s1_argv = _stage1_argv(wt, rel, ctx.cfg, ctx.root)
                    s1 = run_subprocess(
                        s1_argv, wt,
                        full_timeout if s1_argv == full_argv else mutant_timeout,
                        env=worktree_import_env(wt))
                    if s1.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                        t_of(m.func)["timeouts"] += 1
                        continue
                    if s1.state is ToolState.OK and s1.returncode in (1, 2):
                        # 1 = test failures; 2 = interrupted/collection error
                        # (an import-breaking mutant genuinely causes 2).
                        stats["killed_s1"] += 1
                        t = t_of(m.func)
                        t["killed_s1"] += 1
                        fp = _mutant_fp(rel, m.op, m.line, lines)
                        t["killed_fps"].append(fp)
                        # A stage-1 kill is a SCORE anywhere else, but here it
                        # would resolve a finding -- so it needs the same
                        # confirmation a survivor needs, for the same reason
                        # and in the other direction. rc 2 is a collection
                        # error, so a test file that merely fails to IMPORT
                        # reads as "the suite killed this", and stage 1
                        # selects exactly one file by module name. Claiming
                        # that as a repair writes a fix that never happened
                        # into an append-only ledger.
                        # `examined`, not "open": a survivor the gate has
                        # already moved to `pending_retest` (gap_addressed)
                        # is waiting for exactly this kill; admitting only
                        # `open` here left that state unclaimable -- the
                        # row read `killed_s1 1` beside `retest_killed 0`
                        # and no yield (interop round 188).
                        if fp in examined:
                            if confirms_used >= confirm_cap:
                                stats["truncated"] = True
                                continue
                            confirms_used += 1
                            s2 = run_subprocess(full_argv, wt, full_timeout,
                                                env=worktree_import_env(wt))
                            if s2.state is ToolState.OK and s2.returncode in (1, 2):
                                repaired_ids.add(fp)
                            else:
                                # Timeout, pass, or a non-verdict outcome: the
                                # narrow selection produced that exit code,
                                # not a new test. No claim -- the finding
                                # stays open, which keeps a real gap visible.
                                stats["unconfirmed_kills"] += 1
                        continue
                    if s1.state is ToolState.OK and s1.returncode not in (0, 5):
                        # 3 = internal error, 4 = usage error: argv's fault,
                        # never the mutant's -- unattributable, like timeouts.
                        stats["errors"] += 1
                        t_of(m.func)["errors"] += 1
                        continue
                    # putative survivor (pass, or exit 5 = nothing selected).
                    # `stats["survived"]` is the item-level count of exactly
                    # that -- passed stage 1 -- and stays so. The per-target
                    # `survived_s1` is the SCORE's term and means "and the
                    # full suite passed on it": every other confirm outcome
                    # below moves the mutant out of it again, otherwise a
                    # confirm that never reached a verdict read downstream as
                    # a survivor, and a full-suite kill as both (round 174).
                    stats["survived"] += 1
                    t = t_of(m.func)
                    t["survived_s1"] += 1
                    if confirms_used >= confirm_cap:
                        # Never confirmed: not a survivor, not a kill, and
                        # not a measurement either.
                        stats["truncated"] = True
                        t["survived_s1"] -= 1
                        t["unconfirmed"] += 1
                        continue
                    confirms_used += 1
                    s2 = run_subprocess(full_argv, wt, full_timeout,
                                        env=worktree_import_env(wt))
                    if s2.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                        t["survived_s1"] -= 1
                        t["timeouts"] += 1
                    elif s2.state is ToolState.OK and s2.returncode == 0:
                        stats["confirmed"] += 1
                        t["survivor_fps"].append(
                            _mutant_fp(rel, m.op, m.line, lines))
                        findings.append(RawFinding(
                            tool="mutation", rule=m.op, severity_raw="medium",
                            file=rel, line=m.line,
                            message=(f"mutant survived: {m.description}"
                                     f" (unkilled by: {_suite_label(full_argv)})")))
                    elif s2.state is ToolState.OK and s2.returncode in (1, 2):
                        stats["killed_s2"] += 1
                        t["survived_s1"] -= 1
                        t["killed_s2"] += 1
                        fp = _mutant_fp(rel, m.op, m.line, lines)
                        t["killed_fps"].append(fp)
                        # Already a full-suite verdict -- this IS the
                        # confirmation the stage-1 branch has to go and buy.
                        repaired_ids.add(fp)
                    else:
                        # Non-verdict full-suite outcome (internal/usage error,
                        # crash): the putative survivor is NOT reported -- a
                        # survivor requires the full suite to PASS on it.
                        stats["errors"] += 1
                        t["survived_s1"] -= 1
                        t["errors"] += 1
                except Exception:
                    stats["errors"] += 1
                finally:
                    # Restore by rewriting the captured original -- equivalent
                    # to the spec's `git checkout -- <file>` with one fewer
                    # subprocess per mutant (sanctioned deviation).
                    try:
                        src_path.write_text(original, encoding="utf-8")
                    except OSError:
                        stats["errors"] += 1
                        t_of(m.func)["errors"] += 1

        for rel in files:
            if done:
                break
            _mutate(rel, changed[rel])

        # The hygiene pass runs LAST so it can never starve the range of its
        # budget, and only over survivors this run did not just test anyway.
        # A re-test spends one stage-1 run and, usually, one full-suite
        # confirmation -- the same price a fresh mutant pays -- so it is
        # capped on its own (`retest_cap`) as well as by the item's budget.
        for fid, rel, line in retests:
            if fid in tested_fps:
                continue
            if done or stats["retested"] >= retest_cap:
                stats["retest_truncated"] = True
                break
            before = len(repaired_ids)
            _mutate(rel, {line}, survivor=fid)
            stats["retest_killed"] += len(repaired_ids) - before
    finally:
        try:
            gitutil._run(ctx.root, "worktree", "remove", "--force", str(wt))
            gitutil._run(ctx.root, "worktree", "prune")
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            print(f"aramid: mutation: worktree cleanup leaked at {wt}",
                  file=sys.stderr)

    if stats["tested"] == 0 and stats["generated"] > 0:
        # CERTIFIED NOTHING. `0 confirmed survivor(s) of 0 mutant(s) tested`
        # is literally true and reads as a clean result, which is how a repo
        # spent 690s per drain generating 18 mutants, testing none, and
        # reporting `ok` with no degraded streak and no stand-down.
        #
        # The cause is structural rather than a bad number: `wall_budget_s`
        # covers the WHOLE item and its clock starts before the baseline, so a
        # baseline that nearly fills it leaves nothing for the mutants it just
        # generated. Raising `baseline_timeout_s` alone makes this MORE likely,
        # not less -- it converts a loud stand-down into this silent success,
        # which is why the two had to be fixed together.
        note = (f"no mutants tested: {stats['generated']} generated, 0 certified"
                f" -- the {wall_budget:.0f}s wall budget covers the whole item and"
                f" the baseline alone took {baseline_s:.0f}s. Raise"
                f" [mutation].wall_budget_s, or point [mutation].test_command at a"
                f" narrower suite.")
    else:
        note = (f"{stats['confirmed']} confirmed survivor(s) of "
                f"{stats['tested']} mutant(s) tested")
        if stats["truncated"]:
            note += " (truncated: budget/cap hit, remainder dropped)"
    if retests:
        # "N of M" rather than N alone: the shortfall is the operator's
        # signal that `retest_cap` or the budget cut the hygiene pass short.
        note += (f"; re-tested {stats['retested']} of {len(retests)} open "
                 f"survivor(s), {stats['retest_killed']} killed")
    extra = dict(stats)
    extra["mutation_scores"] = _finalize_scores(scores)
    # How long the configured suite actually took, measured. Recorded so an
    # operator sizing `baseline_timeout_s` has a real number to size it
    # against rather than doubling the budget until the timeouts stop.
    extra["baseline_s"] = baseline_s
    # A repair claim is a FULL-SUITE-CONFIRMED kill, which is a strictly
    # smaller set than `killed_fps`. `_mutant_fp` is the same
    # `compute_fingerprint` call `normalize` makes for a survivor (same
    # tool/op/path, the line content read at the item's head on both sides,
    # and PIN_OCCURRENCE forcing occurrence 0), so these ids are exactly the
    # ones an earlier drain recorded. Timeouts and errors are unattributable
    # and never get here at all.
    killed = tuple(sorted(repaired_ids))
    # Reported on EVERY completed run, kills or none: `examined` names the
    # recorded survivors this run read, so an empty claim is still a run
    # that looked (consumers.base.Repaired; interop round 180).
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=time.monotonic() - started, cost=0.0,
                          note=note, extra=extra,
                          repaired=base.Repaired(tool="mutation",
                                                 reason="mutant_killed",
                                                 ids=killed,
                                                 examined=tuple(sorted(examined))))


base.CONSUMERS[NAME] = sys.modules[__name__]
