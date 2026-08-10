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
_SAFE_STEM = re.compile(r"^[A-Za-z0-9_]+$")
_K_KEYWORDS = {"not", "and", "or"}   # pytest -k expression keywords

# pytest exits 5 for "no tests were collected" -- mirrors
# runners/tests.py's _PYTEST_NO_TESTS_RC. On the BASELINE run (the full-suite
# check at the top of the try block below) this is PERMANENT structural
# absence, the same condition the detect_tests() skip earlier in consume()
# exists for: a repo that has committed to pytest (e.g. a root conftest.py,
# one of Task 1's three positive detect_tests signals) but has no tests to
# run AT THIS HEAD. It is never a transiently failing baseline, so it must
# not share the "baseline failing @ " note family -- that literal prefix is
# what base.prior_note_count's give-up counter matches (see the give-up
# check above the worktree try block), and this rc is not a failure at all.
_PYTEST_NO_TESTS_RC = 5

# M5: batches are budget-truncated (variable membership across drains), so
# the drain normalizes them with occurrence_index pinned to 0 -- one finding
# per (tool, rule, file, line-content), truncation-stable fingerprints.
PIN_OCCURRENCE = True


def _mutant_fp(rel: str, op: str, line: int, lines: list[str]) -> str:
    lc = lines[line - 1] if 0 <= line - 1 < len(lines) else ""
    return compute_fingerprint("mutation", op, rel, lc, 0)


def _open_finding_ids(ledger) -> set:
    """Ids of this producer's currently-OPEN findings.

    Read for one reason only: to know which kills are load-bearing. A kill
    that matches nothing open changes no state, so it needs no confirmation
    and costs nothing -- which is almost every kill, and is what keeps the
    confirmation below affordable. Never raises: an unreadable ledger yields
    an empty set, i.e. no claims, which is the safe direction."""
    try:
        return {fid for fid, rec in ledger.open_findings().items()
                if rec.get("tool") == "mutation" and rec.get("status") == "open"}
    except Exception:
        return set()


def _new_target() -> dict:
    return {"generated": 0, "killed_s1": 0, "survived_s1": 0,
            "timeouts": 0, "errors": 0, "killed_fps": [], "survivor_fps": []}


def _tgt(scores: dict, rel: str, func: str) -> dict:
    key = f"{rel}::{func}"
    t = scores.get(key)
    if t is None:
        t = _new_target()
        scores[key] = t
    return t


def _finalize_scores(scores: dict) -> dict:
    for t in scores.values():
        t["fully_mutated"] = (t["killed_s1"] + t["survived_s1"] == t["generated"])
    return {"schema": 1, "targets": scores}


def _is_test_file(rel: str) -> bool:
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if p.startswith("tests/") or "/tests/" in p:
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _stage1_argv(wt: Path, rel: str, cfg=None) -> list[str]:
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
    return _full_argv(cfg)


def _full_argv(cfg=None) -> list[str]:
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
    copy of that logic is how the two would drift.
    """
    if cfg is not None:
        for section, key in (("mutation", "test_command"), ("tests", "command")):
            command = (getattr(cfg, section, None) or {}).get(key)
            if command:
                argv = tests_runner._argv(command)
                if argv:
                    return argv
    return [sys.executable, "-m", "pytest", "-q"]


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
    if not files:
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
    if base.prior_note_count(ctx.ledger, NAME, item.id,
                             f"baseline failing @ {item.head[:12]}") >= _BASELINE_GIVE_UP:
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
             "unconfirmed_kills": 0, "truncated": False}
    scores: dict[str, dict] = {}
    open_ids = _open_finding_ids(ctx.ledger)
    repaired_ids: set = set()
    findings: list[RawFinding] = []
    tmp = Path(tempfile.mkdtemp(prefix="aramid-mut-"))
    wt = tmp / "wt"
    try:
        cp = gitutil._run(ctx.root, "worktree", "add", "--detach", str(wt), item.head)
        if cp.returncode != 0:
            return ConsumerResult(consumer=NAME, state="error",
                                  note=f"worktree add failed: {(cp.stderr or '').strip()[:200]}")

        full_argv = _full_argv(ctx.cfg)
        # A run of the WHOLE configured command gets the whole-command
        # budget; only a TARGETED run gets the per-mutant one. Pointing the
        # confirm below at a ~305 s command inside `mutant_timeout` (120 s)
        # would move the timeout from the baseline to stage 2, where it is
        # counted as an unattributable timeout and emits NO finding -- so
        # mutation would report `ok` with permanently zero findings instead
        # of `degraded`. Healthy-looking and silent is worse than broken
        # and loud, and is the exact failure class this tool exists to stop.
        full_timeout = mutant_timeout * 4
        base_res = run_subprocess(full_argv, wt, full_timeout,
                                  env=worktree_import_env(wt))
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
        if base_res.state is not ToolState.OK or base_res.returncode != 0:
            # Note text is load-bearing: the give-up counter above matches
            # notes starting with "baseline failing @ <head12>".
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=f"baseline failing @ {item.head[:12]}",
                                  duration_s=time.monotonic() - started)

        confirms_used = 0
        done = False
        for rel in files:
            if done:
                break
            src_path = wt / rel
            if not src_path.exists():
                continue
            try:
                original = src_path.read_text(encoding="utf-8")
            except OSError:
                stats["errors"] += 1
                continue
            muts = mutation.generate_mutants(original, changed[rel])
            stats["generated"] += len(muts)
            lines = original.splitlines()
            for m in muts:
                _tgt(scores, rel, m.func)["generated"] += 1
            for m in muts:
                if stats["tested"] >= max_mutants \
                        or time.monotonic() - started > wall_budget:
                    stats["truncated"] = True
                    done = True
                    break
                stats["tested"] += 1
                try:
                    src_path.write_text(m.source, encoding="utf-8")
                    s1_argv = _stage1_argv(wt, rel, ctx.cfg)
                    s1 = run_subprocess(
                        s1_argv, wt,
                        full_timeout if s1_argv == full_argv else mutant_timeout,
                        env=worktree_import_env(wt))
                    if s1.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                        _tgt(scores, rel, m.func)["timeouts"] += 1
                        continue
                    if s1.state is ToolState.OK and s1.returncode in (1, 2):
                        # 1 = test failures; 2 = interrupted/collection error
                        # (an import-breaking mutant genuinely causes 2).
                        stats["killed_s1"] += 1
                        t = _tgt(scores, rel, m.func)
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
                        if fp in open_ids:
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
                        _tgt(scores, rel, m.func)["errors"] += 1
                        continue
                    # putative survivor (pass, or exit 5 = nothing selected)
                    stats["survived"] += 1
                    _tgt(scores, rel, m.func)["survived_s1"] += 1
                    if confirms_used >= confirm_cap:
                        stats["truncated"] = True
                        continue
                    confirms_used += 1
                    s2 = run_subprocess(full_argv, wt, full_timeout,
                                        env=worktree_import_env(wt))
                    if s2.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                    elif s2.state is ToolState.OK and s2.returncode == 0:
                        stats["confirmed"] += 1
                        _tgt(scores, rel, m.func)["survivor_fps"].append(
                            _mutant_fp(rel, m.op, m.line, lines))
                        findings.append(RawFinding(
                            tool="mutation", rule=m.op, severity_raw="medium",
                            file=rel, line=m.line,
                            message=f"mutant survived: {m.description}"))
                    elif s2.state is ToolState.OK and s2.returncode in (1, 2):
                        stats["killed_s2"] += 1
                        fp = _mutant_fp(rel, m.op, m.line, lines)
                        _tgt(scores, rel, m.func)["killed_fps"].append(fp)
                        # Already a full-suite verdict -- this IS the
                        # confirmation the stage-1 branch has to go and buy.
                        repaired_ids.add(fp)
                    else:
                        # Non-verdict full-suite outcome (internal/usage error,
                        # crash): the putative survivor is NOT reported -- a
                        # survivor requires the full suite to PASS on it.
                        stats["errors"] += 1
                        _tgt(scores, rel, m.func)["errors"] += 1
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
                        _tgt(scores, rel, m.func)["errors"] += 1
    finally:
        try:
            gitutil._run(ctx.root, "worktree", "remove", "--force", str(wt))
            gitutil._run(ctx.root, "worktree", "prune")
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            print(f"aramid: mutation: worktree cleanup leaked at {wt}",
                  file=sys.stderr)

    note = (f"{stats['confirmed']} confirmed survivor(s) of "
            f"{stats['tested']} mutant(s) tested")
    if stats["truncated"]:
        note += " (truncated: budget/cap hit, remainder dropped)"
    extra = dict(stats)
    extra["mutation_scores"] = _finalize_scores(scores)
    # A repair claim is a FULL-SUITE-CONFIRMED kill, which is a strictly
    # smaller set than `killed_fps`. `_mutant_fp` is the same
    # `compute_fingerprint` call `normalize` makes for a survivor (same
    # tool/op/path, the line content read at the item's head on both sides,
    # and PIN_OCCURRENCE forcing occurrence 0), so these ids are exactly the
    # ones an earlier drain recorded. Timeouts and errors are unattributable
    # and never get here at all.
    killed = tuple(sorted(repaired_ids))
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=time.monotonic() - started, cost=0.0,
                          note=note, extra=extra,
                          repaired=base.Repaired(tool="mutation",
                                                 reason="mutant_killed",
                                                 ids=killed) if killed else None)


base.CONSUMERS[NAME] = sys.modules[__name__]
