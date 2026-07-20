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
from aramid.normalizer import RawFinding
from aramid.runners.base import ToolState, run_subprocess

NAME = "mutation"
_BASELINE_GIVE_UP = 3   # mirrors llm_review._MALFORMED_GIVE_UP
_SAFE_STEM = re.compile(r"^[A-Za-z0-9_]+$")
_K_KEYWORDS = {"not", "and", "or"}   # pytest -k expression keywords

# M5: batches are budget-truncated (variable membership across drains), so
# the drain normalizes them with occurrence_index pinned to 0 -- one finding
# per (tool, rule, file, line-content), truncation-stable fingerprints.
PIN_OCCURRENCE = True


def _is_test_file(rel: str) -> bool:
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if p.startswith("tests/") or "/tests/" in p:
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _stage1_argv(wt: Path, rel: str) -> list[str]:
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
    return _full_argv()


def _full_argv() -> list[str]:
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
             "truncated": False}
    findings: list[RawFinding] = []
    tmp = Path(tempfile.mkdtemp(prefix="aramid-mut-"))
    wt = tmp / "wt"
    try:
        cp = gitutil._run(ctx.root, "worktree", "add", "--detach", str(wt), item.head)
        if cp.returncode != 0:
            return ConsumerResult(consumer=NAME, state="error",
                                  note=f"worktree add failed: {(cp.stderr or '').strip()[:200]}")

        base_res = run_subprocess(_full_argv(), wt, mutant_timeout * 4)
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
            for m in muts:
                if stats["tested"] >= max_mutants \
                        or time.monotonic() - started > wall_budget:
                    stats["truncated"] = True
                    done = True
                    break
                stats["tested"] += 1
                try:
                    src_path.write_text(m.source, encoding="utf-8")
                    s1 = run_subprocess(_stage1_argv(wt, rel), wt, mutant_timeout)
                    if s1.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                        continue
                    if s1.state is ToolState.OK and s1.returncode in (1, 2):
                        # 1 = test failures; 2 = interrupted/collection error
                        # (an import-breaking mutant genuinely causes 2).
                        stats["killed_s1"] += 1
                        continue
                    if s1.state is ToolState.OK and s1.returncode not in (0, 5):
                        # 3 = internal error, 4 = usage error: argv's fault,
                        # never the mutant's -- unattributable, like timeouts.
                        stats["errors"] += 1
                        continue
                    # putative survivor (pass, or exit 5 = nothing selected)
                    stats["survived"] += 1
                    if confirms_used >= confirm_cap:
                        stats["truncated"] = True
                        continue
                    confirms_used += 1
                    s2 = run_subprocess(_full_argv(), wt, mutant_timeout)
                    if s2.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                    elif s2.state is ToolState.OK and s2.returncode == 0:
                        stats["confirmed"] += 1
                        findings.append(RawFinding(
                            tool="mutation", rule=m.op, severity_raw="medium",
                            file=rel, line=m.line,
                            message=f"mutant survived: {m.description}"))
                    elif s2.state is ToolState.OK and s2.returncode in (1, 2):
                        stats["killed_s2"] += 1
                    else:
                        # Non-verdict full-suite outcome (internal/usage error,
                        # crash): the putative survivor is NOT reported -- a
                        # survivor requires the full suite to PASS on it.
                        stats["errors"] += 1
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
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=time.monotonic() - started, cost=0.0,
                          note=note, extra=dict(stats))


base.CONSUMERS[NAME] = sys.modules[__name__]
