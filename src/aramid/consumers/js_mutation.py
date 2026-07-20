"""Drain-time JS/TS mutation consumer (2c-1b spec). Mutate the lines the queue
item's commits touched, inside a throwaway git worktree at the item's head with
the main repo's node_modules junctioned in, and report mutants the repo's own
`<pm> test` cannot kill as WARN-tier test-gap findings.

Single-stage (spec section 5): JS test runners have no portable "narrow to
module" flag, so `<pm> test` runs the FULL suite once per mutant -- a full-suite
PASS on a mutant IS a confirmed survivor. Mirrors consumers/mutation.py
otherwise (worktree at head, baseline give-up, WARN survivors, cost 0.0). Zero
tokens. OK-not-degraded for structural absence so a non-JS repo never pins the
queue item."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from aramid import config as config_mod
from aramid import detectors, gitutil, jsmutate
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.normalizer import RawFinding
from aramid.runners.base import ToolState, run_subprocess

NAME = "js_mutation"
_BASELINE_GIVE_UP = 3
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

# See consumers/mutation.py: budget-truncated batches -> pin occurrence_index 0.
PIN_OCCURRENCE = True


def _is_test_file(rel: str) -> bool:
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if "__tests__/" in p:
        return True
    stem = name.rsplit(".", 1)[0].lower()
    return stem.endswith(".test") or stem.endswith(".spec")


def _pm_test_argv(pm: str) -> list[str] | None:
    """Resolve `<pm> test` to a runnable argv, or None if the pm binary is not
    on PATH. shutil.which finds the `.cmd` shim on Windows (npm.cmd/pnpm.cmd/
    yarn.cmd) -- mirrors eslint/typecheck's Windows-aware binary resolution."""
    binp = shutil.which(pm)
    if binp is None:
        return None
    return [binp, "test"]


def _link_node_modules(src_root: Path, wt: Path) -> bool:
    """Junction (Windows) / symlink (Unix) src_root/node_modules into the
    worktree so `<pm> test` resolves deps. Returns False if the source has no
    node_modules; raises OSError on a link failure."""
    src_nm = src_root / "node_modules"
    if not src_nm.exists():
        return False
    dst_nm = wt / "node_modules"
    if sys.platform == "win32":
        cp = subprocess.run(["cmd", "/c", "mklink", "/J", str(dst_nm), str(src_nm)],
                            capture_output=True, text=True)
        if cp.returncode != 0:
            raise OSError(f"mklink /J failed: {(cp.stderr or '').strip()[:200]}")
    else:
        os.symlink(src_nm, dst_nm, target_is_directory=True)
    return True


def _unlink_node_modules(wt: Path) -> None:
    """Remove ONLY the link, never its target (invariant #7). Must run BEFORE
    the worktree directory is removed, or shutil.rmtree could follow the
    junction into the real node_modules."""
    dst = wt / "node_modules"
    try:
        if not dst.exists() and not dst.is_symlink():
            return
    except OSError:
        pass
    try:
        dst.unlink()          # Unix symlink
    except (OSError, PermissionError):
        try:
            os.rmdir(dst)     # Windows junction: unlinks the reparse point only
        except OSError:
            pass


def consume(item, ctx: DrainContext) -> ConsumerResult:
    mcfg = getattr(ctx.cfg, "js_mutation", None) or {}
    if not mcfg.get("enabled", True):
        return ConsumerResult(consumer=NAME, state="ok", note="disabled")
    max_mutants = int(mcfg.get("max_mutants", 20))
    wall_budget = float(mcfg.get("wall_budget_s", 600))
    mutant_timeout = float(mcfg.get("mutant_timeout_s", 120))

    changed = gitutil.diff_new_lines(ctx.root, item.base, item.head)
    files = sorted(f for f in changed
                   if f.lower().endswith(_JS_SUFFIXES) and not _is_test_file(f))
    if ctx.cfg is not None:
        files = config_mod.filter_paths(files, ctx.cfg)
    if not files:
        return ConsumerResult(consumer=NAME, state="ok", note="no js files in range")

    if "npm" not in detectors.detect_tests(ctx.root):
        # PERMANENT structural absence -> OK, never degraded (the drain refuses
        # to mark an item drained while any consumer is degraded). The 2c-1b
        # seam, mirroring the Python consumer's pytest gate.
        return ConsumerResult(consumer=NAME, state="ok",
                              note="no js test stack (mutation skipped)")

    pm = detectors.detect_package_manager(ctx.root) or "npm"
    test_argv = _pm_test_argv(pm)
    if test_argv is None:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="js package manager not found (mutation skipped)")
    if not (ctx.root / "node_modules").exists():
        return ConsumerResult(consumer=NAME, state="ok",
                              note="node_modules not installed (js mutation skipped)")

    if base.prior_note_count(ctx.ledger, NAME, item.id,
                             f"baseline failing @ {item.head[:12]}") >= _BASELINE_GIVE_UP:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="js mutation giving up: baseline persistently failing")

    started = time.monotonic()
    stats = {"generated": 0, "tested": 0, "killed": 0, "survived": 0,
             "timeouts": 0, "errors": 0, "truncated": False}
    findings: list[RawFinding] = []
    tmp = Path(tempfile.mkdtemp(prefix="aramid-jsmut-"))
    wt = tmp / "wt"
    linked = False
    try:
        cp = gitutil._run(ctx.root, "worktree", "add", "--detach", str(wt), item.head)
        if cp.returncode != 0:
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=f"worktree add failed: {(cp.stderr or '').strip()[:200]}")
        try:
            linked = _link_node_modules(ctx.root, wt)
        except OSError as exc:
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=f"could not link node_modules: {str(exc)[:150]}",
                                  duration_s=time.monotonic() - started)

        base_res = run_subprocess(test_argv, wt, mutant_timeout * 4)
        if base_res.state is not ToolState.OK or base_res.returncode != 0:
            # Load-bearing note prefix: the give-up counter matches it.
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=f"baseline failing @ {item.head[:12]}",
                                  duration_s=time.monotonic() - started)

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
            try:
                muts = jsmutate.generate_mutants(original, changed[rel])
            except Exception:
                stats["errors"] += 1
                continue
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
                    res = run_subprocess(test_argv, wt, mutant_timeout)
                    if res.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                    elif res.state is ToolState.OK and res.returncode == 0:
                        # Full suite PASSED with the mutant applied -> confirmed
                        # survivor (single stage IS the full suite).
                        stats["survived"] += 1
                        findings.append(RawFinding(
                            tool="js-mutation", rule=m.op, severity_raw="medium",
                            file=rel, line=m.line,
                            message=f"mutant survived: {m.description}"))
                    elif res.state is ToolState.OK:
                        # non-zero exit -> the suite (or compile) failed -> killed
                        stats["killed"] += 1
                    else:
                        # MISSING/CRASHED mid-run: unattributable, not a survivor
                        stats["errors"] += 1
                except Exception:
                    stats["errors"] += 1
                finally:
                    try:
                        src_path.write_text(original, encoding="utf-8")
                    except OSError:
                        stats["errors"] += 1
    finally:
        try:
            if linked:
                _unlink_node_modules(wt)   # BEFORE removing the worktree dir
            gitutil._run(ctx.root, "worktree", "remove", "--force", str(wt))
            gitutil._run(ctx.root, "worktree", "prune")
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            print(f"aramid: js_mutation: worktree cleanup leaked at {wt}", file=sys.stderr)

    note = f"{stats['survived']} survivor(s) of {stats['tested']} mutant(s) tested"
    if stats["truncated"]:
        note += " (truncated: budget/cap hit, remainder dropped)"
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=time.monotonic() - started, cost=0.0,
                          note=note, extra=dict(stats))


base.CONSUMERS[NAME] = sys.modules[__name__]
