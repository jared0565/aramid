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
from aramid.consumers import base, mutation
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.fingerprint import compute_fingerprint
from aramid.normalizer import RawFinding
from aramid.runners.base import ToolState, run_subprocess

NAME = "js_mutation"
# The string the FINDINGS carry, which is NOT `NAME` -- note the hyphen. Both
# spellings are load-bearing and they are not interchangeable: a repair claim
# tagged "js_mutation" would match no open finding and report success doing it.
TOOL = "js-mutation"
_BASELINE_GIVE_UP = 3
_LINK_GIVE_UP = 3
_TIMEOUT_GIVE_UP = 3
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

# See consumers/mutation.py: budget-truncated batches -> pin occurrence_index 0.
PIN_OCCURRENCE = True


def link_note_prefix(head: str) -> str:
    """Stem of the "could not link node_modules into the worktree" family.

    A true stem, unlike `mutation.failing_note_prefix`: the emit site appends
    `: <exc>`, so the give-up counter matches a prefix of a longer note.

    Head-scoped for the same reason the failing-baseline family is -- a link
    failure can be a property of this checkout -- and worded to the same
    `(last seen @ ...)` grammar, because this note shares the `status` column
    with the other two and the whole point of that grammar is that the column
    reads consistently. See `mutation.failing_note_prefix`.
    """
    return f"node_modules link failing (last seen @ {head[:12]})"


def _is_test_file(rel: str) -> bool:
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if "__tests__/" in p:
        return True
    stem = name.rsplit(".", 1)[0].lower()
    return stem.endswith(".test") or stem.endswith(".spec")


def _mutant_fp(rel: str, op: str, line: int, lines: list[str]) -> str:
    """The id a survivor of THIS mutant would carry.

    Deliberately the same `compute_fingerprint` call `normalizer.normalize`
    makes for the RawFinding this consumer emits: same tool/op/path, the line
    content read at the item's head on both sides (the worktree is a checkout
    of that head), and PIN_OCCURRENCE forcing occurrence 0. That equality is
    what lets a kill be matched against a finding an earlier drain recorded --
    and it is pinned by the end-to-end drain test, not by any test that reads
    both sides from here.
    """
    lc = lines[line - 1] if 0 <= line - 1 < len(lines) else ""
    return compute_fingerprint(TOOL, op, rel, lc, 0)


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
        # S603/S607 justification: `mklink` is a cmd.exe BUILTIN, so there is
        # no executable to name by absolute path -- `cmd /c` is the only way
        # to invoke it, and cmd.exe is resolved from PATH on every Windows
        # host. argv is a fixed list; both paths are ones aramid constructed
        # itself (the worktree it just created and the source node_modules),
        # passed as separate argv entries rather than a shell string.
        cp = subprocess.run(["cmd", "/c", "mklink", "/J", str(dst_nm), str(src_nm)],  # noqa: S603,S607
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

    # Same split as consumers/mutation.py, and it reuses that module's
    # `timeout_note_prefix` rather than restating the format: this consumer was
    # cloned from the Python one and inherited the exact defect -- a TIMEOUT
    # merged into the failing-baseline branch below. Only the Python path was
    # exercised downstream, so fixing that one alone would have left the same
    # bug armed here with nothing to find it.
    baseline_budget = float(mcfg.get("baseline_timeout_s", mutant_timeout * 4))
    suite = " ".join(test_argv)

    if base.note_count_any_item(
            ctx.ledger, NAME,
            mutation.timeout_note_prefix(baseline_budget, suite)) >= _TIMEOUT_GIVE_UP:
        return ConsumerResult(
            consumer=NAME, state="ok",
            note=(f"js mutation giving up: {suite} does not fit the "
                  f"{baseline_budget:.0f}s baseline budget after "
                  f"{_TIMEOUT_GIVE_UP} attempts -- raise "
                  f"[js_mutation].baseline_timeout_s"))

    if base.prior_note_count(ctx.ledger, NAME, item.id,
                             mutation.failing_note_prefix(item.head)) >= _BASELINE_GIVE_UP:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="js mutation giving up: baseline persistently failing")

    if base.prior_note_count(ctx.ledger, NAME, item.id,
                             link_note_prefix(item.head)) >= _LINK_GIVE_UP:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="js mutation giving up: node_modules link persistently failing")

    started = time.monotonic()
    stats = {"generated": 0, "tested": 0, "killed": 0, "survived": 0,
             "timeouts": 0, "errors": 0, "unconfirmed_kills": 0,
             "killed_fps": [], "truncated": False}
    open_ids = set(base.open_findings_for(ctx.ledger, TOOL))
    repaired_ids: tuple = ()
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
            # Load-bearing prefix: the give-up counter matches note.startswith(prefix).
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=f"{link_note_prefix(item.head)}: {str(exc)[:150]}",
                                  duration_s=time.monotonic() - started)

        base_res = run_subprocess(test_argv, wt, baseline_budget)
        if base_res.state is ToolState.TIMEOUT:
            # A timeout is a property of the repo's suite and budget, not of
            # this commit -- see consumers/mutation.py for the full account.
            return ConsumerResult(
                consumer=NAME, state="degraded",
                note=(f"{mutation.timeout_note_prefix(baseline_budget, suite)}"
                      f" (last seen @ {item.head[:12]})"),
                duration_s=time.monotonic() - started)
        if base_res.state is not ToolState.OK or base_res.returncode != 0:
            # Load-bearing note prefix: the give-up counter matches it. Shared
            # with the Python consumer so the two cannot drift apart.
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=mutation.failing_note_prefix(item.head),
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
                        stats["killed_fps"].append(
                            _mutant_fp(rel, m.op, m.line, original.splitlines()))
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

        # A kill only has to be confirmed when it would RESOLVE something --
        # almost never, so the confirming run below is almost never paid for.
        #
        # Single-stage means `<pm> test` already IS the full suite, so unlike
        # the python consumer there is no narrow-selection doubt about the kill
        # itself. The doubt is the ENVIRONMENT: if the node_modules junction or
        # node dies mid-run, every remaining mutant exits non-zero and reads as
        # killed, and claiming those would write a fix that never happened for
        # every open finding at once. The opening baseline proved health at the
        # start; this proves it at the end, on the restored tree.
        #
        # Residual, stated rather than hidden: an environment that broke and
        # then recovered passes both ends. Bounding that would cost one run per
        # claim and still not be airtight, so it is accepted and counted.
        claimable = sorted({fp for fp in stats["killed_fps"] if fp in open_ids})
        if claimable:
            final = run_subprocess(test_argv, wt, mutant_timeout * 4)
            if final.state is ToolState.OK and final.returncode == 0:
                repaired_ids = tuple(claimable)
            else:
                stats["unconfirmed_kills"] = len(claimable)
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
    # Reported on EVERY completed run, kills or none: `examined` names the
    # open findings this run read, so an empty claim is still a run that
    # looked (consumers.base.Repaired; interop round 180).
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=time.monotonic() - started, cost=0.0,
                          note=note, extra=dict(stats),
                          repaired=base.Repaired(tool=TOOL, reason="mutant_killed",
                                                 ids=repaired_ids,
                                                 examined=tuple(sorted(open_ids))))


base.CONSUMERS[NAME] = sys.modules[__name__]
