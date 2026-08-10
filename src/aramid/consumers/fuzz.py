"""Drain-time fuzz consumer (Phase 2c-2 spec section 4): call the top-level
type-hinted functions the queue item's commits touched with deterministic
seeded inputs, inside a throwaway git worktree at the item's head, and report
DEEP-CRASH exceptions as WARN-tier findings.

Candidacy is AST-only here (top-level def overlapping a changed line, not
async, not scary-named); the driver subprocess re-checks type hints at import
time and skips what it cannot fuzz. All calling happens in the driver, never
in this process -- the worktree + subprocess boundary is the safety line.
Zero tokens; cost stays 0.0 (CPU only, bounded by [fuzz] budgets)."""
import ast
import fnmatch
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

from aramid import config as config_mod
from aramid import gitutil
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.fingerprint import compute_fingerprint
from aramid.normalizer import RawFinding
from aramid.runners.base import ToolState, run_subprocess

NAME = "fuzz"
TOOL = "fuzz"

# M5: batches are budget-truncated (variable membership across drains), so
# the drain normalizes them with occurrence_index pinned to 0 -- one finding
# per (tool, rule, file, line-content), truncation-stable fingerprints.
PIN_OCCURRENCE = True

# The message prefix is LOAD-BEARING, not cosmetic: repair scoping reads the
# function name back out of it (`_names_function`), because that is the only
# place a stored finding records which function crashed. Built from one
# constant so the writer and the reader cannot drift.
_CRASH_MSG = "fuzz crash: "


def _names_function(message, func: str) -> bool:
    """Does this stored finding belong to `func`?

    Matched on the message rather than on the line number. Line numbers move
    when the file is edited -- which is exactly the situation a repair claim
    arises in -- and a shifted line can land inside a DIFFERENT function's
    span, resolving a finding about one function because another was fuzzed.
    The trailing "(" is what stops `pick` from matching `picker`.
    """
    return str(message).startswith(f"{_CRASH_MSG}{func}(")


def _is_test_file(rel: str) -> bool:
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if p.startswith("tests/") or "/tests/" in p:
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _reported_ids(raws, wt: Path) -> set:
    """The ids `normalize` will give THIS run's findings.

    The same `compute_fingerprint` call the normalizer makes: the line content
    is read at the item's head, which is what the worktree is a checkout of,
    and PIN_OCCURRENCE forces occurrence 0. Used only to subtract findings that
    are still crashing from the repair claim, so being wrong here can only
    fail to exclude -- and the drain's `present_ids` excludes them again.
    """
    out: set = set()
    cache: dict = {}
    for raw in raws:
        lines = cache.get(raw.file)
        if lines is None:
            try:
                lines = (wt / raw.file).read_text(encoding="utf-8").splitlines()
            except OSError:
                lines = []
            cache[raw.file] = lines
        idx = raw.line - 1
        lc = lines[idx] if 0 <= idx < len(lines) else ""
        out.add(compute_fingerprint(TOOL, raw.rule, raw.file, lc, 0))
    return out


def _candidate_functions(source: str, changed: set[int], skip_patterns):
    """Top-level, non-async def names whose line span overlaps `changed` and
    whose name matches no skip pattern. Returns (candidates, skipped_name,
    skipped_async)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], 0, 0
    candidates, skipped_name, skipped_async = [], 0, 0
    for node in tree.body:  # top-level only
        if isinstance(node, ast.AsyncFunctionDef):
            skipped_async += 1
            continue
        if not isinstance(node, ast.FunctionDef):
            continue
        end = node.end_lineno or node.lineno
        if not (set(range(node.lineno, end + 1)) & changed):
            continue
        if any(fnmatch.fnmatch(node.name.lower(), pat.lower()) for pat in skip_patterns):
            skipped_name += 1
            continue
        candidates.append(node.name)
    return candidates, skipped_name, skipped_async


def _any_candidates_remain(wt: Path, rels, changed: dict, skip_patterns) -> bool:
    """Candidacy-only sweep (AST parse, no fuzzing) over not-yet-visited
    changed files: keeps the truncated flag honest on exact-fit budget
    exhaustion. Unreadable/missing files count as no-candidates, matching
    the main loop's skip."""
    for rel in rels:
        src_path = wt / rel
        if not src_path.exists():
            continue
        try:
            source = src_path.read_text(encoding="utf-8")
        except OSError:
            continue
        cands, _, _ = _candidate_functions(source, changed[rel], skip_patterns)
        if cands:
            return True
    return False


def consume(item, ctx: DrainContext) -> ConsumerResult:
    fcfg = getattr(ctx.cfg, "fuzz", None) or {}
    if not fcfg.get("enabled", True):
        return ConsumerResult(consumer=NAME, state="ok", note="disabled")
    max_functions = int(fcfg.get("max_functions", 10))
    cases = int(fcfg.get("cases_per_function", 50))
    wall_budget = float(fcfg.get("wall_budget_s", 300))
    batch_timeout = float(fcfg.get("batch_timeout_s", 120))
    skip_patterns = list(fcfg.get("skip_name_patterns", []))

    changed = gitutil.diff_new_lines(ctx.root, item.base, item.head)
    files = sorted(f for f in changed
                   if f.endswith(".py") and not _is_test_file(f))
    if ctx.cfg is not None:
        files = config_mod.filter_paths(files, ctx.cfg)
    if not files:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="no python files in range")

    started = time.monotonic()
    stats = {"functions_seen": 0, "functions_fuzzed": 0, "skipped_unhinted": 0,
             "skipped_name": 0, "skipped_async": 0, "cases_run": 0,
             "crashes": 0, "contract_exceptions": 0, "findings": 0,
             "timeouts": 0, "import_failures": 0, "truncated": False}
    findings: list[RawFinding] = []
    repaired_ids: tuple = ()
    tmp = Path(tempfile.mkdtemp(prefix="aramid-fuzz-"))
    wt = tmp / "wt"
    try:
        cp = gitutil._run(ctx.root, "worktree", "add", "--detach", str(wt), item.head)
        if cp.returncode != 0:
            return ConsumerResult(consumer=NAME, state="error",
                                  note=f"worktree add failed: {(cp.stderr or '').strip()[:200]}")

        targets, budget = [], max_functions
        for i, rel in enumerate(files):
            if budget <= 0:
                # Exact fit must not over-report (fuzz M4): only claim
                # truncation if a remaining file actually has candidates.
                if _any_candidates_remain(wt, files[i:], changed, skip_patterns):
                    stats["truncated"] = True
                break
            src_path = wt / rel
            if not src_path.exists():
                continue
            try:
                source = src_path.read_text(encoding="utf-8")
            except OSError:
                continue
            cands, skip_name, skip_async = _candidate_functions(
                source, changed[rel], skip_patterns)
            stats["functions_seen"] += len(cands) + skip_name + skip_async
            stats["skipped_name"] += skip_name
            stats["skipped_async"] += skip_async
            if not cands:
                continue
            if len(cands) > budget:
                cands = cands[:budget]
                stats["truncated"] = True
            targets.append({"file": rel, "functions": cands, "cases": cases})
            budget -= len(cands)

        if not targets:
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="no fuzzable functions in range",
                                  duration_s=time.monotonic() - started,
                                  extra=dict(stats))

        spec = {"root": str(wt), "targets": targets}
        spec_path = tmp / "spec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        remaining = max(1.0, min(batch_timeout, wall_budget - (time.monotonic() - started)))
        # PYTHONHASHSEED=0 pins the driver's hash randomization so set/dict
        # iteration (and thus a crash's args_repr in the finding message) is
        # reproducible across drains, not just its fingerprint.
        result = run_subprocess(
            [sys.executable, "-m", "aramid.fuzzdriver", str(spec_path)],
            wt, remaining, env={"PYTHONHASHSEED": "0"})
        if result.state is ToolState.TIMEOUT:
            stats["timeouts"] += 1
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="driver timed out (budget did its job)",
                                  duration_s=time.monotonic() - started,
                                  extra=dict(stats))
        if result.state is not ToolState.OK or result.returncode != 0:
            return ConsumerResult(consumer=NAME, state="ok",
                                  note=f"driver error: {result.stderr.strip()[:120]}",
                                  duration_s=time.monotonic() - started,
                                  extra=dict(stats))
        try:
            out = json.loads(result.raw)
        except (ValueError, TypeError):
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="driver produced no parseable output",
                                  duration_s=time.monotonic() - started,
                                  extra=dict(stats))

        stats["cases_run"] = out.get("cases_run", 0)
        stats["crashes"] = out.get("crashes", 0)
        stats["contract_exceptions"] = out.get("contract_exceptions", 0)
        stats["import_failures"] = len(out.get("import_failures", []))
        stats["skipped_unhinted"] = out.get("unfuzzable", 0)
        # A target whose file import-failed never reaches the driver's
        # per-function loop, so its functions never count as unfuzzable --
        # subtract them explicitly, else functions_fuzzed silently overcounts
        # (spec: "skips are never silent").
        failed_files = set(out.get("import_failures", []))
        failed_fn_count = sum(len(t["functions"]) for t in targets
                              if t["file"] in failed_files)
        stats["functions_fuzzed"] = (sum(len(t["functions"]) for t in targets)
                                     - stats["skipped_unhinted"] - failed_fn_count)
        for rec in out.get("records", []):
            findings.append(RawFinding(
                tool="fuzz", rule=f"crash-{rec['exc'].lower()}",
                severity_raw="medium", file=rec["file"], line=int(rec.get("line", 1)),
                message=(f"{_CRASH_MSG}{rec['func']}({rec.get('args_repr', '')}) "
                         f"raised {rec['exc']}: {rec.get('msg', '')}")))
        stats["findings"] = len(findings)

        # Repair claim. Only reached when the driver produced a PARSEABLE
        # verdict -- a timeout, a non-zero exit and unreadable output all
        # returned above, and each of them looks identical to a clean sweep in
        # the records alone (nothing). That ordering is the guard.
        #
        # Determinism is what makes absence meaningful here at all:
        # `fuzzgen.case_seed(file, func, i)` replays exactly the corpus that
        # found the crash, so for a function that really was CALLED, "no crash"
        # is a re-examination rather than a coverage gap. Scope therefore comes
        # from the driver's `fuzzed` list -- never from the targets it was
        # asked to run, because a function whose hints were removed is skipped
        # in silence and would otherwise be resolved for having become
        # uncheckable.
        #
        # Anything still crashing is excluded here and again by the drain's
        # `present_ids`; a producer claiming repair for a finding it is
        # reporting in the same breath is the worst failure available to it, so
        # it is not left to a single filter.
        fuzzed_by_file: dict = {}
        for entry in out.get("fuzzed", []):
            if isinstance(entry, (list, tuple)) and len(entry) == 2:
                fuzzed_by_file.setdefault(entry[0], set()).add(entry[1])
        still_crashing = _reported_ids(findings, wt)
        repaired_ids = tuple(sorted(
            fid for fid, rec in base.open_findings_for(ctx.ledger, TOOL).items()
            if fid not in still_crashing
            and any(_names_function(rec.get("message", ""), func)
                    for func in fuzzed_by_file.get(rec.get("file", ""), ()))))
    finally:
        try:
            gitutil._run(ctx.root, "worktree", "remove", "--force", str(wt))
            gitutil._run(ctx.root, "worktree", "prune")
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            print(f"aramid: fuzz: worktree cleanup leaked at {wt}", file=sys.stderr)

    note = (f"{stats['findings']} crash finding(s) from {stats['cases_run']} "
            f"case(s) over {stats['functions_fuzzed']} function(s)")
    if stats["truncated"]:
        note += " (truncated: max_functions cap hit)"
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=time.monotonic() - started, cost=0.0,
                          note=note, extra=dict(stats),
                          repaired=base.Repaired(tool=TOOL,
                                                 reason="crash_not_reproduced",
                                                 ids=repaired_ids)
                          if repaired_ids else None)


base.CONSUMERS[NAME] = sys.modules[__name__]
