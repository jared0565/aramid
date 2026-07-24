"""red_proof -- synchronous red-first-proof producer for the pre-push gate
(sub-project 3, spec sections 3-4). The range's changed test files (head
version) are run against a throwaway worktree at the range BASE: a file
whose tests all pass on the pre-change tree was never red, so it proves
nothing about the change -- one WARN-tier RawFinding per such file (tool
"red-proof", rule "test-not-red", line=0 so the fingerprint is stable per
tool+rule+path, the 1a trick).

Per-file verdict (pytest rc on the base tree): 0 -> never-red FINDING;
1/2 -> red proven, nothing (a collection error IS red -- a test importing
a brand-new module fails on base; documented lenient, spec s10.2-3);
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
fallback. Limitations (spec s10): whole-file verdict -- an old test in a
changed file failing on base masks a never-red new test (recall loss only,
never a false positive); only subject files are materialized at head, so a
new test depending on head changes to non-test files it imports usually
collection-errors -> counts as red; single run, no flake retries."""
import shutil
import sys
import tempfile
import time
from pathlib import Path

from aramid import gitutil
from aramid.normalizer import RawFinding
from aramid.runners.base import ToolState, run_subprocess
from aramid.tdd import _split_range

RULE = "test-not-red"
_TOOL = "red-proof"
_MESSAGE = "new test lines pass against the pre-change tree (never red)"


def scan(ctx, cfg) -> list[RawFinding]:
    """Red-first proof for the pre-push range (PRE_PUSH caller-gated, like
    tdd.scan). Fail-open: any error yields no findings -- a broken producer
    must never block a push or crash the gate."""
    try:
        rcfg = getattr(cfg, "red_proof", None) or {}
        if not rcfg.get("enabled", True):
            return []
        if not ctx.rng:
            return []       # no meaningful base: first push / staged / all
        wall_budget = float(rcfg.get("wall_budget_s", 120))
        test_timeout = float(rcfg.get("test_timeout_s", 60))
        base, head = _split_range(ctx.rng)
        if base is None:
            return []       # rangeless rng: no base tree to prove against
        in_scope = set(ctx.files)
        new_lines = gitutil.diff_new_lines(ctx.root, base, head)
        subjects = sorted(
            path for path, lines in new_lines.items()
            if lines and gitutil.is_test_file(path) and path in in_scope)
        if not subjects:
            return []       # zero-cost guard: no worktree, no subprocess
        started = time.monotonic()
        out: list[RawFinding] = []
        tmp = Path(tempfile.mkdtemp(prefix="aramid-red-"))
        wt = tmp / "wt"
        try:
            cp = gitutil._run(ctx.root, "worktree", "add", "--detach",
                              str(wt), base)
            if cp.returncode != 0:
                return []
            for rel in subjects:
                if time.monotonic() - started > wall_budget:
                    break   # budget exhausted: skip remainder silently
                content = gitutil.read_blob(ctx.root, head, rel)
                if not content:
                    continue        # unreadable/empty head blob: fail-open
                dest = wt / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
                res = run_subprocess(
                    [sys.executable, "-m", "pytest", "-q", rel],
                    wt, test_timeout)
                if res.state is ToolState.OK and res.returncode == 0:
                    out.append(RawFinding(
                        tool=_TOOL, rule=RULE, severity_raw="medium",
                        file=rel, line=0, message=_MESSAGE))
                # rc 1/2: red proven. rc 5: nothing collected. timeout /
                # other rc: unattributable. All -> nothing (spec s3.6).
        finally:
            try:
                gitutil._run(ctx.root, "worktree", "remove", "--force", str(wt))
                gitutil._run(ctx.root, "worktree", "prune")
                shutil.rmtree(tmp, ignore_errors=True)
            except Exception:
                print(f"aramid: red-proof: worktree cleanup leaked at {wt}",
                      file=sys.stderr)
        return out
    except Exception:
        return []
