"""gitleaks adapter -- secrets scanning.

gitleaks' --report-path is a filesystem path, not a stdout sentinel: passing
"-" would create a literal file named "-" rather than writing to stdout. We
always write to a real temp file and read it back afterwards.

gitleaks exits non-zero when it finds leaks (that is the whole point of the
tool) -- that is NOT a crash. gitleaks' own documented exit codes are 0 (no
leaks) and 1 (leaks found); anything else (bad --log-opts range, not-a-git-
repo, permission error, ...) means gitleaks errored before/instead of
producing a trustworthy report. An errored run typically leaves the report
file missing or empty, which parses just as cleanly as a genuinely-clean
"[]" -- so the returncode is checked explicitly and BEFORE trusting an
empty/absent report as "no leaks"; without that check a crashed gitleaks
(a BLOCK-tier secrets gate) would silently read as "scanned clean".
"""
import json
import tempfile
from pathlib import Path

from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState, run_subprocess
from aramid.fingerprint import normalize_path
from aramid.runners._util import relativize

NAME = "gitleaks"
TIMEOUT_S = 120.0

# gitleaks' own documented exit-code contract: 0 = ran clean, no leaks;
# 1 = ran clean, leaks found. Anything else is an error, not a verdict.
_OK_RETURNCODES = frozenset({0, 1})

# gitleaks doesn't emit a per-finding severity in its report; a discovered
# secret is treated as high severity by default (documented assumption --
# the real severity/verdict split for secrets is a policy.classify decision,
# task 5.1, keyed off tool+rule, not this raw string).
_SEVERITY_RAW = "high"


def _build_argv(ctx, report_path: Path) -> list[str]:
    # `ctx.rng is not None`, NOT truthiness: `pipeline.FULL_HISTORY_RNG`
    # ("") is a deliberately falsy-but-not-None sentinel meaning "range
    # mode, no @{u}/origin/HEAD yet -- scan every commit reachable from
    # HEAD" (first push of a brand-new repo, spec §3). `git log`/gitleaks'
    # `--log-opts` with an empty options string defaults to walking every
    # commit reachable from HEAD -- exactly that. Only a genuine `None`
    # (staged mode -- `RunContext.rng`'s other documented meaning) falls
    # back to `git --staged`.
    if ctx.rng is not None:
        return [
            "gitleaks", "git", "--log-opts", ctx.rng,
            "--report-format", "json", "--report-path", str(report_path),
        ]
    # `--all` (mode "all") also arrives here with rng None, because None was
    # overloaded to mean both "staged" and "not range-based". Scanning the
    # index in that mode means scanning an EMPTY index -- and reporting OK
    # for it, which is worse than useless: OK puts gitleaks in `scope_tools`,
    # so `record_run` then resolves open secret findings across the whole
    # tracked tree. Measured on the 0.2.0 wheel: two committed secrets that
    # gitleaks finds when run directly were invisible to `check --all`, and
    # both prior BLOCK findings were written `finding_resolved` while the
    # secrets sat untouched in the files. Committing a leak marked it fixed.
    #
    # `dir` is gitleaks' working-tree scan. It cannot attribute a leak to the
    # commit that introduced it, which is why range mode above still wins --
    # that attribution is the whole value of the pre-push path.
    if getattr(ctx, "full_tree", False):
        return [
            "gitleaks", "dir", str(ctx.root),
            "--report-format", "json", "--report-path", str(report_path),
        ]
    return [
        "gitleaks", "git", "--staged",
        "--report-format", "json", "--report-path", str(report_path),
    ]


def run(ctx) -> RunnerResult:
    with tempfile.TemporaryDirectory() as td:
        report_path = Path(td) / "gitleaks-report.json"
        argv = _build_argv(ctx, report_path)
        result = run_subprocess(argv, ctx.root, TIMEOUT_S)
        if result.state in (ToolState.MISSING, ToolState.TIMEOUT):
            return result

        text = report_path.read_text() if report_path.exists() else ""

        if result.returncode not in _OK_RETURNCODES:
            return RunnerResult(NAME, ToolState.CRASHED, raw=text, stderr=result.stderr,
                                 duration_s=result.duration_s, returncode=result.returncode)
        try:
            json.loads(text or "[]")
        except json.JSONDecodeError:
            return RunnerResult(NAME, ToolState.CRASHED, raw=text, stderr=result.stderr,
                                 duration_s=result.duration_s, returncode=result.returncode)
        return RunnerResult(NAME, ToolState.OK, raw=text or "[]", stderr=result.stderr,
                             duration_s=result.duration_s, returncode=result.returncode)


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    items = json.loads(result.raw or "[]")
    # Only the `gitleaks git ...` history path (ctx.rng is not None, per
    # _build_argv above -- matches its is-not-None check, not truthiness, so
    # the FULL_HISTORY_RNG "" sentinel counts as a history scan too) can
    # attribute a leak to a specific historical commit; the `git --staged`
    # path scans the working tree/index, not commits, so it
    # always leaves RawFinding.commit as None (its Commit field, if present
    # at all, carries no meaningful ref there).
    is_history_scan = ctx.rng is not None
    # SCAN WIDE, REPORT NARROW. `gitleaks dir` takes a single path and walks
    # everything under it -- including files git ignores. Measured on this
    # repo: 24 hits, of which 14 were in `.superpowers/` local review
    # artifacts and `__pycache__/`. Reporting those would be wrong twice
    # over: `--all` is defined as all TRACKED files (`all_tracked_files`), and
    # a finding in a path that can never be committed is a finding nobody can
    # ever fix or retire.
    #
    # Filtering here rather than narrowing the scan because `gitleaks dir`
    # accepts one path only -- passing a file list is silently ignored and it
    # rescans the whole tree, which is how this was confirmed rather than
    # assumed.
    scope = None
    if getattr(ctx, "full_tree", False) and ctx.files:
        scope = {normalize_path(f) for f in ctx.files}
    out = []
    for item in items:
        rel = relativize(item["File"], ctx.root)
        if scope is not None and normalize_path(rel) not in scope:
            continue
        out.append(RawFinding(
            tool=NAME,
            rule=item["RuleID"],
            severity_raw=_SEVERITY_RAW,
            file=rel,
            line=item["StartLine"],
            message=item.get("Description") or item["RuleID"],
            secret=item["Secret"],
            commit=(item.get("Commit") or None) if is_history_scan else None,
        ))
    return out
