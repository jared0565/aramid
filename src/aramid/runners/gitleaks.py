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
    # back to `protect --staged`.
    if ctx.rng is not None:
        return [
            "gitleaks", "git", "--log-opts", ctx.rng,
            "--report-format", "json", "--report-path", str(report_path),
        ]
    return [
        "gitleaks", "protect", "--staged",
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
    # attribute a leak to a specific historical commit; the `protect
    # --staged` path scans the working tree/index, not commits, so it
    # always leaves RawFinding.commit as None (its Commit field, if present
    # at all, carries no meaningful ref there).
    is_history_scan = ctx.rng is not None
    return [
        RawFinding(
            tool=NAME,
            rule=item["RuleID"],
            severity_raw=_SEVERITY_RAW,
            file=relativize(item["File"], ctx.root),
            line=item["StartLine"],
            message=item.get("Description") or item["RuleID"],
            secret=item["Secret"],
            commit=(item.get("Commit") or None) if is_history_scan else None,
        )
        for item in items
    ]
