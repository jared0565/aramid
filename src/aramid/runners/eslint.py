"""eslint adapter -- JS/TS lint, repo-local only.

Resolves `<root>/node_modules/.bin/eslint` (`.cmd` on Windows). If it's
absent we report MISSING (skip + doctor-note) and never fall back to a
globally-installed eslint -- a global eslint may not match the repo's
configured rules/plugins and would produce misleading results.
"""
import json
import sys
from pathlib import Path

from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState, run_subprocess
from aramid.runners._util import json_or_crashed, relativize

NAME = "eslint"
TIMEOUT_S = 60.0

# eslint's documented exit codes: 0 = clean, 1 = lint problems reported.
# 2 = fatal error (bad config, internal crash, ...) -- not a verdict.
_OK_RETURNCODES = frozenset({0, 1})


def _eslint_bin(root: Path) -> Path:
    name = "eslint.cmd" if sys.platform == "win32" else "eslint"
    return root / "node_modules" / ".bin" / name


def run(ctx) -> RunnerResult:
    binp = _eslint_bin(ctx.root)
    if not binp.exists():
        return RunnerResult(NAME, ToolState.MISSING)
    argv = [str(binp), "-f", "json", *ctx.files]
    result = run_subprocess(argv, ctx.root, TIMEOUT_S)
    return json_or_crashed(NAME, result, _OK_RETURNCODES)


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    data = json.loads(result.raw or "[]")
    findings = []
    for file_result in data:
        file_rel = relativize(file_result["filePath"], ctx.root)
        for msg in file_result.get("messages", []):
            findings.append(RawFinding(
                tool=NAME,
                rule=msg.get("ruleId") or "eslint-parse-error",
                severity_raw=str(msg["severity"]),
                file=file_rel,
                line=msg.get("line", 0),
                message=msg["message"],
            ))
    return findings
