"""typecheck adapter -- tsc (TypeScript) and mypy (Python), config-dispatched.

Both tools emit plain diagnostic text (not JSON), so there's no
JSON-parseable-or-CRASHED signal available the way there is for the JSON
tools; a tool that errors before emitting any matching diagnostic lines
just yields zero findings for this run. Both are WARN-tier (design doc §3).

tsc only runs when tsconfig.json exists at the repo root, resolved
repo-locally like eslint (node_modules/.bin/tsc[.cmd], MISSING if absent,
never a global fallback). mypy only runs when a mypy config
([tool.mypy] in pyproject.toml, or mypy.ini) is present, and is looked up
on PATH (it isn't part of aramid's own owned/vendored toolchain).
"""
import re
import sys
import tomllib
from pathlib import Path

from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState, run_subprocess
from aramid.runners._util import relativize

NAME_TSC = "tsc"
NAME_MYPY = "mypy"
TIMEOUT_S = 120.0

# tsc --noEmit diagnostic line, e.g.:
#   src/app.ts(10,5): error TS2322: Type 'string' is not assignable ...
_TSC_LINE = re.compile(
    r"^(?P<file>.+?)\((?P<line>\d+),(?P<col>\d+)\): error (?P<code>TS\d+): (?P<message>.+)$"
)

# mypy --show-column-numbers diagnostic line, e.g.:
#   app.py:10:5: error: Argument 1 to "foo" has incompatible type ...  [arg-type]
# "note:" continuation lines (no [code], different level) are skipped.
_MYPY_LINE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+): (?P<level>error|warning): "
    r"(?P<message>.+?)(?:\s+\[(?P<code>[\w\-]+)\])?$"
)


def _tsc_bin(root: Path) -> Path:
    name = "tsc.cmd" if sys.platform == "win32" else "tsc"
    return root / "node_modules" / ".bin" / name


def has_tsconfig(root: Path) -> bool:
    return (root / "tsconfig.json").exists()


def has_mypy_config(root: Path) -> bool:
    if (root / "mypy.ini").exists():
        return True
    pp = root / "pyproject.toml"
    if pp.exists():
        try:
            data = tomllib.loads(pp.read_text())
        except (tomllib.TOMLDecodeError, OSError):
            return False
        return "mypy" in data.get("tool", {})
    return False


def run_tsc(ctx) -> RunnerResult:
    binp = _tsc_bin(ctx.root)
    if not binp.exists():
        return RunnerResult(NAME_TSC, ToolState.MISSING)
    return run_subprocess([str(binp), "--noEmit"], ctx.root, TIMEOUT_S)


def run_mypy(ctx) -> RunnerResult:
    argv = ["mypy", "--no-error-summary", "--show-column-numbers", *ctx.files]
    return run_subprocess(argv, ctx.root, TIMEOUT_S)


def run(ctx) -> RunnerResult:
    if has_tsconfig(ctx.root):
        return run_tsc(ctx)
    if has_mypy_config(ctx.root):
        return run_mypy(ctx)
    return RunnerResult("typecheck", ToolState.MISSING)


def parse_tsc(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    findings = []
    for line in result.raw.splitlines():
        m = _TSC_LINE.match(line.strip())
        if not m:
            continue
        findings.append(RawFinding(
            tool=NAME_TSC, rule=m["code"], severity_raw="error",
            file=relativize(m["file"], ctx.root), line=int(m["line"]),
            message=m["message"],
        ))
    return findings


def parse_mypy(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    findings = []
    for line in result.raw.splitlines():
        m = _MYPY_LINE.match(line.strip())
        if not m:
            continue
        findings.append(RawFinding(
            tool=NAME_MYPY, rule=m["code"] or "mypy-error", severity_raw=m["level"],
            file=relativize(m["file"], ctx.root), line=int(m["line"]),
            message=m["message"],
        ))
    return findings


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.tool == NAME_TSC:
        return parse_tsc(result, ctx)
    if result.tool == NAME_MYPY:
        return parse_mypy(result, ctx)
    return []
