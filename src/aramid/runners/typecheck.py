"""typecheck adapter -- tsc (TypeScript) and mypy (Python), config-dispatched.

Both tools emit plain diagnostic text (not JSON), so there's no
JSON-parseable-or-CRASHED signal available the way there is for the JSON
tools; a tool that errors before emitting any matching diagnostic lines
just yields zero findings for this run. Both are WARN-tier (design doc §3).

tsc only runs when tsconfig.json exists at the repo root, resolved
repo-locally like eslint (node_modules/.bin/tsc[.cmd], MISSING if absent,
never a global fallback). mypy only runs when a mypy config
([tool.mypy] in pyproject.toml, or mypy.ini) is present, and is looked up
on PATH (it isn't part of aramid's own owned/vendored toolchain). It is
handed only the `.py`/`.pyi` files in range -- see `_PY_SUFFIXES` for the
false BLOCK that handing it everything produced.
"""
import dataclasses
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


def _split_listed_files(raw: str, root: Path) -> tuple[str, frozenset[str]]:
    """Separate `--listFiles` path lines from tsc's diagnostics.

    Returns `(raw_without_paths, examined)`. The path lines are CONSUMED, so
    `raw` still holds exactly the diagnostics it held before the flag was
    added -- which is what `parse_tsc` and every log this result reaches want.
    Measured on TypeScript 7.0.2 with only `typescript` + `@types/node`
    installed, `--listFiles` emitted 65 path lines to 1 diagnostic, 63 of them
    lib/`node_modules` `.d.ts`; a real application project emits thousands.

    Classification is positional and needs no filesystem access:
      - a line matching `_TSC_LINE` is a diagnostic (it carries `(line,col):
        error TSxxxx`, which a bare path never does);
      - a line that is otherwise an ABSOLUTE path is a `--listFiles` entry,
        and is consumed whether or not it lives in this repo -- tsc lists its
        own bundled `lib.es*.d.ts` from wherever TypeScript is installed, and
        those are real inputs that simply cannot hold a repo finding;
      - anything else is unrecognised tsc output and is KEPT, so a message
        like `error TS5083: Cannot read file ...` is never silently eaten.
    """
    diagnostics: list[str] = []
    examined: set[str] = set()
    base = root.resolve()
    for line in (raw or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if _TSC_LINE.match(stripped):
            diagnostics.append(line)
            continue
        candidate = Path(stripped.replace("\\", "/"))
        if not candidate.is_absolute():
            diagnostics.append(line)
            continue
        try:
            resolved = candidate.resolve()
            if resolved.is_relative_to(base):
                examined.add(resolved.relative_to(base).as_posix())
        except (OSError, ValueError):
            pass
    return "\n".join(diagnostics), frozenset(examined)


def run_tsc(ctx) -> RunnerResult:
    binp = _tsc_bin(ctx.root)
    if not binp.exists():
        return RunnerResult(NAME_TSC, ToolState.MISSING, examined=frozenset())
    # `--listFiles` closes tsconfig's version of ruff's `exclude` hole: this
    # runner checks the PROJECT, not ctx.files, so a source file left out of
    # tsconfig `include`/`files` is never checked, tsc still exits 0, and
    # resolution recorded every open finding in it as fixed. Measured free in
    # time (0.93s vs 0.98s for a bare --noEmit -- tsc already reads all of
    # them); its cost is output volume, which `_split_listed_files` absorbs.
    result = run_subprocess([str(binp), "--noEmit", "--listFiles"], ctx.root, TIMEOUT_S)
    # T-8 section 11: run_subprocess labels RunnerResult.tool from argv[0]'s
    # basename ("tsc.cmd" on win32), which both mismatches parse_tsc's
    # stamped tool AND makes typecheck.parse()'s own dispatch (`if
    # result.tool == NAME_TSC`) miss entirely -- not just a
    # ledger-resolution gap, a total detection gap. Relabel unconditionally
    # (not just the OK branch): run_subprocess's own TIMEOUT path also
    # carries the wrong name. Mirrors eslint.py's json_or_crashed relabel.
    result = dataclasses.replace(result, tool=NAME_TSC)
    # A degraded tsc vouches for nothing (see the ruff/eslint adapters); only
    # an OK run produced a file list to trust.
    if result.state is not ToolState.OK:
        return dataclasses.replace(result, examined=frozenset())
    raw, examined = _split_listed_files(result.raw, ctx.root)
    return dataclasses.replace(result, raw=raw, examined=examined)


# ctx.files is the gate's whole file set. mypy tokenises whatever explicit
# path it is handed as Python, so a YAML or Markdown file in range is a
# `syntax` error at its first odd token -- BLOCK-tier, since the rule id
# says "syntax". Measured by graphite on its own gate (interop round 139):
# a lone `ci.yml` blocked a push on "Leading zeros in decimal integer
# literals"; two non-Python files made mypy bail on a duplicate `__main__`
# BEFORE parsing and the push passed. Same edit, opposite verdicts, decided
# by what else was in the range. Same scoping as the ruff runner.
_PY_SUFFIXES = (".py", ".pyi")


def _py_files(ctx) -> list[str]:
    return [f for f in ctx.files if f.lower().endswith(_PY_SUFFIXES)]


def run_mypy(ctx) -> RunnerResult:
    files = _py_files(ctx)
    if not files:
        # No Python in scope: a clean no-op, NOT a tool invocation -- mypy
        # given zero paths falls back to its config's `files=` (or errors),
        # either way a run that looked at none of the range. It examined
        # nothing and says so (the empty set, not None), so nothing
        # resolves off this run.
        return RunnerResult(NAME_MYPY, ToolState.OK, raw="", examined=frozenset())
    argv = ["mypy", "--no-error-summary", "--show-column-numbers", *files]
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
