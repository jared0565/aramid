"""eslint adapter -- JS/TS lint, repo-local only.

Resolves `<root>/node_modules/.bin/eslint` (`.cmd` on Windows). If it's
absent we report MISSING (skip + doctor-note) and never fall back to a
globally-installed eslint -- a global eslint may not match the repo's
configured rules/plugins and would produce misleading results.
"""
import json
import sys
from dataclasses import replace
from pathlib import Path

from aramid.normalizer import RawFinding
from aramid.runners.base import (CMD_EXE_LINE_LIMIT, RunnerResult, ToolState, cmd_line_length,
                                 run_subprocess)
from aramid.runners._util import json_or_crashed, relativize

NAME = "eslint"
# Per launch. A long file list is linted in several launches (see
# `_line_budget`), each with this timeout; the gate's own runner budget still
# bounds the whole, and a run it abandons reads as TIMEOUT, never as clean.
TIMEOUT_S = 60.0

# eslint's documented exit codes: 0 = clean, 1 = lint problems reported.
# 2 = fatal error (bad config, internal crash, ...) -- not a verdict.
_OK_RETURNCODES = frozenset({0, 1})

# Headroom under cmd.exe's limit for what the npm shim adds when it re-expands
# `%*`: the node path and eslint's own script path, absolute.
_CMD_SHIM_HEADROOM = 1191

# ctx.files is the gate's whole file set (every staged/changed/tracked file);
# eslint must only be handed JS/TS-family paths (same class of bug as
# aramid.runners.ruff._py_files -- see that module).
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")


def _js_files(ctx) -> list[str]:
    return [f for f in ctx.files if f.lower().endswith(_JS_SUFFIXES)]


def _eslint_bin(root: Path) -> Path:
    name = "eslint.cmd" if sys.platform == "win32" else "eslint"
    return root / "node_modules" / ".bin" / name


def _line_budget(binp: Path) -> int | None:
    """The longest command line one launch may have, or None for no limit
    worth batching for.

    On Windows the binary is npm's `eslint.cmd` shim, so the line goes through
    cmd.exe, which refuses one over its limit: it prints "The command line is
    too long." and exits 1 -- an exit code eslint itself uses for "problems
    reported" (FN-34, channel round 314: a whole-tree run read as a clean
    lint). The launcher refuses a line over `base.cmd_exe_line_budget()`
    (8,160 on a standard install) without starting it; this budget sits well
    under that, because the shim then re-expands the line with node's path and
    eslint's script in front. A POSIX binary is exec'd directly, where the
    limit is far beyond any file list a gate builds."""
    if binp.suffix.lower() in (".cmd", ".bat"):
        return CMD_EXE_LINE_LIMIT - _CMD_SHIM_HEADROOM
    return None


def _batches(prefix: list[str], files: list[str], budget: int | None) -> list[list[str]]:
    """`files` split, in order, so that every `prefix + batch` stays within
    `budget` as `base.cmd_line_length` counts it -- the exact line
    CreateProcess receives, quoting included, in the UTF-16 units cmd.exe
    counts, as the launcher measures it. A file that alone does not fit gets
    a batch of its own; the launcher refuses that one, visibly."""
    if budget is None:
        return [files]
    out: list[list[str]] = []
    batch: list[str] = []
    length = cmd_line_length(prefix)
    for f in files:
        cost = 1 + cmd_line_length([f])     # a space, then the quoted path
        if batch and length + cost > budget:
            out.append(batch)
            batch, length = [], cmd_line_length(prefix)
        batch.append(f)
        length += cost
    if batch:
        out.append(batch)
    return out


def _reported_an_error(data) -> bool:
    """Valid JSON that is not eslint's report shape reported nothing."""
    if not isinstance(data, list):
        return False
    return any(isinstance(m, dict) and m.get("severity") == 2
               for entry in data if isinstance(entry, dict)
               for m in (entry.get("messages") or []))


def _judge(result: RunnerResult) -> RunnerResult:
    """`json_or_crashed`, plus the one exit/output pair eslint never produces.

    eslint exits 1 only when its report carries at least one error (aramid
    never passes --max-warnings). An exit 1 with no error in the report did
    not come from eslint's verdict: it is what cmd.exe returns when it
    refuses the command line, with nothing on stdout -- which the generic
    check accepts as "[]" and so reads as a clean lint."""
    out = json_or_crashed(NAME, result, _OK_RETURNCODES)
    if out.state is ToolState.OK and out.returncode == 1 and not _reported_an_error(
            json.loads(out.raw or "[]")):
        return RunnerResult(NAME, ToolState.CRASHED, result.raw, result.stderr,
                            result.duration_s, result.returncode)
    return out


def _is_file_notice(msg: dict) -> bool:
    """True when eslint is talking ABOUT a file rather than reporting
    something IN it -- "File ignored because of a matching ignore pattern",
    "File ignored by default", "File ignored because outside of base path".

    Discriminated on SHAPE, never on the message text: a notice has no rule
    id, is not fatal, and carries no position. A genuine parse error also has
    a null rule id -- what separates the two is `fatal: true` plus a
    line/column -- so keying on the wording would be brittle for no gain.
    Shape is also what makes this version-agnostic, which is why the adapter
    does not simply pass eslint 9's `--no-warn-ignored`: that flag does not
    exist in eslint 8, where an unrecognised option exits 2 and takes the
    whole runner to CRASHED.
    """
    return (msg.get("ruleId") is None and not msg.get("fatal")
            and msg.get("line") is None)


def _examined(data: list, ctx) -> frozenset[str]:
    """Repo-relative paths eslint can vouch for having linted.

    Free, unlike ruff's: eslint's JSON formatter emits one entry per file it
    processed -- including clean ones -- so the set is already in the output.
    (ruff's JSON names only files WITH findings, which is why that adapter
    needs a second `--show-files` invocation to learn the same thing.)

    Two kinds of entry are dropped, because in both eslint analysed nothing
    in the file and so cannot vouch for it:
      - a file it declined to lint (ignore notice);
      - a file it could not parse -- otherwise introducing a syntax error
        would silently resolve every other open finding in that file.
    """
    out = set()
    for entry in data:
        path = entry.get("filePath")
        if not path:
            continue
        msgs = entry.get("messages") or []
        if any(_is_file_notice(m) or m.get("fatal") for m in msgs):
            continue
        out.add(relativize(path, ctx.root))
    return frozenset(out)


def run(ctx) -> RunnerResult:
    files = _js_files(ctx)
    if not files:
        # No JS/TS in scope: a clean no-op (checked before the binary so a
        # Python-only diff in a mixed repo can't degrade on a missing eslint).
        #
        # `examined` is the EMPTY SET, not None: eslint did not run, so it
        # vouches for nothing. None would fall back to the gate-wide file set
        # and resolve open findings on paths this adapter never even passed to
        # eslint -- e.g. `.vue`/`.svelte`/`.astro`, which a repo's eslint
        # config may well lint but `_JS_SUFFIXES` does not list.
        return RunnerResult(NAME, ToolState.OK, raw="[]", examined=frozenset())
    binp = _eslint_bin(ctx.root)
    if not binp.exists():
        return RunnerResult(NAME, ToolState.MISSING, examined=frozenset())
    prefix = [str(binp), "-f", "json"]
    outs = []
    for batch in _batches(prefix, files, _line_budget(binp)):
        out = _judge(run_subprocess([*prefix, *batch], ctx.root, TIMEOUT_S))
        # Every degraded result vouches for nothing, matching the ruff adapter.
        # aramid.pipeline only reads `examined` off OK results today, so this is
        # defense in depth rather than a live path -- but "eslint timed out" must
        # never be one refactor away from "eslint approved the whole gate scope".
        # One degraded batch degrades the run: a partial OK would vouch for the
        # batches that ran and say nothing of the rest.
        if out.state is not ToolState.OK:
            return replace(out, examined=frozenset())
        outs.append(out)
    if len(outs) == 1:
        out = outs[0]
        data = json.loads(out.raw or "[]")
    else:
        # eslint's report is one entry per file, so the batches' reports
        # concatenate into the report one launch would have written.
        data = [entry for o in outs for entry in json.loads(o.raw or "[]")]
        out = RunnerResult(NAME, ToolState.OK, json.dumps(data),
                           "\n".join(o.stderr for o in outs if o.stderr),
                           sum(o.duration_s for o in outs),
                           max(o.returncode for o in outs))
    return replace(out, examined=_examined(data, ctx))


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    data = json.loads(result.raw or "[]")
    findings = []
    for file_result in data:
        file_rel = relativize(file_result["filePath"], ctx.root)
        for msg in file_result.get("messages", []):
            # A file-level notice is not a finding. Without this, eslint's
            # "File ignored because of a matching ignore pattern" warning --
            # null ruleId -- fell through the `or` below and was reported as
            # an `eslint-parse-error` on a file eslint never linted.
            if _is_file_notice(msg):
                continue
            findings.append(RawFinding(
                tool=NAME,
                rule=msg.get("ruleId") or "eslint-parse-error",
                severity_raw=str(msg["severity"]),
                file=file_rel,
                line=msg.get("line", 0),
                message=msg["message"],
            ))
    return findings
