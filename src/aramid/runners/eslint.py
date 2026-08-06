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
from aramid.runners.base import RunnerResult, ToolState, run_subprocess
from aramid.runners._util import json_or_crashed, relativize

NAME = "eslint"
TIMEOUT_S = 60.0

# eslint's documented exit codes: 0 = clean, 1 = lint problems reported.
# 2 = fatal error (bad config, internal crash, ...) -- not a verdict.
_OK_RETURNCODES = frozenset({0, 1})

# ctx.files is the gate's whole file set (every staged/changed/tracked file);
# eslint must only be handed JS/TS-family paths (same class of bug as
# aramid.runners.ruff._py_files -- see that module).
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")


def _js_files(ctx) -> list[str]:
    return [f for f in ctx.files if f.lower().endswith(_JS_SUFFIXES)]


def _eslint_bin(root: Path) -> Path:
    name = "eslint.cmd" if sys.platform == "win32" else "eslint"
    return root / "node_modules" / ".bin" / name


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
    argv = [str(binp), "-f", "json", *files]
    result = run_subprocess(argv, ctx.root, TIMEOUT_S)
    out = json_or_crashed(NAME, result, _OK_RETURNCODES)
    # Every degraded result vouches for nothing, matching the ruff adapter.
    # aramid.pipeline only reads `examined` off OK results today, so this is
    # defense in depth rather than a live path -- but "eslint timed out" must
    # never be one refactor away from "eslint approved the whole gate scope".
    if out.state is not ToolState.OK:
        return replace(out, examined=frozenset())
    try:
        data = json.loads(out.raw or "[]")
    except json.JSONDecodeError:  # pragma: no cover - json_or_crashed pre-screens
        return replace(out, examined=frozenset())
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
