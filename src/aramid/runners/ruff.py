"""ruff adapter -- Python lint + security (bandit-derived `S` family).

`--extend-select S` is mandatory: ruff's default rule set excludes the
flake8-bandit `S` family, so without this flag the security rules never fire
regardless of the target repo's own pyproject.toml/ruff.toml config. This is
how aramid enforces its own security baseline independent of repo config.
"""
import json
import re
from dataclasses import replace

from aramid.normalizer import RawFinding
from aramid.runners import inline
from aramid.runners.base import (RunnerResult, ToolState, run_subprocess,
                                  scanned_line_reader)
from aramid.runners._util import json_or_crashed, relativize

NAME = "ruff"
TIMEOUT_S = 30.0

# ruff check's documented exit codes: 0 = clean, 1 = violations found.
# Anything else means ruff errored (bad args, internal error, ...).
_OK_RETURNCODES = frozenset({0, 1})

# ctx.files is the gate's whole file set (every staged/changed/tracked file);
# ruff parses whatever explicit paths it is handed as Python, so anything
# else (YAML, templates, ...) floods the report with invalid-syntax findings.
_PY_SUFFIXES = (".py", ".pyi")


def _py_files(ctx) -> list[str]:
    return [f for f in ctx.files if f.lower().endswith(_PY_SUFFIXES)]


def _build_argv(ctx) -> list[str]:
    return [
        "ruff", "check", "--output-format", "json", "--force-exclude",
        "--extend-select", "S", "--", *_py_files(ctx),
    ]


def _show_files_argv(ctx) -> list[str]:
    """The files ruff WILL check, honouring `--force-exclude`."""
    return ["ruff", "check", "--force-exclude", "--show-files", "--", *_py_files(ctx)]


def _examined(ctx) -> frozenset[str]:
    """What ruff actually opened, not what we handed it.

    `--force-exclude` makes ruff honour the repo's own `exclude` config even
    for explicitly-passed paths, and it still exits 0 with zero findings when
    everything is excluded. So `_py_files(ctx)` is what we ASKED for and can
    overstate coverage; `--show-files` is what ruff agrees to look at.

    Costs one extra invocation. That is the price of being able to tell
    "clean" from "never looked", and resolution now depends on the difference.
    On any failure this returns the empty set -- the safe direction, since an
    unproven examination leaves findings open rather than clearing them.
    """
    probe = run_subprocess(_show_files_argv(ctx), ctx.root, TIMEOUT_S)
    if probe.state is not ToolState.OK or probe.returncode != 0:
        return frozenset()
    return frozenset(
        relativize(line.strip(), ctx.root)
        for line in (probe.raw or "").splitlines() if line.strip()
    )


def _run_own(ctx) -> RunnerResult:
    if not _py_files(ctx):
        # No Python in scope: a clean no-op, NOT a tool invocation -- ruff
        # given zero paths would fall back to scanning the whole cwd. It
        # examined nothing, and says so, so nothing resolves off this run.
        return RunnerResult(NAME, ToolState.OK, raw="[]", examined=frozenset())
    result = run_subprocess(_build_argv(ctx), ctx.root, TIMEOUT_S)
    out = json_or_crashed(NAME, result, _OK_RETURNCODES)
    if out.state is not ToolState.OK:
        return out
    return replace(out, examined=_examined(ctx))


def _inline_argv(codes: list[str], files: list[str]) -> list[str]:
    """FN-38's second pass: the repo's markers OFF. `--isolated` drops every
    config file (so `per-file-ignores` and a file-level `# ruff: noqa` with
    it), `--ignore-noqa` drops line comments, and `--select` asks for the
    resolved BLOCK rules only. `--isolated` drops the repo's `exclude` too,
    which is why `files` is what the first run EXAMINED, never what it was
    handed: an excluded file must never come back as "hidden"."""
    return ["ruff", "check", "--isolated", "--ignore-noqa", "--output-format", "json",
            "--select", ",".join(codes), "--", *files]


# ruff exits 2 on a `--select` code it does not know (measured on 0.16.10:
# "Unknown rule selector `S9999` in `select` from the CLI"), naming the first.
_UNKNOWN_SELECTOR = re.compile(r"Unknown rule selector `([^`]+)`")


def _inline_subprocess(ctx, files: list[str]) -> RunnerResult:
    """Run the second pass, dropping each code this ruff does not know.

    The list is the RESOLVED one, repo additions included, and nothing else
    validates it: a typo there, or a curated code a future ruff removes, would
    otherwise degrade the inline label on every run, and `--strict` would then
    refuse every push. A code ruff does not know is one it can never report,
    so no marker can hide anything under it. What was dropped is said on the
    result's stderr, which reaches the run's log."""
    codes, dropped = list(ctx.ruff_block_rules), []
    while True:
        timeout = inline.second_pass_timeout(ctx, TIMEOUT_S)
        if timeout is None:
            return inline.skipped(inline.RUFF)
        if not codes:
            return RunnerResult(inline.RUFF, ToolState.OK, raw="[]", stderr=(
                f"aramid: this ruff knows none of {', '.join(dropped)}"))
        result = run_subprocess(_inline_argv(codes, files), ctx.root, timeout)
        unknown = (_UNKNOWN_SELECTOR.search(result.stderr or "")
                   if result.returncode == 2 else None)
        if unknown is None or unknown.group(1) not in codes:
            if dropped:
                result = replace(result, stderr=(
                    f"aramid: this ruff does not know {', '.join(dropped)}; not asked "
                    f"about them\n{result.stderr or ''}"))
            return result
        codes.remove(unknown.group(1))
        dropped.append(unknown.group(1))


def _key(item, root) -> tuple:
    return (item["code"] or item["name"], relativize(item["filename"], root),
            item["location"]["row"])


def _run_inline(own: RunnerResult, ctx) -> RunnerResult:
    """The hits the second pass has and the first does not, matched by (rule,
    file, line). OK-and-empty when the first run examined nothing, like ruff's
    own result then: the label is in each gate's expected set."""
    examined = own.examined or frozenset()
    if not examined or not ctx.ruff_block_rules:
        return RunnerResult(inline.RUFF, ToolState.OK, raw="[]", examined=frozenset())
    out = json_or_crashed(inline.RUFF, _inline_subprocess(ctx, sorted(examined)),
                          _OK_RETURNCODES)
    if out.state is not ToolState.OK:
        return replace(out, examined=frozenset())
    seen = {_key(item, ctx.root) for item in json.loads(own.raw or "[]")}
    hidden = [item for item in json.loads(out.raw or "[]")
              if _key(item, ctx.root) not in seen]
    return replace(out, raw=json.dumps(hidden), examined=examined)


def run(ctx) -> RunnerResult:
    own = _run_own(ctx)
    if not ctx.inline_pass or own.state is not ToolState.OK:
        return own
    return inline.bundle(own, inline.within_deadline(
        ctx, inline.RUFF, lambda: _run_inline(own, ctx)))


# A `# noqa` on the flagged line. A file-level `# ruff: noqa` is config-shaped
# (it is on line 1, not on the hit), and is named with the config below.
_NOQA = re.compile(r"#\s*noqa\b", re.IGNORECASE)


def _parse_inline(sub: RunnerResult, ctx) -> list[RawFinding]:
    line_at = scanned_line_reader(ctx.root)
    out = []
    for item in json.loads(sub.raw or "[]"):
        code = item["code"] or item["name"]
        row = item["location"]["row"]
        line = line_at(item["filename"], row)
        marker = ("a `# noqa` comment" if _NOQA.search(line) else
                  "the repo's ruff config (`per-file-ignores`, or a file-level "
                  "`# ruff: noqa`)")
        out.append(RawFinding(
            tool=inline.RUFF, rule=inline.RULE,
            severity_raw=item.get("severity", "error"),
            file=relativize(item["filename"], ctx.root), line=row,
            message=inline.message(NAME, code, marker, item["message"]),
            line_content=line, subject=(NAME, code)))
    return out


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    items = json.loads(result.raw or "[]")
    # ruff's JSON carries the row but not the source line, so read it back from
    # the file ruff just scanned. See runners/base.scanned_line_reader.
    line_at = scanned_line_reader(ctx.root)
    found = [
        RawFinding(
            tool=NAME,
            rule=item["code"] or item["name"],
            severity_raw=item.get("severity", "error"),
            file=relativize(item["filename"], ctx.root),
            line=item["location"]["row"],
            message=item["message"],
            line_content=line_at(item["filename"], item["location"]["row"]),
        )
        for item in items
    ]
    # `result` is ruff's own result; its second pass, when one ran, rides in
    # `.sub_results` beside a copy of it (inline.bundle).
    for sub in getattr(result, "sub_results", None) or ():
        if sub.tool == inline.RUFF and sub.state is ToolState.OK:
            found.extend(_parse_inline(sub, ctx))
    return found
