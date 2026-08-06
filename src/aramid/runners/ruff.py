"""ruff adapter -- Python lint + security (bandit-derived `S` family).

`--extend-select S` is mandatory: ruff's default rule set excludes the
flake8-bandit `S` family, so without this flag the security rules never fire
regardless of the target repo's own pyproject.toml/ruff.toml config. This is
how aramid enforces its own security baseline independent of repo config.
"""
import json
from dataclasses import replace

from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState, run_subprocess
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


def run(ctx) -> RunnerResult:
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


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    items = json.loads(result.raw or "[]")
    return [
        RawFinding(
            tool=NAME,
            rule=item["code"] or item["name"],
            severity_raw=item.get("severity", "error"),
            file=relativize(item["filename"], ctx.root),
            line=item["location"]["row"],
            message=item["message"],
        )
        for item in items
    ]
