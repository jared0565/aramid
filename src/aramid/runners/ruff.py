"""ruff adapter -- Python lint + security (bandit-derived `S` family).

`--extend-select S` is mandatory: ruff's default rule set excludes the
flake8-bandit `S` family, so without this flag the security rules never fire
regardless of the target repo's own pyproject.toml/ruff.toml config. This is
how aramid enforces its own security baseline independent of repo config.
"""
import json

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


def run(ctx) -> RunnerResult:
    if not _py_files(ctx):
        # No Python in scope: a clean no-op, NOT a tool invocation -- ruff
        # given zero paths would fall back to scanning the whole cwd.
        return RunnerResult(NAME, ToolState.OK, raw="[]")
    result = run_subprocess(_build_argv(ctx), ctx.root, TIMEOUT_S)
    return json_or_crashed(NAME, result, _OK_RETURNCODES)


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
