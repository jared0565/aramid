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


def _build_argv(ctx) -> list[str]:
    return [
        "ruff", "check", "--output-format", "json", "--force-exclude",
        "--extend-select", "S", "--", *ctx.files,
    ]


def run(ctx) -> RunnerResult:
    result = run_subprocess(_build_argv(ctx), ctx.root, TIMEOUT_S)
    return json_or_crashed(NAME, result)


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
