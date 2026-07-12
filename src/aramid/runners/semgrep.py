"""semgrep adapter -- SAST via a curated, vendored, offline OWASP rule pack.

`--metrics=off` (never phone home) and `--config <vendored path>` (never
fetch the registry at commit/push time -- offline by design, see design
doc §3). The actual rule YAML is populated by a later task; this module
only owns the path constant and the invocation/parse contract.
"""
import json
from pathlib import Path

from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState, run_subprocess
from aramid.runners._util import json_or_crashed, relativize

NAME = "semgrep"
TIMEOUT_S = 120.0

# semgrep's documented exit codes: 0 = clean, 1 = findings reported.
# 2 = fatal error (bad config, parse failure, ...) -- not a verdict.
_OK_RETURNCODES = frozenset({0, 1})

# Placeholder vendored rules path -- the real curated OWASP ruleset YAML is
# provided by a later task (ships inside the aramid package so `--config`
# never needs network access).
VENDORED_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "owasp.yml"


def _build_argv(ctx) -> list[str]:
    return [
        "semgrep", "--config", str(VENDORED_RULES_PATH), "--json",
        "--metrics=off", "--quiet", "--", *ctx.files,
    ]


def run(ctx) -> RunnerResult:
    result = run_subprocess(_build_argv(ctx), ctx.root, TIMEOUT_S)
    return json_or_crashed(NAME, result, _OK_RETURNCODES, empty="{}")


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    data = json.loads(result.raw or "{}")
    return [
        RawFinding(
            tool=NAME,
            rule=item["check_id"],
            severity_raw=item["extra"]["severity"],
            file=relativize(item["path"], ctx.root),
            line=item["start"]["line"],
            message=item["extra"]["message"],
        )
        for item in data.get("results", [])
    ]
