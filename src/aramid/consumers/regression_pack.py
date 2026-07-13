"""Drain-time pack replay (spec section 5): run semgrep with ONLY the
regression ruleset against the queue item's changed files. Zero tokens;
cost is always 0.0. The normal gates already replay the pack on diffs
(Task 15) -- this consumer covers drained ranges, including commits that
bypassed hooks."""
import sys
import time

from aramid import config as config_mod
from aramid import gitutil
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.pack import RULES_REL_PATH
from aramid.runners import semgrep as semgrep_runner
from aramid.runners._util import json_or_crashed
from aramid.runners.base import RunContext, ToolState, run_subprocess

NAME = "regression_pack"
TIMEOUT_S = 120.0
_OK_RETURNCODES = frozenset({0, 1})


def _changed_paths(root, item) -> list[str]:
    return gitutil.diff_paths(root, item.base, item.head)


def consume(item, ctx: DrainContext) -> ConsumerResult:
    pack_file = ctx.root / RULES_REL_PATH
    if not pack_file.exists():
        return ConsumerResult(consumer=NAME, state="ok", note="no pack file")
    files = _changed_paths(ctx.root, item)
    if ctx.cfg is not None:
        files = config_mod.filter_paths(files, ctx.cfg)
    files = [f for f in files if (ctx.root / f).exists()]
    if not files:
        return ConsumerResult(consumer=NAME, state="ok", note="no files in range")
    started = time.monotonic()
    argv = ["semgrep", "--config", str(pack_file), "--json", "--metrics=off",
            "--quiet", "--", *files]
    result = run_subprocess(argv, ctx.root, TIMEOUT_S)
    checked = json_or_crashed("semgrep", result, _OK_RETURNCODES, empty="{}")
    duration = time.monotonic() - started
    if checked.state is not ToolState.OK:
        return ConsumerResult(consumer=NAME, state="degraded",
                              duration_s=duration, note=f"semgrep {checked.state}")
    findings = semgrep_runner.parse(checked, RunContext(root=ctx.root, files=files))
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=duration, cost=0.0)


base.CONSUMERS[NAME] = sys.modules[__name__]
