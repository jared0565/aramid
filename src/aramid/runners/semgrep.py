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

# Every vendored rule `id:` in owasp.yml starts with this. semgrep's LIVE
# JSON `check_id` is NOT the bare rule id -- it is prefixed with the
# `--config` file's *directory* path, dot-joined (drive letter and every
# path separator collapse to `.`), e.g. for a checkout at
# `F:\Projects\aramid\...\rules\owasp.yml`:
#   "F.Projects.aramid.src.aramid.rules.owasp-top-ten.a03-injection.python-sqli-string-concat"
# block_rules.toml's `[semgrep] block` list contains the fnmatch pattern
# "owasp-top-ten.*", which anchors at the START of the string -- against the
# raw, prefixed check_id above that pattern NEVER matches (only the
# substring globs like "*sqli*" happen to still fire, which silently masked
# this for rule ids containing "sqli"/"deserialization"/"command-injection",
# but NOT for e.g. "owasp-top-ten.a02-crypto-failures.python-weak-hash-md5-
# sha1", which has no such substring and was reaching WARN instead of the
# intended BLOCK). See Task 81b.
_CANONICAL_RULE_PREFIX = "owasp-top-ten."


def _canonical_rule_id(check_id: str) -> str:
    """Strip semgrep's config-path prefix back to the canonical vendored
    rule id (block_rules.toml, and every override/suppression keyed by
    `rule`, is written against the canonical form). Finds the LEFTMOST
    occurrence of `_CANONICAL_RULE_PREFIX` and keeps everything from there
    onward -- every vendored rule id starts with it, so this recovers the
    exact `id:` from owasp.yml regardless of how deep the repo checkout
    path is. Falls back to the raw check_id, unchanged, when the prefix is
    absent (e.g. a future non-vendored/registry rule, like
    "python.lang.security.audit.exec-detected.exec-detected" in
    tests/fixtures/semgrep.json) -- there is no vendored-prefix convention
    to strip for those, and returning them unchanged preserves today's
    behavior exactly."""
    idx = check_id.find(_CANONICAL_RULE_PREFIX)
    return check_id[idx:] if idx != -1 else check_id


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
            rule=_canonical_rule_id(item["check_id"]),
            severity_raw=item["extra"]["severity"],
            file=relativize(item["path"], ctx.root),
            line=item["start"]["line"],
            message=item["extra"]["message"],
        )
        for item in data.get("results", [])
    ]
