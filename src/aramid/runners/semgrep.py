"""semgrep adapter -- SAST via a curated, vendored, offline OWASP rule pack.

`--metrics=off` (never phone home) and `--config <vendored path>` (never
fetch the registry at commit/push time -- offline by design, see design
doc §3). The actual rule YAML is populated by a later task; this module
only owns the path constant and the invocation/parse contract.
"""
import json
from dataclasses import replace
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

# Every namespace the VENDORED ruleset ships. The semgrep tier is rule-id
# driven -- block_rules.toml blocks "owasp-top-ten.*" wholesale -- so a rule
# that should NOT block by default has to live under a different namespace.
# Rust memory-safety lints (transmute, get_unchecked, set_len) are that case:
# worth surfacing, but legitimate in FFI and perf-critical code, so blocking
# a push on them by default would be exactly the noisy-BLOCK trap ARAMID.md
# warns about. An operator promotes them via block_rules if they want that.
# Each namespace must be listed here or `_canonical_rule_id` leaves the
# config-path prefix attached, and that path is machine-dependent -- which
# would make fingerprints, overrides and suppressions differ per checkout.
VENDORED_RULE_PREFIXES = (_CANONICAL_RULE_PREFIX, "rust-memory-safety.")

# The regression pack (aramid.pack, Task 13/15, spec §5) is a second
# `--config` file replayed alongside the vendored OWASP ruleset -- its rule
# ids are namespaced "aramid-regression.<block|warn>.<finding-id[:8]>".
# semgrep prefixes those with the SAME config-path-dot-joined scheme (see
# _CANONICAL_RULE_PREFIX above), so the LIVE check_id needs the identical
# rightmost-occurrence strip to recover the canonical id block_rules.toml /
# policy.classify() match against.
_PACK_RULE_PREFIX = "aramid-regression."


def _canonical_rule_id(check_id: str) -> str:
    """Strip semgrep's config-path prefix back to the canonical vendored
    rule id (block_rules.toml, and every override/suppression keyed by
    `rule`, is written against the canonical form). Finds the RIGHTMOST
    occurrence of any `VENDORED_RULE_PREFIXES` entry (or, failing
    that, `_PACK_RULE_PREFIX`) and keeps everything from there onward -- every
    vendored/pack rule id starts with one of these, so this recovers the
    exact `id:` even when the repo checkout path itself embeds the literal
    prefix (leftmost `.find` would truncate the id early). Falls
    back to the raw check_id, unchanged, when neither prefix is present
    (e.g. a future non-vendored/registry rule, like
    "python.lang.security.audit.exec-detected.exec-detected" in
    tests/fixtures/semgrep.json) -- there is no vendored-prefix convention
    to strip for those, and returning them unchanged preserves today's
    behavior exactly."""
    for prefix in (*VENDORED_RULE_PREFIXES, _PACK_RULE_PREFIX):
        idx = check_id.rfind(prefix)
        if idx != -1:
            return check_id[idx:]
    return check_id


def _build_argv(ctx) -> list[str]:
    argv = ["semgrep", "--config", str(VENDORED_RULES_PATH)]
    for extra in getattr(ctx, "extra_semgrep_configs", ()):
        argv += ["--config", extra]
    argv += ["--json", "--metrics=off", "--quiet", "--", *ctx.files]
    return argv


def _error_paths(data: dict) -> set[str]:
    """Files semgrep reported an error against, as semgrep spells them."""
    out = set()
    for err in data.get("errors") or []:
        for candidate in (err.get("path"), (err.get("location") or {}).get("path")):
            if candidate:
                out.add(candidate)
    return out


def _examined(data: dict, ctx) -> frozenset[str] | None:
    """Repo-relative paths semgrep can vouch for having analysed.

    Free -- semgrep already reports `paths.scanned`, so nothing extra runs.

    Three behaviours were MEASURED against semgrep 1.169.0 rather than
    assumed, and two of them say this adapter never had ruff's hole:
      - `.semgrepignore` is BYPASSED for explicitly-passed paths (an ignored
        file was scanned and did produce a finding);
      - so is the default 1MB `--max-target-bytes` limit (a 1,224,024-byte
        file was scanned and did produce a finding).
    What IS real: `paths.scanned` is genuinely narrower than the list handed
    over, because `_build_argv` passes `ctx.files` UNFILTERED -- no suffix
    screen, unlike ruff and eslint -- so `.md`, `.bin` and images go to
    semgrep and simply never come back as scanned.

    And a file semgrep could not parse is listed as `scanned`, yields no
    findings, and still exits 0 -- so it is subtracted here. Same reasoning as
    the eslint adapter's fatal-entry exclusion: without it, introducing a
    syntax error silently resolves every open finding in that file. Note
    `PartialParsing` means semgrep parsed *some* of the file; partial
    analysis is still not analysis it can be held to.

    Returns None -- "cannot report", falling back to the gate's file set --
    when `paths` is absent, as on a semgrep old enough not to emit it. That
    is what the None/empty-set distinction on `RunnerResult.examined` exists
    for: blocking every semgrep resolution forever would be a worse answer
    than the behaviour those users already have.
    """
    paths = (data.get("paths") or {}).get("scanned")
    if paths is None:
        return None
    unparsed = {relativize(p, ctx.root) for p in _error_paths(data)}
    return frozenset(
        rel for rel in (relativize(p, ctx.root) for p in paths)
        if rel not in unparsed
    )


def run(ctx) -> RunnerResult:
    result = run_subprocess(_build_argv(ctx), ctx.root, TIMEOUT_S)
    out = json_or_crashed(NAME, result, _OK_RETURNCODES, empty="{}")
    # A degraded semgrep vouches for nothing (see the eslint adapter).
    if out.state is not ToolState.OK:
        return replace(out, examined=frozenset())
    try:
        data = json.loads(out.raw or "{}")
    except json.JSONDecodeError:  # pragma: no cover - json_or_crashed pre-screens
        return replace(out, examined=frozenset())
    return replace(out, examined=_examined(data, ctx))


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
