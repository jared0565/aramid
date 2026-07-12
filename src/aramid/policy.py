"""policy -- raw-severity-to-verdict classification, the curated BLOCK-tier
rule list, override/suppression application, and the pre-push degraded-tool
escalation rule.

`classify` is deliberately pure and only reads `tool`, `rule`, `severity_raw`,
and (from `cfg`) `cfg.semgrep_block_armed` / `cfg.block_rules` -- `gate` is
accepted to match the brief's fixed 5-arg signature (and because a future
gate-specific policy tweak is plausible) but no current rule keys off it;
runner selection per gate is aramid.pipeline's job (Task 5.3), not policy's.
"""
import fnmatch
from dataclasses import dataclass, replace
from importlib import resources

import tomllib

from aramid.fingerprint import normalize_path
from aramid.models import Finding, Gate, Severity, Verdict

# Tool names that report dependency-CVE findings (see runners/deps.py).
_DEPS_TOOLS = {"pip-audit", "npm", "pnpm", "yarn"}

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# Raw severity vocabularies are tool-specific (ruff: "error"; semgrep:
# "ERROR"/"WARNING"/"INFO"; eslint: "1"/"2"; npm-family audits: "low".."critical";
# gitleaks/tests: constant "high"). This table is aramid's own, best-effort
# normalization onto the Severity enum -- not pinned by the brief, and never
# consulted for the BLOCK/WARN verdict decision itself (that's rule-id /
# threshold based, below). Unrecognized strings fall back to MEDIUM.
_SEVERITY_ALIASES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "2": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "1": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "note": Severity.INFO,
}


def _map_severity(severity_raw: str) -> Severity:
    return _SEVERITY_ALIASES.get(str(severity_raw).strip().lower(), Severity.MEDIUM)


def load_block_rules() -> dict:
    """Read the packaged `data/block_rules.toml` (curated BLOCK-tier rule
    list). Loaded via `importlib.resources` against the `aramid` package
    itself -- `data/` is a plain data directory, not a subpackage, so no
    `data/__init__.py` is needed; the file just needs to be listed under
    `[tool.setuptools.package-data]` for wheel builds. Editable installs
    resolve straight back to the source tree."""
    text = resources.files("aramid").joinpath("data", "block_rules.toml").read_text(encoding="utf-8")
    return tomllib.loads(text)


def classify(tool: str, rule: str, severity_raw: str, gate: Gate, cfg) -> tuple[Severity, Verdict]:
    severity = _map_severity(severity_raw)
    block_rules = cfg.block_rules

    if tool == "gitleaks":
        return severity, Verdict.BLOCK

    ruff_block = block_rules.get("ruff", {}).get("block", [])
    if tool == "ruff" and rule in ruff_block:
        return severity, Verdict.BLOCK

    if tool == "semgrep":
        semgrep_block = block_rules.get("semgrep", {}).get("block", [])
        if any(fnmatch.fnmatch(rule, pattern) for pattern in semgrep_block):
            verdict = Verdict.BLOCK if cfg.semgrep_block_armed else Verdict.WARN
            return severity, verdict
        return severity, Verdict.WARN

    if rule == "tests-failed":
        return severity, Verdict.BLOCK

    if tool in _DEPS_TOOLS:
        threshold = _map_severity(block_rules.get("deps", {}).get("block_severity", "critical"))
        if _SEVERITY_ORDER.index(severity) >= _SEVERITY_ORDER.index(threshold):
            return severity, Verdict.BLOCK
        return severity, Verdict.WARN

    return severity, Verdict.WARN


@dataclass
class OverrideRecord:
    id: str
    tool: str
    rule: str
    path: str  # normalized (forward slashes, case-normalized)
    reason: str


def apply_overrides(findings: list[Finding], overrides: list[OverrideRecord],
                     suppressions: list[OverrideRecord]) -> tuple[list[Finding], list[OverrideRecord]]:
    override_ids = {o.id for o in overrides}
    suppress_ids = {s.id for s in suppressions}

    downgraded: list[Finding] = []
    for f in findings:
        if f.verdict is Verdict.WARN and f.id in override_ids:
            downgraded.append(replace(f, verdict=Verdict.INFO))
        elif f.verdict is Verdict.BLOCK and f.id in suppress_ids:
            downgraded.append(replace(f, verdict=Verdict.INFO))
        else:
            downgraded.append(f)

    matched_ids = {f.id for f in findings}
    stale: list[OverrideRecord] = []
    for record in (*overrides, *suppressions):
        if record.id in matched_ids:
            continue
        near_miss = any(
            f.tool == record.tool and f.rule == record.rule
            and normalize_path(f.file) == normalize_path(record.path)
            for f in findings
        )
        if near_miss:
            stale.append(record)

    return downgraded, stale


def escalate_degraded(verdict_exit: int, degraded_block_tier: bool, gate: Gate) -> int:
    if gate is Gate.PRE_PUSH and degraded_block_tier:
        return 1
    return verdict_exit
