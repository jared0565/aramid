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

# Regression pack block-tier rule ids (aramid.pack, Task 13/15, spec §5) are
# namespaced "aramid-regression.block.<finding-id[:8]>". They ride their OWN
# arming flag, `cfg.pack["pack_block_armed"]` (default true), deliberately
# SEPARATE from `semgrep_block_armed` (the OWASP bake): a pack rule's source
# finding already passed the block decision once, when it was resolved and
# the rule compiled (aramid.pack._tier), so a resolved-then-reintroduced
# finding shouldn't wait out the generic SAST bake -- but an operator can
# still demote a noisy pack rule by setting [pack].pack_block_armed = false
# in aramid.toml. Checked before the general `block_rules.toml`
# [semgrep].block match (which IS gated by `semgrep_block_armed`) so
# pack-block rules never ride that gate even though
# "aramid-regression.block.*" is also listed there (that list entry is for
# discoverability/consumers.regression_pack, Task 16 -- not consulted for
# this decision). Resolves the spec-vs-implementation conflict ("ride
# semgrep's existing arming state" vs the Task 15 brief's block-with-
# default-config test) per the user's decision, 2026-07-13.
_PACK_BLOCK_PREFIX = "aramid-regression.block."

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

    # Phase 2b (spec section 3): LLM findings are classified at drain time
    # with the severity the reviewer reported (post-refute demotion already
    # applied by consumers.llm_review) but NEVER a drain-time BLOCK -- the
    # blocking verdict for confirmed-CRITICAL LLM findings is computed at
    # the pre-push gate from materialized ledger state + [llm].llm_block_armed
    # (aramid.review.llm_gate_findings), so arming applies retroactively.
    if tool == "llm-review":
        return severity, Verdict.WARN

    # TDD gate (1a): the git-fact code-without-test signal. WARN during the
    # bake; BLOCK once the repo opts in via `tdd_block_armed` -- routing the
    # verdict through classify (not a gate-only computation like llm-review)
    # means _has_genuine_block treats an armed tdd BLOCK as genuine with no
    # check.py change, and it survives the fresh-clone downgrade.
    if tool == "tdd":
        armed = getattr(cfg, "tdd_block_armed", False)
        return severity, Verdict.BLOCK if armed else Verdict.WARN

    # Mutation gate (1b): the drain's surviving-mutant findings. WARN during
    # the bake; BLOCK once the repo opts in via [mutation].mutation_block_armed.
    # Same shape as the tdd branch -- routing the verdict through classify (not
    # only the gate seam) makes _has_genuine_block treat an armed mutation BLOCK
    # as genuine with no check.py change, so it survives the fresh-clone
    # downgrade. mutation_gate.mutation_gate_findings computes this SAME rule
    # inline (mirroring llm_gate_findings); the two must agree.
    if tool == "mutation":
        armed = cfg.mutation.get("mutation_block_armed", False)
        return severity, Verdict.BLOCK if armed else Verdict.WARN

    ruff_block = block_rules.get("ruff", {}).get("block", [])
    if tool == "ruff" and rule in ruff_block:
        return severity, Verdict.BLOCK

    if tool == "semgrep":
        if rule.startswith(_PACK_BLOCK_PREFIX):
            armed = cfg.pack.get("pack_block_armed", True)
            return severity, Verdict.BLOCK if armed else Verdict.WARN
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
