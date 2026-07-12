"""pipeline -- wires detectors, runners, normalizer, policy, config, ledger,
redact, and gitutil into a single gate run (`run_gate`).

Two ignore-path filter passes (spec section 8b -- graphite artifacts must
never be scanned/fingerprinted):
  1. the discovered file set is filtered via `config.filter_paths` BEFORE
     it is handed to any runner as `RunContext.files` -- file-scoped tools
     (ruff/eslint/tsc/mypy/semgrep) never see an ignored path;
  2. the parsed RawFindings are filtered AGAIN, by path, before
     `normalizer.normalize()` runs -- because gitleaks scans by git log
     range (`--log-opts <rng>` / `--staged`), not by `ctx.files`, it can
     surface a finding for a path that was never in the file set at all.
     Filtering only step 1 would leave such a finding to be fingerprinted;
     this second pass is what actually guarantees "never fingerprinted".

Runner selection is a monkeypatchable module-level registry (`RUNNERS`,
`GATE_RUNNER_KEYS`) precisely so tests can swap in fake runner doubles
without touching real tool binaries -- see tests/unit/test_pipeline.py.
"""
import functools
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from aramid import config as config_mod
from aramid import gitutil, policy, redact
from aramid.detectors import detect_package_manager
from aramid.fingerprint import normalize_path
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Verdict
from aramid.normalizer import RawFinding, normalize
from aramid.policy import OverrideRecord
from aramid.runners import deps, eslint, gitleaks, ruff, semgrep, tests, typecheck
from aramid.runners.base import RunContext, RunnerResult, ToolState

# --------------------------------------------------------------- registry ----
# Monkeypatchable: tests replace entries/keys here to inject fake runner
# doubles instead of invoking real tool binaries.

RUNNERS: dict[str, object] = {
    "gitleaks": gitleaks,
    "ruff": ruff,
    "semgrep": semgrep,
    "eslint": eslint,
    "typecheck": typecheck,
    "deps": deps,
    "tests": tests,
}

GATE_RUNNER_KEYS: dict[Gate, list[str]] = {
    Gate.PRE_COMMIT: ["gitleaks", "ruff"],
    Gate.PRE_PUSH: ["gitleaks", "semgrep", "eslint", "typecheck", "deps", "tests"],
    # Gate.ALL isn't specified by the brief's runner-selection table; the
    # comprehensive (pre-push) set is the reasonable default for a full scan.
    Gate.ALL: ["gitleaks", "semgrep", "eslint", "typecheck", "deps", "tests"],
}

# Tool keys whose degradation (MISSING/CRASHED/TIMEOUT) drives the pre-push
# degraded-BLOCK-tier escalation (brief's "CRITICAL correctness" note).
BLOCK_TIER_KEYS = frozenset({"gitleaks", "semgrep", "tests"})

_BUDGET_KEY = {Gate.PRE_COMMIT: "pre_commit", Gate.PRE_PUSH: "pre_push", Gate.ALL: "pre_push"}
_BAD_STATES = (ToolState.MISSING, ToolState.CRASHED, ToolState.TIMEOUT)


@dataclass
class GateResult:
    exit_code: int
    findings: list[Finding]
    degraded: list[str]
    new_ids: list[str]
    stale_overrides: list[OverrideRecord]
    run_id: str


def _default_clock() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------- file set ------

def _discover_files(root: Path, mode: str) -> tuple[list[str], str | None]:
    if mode == "staged":
        return gitutil.staged_files(root), None
    if mode == "range":
        rng = gitutil.resolve_range(root)
        return gitutil.changed_files(root, rng), rng
    if mode == "all":
        return gitutil.all_tracked_files(root), None
    raise ValueError(f"unknown mode: {mode!r}")


def _ref_for_builder(mode: str, root: Path, rng: str | None) -> Callable[[str], str]:
    if mode == "staged":
        return lambda f: ":"
    if mode == "range":
        return lambda f: gitutil.newest_commit_touching(root, rng, f)
    return lambda f: "HEAD"  # mode == "all"


# ------------------------------------------------------------- execution -----

def _select_runners(gate: Gate) -> dict[str, object]:
    keys = GATE_RUNNER_KEYS.get(gate, [])
    return {key: RUNNERS[key] for key in keys}


def _run_selected(selected: dict[str, object], ctx: RunContext,
                   budget_s: float) -> dict[str, RunnerResult]:
    results: dict[str, RunnerResult] = {}
    if not selected:
        return results
    with ThreadPoolExecutor(max_workers=len(selected)) as ex:
        future_to_key = {ex.submit(module.run, ctx): key for key, module in selected.items()}
        done, not_done = wait(future_to_key, timeout=budget_s)
        for fut in done:
            key = future_to_key[fut]
            try:
                results[key] = fut.result()
            except Exception as exc:  # a runner raising is a crash, not a pipeline failure
                results[key] = RunnerResult(key, ToolState.CRASHED, stderr=str(exc))
        for fut in not_done:
            key = future_to_key[fut]
            results[key] = RunnerResult(key, ToolState.TIMEOUT)
    return results


def _flatten(results: dict[str, RunnerResult]) -> list[RunnerResult]:
    """Expand deps.py's `.sub_results` (mixed py+js audits collapse into one
    top-level RunnerResult -- see aramid.runners.deps module docstring) so
    each real sub-tool gets its own degraded flag and log file."""
    flat: list[RunnerResult] = []
    for r in results.values():
        subs = getattr(r, "sub_results", None)
        flat.extend(subs) if subs else flat.append(r)
    return flat


def _write_logs(root: Path, run_id: str, flat_results: list[RunnerResult],
                 raw_secrets: list[str]) -> None:
    logs_dir = root / ".aramid" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    for r in flat_results:
        scrubbed = redact.scrub(r.stderr or "", raw_secrets)
        (logs_dir / f"{r.tool}-{run_id}.log").write_text(scrubbed, encoding="utf-8")


# --------------------------------------------------------------- overrides ---

def _overrides_from_ledger(ledger: Ledger) -> list[OverrideRecord]:
    records = []
    for finding_id, rec in ledger.open_findings().items():
        if rec.get("status") == "overridden":
            records.append(OverrideRecord(
                id=finding_id, tool=rec.get("tool", ""), rule=rec.get("rule", ""),
                path=normalize_path(rec.get("file", "")), reason=""))
    return records


# -------------------------------------------------------------------- run ----

def run_gate(root: Path, gate: Gate, mode: str, cfg: config_mod.Config, ledger: Ledger,
             accept_degraded: str | None = None, *,
             clock: Callable[[], str] = _default_clock,
             run_id: str | None = None) -> GateResult:
    run_id = run_id if run_id is not None else uuid.uuid4().hex
    at = clock()

    # 1. file set for mode, then the always-on ignore-path filter (spec §8b).
    raw_files, rng = _discover_files(root, mode)
    files = config_mod.filter_paths(raw_files, cfg)

    # 2. select runners for this gate; build the shared RunContext.
    selected = _select_runners(gate)
    ctx = RunContext(root=root, files=files, rng=rng, pkg_manager=detect_package_manager(root))

    # 3. run concurrently under the gate's wall-clock budget.
    budget_s = cfg.timeouts.get(_BUDGET_KEY.get(gate, "pre_push"), 60.0)
    results = _run_selected(selected, ctx, budget_s)
    flat_results = _flatten(results)

    # 4/5. parse every result -> RawFindings (deps.parse recurses into its
    # own sub_results already, so top-level results are enough here).
    all_raws: list[RawFinding] = []
    for key, result in results.items():
        all_raws.extend(selected[key].parse(result, ctx))

    # secrets never land in logs, raw -- collected before writing them out.
    raw_secrets = [r.secret for r in all_raws if r.secret]
    _write_logs(root, run_id, flat_results, raw_secrets)

    # second ignore-path pass: drop any raw finding for an ignored path
    # BEFORE fingerprinting, regardless of whether it ever went through
    # ctx.files (gitleaks scans by git-log range, not by file list).
    raws_in_scope = [r for r in all_raws if not config_mod.is_ignored(r.file, cfg.ignore_paths)]

    salt = redact.load_or_create_salt(root / ".aramid")
    ref_for = _ref_for_builder(mode, root, rng)
    classify = functools.partial(policy.classify, cfg=cfg)
    findings = normalize(raws_in_scope, root, ref_for, salt, gate, classify)

    # 6. overrides (ledger-recorded WARN overrides) + suppressions (BLOCK
    # suppressions + reasonless-suppression synthetic WARN findings).
    overrides = _overrides_from_ledger(ledger)
    suppress_records, suppress_warnings = config_mod.load_suppressions(root)
    findings = findings + suppress_warnings
    findings, stale = policy.apply_overrides(findings, overrides, suppress_records)

    # 7. record this run; enforce the pre-push no-new-warnings ratchet.
    scope_tools = {r.tool for r in flat_results if r.state is ToolState.OK}
    scope_files = set(files)
    new_ids = ledger.record_run(run_id, at, str(gate), scope_tools, scope_files, findings)

    if gate is Gate.PRE_PUSH:
        findings = [
            replace(f, verdict=Verdict.BLOCK) if f.id in new_ids and f.verdict is Verdict.WARN
            else f
            for f in findings
        ]

    # 8. exit code.
    degraded_tools = sorted({r.tool for r in flat_results if r.state in _BAD_STATES})
    degraded_block_tier = any(
        key in results and results[key].state in _BAD_STATES for key in BLOCK_TIER_KEYS
    )
    block_findings = any(f.verdict is Verdict.BLOCK for f in findings)

    if block_findings:
        exit_code = 1
    elif accept_degraded and gate is Gate.PRE_PUSH and degraded_block_tier:
        ledger.append(Event(
            EventType.INFRASTRUCTURE_BYPASS, run_id, at,
            payload={"reason": accept_degraded, "gate": str(gate), "degraded": degraded_tools}))
        exit_code = 2 if degraded_tools else 0
    else:
        exit_code = policy.escalate_degraded(0, degraded_block_tier, gate)
        if exit_code == 0 and degraded_tools:
            exit_code = 2

    return GateResult(exit_code=exit_code, findings=findings, degraded=degraded_tools,
                       new_ids=new_ids, stale_overrides=stale, run_id=run_id)
