"""deps adapter -- dependency CVE audit for Python (pip-audit) and JS
(npm/pnpm/yarn), lockfile-keyed cache with a 24h TTL.

Python: `pip-audit -r <requirements*.txt> -f json` over every
requirements*.txt found at the repo root (skip+note via MISSING if none
exist -- pip-audit against a repo venv is not implemented here, see report).
pip-audit's own JSON output carries no per-vulnerability severity field at
all (verified against pip_audit/_format/json.py upstream); per design doc §3
("advisories with no severity data default to WARN"), every pip-audit
finding uses a constant "low" severity_raw so policy.classify (task 5.1)
resolves it to WARN, never BLOCK.

JS: dispatched by lockfile presence -- `npm audit --json` / `pnpm audit
--json` / `yarn npm audit --json`. The three tools' JSON shapes are NOT
compatible with each other:
  - npm (v7+, "vulnerabilities" keyed by package name, each with a "via"
    array carrying severity/title/url) -- this shape is authoritative
    (widely documented, npm's own schema).
  - pnpm ({"report": {"advisories": {<id>: {...}}}}) -- reconstructed from
    documentation/community reports, not a live capture; flagged as an
    assumption to verify in integration.
  - yarn (Berry >=4.0.1) emits NDJSON, one JSON object per line, each
    shaped {"value": "<pkg>@<version>", "children": {"ID", "Issue",
    "Severity", "URL", ...}} -- confirmed via yarnpkg/berry#5892, but only
    for the >=4.0.1 wire format; older Yarn Berry/Classic emit a different
    single-JSON-document shape and are not handled here.

Cache: `.aramid/cache/deps-<sha256(lockfile bytes)>.json`, 24h TTL. "lockfile"
means the JS lockfile for the JS path, and the concatenated bytes of all
discovered requirements*.txt files for the Python path (pip has no lockfile
in the brief's scope). `ctx.force_refresh` (a RunContext field, default
False; `run_gate` sets it True for mode=="all") bypasses a fresh cache, so
`check --all` re-audits instead of serving a <=24h cache.

Mixed-stack repos (both requirements*.txt AND a JS lockfile -- a common
full-stack layout): `run()` runs BOTH `run_python()` and `run_js()` rather
than picking one and silently skipping the other. Since the Runner
protocol is one `run()` -> one RunnerResult, the two sub-results are
attached to the combined result via an ad-hoc `.sub_results` attribute
(not a declared RunnerResult field) instead
of being serialized/lossily merged into `.raw` -- each sub-result keeps its
own `.state`/`.tool`/`.returncode` intact. `parse()` checks for
`.sub_results` first and recurses into each. NOTE for Task 5.3: collapsing
two independent results into one top-level `.state` is inherently lossy --
the combined state is OK if *either* side is OK, so a caller that only
checks the combined `.state` can miss one side having CRASHED/TIMEOUT.
A consumer that needs to gate on "did BOTH audits succeed" must inspect
`.sub_results` directly (or call `run_python`/`run_js` independently, both
still exported for exactly this reason).
"""
import hashlib
import json
import time
from pathlib import Path

from aramid.detectors import detect_package_manager
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState, run_subprocess
from aramid.runners._util import json_or_crashed, relativize

NAME_PIP_AUDIT = "pip-audit"
TIMEOUT_S = 180.0
CACHE_TTL_S = 24 * 3600

# pip-audit's JSON output never carries severity -- see module docstring.
_PIP_AUDIT_SEVERITY_RAW = "low"

# Documented exit-code contracts: 0 = clean, 1 = vulnerabilities/issues
# found. Anything else means the tool errored before producing a report
# (pip-audit and all three JS audit tools share this 0/1 convention).
_OK_RETURNCODES = frozenset({0, 1})

_LOCKFILES = {"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "yarn": "yarn.lock"}
_JS_AUDIT_ARGV = {
    "npm": ["npm", "audit", "--json"],
    "pnpm": ["pnpm", "audit", "--json"],
    "yarn": ["yarn", "npm", "audit", "--json"],
}


# ---------------------------------------------------------------- cache ----

def _cache_path(root: Path, key_bytes: bytes) -> Path:
    digest = hashlib.sha256(key_bytes).hexdigest()
    return root / ".aramid" / "cache" / f"deps-{digest}.json"


def _read_cache(path: Path) -> str | None:
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > CACHE_TTL_S:
        return None
    try:
        return path.read_text()
    except OSError:
        return None


def _write_cache(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# --------------------------------------------------------------- python ----

def _find_requirements(root: Path) -> list[Path]:
    return sorted(p for p in root.glob("requirements*.txt") if p.is_file())


def _locate_in_requirements(root: Path, pkg_name: str) -> tuple[str, int]:
    """Best-effort: find the requirements*.txt line naming pkg_name."""
    reqs = _find_requirements(root)
    for req in reqs:
        try:
            lines = req.read_text().splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, start=1):
            if line.strip().lower().startswith(pkg_name.lower()):
                return relativize(str(req), root), i
    if reqs:
        return relativize(str(reqs[0]), root), 1
    return "requirements.txt", 1


def run_python(ctx) -> RunnerResult:
    reqs = _find_requirements(ctx.root)
    if not reqs:
        return RunnerResult(NAME_PIP_AUDIT, ToolState.MISSING)

    key_bytes = b"\x00".join(r.read_bytes() for r in reqs)
    cache_path = _cache_path(ctx.root, key_bytes)
    if not getattr(ctx, "force_refresh", False):
        cached = _read_cache(cache_path)
        if cached is not None:
            return RunnerResult(NAME_PIP_AUDIT, ToolState.OK, raw=cached)

    argv = ["pip-audit"]
    for r in reqs:
        argv += ["-r", str(r)]
    argv += ["-f", "json"]

    result = run_subprocess(argv, ctx.root, TIMEOUT_S)
    result = json_or_crashed(NAME_PIP_AUDIT, result, _OK_RETURNCODES, empty="{}")
    if result.state is ToolState.OK:
        _write_cache(cache_path, result.raw)
    return result


def parse_pip_audit(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    data = json.loads(result.raw or "{}")
    findings = []
    for dep in data.get("dependencies", []):
        if dep.get("skip_reason"):
            continue
        for vuln in dep.get("vulns", []):
            file_, line = _locate_in_requirements(ctx.root, dep["name"])
            desc = vuln.get("description") or vuln["id"]
            findings.append(RawFinding(
                tool=NAME_PIP_AUDIT,
                rule=vuln["id"],
                severity_raw=_PIP_AUDIT_SEVERITY_RAW,
                file=file_,
                line=line,
                message=f"{dep['name']} {dep['version']}: {desc}",
            ))
    return findings


# -------------------------------------------------------------------- js ----

def _lockfile_path(root: Path, pm: str) -> Path | None:
    name = _LOCKFILES.get(pm)
    if not name:
        return None
    p = root / name
    return p if p.exists() else None


def run_js(ctx) -> RunnerResult:
    pm = ctx.pkg_manager or detect_package_manager(ctx.root)
    if not pm or pm not in _JS_AUDIT_ARGV:
        return RunnerResult("deps-js", ToolState.MISSING)
    lockfile = _lockfile_path(ctx.root, pm)
    if lockfile is None:
        return RunnerResult(pm, ToolState.MISSING)

    cache_path = _cache_path(ctx.root, lockfile.read_bytes())
    if not getattr(ctx, "force_refresh", False):
        cached = _read_cache(cache_path)
        if cached is not None:
            # A cached payload is still shape-checked at parse time (parse runs
            # on every result, fresh or cached), so an unrecognized shape can't
            # hide behind the cache -- it surfaces as an advisory WARN either way.
            return RunnerResult(pm, ToolState.OK, raw=cached)

    result = run_subprocess(_JS_AUDIT_ARGV[pm], ctx.root, TIMEOUT_S)
    if pm == "yarn":
        result = _ndjson_or_crashed(pm, result, _OK_RETURNCODES)
    else:
        result = json_or_crashed(pm, result, _OK_RETURNCODES, empty="{}")
    if result.state is ToolState.OK:
        _write_cache(cache_path, result.raw)
    return result


def _ndjson_or_crashed(tool: str, result: RunnerResult, ok_returncodes: set[int]) -> RunnerResult:
    if result.state in (ToolState.MISSING, ToolState.TIMEOUT):
        return result
    if result.returncode not in ok_returncodes:
        return RunnerResult(tool, ToolState.CRASHED, result.raw, result.stderr,
                             result.duration_s, result.returncode)
    lines = [line for line in (result.raw or "").splitlines() if line.strip()]
    try:
        for line in lines:
            json.loads(line)
    except json.JSONDecodeError:
        return RunnerResult(tool, ToolState.CRASHED, result.raw, result.stderr,
                             result.duration_s, result.returncode)
    return RunnerResult(tool, ToolState.OK, result.raw, result.stderr,
                         result.duration_s, result.returncode)


def parse_npm(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    data = json.loads(result.raw or "{}")
    vulns = data.get("vulnerabilities")
    if vulns is None:
        return _parse_advisories_dict("npm", data.get("advisories", {}))
    findings = []
    for name, entry in vulns.items():
        via = next((v for v in (entry.get("via") or []) if isinstance(v, dict)), {})
        rule = via.get("url", "").rsplit("/", 1)[-1] or name
        findings.append(RawFinding(
            tool="npm",
            rule=rule,
            severity_raw=entry.get("severity", "low"),
            file=_LOCKFILES["npm"],
            line=1,
            message=via.get("title") or f"{name}: vulnerable dependency",
        ))
    return findings


def _parse_advisories_dict(tool: str, advisories: dict) -> list[RawFinding]:
    findings = []
    for adv_id, adv in advisories.items():
        findings.append(RawFinding(
            tool=tool,
            rule=str(adv.get("id", adv_id)),
            severity_raw=adv.get("severity", "low"),
            file=_LOCKFILES.get(tool, "package.json"),
            line=1,
            message=adv.get("title") or adv.get("overview") or f"advisory {adv_id}",
        ))
    return findings


def parse_pnpm(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    if not _pnpm_shape_recognized(result.raw):
        # Unrecognized-but-present shape (incl. a non-dict advisories that would
        # crash _parse_advisories_dict): surface an advisory WARN instead.
        return [_shape_drift_finding("pnpm")]
    data = json.loads(result.raw or "{}")
    advisories = data.get("report", {}).get("advisories") or data.get("advisories", {})
    return _parse_advisories_dict("pnpm", advisories)


def parse_yarn(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    if not _yarn_shape_recognized(result.raw):
        # Parseable NDJSON lines but none carry `children` -> format drift.
        return [_shape_drift_finding("yarn")]
    findings = []
    for line in (result.raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        children = obj.get("children")
        if not isinstance(children, dict):
            continue
        findings.append(RawFinding(
            tool="yarn",
            rule=str(children.get("ID", obj.get("value", "yarn-advisory"))),
            severity_raw=str(children.get("Severity", "low")),
            file=_LOCKFILES["yarn"],
            line=1,
            message=children.get("Issue") or obj.get("value", "vulnerable dependency"),
        ))
    return findings


def _pnpm_shape_recognized(raw: str) -> bool:
    """A clean pnpm audit carries an empty-but-PRESENT advisories DICT
    (report.advisories or a top-level advisories key); an unrecognized shape
    (wire-format drift) has neither. We require the container to be a dict, not
    merely present: `parse_pnpm` -> _parse_advisories_dict calls `.items()` on
    it, so a present-but-non-dict advisories (e.g. a string/list) would raise
    uncaught out of parse -- treating it as unrecognized makes parse_pnpm
    early-return the advisory-WARN drift finding instead. Non-JSON / empty /
    non-dict payload is not our concern here (json_or_crashed handled non-JSON)
    -> recognized."""
    try:
        data = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return True
    if not isinstance(data, dict) or not data:
        return True
    report = data.get("report")
    report = report if isinstance(report, dict) else {}
    return isinstance(report.get("advisories"), dict) or isinstance(data.get("advisories"), dict)


DEPS_SHAPE_DRIFT_RULE = "deps-audit-shape-unrecognized"


def _shape_drift_finding(pm: str) -> RawFinding:
    """A non-blocking advisory (medium severity -> WARN, below the deps critical
    block threshold) emitted when a pnpm/yarn audit's shape is unrecognized.
    Fail toward VISIBILITY without a hard CI failure on a possible false
    positive: the hand-authored shape fixtures are unverified (see module
    docstring), so a genuinely clean-but-drifted shape must not exit-2 the gate.
    The reviewer/operator still sees it and can verify the audit manually."""
    return RawFinding(
        tool=pm,
        rule=DEPS_SHAPE_DRIFT_RULE,
        severity_raw="medium",
        file=_LOCKFILES.get(pm, "package.json"),
        line=1,
        message=(f"{pm} audit output shape was not recognized (possible tool "
                 "version drift); findings may be incomplete -- verify the audit "
                 "manually"),
    )


def _yarn_shape_recognized(raw: str) -> bool:
    """Yarn Berry audit is NDJSON of advisory objects each carrying a
    `children` dict. If there are parseable object lines but NONE carry
    `children`, the wire format drifted (return False). No parseable lines
    (a clean audit emits nothing) -> recognized."""
    saw_line = saw_recognized = False
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        saw_line = True
        if isinstance(obj, dict) and isinstance(obj.get("children"), dict):
            saw_recognized = True
    return saw_recognized or not saw_line


# --------------------------------------------------------------- dispatch ----

def _run_mixed(ctx) -> RunnerResult:
    """Both a Python requirements*.txt AND a JS lockfile are present: run
    BOTH audits and bundle their results (see module docstring for why
    `.sub_results` rather than serializing into `.raw`)."""
    py_result = run_python(ctx)
    js_result = run_js(ctx)
    ok = py_result.state is ToolState.OK or js_result.state is ToolState.OK
    combined = RunnerResult("deps", ToolState.OK if ok else ToolState.MISSING)
    combined.sub_results = [py_result, js_result]
    return combined


def run(ctx) -> RunnerResult:
    reqs = _find_requirements(ctx.root)
    pm = ctx.pkg_manager or detect_package_manager(ctx.root)
    has_js = pm is not None and _lockfile_path(ctx.root, pm) is not None

    if reqs and has_js:
        return _run_mixed(ctx)
    if reqs:
        return run_python(ctx)
    if pm:
        return run_js(ctx)
    return RunnerResult("deps", ToolState.MISSING)


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    sub_results = getattr(result, "sub_results", None)
    if sub_results is not None:
        findings: list[RawFinding] = []
        for sub in sub_results:
            findings.extend(parse(sub, ctx))
        return findings
    if result.tool == NAME_PIP_AUDIT:
        return parse_pip_audit(result, ctx)
    if result.tool == "npm":
        return parse_npm(result, ctx)
    if result.tool == "pnpm":
        return parse_pnpm(result, ctx)
    if result.tool == "yarn":
        return parse_yarn(result, ctx)
    return []
