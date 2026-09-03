"""deps adapter -- dependency CVE audit for Python (pip-audit) and JS
(npm/pnpm/yarn), lockfile-keyed cache with a 24h TTL.

Python: `pip-audit -r <requirements*.txt> -f json` over every
requirements*.txt found at the repo root; with none, `pip-audit <root>
-f json` (project-path mode) when pyproject.toml carries a `[project]`
table, which is the dependency source pip-audit resolves there. Neither
-> MISSING. The two modes never combine (pip-audit refuses `-r` beside a
project path), so requirements files keep precedence -- the behaviour
every requirements-based repo already had. A tool-only pyproject (no
`[project]` table) is NOT a source: pip-audit exits 1 with empty stdout on
it, and 1 is in the OK set ("vulnerabilities found"), so asking would
read as a clean audit. `python_sources()` is the one predicate; pipeline
applicability, toolset expectation and doctor all call it rather than
globbing themselves. pip-audit against a repo venv is not implemented.
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
import dataclasses
import hashlib
import json
import time
import tomllib
from pathlib import Path

from aramid import toolpath
from aramid.detectors import detect_package_manager
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState, run_subprocess
from aramid.runners._util import json_or_crashed, relativize

NAME_PIP_AUDIT = "pip-audit"
PYPROJECT = "pyproject.toml"
NAME_CARGO_AUDIT = "cargo-audit"
# A DISTINCT tool name, not a rule namespace under NAME_CARGO_AUDIT: keeping
# it out of `policy._DEPS_TOOLS` is guarantee 1 of three (see
# `_parse_cargo_warnings`), and a separate tool also keeps these findings'
# fingerprints disjoint from the blocking advisory path, so a crate that is
# unmaintained today and CVE'd tomorrow produces two distinct findings rather
# than one mutating in place.
NAME_CARGO_AUDIT_WARNINGS = "cargo-audit-warnings"
TIMEOUT_S = 180.0
CACHE_TTL_S = 24 * 3600

# pip-audit's JSON output never carries severity -- see module docstring.
_PIP_AUDIT_SEVERITY_RAW = "low"

# Documented exit-code contracts: 0 = clean, 1 = vulnerabilities/issues
# found. Anything else means the tool errored before producing a report
# (pip-audit and all three JS audit tools share this 0/1 convention).
_OK_RETURNCODES = frozenset({0, 1})

_LOCKFILES = {"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "yarn": "yarn.lock",
              # Not a package-manager key like the three above (cargo the
              # package manager and cargo-audit the security tool are
              # different names, unlike npm/pnpm/yarn where the audit
              # subcommand shares its package manager's name) -- present
              # here only so _shape_drift_finding(NAME_CARGO_AUDIT) resolves
              # the right lockfile path, not for _lockfile_path's
              # package-manager-keyed JS dispatch.
              NAME_CARGO_AUDIT: "Cargo.lock"}
_JS_AUDIT_ARGV = {
    "npm": ["npm", "audit", "--json"],
    "pnpm": ["pnpm", "audit", "--json"],
    "yarn": ["yarn", "npm", "audit", "--json"],
}
_CARGO_LOCKFILE = "Cargo.lock"


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


def _pyproject_with_project_table(root: Path) -> Path | None:
    """pyproject.toml when it parses and declares a `[project]` table --
    the only shape pip-audit's project-path mode accepts. A file that is
    missing, unreadable, malformed or tool-only reads as no source."""
    path = root / PYPROJECT
    if not path.is_file():
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    return path if isinstance(data.get("project"), dict) else None


def python_sources(root: Path) -> list[Path]:
    """The files pip-audit would audit here: every requirements*.txt at the
    root, else the pyproject.toml with a `[project]` table, else nothing.
    THE predicate for "does the Python dependency audit apply" -- shared by
    run_python, pipeline._is_applicable, toolset.expected_tool_names and
    doctor.probe_deps so the four cannot drift."""
    reqs = _find_requirements(root)
    if reqs:
        return reqs
    pyproject = _pyproject_with_project_table(root)
    return [pyproject] if pyproject is not None else []


def _locate_dependency(root: Path, pkg_name: str) -> tuple[str, int]:
    """Best-effort: the source line naming pkg_name -- a requirements*.txt
    line, or the `[project]` dependency entry in pyproject.toml (project
    mode). Falls back to line 1 of the first source."""
    sources = python_sources(root)
    want = pkg_name.lower().replace("_", "-")
    for src in sources:
        try:
            lines = src.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(lines, start=1):
            if line.strip().strip("'\",").lower().replace("_", "-").startswith(want):
                return relativize(str(src), root), i
    if sources:
        return relativize(str(sources[0]), root), 1
    return "requirements.txt", 1


def run_python(ctx) -> RunnerResult:
    sources = python_sources(ctx.root)
    if not sources:
        return RunnerResult(NAME_PIP_AUDIT, ToolState.MISSING)
    reqs = [s for s in sources if s.name != PYPROJECT]

    key_bytes = b"\x00".join(s.read_bytes() for s in sources)
    cache_path = _cache_path(ctx.root, key_bytes)
    if not getattr(ctx, "force_refresh", False):
        cached = _read_cache(cache_path)
        if cached is not None:
            return RunnerResult(NAME_PIP_AUDIT, ToolState.OK, raw=cached)

    argv = ["pip-audit"]
    if reqs:
        for r in reqs:
            argv += ["-r", str(r)]
    else:
        argv.append(str(ctx.root))  # project-path mode: the [project] table
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
            file_, line = _locate_dependency(ctx.root, dep["name"])
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
    # Restamps MISSING/TIMEOUT rather than returning them unchanged, for the
    # reason `_util.json_or_crashed` documents at length: run_subprocess names
    # results after argv[0], which is not the runner's name whenever the two
    # differ. Kept in step with that helper deliberately -- yarn taking this
    # branch while npm/pnpm take the JSON one must not mean the two disagree
    # about what a degraded result is called.
    if result.state in (ToolState.MISSING, ToolState.TIMEOUT):
        return dataclasses.replace(result, tool=tool)
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


# ------------------------------------------------------------------ cargo ----

def run_cargo(ctx) -> RunnerResult:
    lockfile = ctx.root / _CARGO_LOCKFILE
    if not lockfile.exists():
        return RunnerResult(NAME_CARGO_AUDIT, ToolState.MISSING)

    # `cargo` resolving is NOT evidence that `cargo audit` works. cargo-audit
    # is a separately-installed subcommand plugin (`cargo install
    # cargo-audit`), shipped as a `cargo-audit` binary that cargo dispatches
    # to. Without it, `cargo audit --json` exits 101 with "no such command:
    # audit" and no JSON -- which json_or_crashed reads as CRASHED, i.e.
    # "this tool broke" for what is really "this tool isn't installed"
    # (measured against a live Rust repo, 2026-07-31). Probe the plugin
    # directly and report MISSING, the same signal run_subprocess gives for
    # any other unresolvable binary. Resolved via toolpath, not shutil.which,
    # for the reason run_subprocess documents: the two must agree or `doctor`
    # becomes a false green light.
    if toolpath.resolve(NAME_CARGO_AUDIT) is None:
        return RunnerResult(NAME_CARGO_AUDIT, ToolState.MISSING)

    cache_path = _cache_path(ctx.root, lockfile.read_bytes())
    if not getattr(ctx, "force_refresh", False):
        cached = _read_cache(cache_path)
        if cached is not None:
            return RunnerResult(NAME_CARGO_AUDIT, ToolState.OK, raw=cached)

    result = run_subprocess(["cargo", "audit", "--json"], ctx.root, TIMEOUT_S)
    result = json_or_crashed(NAME_CARGO_AUDIT, result, _OK_RETURNCODES, empty="{}")
    if result.state is ToolState.OK:
        _write_cache(cache_path, result.raw)
    return result


def _cargo_shape_recognized(raw: str) -> bool:
    """cargo-audit's `--json` report has a long-stable, documented top-level
    shape: `{"vulnerabilities": {"found": bool, "count": int, "list": [...]}}`.
    NOT a live capture -- correcting this docstring's first version, which
    claimed cargo was absent: cargo IS installed here, but the `cargo-audit`
    subcommand plugin is not (`toolpath.resolve("cargo-audit") is None`,
    checked 2026-07-31), so no real `--json` payload was ever captured. This
    is built from documented/community-known output, same honesty convention
    as `_pnpm_shape_recognized`'s own
    "reconstructed from documentation... flagged as an assumption to verify
    in integration" precedent. Requires the container shape parse_cargo
    actually reads (a dict `vulnerabilities` with a list `list`) to be
    present; anything else degrades to the shape-drift advisory rather than
    a crash or a silently empty result."""
    try:
        data = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return True
    if not isinstance(data, dict) or not data:
        return True
    vulns = data.get("vulnerabilities")
    return isinstance(vulns, dict) and isinstance(vulns.get("list"), list)


# Fallback severity for an advisory with no usable CVSS vector. "medium"
# (rather than pip-audit's "low") reflects that a RUSTSEC id is already a
# curated, confirmed advisory, not a broad unconfirmed scan hit. This is also
# the FLOOR: `_cvss_severity` never returns anything below it, so parsing a
# vector can only raise the severity, never quietly lower it.
#
# This constant used to be applied unconditionally, on the stated premise
# that "many RUSTSEC advisories carry no CVSS score at all". That premise was
# falsified the first time real `cargo audit --json` output was captured
# (2026-07-31): both advisories in `tests/fixtures/cargo-audit-cvss.json`
# carry full CVSS v3.1 vectors. The bug that hid behind it was not cosmetic
# -- `deps.block_severity` defaults to "critical", so a flat "medium" meant a
# network-reachable, no-privileges-required total-compromise advisory
# (RUSTSEC-2021-0003, AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H) was reported as a WARN
# and could never block a push, while the equivalent npm advisory does.
_CARGO_AUDIT_SEVERITY_RAW = "medium"

# Informational warnings are stamped "info", but the severity is NOT what
# keeps them out of the block path -- `block_rules.deps.block_severity` is
# operator-tunable, so a severity constant is a preference, not a guarantee.
# See `_parse_cargo_warnings` for the three mechanisms that are the guarantee.
_CARGO_AUDIT_WARNING_SEVERITY_RAW = "info"

# CVSS v3.1 metric bands -> the five severity names policy._SEVERITY_ALIASES
# accepts. Deliberately NOT a base-score calculation: the real formula is
# exploitability/impact sub-scores with specific rounding, there is no oracle
# for it in this repo, and a subtly wrong score is worse than a coarse band
# because it looks authoritative. This reads only the metrics that decide the
# band -- impact (C/I/A), reachability (AV) and friction (AC/PR/UI) -- plus
# scope (S), where a changed scope escalates because CVSS treats it as
# breaking out of the vulnerable component.
def _cvss_severity(vector):
    """Band a CVSS v3.1 vector string, or None when there is nothing usable
    to band (absent, non-string, non-v3, or no High impact metric). Returning
    None means "fall back to the constant" -- never a downgrade. Verified
    against the only two real vectors available: the smallvec one bands
    critical, the time one (local, availability-only) does not."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        if value:
            metrics[key] = value
    high = sum(1 for m in ("C", "I", "A") if metrics.get(m) == "H")
    if high == 0:
        # Only Low/None impacts: nothing here justifies exceeding the floor.
        return None
    reachable = metrics.get("AV") in ("N", "A")
    unimpeded = (metrics.get("AC") == "L" and metrics.get("PR") == "N"
                 and metrics.get("UI") == "N")
    if reachable and unimpeded:
        if high >= 2 or metrics.get("S") == "C":
            return "critical"
        return "high"
    return "medium"


def parse_cargo(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    if not _cargo_shape_recognized(result.raw):
        return [_shape_drift_finding(NAME_CARGO_AUDIT)]
    data = json.loads(result.raw or "{}")
    findings = []
    for entry in data.get("vulnerabilities", {}).get("list", []):
        advisory = entry.get("advisory") or {}
        package = entry.get("package") or {}
        adv_id = str(advisory.get("id") or "cargo-audit-advisory")
        pkg_name = package.get("name", "unknown")
        pkg_version = package.get("version", "")
        title = advisory.get("title") or adv_id
        severity = _cvss_severity(advisory.get("cvss")) or _CARGO_AUDIT_SEVERITY_RAW
        findings.append(RawFinding(
            tool=NAME_CARGO_AUDIT,
            rule=adv_id,
            severity_raw=severity,
            file=_CARGO_LOCKFILE,
            line=1,
            message=f"{pkg_name} {pkg_version}: {title}".strip(),
        ))
    findings.extend(_parse_cargo_warnings(data, ctx))
    return findings


def _parse_cargo_warnings(data: dict, ctx) -> list[RawFinding]:
    """RUSTSEC's informational `warnings` -- unmaintained, unsound and yanked
    crates -- as WARN-tier findings, opt-in via `[deps].cargo_audit_warnings`.

    Requested by Operation Firewall (interop round 20) whose threat model
    names supply-chain compromise: an unmaintained transitive crate is closer
    to a live risk there than to hygiene. Off by default everywhere else,
    because most of these have no fix -- an unmaintained crate stays
    unmaintained -- so they would be a permanent, unactionable finding.

    THREE separate things keep this out of the block path, and all three are
    load-bearing rather than defence in depth (round 20's analysis):

      1. `NAME_CARGO_AUDIT_WARNINGS` is deliberately NOT in
         `policy._DEPS_TOOLS`, so the operator-tunable
         `block_rules.deps.block_severity` comparison cannot reach it. A
         severity constant alone would NOT do: lowering that threshold to
         catch more real CVEs would start blocking on these too.
      2. `policy.classify` returns WARN for this tool unconditionally, ahead
         of every promotion path including `block_rules`.
      3. It is exempt from the pre-push no-new-warnings ratchet. Without
         this, 1 and 2 give a feature that is warn-tier by classification and
         BLOCKING in practice on first appearance -- and first appearance is
         the only appearance that matters, since after that it is baselined.
         An upstream RUSTSEC publication event, on a repo that changed
         nothing, would fail a push with no fix available and no exit but a
         suppression.

    The precedent for 3 is `DEPS_SHAPE_DRIFT_RULE`, already exempt from that
    same list for the same reason.

    Wire format from a verbatim capture (`tests/fixtures/cargo-audit-
    warnings.json`, cargo-audit 0.22.2): `warnings` is an object keyed by
    KIND ("unmaintained", "unsound", "yanked"), each value a LIST -- not a
    flat list, and not keyed by advisory id. `advisory` is nullable: a yanked
    crate has no RUSTSEC advisory behind it, so the kind is the only id
    available and the rule falls back to it.
    """
    if not getattr(ctx, "cargo_audit_warnings", False):
        return []
    findings = []
    warnings = data.get("warnings")
    if not isinstance(warnings, dict):
        return []
    for kind, entries in sorted(warnings.items()):
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            advisory = entry.get("advisory") or {}
            package = entry.get("package") or {}
            pkg_name = package.get("name", "unknown")
            pkg_version = package.get("version", "")
            adv_id = advisory.get("id")
            # Namespaced by kind so a repo can target one class of warning
            # (`unmaintained` vs `yanked`) in triage/overrides without
            # matching real advisory ids, which share the RUSTSEC-* space
            # with the blocking vulnerability path.
            rule = f"{kind}/{adv_id}" if adv_id else str(kind)
            title = advisory.get("title") or f"{pkg_name} is {kind}"
            findings.append(RawFinding(
                tool=NAME_CARGO_AUDIT_WARNINGS,
                rule=rule,
                severity_raw=_CARGO_AUDIT_WARNING_SEVERITY_RAW,
                file=_CARGO_LOCKFILE,
                line=1,
                message=f"{pkg_name} {pkg_version}: {title}".strip(),
            ))
    return findings


# --------------------------------------------------------------- dispatch ----

def _run_combined(ctx, runners: list) -> RunnerResult:
    """Two or more of {python, js, cargo} are applicable: run every one and
    bundle results (see module docstring for why `.sub_results` rather than
    serializing into `.raw`). Generalizes the former python+js-only
    `_run_mixed` to any combination, now that a third ecosystem exists."""
    results = [fn(ctx) for fn in runners]
    ok = any(r.state is ToolState.OK for r in results)
    combined = RunnerResult("deps", ToolState.OK if ok else ToolState.MISSING)
    combined.sub_results = results
    return combined


def run(ctx) -> RunnerResult:
    py_sources = python_sources(ctx.root)
    pm = ctx.pkg_manager or detect_package_manager(ctx.root)
    has_js = pm is not None and _lockfile_path(ctx.root, pm) is not None
    has_cargo = (ctx.root / _CARGO_LOCKFILE).exists()

    applicable = []
    if py_sources:
        applicable.append(run_python)
    if has_js:
        applicable.append(run_js)
    if has_cargo:
        applicable.append(run_cargo)

    if len(applicable) > 1:
        return _run_combined(ctx, applicable)
    if applicable:
        return applicable[0](ctx)
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
    if result.tool == NAME_CARGO_AUDIT:
        return parse_cargo(result, ctx)
    return []
