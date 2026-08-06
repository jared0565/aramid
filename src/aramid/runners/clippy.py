"""clippy adapter -- Rust lint, the analysis half of Rust gate discovery.

Why this exists: Operation Firewall's coding agent reported that aramid's
Cargo misdetection "means Aramid does not natively provide Rust dependency
auditing OR Rust-specific gate discovery". `37a9bd6` closed the dependency
half (cargo-audit); this closes the analysis half. Before it, a Rust repo
got gitleaks, cargo-audit and whatever its own scripts did -- aramid's
language runners were ruff (Python), eslint (JS/TS) and typecheck
(tsc/mypy), and the vendored semgrep ruleset is 13 rules covering only
JS/TS and Python, so semgrep matched nothing on Rust either.

A repo CAN run clippy from its own `[tests].command` wrapper, and Operation
Firewall does. That is not equivalent: findings routed through the tests
gate collapse into a single pass/fail bit with no fingerprint, no
severity tier, no triage, no baseline and no regression-pack entry. Running
clippy as a runner makes each lint a first-class Finding on the same
footing as a ruff or eslint one.

Wire format (verified against a live capture, 2026-07-31, not reconstructed
from docs): `cargo clippy --message-format=json` emits NDJSON, one object
per line, with a `reason` discriminator. Only `compiler-message` records
carry diagnostics; `compiler-artifact` and `build-finished` also appear and
are not findings. Each diagnostic has `level` ("warning"/"error", which map
onto policy's existing alias table with no new vocabulary), `code.code`
(the lint id -- bare for rustc lints, `clippy::`-namespaced for clippy's
own, and the namespacing is preserved so `block_rules.clippy` can target
either), and `spans[]` with `file_name`/`line_start`.

Two behaviours checked live rather than assumed:
  - Cached runs still report. cargo replays stored diagnostics, so a warm
    build does NOT yield an empty stream that would read as a false clean
    (measured: identical diagnostic counts on a second, unchanged run).
  - `cargo clippy` exits 101 both when the crate fails to compile AND when
    the clippy component is not installed. Those are opposite meanings, so
    the component is probed by binary BEFORE cargo is invoked -- the same
    lesson as `6efed44` for cargo-audit, where a return-code-only reading
    reported CRASHED for a tool that simply was not installed.

Scope note: clippy analyses the whole crate, not `ctx.files`. Unlike
ruff/eslint it takes no file list, so findings can name files outside the
current diff. That is the same shape as deps/tests, and the ledger's
baseline is what keeps pre-existing lint from blocking day one.

`--all-targets` is deliberate, not incidental. Without it cargo lints the
DEFAULT targets only, which silently excludes inline `#[cfg(test)]` modules
(the cfg is active only when building the test target), integration tests
under `tests/`, benches and examples. Measured on a throwaway crate: the
same lint in library code, in a `#[cfg(test)]` module and in
`tests/integration.rs` produced one finding by default and three with the
flag. A security-adjacent linter that cannot see a repo's test code is
missing real code, and test helpers are exactly where `unwrap`-heavy,
shell-invoking scaffolding tends to live.

Two costs, both accepted. It compiles more, so a cold cache is likelier to
hit TIMEOUT_S -- honest degradation, and now correctly NAMED as clippy's
(see `_ndjson_or_crashed`). And it makes cargo report a file's lints once
per target that compiles it, which `parse` deduplicates; that dedupe is
load-bearing rather than cosmetic, for the reason given there.
"""
import dataclasses
import json
import re
from pathlib import Path

from aramid import toolpath
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState, run_subprocess
from aramid.runners._util import relativize

NAME = "clippy"

# The separately-installed component (`rustup component add clippy`) that
# `cargo clippy` dispatches to, exactly as cargo-audit is for `cargo audit`.
CLIPPY_BIN = "cargo-clippy"

# Compiling is not free even incrementally, so this is a pre-push runner
# (GATE_RUNNER_KEYS) with a budget well above eslint's. A cold-cache crate
# can still exceed it; that degrades to TIMEOUT, which is honest and
# non-blocking -- clippy is not in pipeline.BLOCK_TIER_KEYS.
TIMEOUT_S = 240.0

# 0 = clean or lint-only; 101 = the crate failed to compile. A failed
# compile still emits real `level: "error"` diagnostics, which are the most
# severe output clippy ever produces -- discarding them as a crash would
# throw away exactly the findings most worth having.
_OK_RETURNCODES = frozenset({0, 101})


def _ndjson_or_crashed(result: RunnerResult) -> RunnerResult:
    """NDJSON variant of `_util.json_or_crashed` -- the stream is one JSON
    object per line, not a single document, so a whole-buffer `json.loads`
    would reject every valid response. Empty output is a legitimately clean
    crate, not a crash.

    Also RESTAMPS the result with this runner's name. `run_subprocess`
    derives `RunnerResult.tool` from `argv[0]`, which here is "cargo" -- so
    without this the pipeline would record the runner as "cargo", a name
    absent from `toolset.RUNNER_TOOL_NAMES` and different from the "clippy"
    that `parse` stamps on every Finding. `_util.json_or_crashed` restamps
    for the same reason; this NDJSON variant must not forget to. (Caught by
    a live gate run, not by unit tests: the fakes returned a result already
    named "clippy" and so never exercised the real naming path.)

    The restamp is UNCONDITIONAL. Gating it on OK was the first fix's own
    blind spot -- a live gate run exercises the OK path, so that is the path
    it was scoped to -- and it left the degraded results wrong. Those are the
    ones that matter most here: `TIMEOUT_S` (240s) is under the 300s pre-push
    budget, so a cold-cache crate trips *this* runner's timeout rather than
    the pipeline's, taking the early return and reporting as "cargo" -- the
    exact name cargo-audit's timeouts also carried, which collapsed both
    gates into one `degraded_tools` entry and one overwritten log file.
    """
    if result.state is not ToolState.OK:
        return dataclasses.replace(result, tool=NAME)
    state = ToolState.OK
    if result.returncode not in _OK_RETURNCODES:
        state = ToolState.CRASHED
    else:
        for line in (result.raw or "").splitlines():
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError:
                state = ToolState.CRASHED
                break
    return RunnerResult(NAME, state, result.raw, result.stderr,
                        result.duration_s, result.returncode)


# A dependency list is space-separated with `\ ` escaping a literal space.
# The lookbehind is what keeps Windows path SEPARATORS out of it: a lone
# backslash in `src\lib.rs` is not an escape, only backslash-space is.
_DEP_SPLIT = re.compile(r"(?<!\\) ")


def _parse_depfile(text: str) -> list[tuple[str, list[str]]]:
    """Parse a cargo dep-info file into `(target, dependencies)` rules.

    Makefile-ish: `<target>: <dep> <dep> ...`, one rule per line, then every
    dependency repeated as a phony target with no deps, then `# env-dep:`
    comments. Only the real rules are returned.

    Split on the first COLON-SPACE, never the first colon: on Windows a
    target line begins `C:\\...`, so splitting at the first `:` would take the
    drive letter for the whole target and drop the rule entirely.
    """
    rules = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        target, sep, rest = line.partition(": ")
        if not sep:
            continue                       # phony line (`src\lib.rs:`)
        deps = [d.replace("\\ ", " ") for d in _DEP_SPLIT.split(rest.strip()) if d]
        rules.append((target.strip(), deps))
    return rules


def _repo_relative_rs(dep: str, pkg_root: Path, root: Path) -> str | None:
    """A dependency, as a repo-relative `.rs` path, or None if it is neither.

    Backslashes are normalized BEFORE `Path` sees the string, for the reason
    spelled out in `_util.relativize`: `\\` is a separator on Windows but a
    legal filename character on POSIX, so delegating to `Path` would work
    here and silently mangle paths on every POSIX CI leg.
    """
    if not dep.lower().endswith(".rs"):
        return None                        # Cargo.toml, build scripts' inputs
    p = Path(dep.replace("\\", "/"))
    if not p.is_absolute():
        p = pkg_root / p
    try:
        resolved = p.resolve()
        if not resolved.is_relative_to(root):
            return None                    # registry / sysroot sources
        return resolved.relative_to(root).as_posix()
    except (OSError, ValueError):
        return None


def _examined(raw: str, ctx) -> frozenset[str]:
    """Repo-relative `.rs` files cargo actually compiled this run.

    The JSON stream alone cannot answer this: `compiler-artifact` records
    name only CRATE ROOTS (`target.src_path`), so a module reached through
    `mod` never appears. The dep-info file cargo writes beside each artifact
    does list them, and is exact -- measured on a live crate, a lib target's
    depfile named `src/lib.rs src/used.rs Cargo.toml` and correctly omitted an
    `src/orphan.rs` that no `mod` declaration reached.

    That omission is the whole point. A finding recorded in a file that later
    stops being compiled -- someone deletes `mod foo;` and leaves foo.rs in
    the tree -- would otherwise be silently recorded as `fixed`, because
    clippy exits 0 having never looked at it.

    Depfiles are never garbage-collected and, measured, are NOT rewritten on a
    cached run (mtimes byte-identical across two runs), so freshness cannot be
    established by timestamp and a directory accumulates one per
    feature/profile combination ever built. They are matched STRUCTURALLY
    instead: a depfile counts only if one of its own target lines is an
    artifact filename THIS run reported. Stale ones name stale artifacts and
    are dropped.

    Dependency paths are relative to the PACKAGE root, not the repo root --
    rustc runs with cwd set to the package -- so each depfile resolves against
    the `manifest_path` of the artifact that claimed it. Getting this wrong
    would quietly vouch for the wrong paths in every workspace.

    Returns the empty set, never None, when nothing can be matched: that is a
    positive "vouches for nothing" that blocks resolution, where None would
    fall back to the gate file set and reopen the hole.
    """
    package_of: dict[Path, Path] = {}
    for line in (raw or "").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") != "compiler-artifact":
            continue
        manifest = record.get("manifest_path")
        pkg_root = Path(manifest).parent if manifest else ctx.root
        for out in record.get("filenames") or []:
            package_of[Path(out)] = pkg_root
    if not package_of:
        return frozenset()

    root = ctx.root.resolve()
    examined: set[str] = set()
    for deps_dir in {artifact.parent for artifact in package_of}:
        try:
            depfiles = sorted(deps_dir.glob("*.d"))
        except OSError:
            continue
        for depfile in depfiles:
            try:
                rules = _parse_depfile(
                    depfile.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            pkg_root = next((package_of[Path(t)] for t, _ in rules
                             if Path(t) in package_of), None)
            if pkg_root is None:
                continue                   # belongs to some other build
            pkg_root = pkg_root.resolve()
            for _, deps in rules:
                for dep in deps:
                    rel = _repo_relative_rs(dep, pkg_root, root)
                    if rel is not None:
                        examined.add(rel)
    return frozenset(examined)


def run(ctx) -> RunnerResult:
    if not (ctx.root / "Cargo.toml").exists():
        return RunnerResult(NAME, ToolState.MISSING, examined=frozenset())
    # Probe BEFORE invoking cargo: see module docstring on 101's two meanings.
    if toolpath.resolve(CLIPPY_BIN) is None:
        return RunnerResult(NAME, ToolState.MISSING, examined=frozenset())
    result = run_subprocess(
        ["cargo", "clippy", "--all-targets", "--message-format=json", "--quiet"],
        ctx.root, TIMEOUT_S)
    out = _ndjson_or_crashed(result)
    # A degraded clippy vouches for nothing (see the ruff/eslint adapters).
    if out.state is not ToolState.OK:
        return dataclasses.replace(out, examined=frozenset())
    return dataclasses.replace(out, examined=_examined(out.raw, ctx))


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    findings = []
    # `--all-targets` compiles a source file once PER TARGET, and each
    # compilation re-reports the lints in it -- so a lint in lib.rs arrives
    # twice, once for the lib target and once for the test target, naming the
    # identical file and line. Nothing downstream would collapse them:
    # `normalizer.normalize` gives gate callers a POSITIONAL occurrence index,
    # so two identical raws become two findings with DIFFERENT ids. One real
    # lint would be reported twice, tracked twice in the ledger, and -- both
    # being new -- escalated to BLOCK twice by the pre-push ratchet.
    #
    # Keyed on (rule, file, line), which is as coarse as it can safely be: the
    # same rule at the same source location IS the same lint, whichever target
    # compiled it, while two rules on one line or one rule on two lines stay
    # distinct.
    seen: set[tuple[str, str, int]] = set()
    for line in (result.raw or "").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") != "compiler-message":
            continue
        message = record.get("message") or {}
        code = (message.get("code") or {}).get("code")
        spans = message.get("spans") or []
        primary = next((s for s in spans if s.get("is_primary")), None) or (
            spans[0] if spans else None)
        # A diagnostic with no lint id or no span is a summary line ("2
        # warnings emitted"). It cannot be fingerprinted to a location, so
        # it could never be triaged or suppressed -- permanent noise.
        if not code or primary is None:
            continue
        rule = str(code)
        file_ = relativize(primary.get("file_name", ""), ctx.root)
        line_no = primary.get("line_start", 0) or 0
        key = (rule, file_, line_no)
        if key in seen:
            continue
        seen.add(key)
        findings.append(RawFinding(
            tool=NAME,
            rule=rule,
            severity_raw=str(message.get("level") or "warning"),
            file=file_,
            line=line_no,
            message=message.get("message") or str(code),
        ))
    return findings
