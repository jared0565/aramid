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
"""
import json

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
    """
    if result.state is not ToolState.OK:
        return result
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


def run(ctx) -> RunnerResult:
    if not (ctx.root / "Cargo.toml").exists():
        return RunnerResult(NAME, ToolState.MISSING)
    # Probe BEFORE invoking cargo: see module docstring on 101's two meanings.
    if toolpath.resolve(CLIPPY_BIN) is None:
        return RunnerResult(NAME, ToolState.MISSING)
    result = run_subprocess(["cargo", "clippy", "--message-format=json", "--quiet"],
                            ctx.root, TIMEOUT_S)
    return _ndjson_or_crashed(result)


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    findings = []
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
        findings.append(RawFinding(
            tool=NAME,
            rule=str(code),
            severity_raw=str(message.get("level") or "warning"),
            file=relativize(primary.get("file_name", ""), ctx.root),
            line=primary.get("line_start", 0) or 0,
            message=message.get("message") or str(code),
        ))
    return findings
