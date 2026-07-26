"""tests adapter -- runs the target repo's own test suite.

`pytest -q` for Python, `npm test` for JS (dispatched via
detectors.detect_tests(), which already encodes "tests/ or test_*.py
present" / "package.json defines a scripts.test entry"). A non-zero exit is
BLOCK-tier (design doc §3: "Tests | ... | BLOCK on fail"); this collapses
into a single RawFinding(rule="tests-failed") rather than attempting to
parse individual failures out of pytest/jest/mocha/vitest output, whose
formats are too varied to parse reliably and generically -- the exit code
is the only universal signal.

A hung suite (TIMEOUT) or an unexpected non-completion (CRASHED) must NOT
read as a pass just because there's no exit code to check -- this is a
BLOCK-tier gate, so both produce the same blocking `tests-failed` finding
as a non-zero exit, rather than silently falling through the
`state is not OK -> []` guard other adapters use for their non-blocking
JSON tools. Only MISSING (no test framework detected -- a legitimate skip,
not a failure) still yields zero findings.

Dual-stack repos (both a real Python test file AND a `package.json`
`scripts.test` entry -- detect_tests() returns both "pytest" and "npm"):
`run()` runs BOTH suites rather than picking one and silently ignoring the
other -- the exact bug class this whole module exists to close, a check
that reports nothing for a reason indistinguishable from "clean". Mirrors
runners/deps.py's `_run_mixed` shape: the two sub-results are attached via
an ad-hoc `.sub_results` attribute (not a declared RunnerResult field) on a
combined `RunnerResult(tool="tests", ...)`; `parse()` recurses into each,
just like deps.parse. UNLIKE deps' OR-rule, the combined `.state` is OK
iff BOTH subs are OK -- inverted deliberately: a degraded/missing suite
here must still block, where deps' two independent audits are each still
a useful, if partial, result on their own. `.returncode` on the combined
result is meaningless (dataclass default 0, which reads as success) --
consult `.sub_results` for the real per-suite exit codes.

The two suites share ONE wall-clock deadline (`ctx.gate_budget_s`, the
current gate's own budget -- see RunContext's docstring) rather than each
getting an independent full per-tool timeout: they run sequentially inside
one `run()` call, so two 300s-timeout suites would otherwise sum to 600s
against a 300s pre-push slot -- well past what
aramid.pipeline._run_selected's ThreadPoolExecutor actually waits for,
which would discard BOTH suites' results behind a single bare
pipeline-level TIMEOUT (tool="tests", no `.sub_results`) naming the wrong
cause. If the shared budget is exhausted before the second suite can run
at all, that suite is reported as TIMEOUT directly -- attributed to ITS
OWN sub-result, not the slot -- while the first suite's real result/
findings are still returned.

The dual-run only happens when the JS side looks genuinely set up -- a JS
package-manager lockfile (package-lock.json/pnpm-lock.yaml/yarn.lock) is
present. A `package.json` `scripts.test` entry with no lockfile installed
behind it is common (e.g. the default `npm init` template's own stub,
"... && exit 1") and promoting every such stub to a second concurrent
BLOCK-tier suite would manufacture false blocks. This check deliberately
lives HERE, not in detectors.detect_tests() -- the C1/B1/B3 decision, see
task-1-brief.md/task-2-brief.md -- so detect_tests()'s own contract stays
lockfile-agnostic for its other callers. The single-suite npm-only
dispatch below is UNCHANGED by this and still runs `npm test` with no
lockfile at all: the lockfile gate only guards promoting a detected npm
suite to a SECOND concurrent suite alongside an already-detected Python
one, never the single-suite case (B1 regression).
"""
import shlex
import sys
import time

from aramid.normalizer import RawFinding
from aramid.detectors import detect_package_manager, detect_tests
from aramid.runners.base import RunnerResult, ToolState, run_subprocess

# Fallback per-invocation timeout when `[tests].timeout_s` is unset (or a
# RunContext is built without config, as unit tests and other callers do).
# Mirrored by the `timeout_s` default in data/defaults.toml.
TIMEOUT_S = 300.0

# pytest exits 5 for "no tests were collected" -- distinct from 1 ("tests
# failed"). Still BLOCK-tier: a `[tests].command` selector that matches
# nothing is a vacuous gate, not a pass. Only the message differs, and only
# for pytest: rc 5 from `npm test` or a custom `make test` means whatever
# that tool says it means, so those keep the generic wording rather than
# being told an invented fact about their own exit code.
_PYTEST_NO_TESTS_RC = 5

# Not a real path -- rule="tests-failed" is a whole-suite signal, not tied
# to one file/line. A constant, deterministic marker keeps the fingerprint
# stable across runs; gitutil safely returns "" for a path that resolves to
# neither a tracked blob nor a file on disk.
_SUITE_FILE_MARKER = "<test-suite>"

# [review B4] The fully-specified finding for "detect_tests() found this
# suite, but its tool binary could not be resolved/run at all" (toolpath
# resolution failure inside run_subprocess -- see runners/base.py). Reported
# as tool="tests" (the registry key), NOT the sub-tool's own name, for two
# reasons: reusing rule="tests-failed" with tool="npm"/"pytest" would
# collide on fingerprint with a genuine test failure (line_content is ""
# for the <test-suite> marker either way, so the two hash identical, and
# ledger.record_run only appends FINDING_DETECTED when a finding id is
# absent or "fixed" -- once "missing" is open a later real failure never
# updates the payload); inventing a new rule while keeping tool="npm" would
# fall into policy.py's `_DEPS_TOOLS` branch and let [deps].block_severity
# govern a missing-test-tool notice instead of policy's own dedicated
# tests-tool-missing BLOCK branch.
TOOL_MISSING_RULE = "tests-tool-missing"

# [review C1/B1/B3] A `package.json` `scripts.test` entry is only promoted
# to a real second BLOCK-tier suite (alongside an already-detected pytest
# suite) when a JS package-manager lockfile says the JS side was actually
# installed here -- see module docstring. Printed to stderr, not folded
# into RawFinding/GateResult: the decision and its announcement live
# together, in the one place (this module) that makes it, rather than
# risking drift with a duplicate detection in aramid.pipeline.
_NO_LOCKFILE_NOTICE = (
    "aramid: tests: both a Python test suite and a package.json test script "
    "were detected, but no JS lockfile (package-lock.json / pnpm-lock.yaml / "
    "yarn.lock) was found -- running pytest only this run; npm test was NOT "
    "run. Run `npm install` (or pnpm/yarn) so aramid runs it too."
)


def _timeout(ctx) -> float:
    configured = getattr(ctx, "test_timeout_s", None)
    return float(configured) if configured else TIMEOUT_S


def _budget(ctx) -> float:
    """The current gate's shared wall-clock budget (RunContext.gate_budget_s
    -- see that field's docstring in runners/base.py), or unbounded when
    unset. A RunContext built outside aramid.pipeline.run_gate (as unit
    tests, and any future caller that doesn't opt in, do) must not have its
    dual-suite behavior silently capped by a budget nobody configured --
    `float("inf")` makes `min(_timeout(ctx), remaining)` degrade to exactly
    today's single per-tool timeout, unchanged, when this field is absent."""
    configured = getattr(ctx, "gate_budget_s", None)
    return float(configured) if configured else float("inf")


def _argv(command: str | list) -> list[str]:
    """A repo's configured `[tests].command` -> argv for run_subprocess.

    A list/tuple is taken verbatim, which sidesteps shell quoting entirely
    and is the form to prefer on Windows: POSIX splitting eats backslashes,
    so `tests\\unit` written as a string would lose its separator. A string
    is split POSIX-style, which is what nearly every real command
    ("pytest -q tests/unit") needs.

    Note there is no shell anywhere in this path -- run_subprocess execs the
    argv directly, so a command is exactly as trusted as the repo's own test
    suite, which the gate already runs.
    """
    if isinstance(command, (list, tuple)):
        return [str(c) for c in command]
    return shlex.split(command)


def run_custom(ctx, command) -> RunnerResult:
    argv = _argv(command)
    if not argv:
        # A configured command that parses to nothing is a misconfiguration.
        # MISSING degrades the BLOCK-tier slot (exit 1 at pre-push) rather
        # than resolving to "no findings" -- a gate cannot fall silent just
        # because its own config is malformed.
        return RunnerResult("tests", ToolState.MISSING)
    return run_subprocess(argv, ctx.root, _timeout(ctx))


def run_pytest(ctx, timeout_s: float | None = None) -> RunnerResult:
    return run_subprocess(["pytest", "-q"], ctx.root,
                           timeout_s if timeout_s is not None else _timeout(ctx))


def run_npm_test(ctx, timeout_s: float | None = None) -> RunnerResult:
    return run_subprocess(["npm", "test"], ctx.root,
                           timeout_s if timeout_s is not None else _timeout(ctx))


def _run_one_within_budget(tool_name: str, run_one, ctx, started: float,
                            budget: float) -> RunnerResult:
    """Run one suite capped by whatever remains of the shared `budget`
    ([review B2]) -- never by its own full per-tool timeout alone. If the
    budget is already exhausted before this suite even starts, it is
    reported as TIMEOUT directly (attributed to its OWN sub-result) instead
    of launching a subprocess we already know cannot finish in time."""
    remaining = budget - (time.monotonic() - started)
    if remaining <= 0:
        return RunnerResult(tool_name, ToolState.TIMEOUT)
    return run_one(ctx, min(_timeout(ctx), remaining))


def _run_dual(ctx) -> RunnerResult:
    """Both `detect_tests()` kinds are present and the lockfile gate passed
    (`_dual_stack_run` below): run BOTH suites sequentially, sharing one
    wall-clock budget, and bundle the results (module docstring)."""
    budget = _budget(ctx)
    started = time.monotonic()

    py_result = _run_one_within_budget("pytest", run_pytest, ctx, started, budget)
    npm_result = _run_one_within_budget("npm", run_npm_test, ctx, started, budget)

    # [review M2]: OK iff BOTH subs OK; otherwise the FIRST non-OK sub-state,
    # in the fixed pytest-then-npm order `.sub_results` carries below.
    # ToolState is an unordered StrEnum (runners/base.py) -- there is no
    # "worst" state to rank, only OK-vs-not-OK is ever consulted downstream
    # (pipeline._BAD_STATES). This INVERTS deps._run_mixed's OR rule --
    # mirror deps' `.sub_results` SHAPE only, never its state rule.
    if py_result.state is ToolState.OK and npm_result.state is ToolState.OK:
        state = ToolState.OK
    elif py_result.state is not ToolState.OK:
        state = py_result.state
    else:
        state = npm_result.state
    # [review M4] `.returncode` is left at its dataclass default (0) --
    # meaningless on the aggregate (two returncodes cannot collapse into
    # one, and 0 reads as success); consult `.sub_results` for the real
    # per-suite exit codes.
    combined = RunnerResult("tests", state)
    combined.sub_results = [py_result, npm_result]
    return combined


def _dual_stack_run(ctx) -> RunnerResult:
    """Entry point for the has-pytest-and-has-npm case. Only promotes to a
    real dual-run when the JS side has a package-manager lockfile -- see
    module docstring for the C1/B1/B3 rationale. Without one: the
    single-suite (pytest-only) path runs, with NO `.sub_results` (same
    shape as any other single-kind repo), and a loud notice fires --
    silently dropping a detected suite is exactly the bug class this
    module exists to fix, so the drop must never be quiet."""
    pkg_manager = getattr(ctx, "pkg_manager", None) or detect_package_manager(ctx.root)
    if pkg_manager is None:
        print(_NO_LOCKFILE_NOTICE, file=sys.stderr)
        return run_pytest(ctx)
    return _run_dual(ctx)


def run(ctx) -> RunnerResult:
    # An explicitly configured command IS the repo's answer -- detection
    # never overrides it (that is the point of configuring one).
    command = getattr(ctx, "test_command", None)
    if command:
        return run_custom(ctx, command)
    kinds = detect_tests(ctx.root)
    if "pytest" in kinds and "npm" in kinds:
        return _dual_stack_run(ctx)
    if "pytest" in kinds:
        return run_pytest(ctx)
    if "npm" in kinds:
        return run_npm_test(ctx)
    return RunnerResult("tests", ToolState.MISSING)


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    # [review I4] This recursion MUST be the first statement, before the
    # MISSING guard below. Under worst-wins (M2) the AGGREGATE's own state
    # IS MISSING in the one-suite-OK-one-MISSING case, so a recursion
    # placed after that guard would return [] and silently discard BOTH
    # suites' findings -- the push still exits 1 via degraded_block_tier,
    # so the bug hides behind a correct exit code. deps.parse can be
    # careless about this ordering because it has no such guard; this
    # module does.
    sub_results = getattr(result, "sub_results", None)
    if sub_results is not None:
        findings: list[RawFinding] = []
        for sub in sub_results:
            findings.extend(parse(sub, ctx))
        return findings
    if result.state is ToolState.MISSING:
        if result.tool != "tests":
            # [review B4] `result.tool` is the SUB-tool's own name
            # ("pytest"/"npm") here, never "tests" -- detect_tests() found
            # this suite, but its binary could not be resolved/run at all
            # (toolpath resolution failure inside run_subprocess). That is
            # a real, actionable gap -- a check reporting nothing for a
            # reason indistinguishable from "clean" -- not the same MISSING
            # as `run()`'s own "nothing detected at all" fallthrough or
            # run_custom's empty-argv misconfiguration, both of which carry
            # tool="tests" and stay a silent skip, below. Reachable both as
            # a top-level single-suite result and (via the recursion above)
            # as one aggregate sub-result -- the rule is the same either way.
            return [RawFinding(
                tool="tests",
                rule=TOOL_MISSING_RULE,
                severity_raw="high",
                file=_SUITE_FILE_MARKER,
                line=0,
                message=(f"{result.tool} was detected in this repo but its "
                         "binary could not be run (not installed, or not "
                         "resolvable) -- the suite never executed"),
            )]
        return []
    if result.state in (ToolState.TIMEOUT, ToolState.CRASHED):
        return [RawFinding(
            tool=result.tool,
            rule="tests-failed",
            severity_raw="high",
            file=_SUITE_FILE_MARKER,
            line=0,
            message=f"{result.tool} {result.state.value}: test suite failed",
        )]
    if result.returncode == 0:
        return []
    if result.returncode == _PYTEST_NO_TESTS_RC and result.tool == "pytest":
        message = ("pytest exited 5: no tests were collected -- the suite, or "
                   "the [tests].command selector if one is set, matches nothing")
    else:
        message = f"{result.tool} exited {result.returncode}: test suite failed"
    return [RawFinding(
        tool=result.tool,
        rule="tests-failed",
        severity_raw="high",
        file=_SUITE_FILE_MARKER,
        line=0,
        message=message,
    )]
