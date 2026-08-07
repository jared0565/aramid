"""tests adapter -- runs the target repo's own test suite.

`pytest -q` for Python, `npm test` for JS (dispatched via
detectors.detect_tests(), which already encodes "a real `conftest.py`,
`test_*.py`, or `*_test.py` file present -- a bare `tests/` directory does
not count on its own" / "package.json defines a scripts.test entry"). A
non-zero exit is
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
JSON tools. MISSING yields zero findings when nothing is detected at all --
a legitimate skip. It also still yields zero findings when a single
detected suite's own tool binary can't be resolved, exactly as before this
module's dual-suite path existed: that case only degrades the BLOCK tier,
via pipeline.run_gate's degraded_block_tier/--accept-degraded escape
hatch, never a finding. Only the third shape -- a sub-result of the
dual-suite run below, one of pytest/npm detected but unable to run at all
-- produces a finding, via TOOL_MISSING_RULE, because there the
aggregate's own state can't otherwise say which suite never ran.

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

The two suites share ONE wall-clock deadline (`ctx.gate_deadline`, an
ABSOLUTE `time.monotonic()` instant set once by aramid.pipeline.run_gate
-- see RunContext's docstring) rather than each getting an independent
full per-tool timeout: they run sequentially inside one `run()` call, so
two 300s-timeout suites would otherwise sum to 600s against a 300s
pre-push slot -- well past what aramid.pipeline._run_selected's
ThreadPoolExecutor actually waits for, which would discard BOTH suites'
results behind a single bare pipeline-level TIMEOUT (tool="tests", no
`.sub_results`) naming the wrong cause. If the shared deadline is already
past before the second suite can run at all, that suite is reported as
TIMEOUT directly -- attributed to ITS OWN sub-result, not the slot --
while the first suite's real result/findings are still returned.

**Why an ABSOLUTE deadline, not a duration measured from a `started`
captured here:** [MUST FIX 6, whole-branch review -- corrects a stale
claim] BEFORE Task 4's detect_tests() caching, this module's own `run()`
called `detect_tests()` (a filesystem walk) directly, and that walk
happened INSIDE the worker thread `_run_selected` dispatches -- i.e. AFTER
its `ThreadPoolExecutor.wait(timeout=budget_s)` had already started
counting in the main thread. A `started = time.monotonic()` captured
after that walk silently dropped however long the walk took from this
module's own accounting, letting its internally-computed "remaining
budget" run later than `_run_selected`'s wait() actually waits -- which
is exactly what let a completed suite's real result be replaced by a
bare TIMEOUT (review B2 follow-up: two clocks, two origins).

That specific walk no longer happens inside this module's worker thread
today: `_detected()` below (Task 4, review M6+B7) reads
`ctx.detected_tests`, precomputed by `aramid.pipeline.run_gate` in the
MAIN thread -- before `ctx.gate_deadline` is ever CONSUMED here in
`runners/tests.py` (this module's own first read of it is inside
`_remaining()`, called from the worker thread below), let alone before
`_select_runners`/`_run_selected` dispatch this module's worker at all
(see `_detected()`'s own docstring below). NOT "before `gate_deadline` is
captured" -- that capture (`aramid.pipeline.run_gate`, `gate_deadline =
time.monotonic() + budget_s`) happens first of all, upstream of this
entire paragraph; see `pipeline.py`'s own comment there for the single-
origin argument in full. A RunContext built outside
run_gate, with no cache populated, still falls back to a fresh in-worker
`detect_tests(ctx.root)` call right here, unchanged from before caching
existed -- so the ORIGINAL hazard this paragraph describes is still live
on that path, just no longer on the run_gate path.

The absolute-deadline design is correct independent of that detail, which
is why it still stands even though its motivating example moved: real
elapsed time still accrues between `ctx.gate_deadline`'s capture in
run_gate and this module's own dual-suite calls (runner selection, thread
dispatch, the first suite's own run), so measuring against
`ctx.gate_deadline` instead -- an instant fixed once, upstream, before any
of that intervening work runs -- means "how much time is left" is always
correct regardless of how much preliminary work already happened or where
in the call chain the check is made. `_run_selected`'s own wait() is
intentionally left as a duration rather than also recomputed from this
deadline: every step between the deadline being set and wait() being
called (runner selection included) can only ADD elapsed time before
wait() starts counting, never remove it, so wait()'s effective cutoff is
provably >= `ctx.gate_deadline` -- this module's worst-case finish
(bounded by that same deadline) can never land after it.

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
import dataclasses
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

# [review B4] The fully-specified finding for "one sub-result of a
# dual-suite aggregate is a suite detect_tests() found, but whose tool
# binary could not be resolved/run at all" (toolpath resolution failure
# inside run_subprocess -- see runners/base.py). Only ever emitted for a
# SUB-result of the aggregate (see parse()'s `_sub` guard below) -- a
# top-level single-suite or run_custom MISSING result stays the existing
# silent-skip/degraded-tool path (parse() -> [], exit code governed by
# pipeline.run_gate's degraded_block_tier / --accept-degraded), because
# there only ONE tool was ever a candidate: `result.degraded`/
# `degraded_tools` already names it, so a Finding here would be
# redundant, not disambiguating -- unlike a dual-suite sub, where the
# aggregate's own combined state can't say WHICH of pytest/npm never ran
# (module docstring above).
#
# [Corrected, MUST FIX 2 whole-branch review] This distinction is no
# longer what keeps `--accept-degraded` working, either way. This comment
# used to also argue that a top-level MISSING must stay on the silent
# path because a BLOCK finding here would short-circuit past
# `--accept-degraded` entirely (pipeline.py's `if block_findings:
# exit_code = 1` ran before the accept_degraded elif) -- true at the
# time, but pipeline.run_gate now excludes any tests-tool-missing finding
# from that check BY RULE, regardless of top-level-vs-sub, precisely
# because this finding only ever EXPLAINS a degradation
# `degraded_block_tier` already carries. Reported as tool="tests" (the
# registry key), NOT the sub-tool's own name, for two more reasons:
# reusing rule="tests-failed" with tool="npm"/"pytest" would collide on
# fingerprint with a genuine test failure (line_content is "" for the
# <test-suite> marker either way, so the two hash identical, and
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


def _remaining(ctx) -> float:
    """How much time is left until `ctx.gate_deadline` (RunContext's
    docstring has the full single-origin argument), measured FRESH
    against `time.monotonic()` every time this is called -- never against
    a `started` captured once and reused, which is exactly the bug this
    replaced (review B2 follow-up: a fresh start captured after this
    module's own detect_tests() walk silently drops however long that
    walk took, letting the internally-computed budget run later than
    aramid.pipeline._run_selected's own wait() already gave up).
    Unbounded (`float("inf")`) when `ctx.gate_deadline` is unset -- a
    RunContext built outside run_gate (as unit tests, and any future
    caller that doesn't opt in, do) must not have its dual-suite behavior
    silently capped by a deadline nobody configured; that makes
    `min(_timeout(ctx), remaining)` degrade to exactly today's single
    per-tool timeout, unchanged, when this field is absent."""
    deadline = getattr(ctx, "gate_deadline", None)
    return (deadline - time.monotonic()) if deadline is not None else float("inf")


def _detected(ctx) -> set[str]:
    """`ctx.detected_tests` if the caller precomputed it -- aramid.pipeline.
    run_gate does, once per gate run (Task 4, review M6+B7), before this
    module's own worker thread even starts -- else a fresh
    `detect_tests(ctx.root)` walk exactly as before caching existed.
    getattr-based, matching `_timeout`/`_remaining`'s own defensive style:
    a RunContext built directly by a unit test (or any caller outside
    run_gate) has no cache to read, and `None` must fall back to a real
    walk rather than being treated as "no suite detected" -- see
    RunContext.detected_tests's own docstring for why the field defaults
    to `None`, never `set()`."""
    cached = getattr(ctx, "detected_tests", None)
    return cached if cached is not None else detect_tests(ctx.root)


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


def run_cargo_test(ctx, timeout_s: float | None = None) -> RunnerResult:
    """`cargo test` -- RESTAMPED to "cargo-test".

    run_subprocess names a result after Path(argv[0]).name, which here is
    plain "cargo" -- the same name clippy and cargo-audit derive before THEY
    restamp. `_write_logs` keys its filename on `.tool` and `degraded_tools`
    is a set, so two runners sharing a name silently overwrite one another's
    diagnostic log (the exact bug json_or_crashed's restamping docstring
    describes). pytest/npm need no such treatment because nothing else in the
    gate is called pytest or npm."""
    r = run_subprocess(["cargo", "test"], ctx.root,
                       timeout_s if timeout_s is not None else _timeout(ctx))
    return dataclasses.replace(r, tool="cargo-test")


def run_go_test(ctx, timeout_s: float | None = None) -> RunnerResult:
    """`go test ./...` -- restamped for symmetry with run_cargo_test; "go" is
    not currently claimed by another runner, but relying on that is how the
    collision above happens the next time one is added."""
    r = run_subprocess(["go", "test", "./..."], ctx.root,
                       timeout_s if timeout_s is not None else _timeout(ctx))
    return dataclasses.replace(r, tool="go-test")


# Fixed order: this is BOTH the order `.sub_results` carries and the order
# the [review M2] "first non-OK state" rule walks. pytest-then-npm is
# unchanged from when this was a hardcoded pair, so a pytest+npm repo
# produces a byte-identical aggregate to before.
_SUITE_RUNNERS = (("pytest", run_pytest), ("npm", run_npm_test),
                  ("cargo", run_cargo_test), ("go", run_go_test))


def _run_one_within_deadline(tool_name: str, run_one, ctx) -> RunnerResult:
    """Run one suite capped by whatever remains until `ctx.gate_deadline`
    ([review B2]) -- never by its own full per-tool timeout alone, and
    checked FRESH via `_remaining(ctx)` right here rather than against a
    duration threaded in from an earlier capture (see `_remaining`'s
    docstring for why that distinction is the whole fix). If the deadline
    has already passed before this suite even starts, it is reported as
    TIMEOUT directly (attributed to its OWN sub-result) instead of
    launching a subprocess we already know cannot finish in time."""
    remaining = _remaining(ctx)
    if remaining <= 0:
        return RunnerResult(tool_name, ToolState.TIMEOUT)
    return run_one(ctx, min(_timeout(ctx), remaining))


def _run_many(ctx, names) -> RunnerResult:
    """Two or more `detect_tests()` kinds are present: run each suite
    sequentially, sharing one wall-clock deadline, and bundle the results
    (module docstring). Generalized from the original hardcoded pytest+npm
    pair when cargo/go were added -- the two-kind case must still produce an
    identical aggregate, which `tests/unit/test_runner_tests.py` pins
    unmodified."""
    results = [_run_one_within_deadline(n, fn, ctx)
               for n, fn in _SUITE_RUNNERS if n in names]

    # [review M2]: OK iff BOTH subs OK; otherwise the FIRST non-OK sub-state,
    # in the fixed pytest-then-npm order `.sub_results` carries below.
    # ToolState is an unordered StrEnum (runners/base.py) -- there is no
    # "worst" state to rank, only OK-vs-not-OK is ever consulted downstream
    # (pipeline._BAD_STATES). This INVERTS deps._run_mixed's OR rule --
    # mirror deps' `.sub_results` SHAPE only, never its state rule.
    if all(r.state is ToolState.OK for r in results):
        state = ToolState.OK
    else:
        state = next(r.state for r in results if r.state is not ToolState.OK)
    # [review M4] `.returncode` is left at its dataclass default (0) --
    # meaningless on the aggregate (two returncodes cannot collapse into
    # one, and 0 reads as success); consult `.sub_results` for the real
    # per-suite exit codes.
    combined = RunnerResult("tests", state)
    combined.sub_results = results
    return combined


def run(ctx) -> RunnerResult:
    # An explicitly configured command IS the repo's answer -- detection
    # never overrides it (that is the point of configuring one).
    command = getattr(ctx, "test_command", None)
    if command:
        return run_custom(ctx, command)
    kinds = set(_detected(ctx))

    # [review C1/B1/B3] The lockfile gate, deliberately kept scoped to the
    # pytest+npm pair exactly as when it was written. Widening it to "npm
    # plus any other kind" would be defensible in the abstract, but
    # _NO_LOCKFILE_NOTICE says "running pytest only this run" -- on an
    # npm+cargo repo that sentence would be false, and a notice this module
    # exists to make trustworthy must not state an invented fact.
    if "pytest" in kinds and "npm" in kinds:
        pkg_manager = getattr(ctx, "pkg_manager", None) or detect_package_manager(ctx.root)
        if pkg_manager is None:
            print(_NO_LOCKFILE_NOTICE, file=sys.stderr)
            kinds.discard("npm")

    selected = [n for n, _ in _SUITE_RUNNERS if n in kinds]
    if not selected:
        return RunnerResult("tests", ToolState.MISSING)
    if len(selected) == 1:
        # SHAPE MATTERS: a single suite returns the raw subprocess result,
        # carrying that tool's own name ("pytest"/"npm"/"cargo-test"), NOT an
        # aggregate named "tests" and NOT `.sub_results`. parse()'s `_sub`
        # guard and ledger.record_run's resolution keying both read `.tool`,
        # so a cargo-only repo must look exactly like a pytest-only repo
        # does, one name over.
        return dict(_SUITE_RUNNERS)[selected[0]](ctx)
    return _run_many(ctx, kinds)


def parse(result: RunnerResult, ctx, *, _sub: bool = False) -> list[RawFinding]:
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
            findings.extend(parse(sub, ctx, _sub=True))
        return findings
    if result.state is ToolState.MISSING:
        if _sub and result.tool != "tests":
            # [review B4] Only "on the sub-result" (`_sub=True`, set solely
            # by the recursion above), never for a bare top-level call.
            # `result.tool` is the SUB-tool's own name ("pytest"/"npm")
            # here, never "tests" -- detect_tests() found this suite, but
            # its binary could not be resolved/run at all (toolpath
            # resolution failure inside run_subprocess). That is a real,
            # actionable gap inside a dual-suite aggregate -- one sub ran,
            # one didn't, and the aggregate's own state alone doesn't say
            # which -- not the same MISSING as `run()`'s own "nothing
            # detected at all" fallthrough or run_custom's empty-argv
            # misconfiguration (both top-level, tool="tests").
            #
            # Deliberately NOT generalized to top-level single-suite/
            # run_custom MISSING results, even though they can ALSO carry
            # tool="pytest"/"npm"/"make" != "tests": there only ONE tool
            # was ever a candidate, so degraded_block_tier/result.degraded
            # already names it and a Finding here would be redundant, not
            # disambiguating -- unlike a dual-suite sub, where the
            # aggregate's own combined state can't say WHICH of pytest/npm
            # never ran.
            #
            # [Corrected, MUST FIX 2 whole-branch review] This is no
            # longer about protecting `--accept-degraded` either. This
            # comment used to argue that generalizing would flow through
            # pipeline.run_gate's `if block_findings: exit_code = 1`
            # BEFORE the `elif accept_degraded and ... degraded_block_tier`
            # branch is ever reached, silently killing the escape hatch
            # for exactly the "CI runner has no test binary" case
            # test_pipeline.py's own accept_degraded tests name -- true at
            # the time, but pipeline.run_gate now excludes any
            # tests-tool-missing finding from that check by rule, so the
            # escape hatch no longer depends on this finding staying
            # sub-only. That existing degraded-tool path (MISSING -> [] ->
            # exit_code governed by degraded_block_tier/accept_degraded)
            # remains the correct, unchanged behavior for a top-level
            # MISSING regardless.
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
