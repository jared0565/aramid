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
"""
import shlex

from aramid.normalizer import RawFinding
from aramid.detectors import detect_tests
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


def _timeout(ctx) -> float:
    configured = getattr(ctx, "test_timeout_s", None)
    return float(configured) if configured else TIMEOUT_S


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


def run_pytest(ctx) -> RunnerResult:
    return run_subprocess(["pytest", "-q"], ctx.root, _timeout(ctx))


def run_npm_test(ctx) -> RunnerResult:
    return run_subprocess(["npm", "test"], ctx.root, _timeout(ctx))


def run(ctx) -> RunnerResult:
    # An explicitly configured command IS the repo's answer -- detection
    # never overrides it (that is the point of configuring one).
    command = getattr(ctx, "test_command", None)
    if command:
        return run_custom(ctx, command)
    kinds = detect_tests(ctx.root)
    if "pytest" in kinds:
        return run_pytest(ctx)
    if "npm" in kinds:
        return run_npm_test(ctx)
    return RunnerResult("tests", ToolState.MISSING)


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is ToolState.MISSING:
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
