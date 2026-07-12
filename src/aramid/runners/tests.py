"""tests adapter -- runs the target repo's own test suite.

`pytest -q` for Python, `npm test` for JS (dispatched via
detectors.detect_tests(), which already encodes "tests/ or test_*.py
present" / "package.json defines a scripts.test entry"). A non-zero exit is
BLOCK-tier (design doc §3: "Tests | ... | BLOCK on fail"); this collapses
into a single RawFinding(rule="tests-failed") rather than attempting to
parse individual failures out of pytest/jest/mocha/vitest output, whose
formats are too varied to parse reliably and generically -- the exit code
is the only universal signal.
"""
from aramid.normalizer import RawFinding
from aramid.detectors import detect_tests
from aramid.runners.base import RunnerResult, ToolState, run_subprocess

TIMEOUT_S = 300.0

# Not a real path -- rule="tests-failed" is a whole-suite signal, not tied
# to one file/line. A constant, deterministic marker keeps the fingerprint
# stable across runs; gitutil safely returns "" for a path that resolves to
# neither a tracked blob nor a file on disk.
_SUITE_FILE_MARKER = "<test-suite>"


def run_pytest(ctx) -> RunnerResult:
    return run_subprocess(["pytest", "-q"], ctx.root, TIMEOUT_S)


def run_npm_test(ctx) -> RunnerResult:
    return run_subprocess(["npm", "test"], ctx.root, TIMEOUT_S)


def run(ctx) -> RunnerResult:
    kinds = detect_tests(ctx.root)
    if "pytest" in kinds:
        return run_pytest(ctx)
    if "npm" in kinds:
        return run_npm_test(ctx)
    return RunnerResult("tests", ToolState.MISSING)


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK or result.returncode == 0:
        return []
    return [RawFinding(
        tool=result.tool,
        rule="tests-failed",
        severity_raw="high",
        file=_SUITE_FILE_MARKER,
        line=0,
        message=f"{result.tool} exited {result.returncode}: test suite failed",
    )]
