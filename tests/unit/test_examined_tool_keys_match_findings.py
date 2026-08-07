"""The `examined_by_tool` map must be keyed the way findings are looked up.

`pipeline._examined_by_tool` keys on `RunnerResult.tool`;
`ledger.record_run` looks up `examined_by_tool[finding.tool]`. If those two
names ever diverge the lookup misses, `tool_scope` comes back `None`, and
resolution falls back to the whole gate file set -- which is exactly the bug
`examined` exists to fix, silently reinstated with nothing in the output to
show for it. No test fails, no finding appears; repairs just start being
forged again.

That is not a hypothetical divergence. `run_subprocess` names every result
after `Path(argv[0]).name`, which is:

    tsc      -> "tsc.cmd" on win32
    clippy   -> "cargo"
    eslint   -> "eslint.cmd" on win32

Each adapter restamps to its own NAME, and this file pins that every adapter
that reports `examined` still does -- on whatever platform the suite runs.
"""
import json

import pytest

from aramid import pipeline
from aramid.runners import clippy, eslint, ruff, semgrep, typecheck
from aramid.runners.base import RunContext, RunnerResult, ToolState

# (module, expected NAME, a raw payload its parse() yields >=1 finding from)
_REPORTING_RUNNERS = [
    pytest.param(
        ruff, ruff.NAME,
        json.dumps([{"code": "S101", "filename": "a.py", "message": "m",
                     "location": {"row": 1, "column": 1}}]),
        id="ruff"),
    pytest.param(
        eslint, eslint.NAME,
        json.dumps([{"filePath": "a.js", "messages": [
            {"ruleId": "no-eval", "severity": 2, "message": "m", "line": 1, "column": 1}]}]),
        id="eslint"),
    pytest.param(
        semgrep, semgrep.NAME,
        json.dumps({"results": [{"check_id": "owasp-top-ten.a01.x", "path": "a.py",
                                 "start": {"line": 1},
                                 "extra": {"severity": "ERROR", "message": "m"}}],
                    "paths": {"scanned": ["a.py"]}}),
        id="semgrep"),
]


@pytest.mark.parametrize("module, name, raw", _REPORTING_RUNNERS)
def test_findings_carry_the_same_tool_name_the_result_is_keyed_by(
        module, name, raw, tmp_path):
    """The invariant, stated directly: whatever name the RunnerResult carries
    is the name its own findings carry, so the map keyed by one is hit by the
    other."""
    result = RunnerResult(name, ToolState.OK, raw=raw, examined=frozenset({"a.py"}))
    ctx = RunContext(root=tmp_path, files=["a.py"])

    findings = module.parse(result, ctx)

    assert findings, f"{name} fixture yielded no findings -- the check is vacuous"
    assert {f.tool for f in findings} == {result.tool}


def test_clippy_findings_match_its_restamped_name(tmp_path):
    """clippy is the sharpest case: run_subprocess names it "cargo" after
    argv[0], and only `_ndjson_or_crashed`'s restamp makes the key match."""
    record = {"reason": "compiler-message",
              "message": {"code": {"code": "clippy::needless_return"},
                          "level": "warning", "message": "m",
                          "spans": [{"is_primary": True, "file_name": "src/lib.rs",
                                     "line_start": 3}]}}
    raw = json.dumps(record) + "\n"
    restamped = clippy._ndjson_or_crashed(
        RunnerResult("cargo", ToolState.OK, raw=raw))

    findings = clippy.parse(restamped, RunContext(root=tmp_path))

    assert restamped.tool == clippy.NAME != "cargo"
    assert findings and {f.tool for f in findings} == {restamped.tool}


def test_tsc_findings_match_its_restamped_name(tmp_path):
    """tsc is the other one: "tsc.cmd" on win32, relabelled by run_tsc."""
    raw = "src/app.ts(4,9): error TS2322: Type 'string' is not assignable.\n"
    result = RunnerResult(typecheck.NAME_TSC, ToolState.OK, raw=raw)

    findings = typecheck.parse_tsc(result, RunContext(root=tmp_path))

    assert findings and {f.tool for f in findings} == {result.tool}


# --- the map construction itself --------------------------------------------

def test_map_includes_only_ok_runners_that_reported():
    """Three exclusions, each load-bearing: a degraded runner never vouches, a
    None runner falls back rather than blocking, and the empty set is KEPT
    because it is a positive claim that nothing was examined."""
    flat = [
        RunnerResult("ruff", ToolState.OK, examined=frozenset({"a.py"})),
        RunnerResult("eslint", ToolState.OK, examined=frozenset()),
        RunnerResult("tests", ToolState.OK, examined=None),
        RunnerResult("semgrep", ToolState.TIMEOUT, examined=frozenset({"z.py"})),
        RunnerResult("clippy", ToolState.CRASHED, examined=frozenset({"y.rs"})),
    ]

    got = pipeline._examined_by_tool(flat)

    assert got == {"ruff": {"a.py"}, "eslint": set()}
    assert "tests" not in got, "None must fall back, not be recorded as empty"
    assert "semgrep" not in got and "clippy" not in got


def test_empty_set_is_preserved_not_collapsed_to_absent():
    """`{}` vs `{"eslint": set()}` is the whole None-vs-empty distinction; a
    truthiness filter here would silently reopen the hole for every runner
    that correctly reported examining nothing."""
    got = pipeline._examined_by_tool(
        [RunnerResult("eslint", ToolState.OK, examined=frozenset())])

    assert got == {"eslint": set()}
