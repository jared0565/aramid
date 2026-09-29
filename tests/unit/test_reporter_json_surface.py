"""`aramid check --json` is public surface (API-2): its key sets, frozen.

A CI step, an agent or a dashboard reads these keys by name. Adding one is
a CHANGELOG `Added` entry and removing or renaming one bumps
`JSON_SCHEMA_VERSION` -- and each of these goes red first, so neither can
happen by accident. Every nested object is a dataclass serialised whole
(`dataclasses.asdict`), so a field added to `Finding`, `Moved` or
`OverrideRecord` for internal use is published the moment it exists.
"""
import dataclasses
import json

from aramid import reporter
from aramid.models import Finding, Gate, Severity, Verdict
from aramid.pipeline import GateResult
from aramid.policy import OverrideRecord
from aramid.pushrefs import Moved


def _payload() -> dict:
    """One of every nested object, so each key set is actually rendered."""
    finding = Finding("id1", "ruff", "S102", "high", Severity.HIGH, Verdict.WARN,
                      "a.py", 1, "m", "e", Gate.PRE_PUSH)
    result = GateResult(exit_code=0, findings=[finding], degraded=[], new_ids=[],
                        stale_overrides=[OverrideRecord("id2", "ruff", "S102", "a.py", "why")],
                        run_id="r1", refs_moved=(Moved("refs/heads/main", "a" * 40, None),))
    return json.loads(reporter.render_json(result))


def test_the_top_level_keys_are_exactly_these():
    assert set(_payload()) == {
        "schema_version", "exit_code", "findings", "degraded", "degraded_reasons",
        "accepted_reason", "refs_moved", "new_ids", "stale_overrides", "tools",
        "tools_ran", "scope_widened", "fresh_ledger_baseline", "grandfathered",
        "run_id", "recorded", "fleet_notices_pending"}


def test_the_schema_version_is_one():
    assert _payload()["schema_version"] == 1 == reporter.JSON_SCHEMA_VERSION


def test_a_finding_is_every_finding_field_plus_the_two_ratchet_keys():
    [finding] = _payload()["findings"]
    assert set(finding) == {
        "id", "tool", "rule", "severity_raw", "severity", "verdict", "file", "line",
        "message", "evidence", "gate", "source", "historical", "confirmed", "refuted",
        "escalated_by_ratchet", "verdict_before_ratchet"}


def test_the_finding_dataclass_fields_are_exactly_these():
    """The model itself, apart from the rendering: `asdict` publishes every
    field, so a new one is surface even if no test renders it."""
    assert [f.name for f in dataclasses.fields(Finding)] == [
        "id", "tool", "rule", "severity_raw", "severity", "verdict", "file", "line",
        "message", "evidence", "gate", "source", "historical", "confirmed", "refuted"]


def test_a_moved_ref_and_a_stale_override_are_exactly_these():
    p = _payload()
    assert set(p["refs_moved"][0]) == {"ref", "before", "after"}
    assert set(p["stale_overrides"][0]) == {"id", "tool", "rule", "path", "reason"}
