from pathlib import Path
from types import SimpleNamespace

from aramid import gitutil, tdd
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Source, Verdict
from aramid.runners.base import RunContext


def _ctx(files, rng="base..head", root=Path("/x")):
    return RunContext(root=root, files=files, rng=rng)


def _cfg(enabled=True):
    return SimpleNamespace(tdd={"enabled": enabled})


def test_is_test_file():
    assert gitutil.is_test_file("tests/test_foo.py") is True
    assert gitutil.is_test_file("pkg/tests/thing.py") is True
    assert gitutil.is_test_file("pkg/test_foo.py") is True
    assert gitutil.is_test_file("pkg/foo_test.py") is True
    assert gitutil.is_test_file("src/aramid/foo.py") is False


def test_prod_change_no_test_flags(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"src/foo.py": {1, 2}})
    findings = tdd.scan(_ctx(["src/foo.py"]), _cfg())
    assert [f.file for f in findings] == ["src/foo.py"]
    f = findings[0]
    assert (f.tool, f.rule, f.severity_raw, f.line) == ("tdd", "code-without-test", "medium", 0)


def test_prod_change_with_new_test_lines_is_clean(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines",
                        lambda root, b, h: {"src/foo.py": {1}, "tests/test_foo.py": {5, 6}})
    findings = tdd.scan(_ctx(["src/foo.py", "tests/test_foo.py"]), _cfg())
    assert findings == []


def test_test_only_change_is_clean(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"tests/test_foo.py": {5}})
    findings = tdd.scan(_ctx(["tests/test_foo.py"]), _cfg())
    assert findings == []


def test_prod_change_with_test_deletion_only_flags(monkeypatch):
    # test file changed but gained NO new lines (pure deletion) -> not "tested"
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"src/foo.py": {1}})
    findings = tdd.scan(_ctx(["src/foo.py", "tests/test_foo.py"]), _cfg())
    assert [f.file for f in findings] == ["src/foo.py"]


def test_disabled_returns_nothing(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"src/foo.py": {1}})
    findings = tdd.scan(_ctx(["src/foo.py"]), _cfg(enabled=False))
    assert findings == []


def test_scan_is_fail_open(monkeypatch):
    def boom(root, b, h):
        raise RuntimeError("git exploded")
    monkeypatch.setattr(gitutil, "diff_new_lines", boom)
    assert tdd.scan(_ctx(["src/foo.py"]), _cfg()) == []


def test_graph_advisory_note_is_inert(tmp_path):
    # No-op stub: no graph -> empty note, never raises.
    assert tdd._graph_advisory_note(tmp_path, "src/foo.py") == ""


def test_first_push_repo_with_test_is_clean(monkeypatch):
    # rng="" (FULL_HISTORY_RNG): tested iff ctx.files has any test file.
    # diff_new_lines returns {} here; if the code wrongly consulted it instead
    # of ctx.files, tests/test_foo.py would be missed and src/foo.py would flag.
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda *a: {})
    findings = tdd.scan(_ctx(["src/foo.py", "tests/test_foo.py"], rng=""), _cfg())
    assert findings == []


def test_first_push_repo_without_test_flags(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda *a: {"src/foo.py": {1}})
    findings = tdd.scan(_ctx(["src/foo.py"], rng=""), _cfg())
    assert [f.file for f in findings] == ["src/foo.py"]


# ------------------------------------------------- auto_resolve_tdd (1a-F2) --
# Build a real Ledger on tmp_path (mirrors tests/unit/test_mutation_gate.py:19),
# seed via record_run, and assert on STATUS -- never on membership.
# open_findings() returns EVERY materialized record keyed by id (never
# deletes a key), so `fid not in open_findings()` can never pass and
# `fid in open_findings()` passes unconditionally -- either would make a
# "stays open" assertion vacuous.

NOW = "2026-07-21T12:00:00+00:00"


def _tdd_finding(fid="f" * 64, file="a.py", rule="code-without-test"):
    return Finding(id=fid, tool="tdd", rule=rule, severity_raw="medium",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file,
                   line=0, message="code changed with no new test in this range",
                   evidence="", gate=Gate.PRE_PUSH, source=Source.DETERMINISTIC)


def _seed(led, finding):
    led.record_run("r0", NOW, "drain", set(), set(), [finding])


def _seed_raw(led, fid, payload):
    led.append(Event(EventType.FINDING_DETECTED, "r0", NOW,
                     finding_id=fid, payload=payload))


def test_auto_resolve_tdd_resolves_when_mapped_test_added(tmp_path):
    # a.py NOT touched -- the canonical case the rejected scope_tools
    # mechanism provably cannot resolve (spec 2.2(1)); the discriminating
    # test of the whole task.
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _tdd_finding())
        resolved = tdd.auto_resolve_tdd(
            led, "r1", NOW, {"tests/test_a.py"}, present_ids=set())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == ["f" * 64]
    assert state["f" * 64]["status"] == "fixed"


def test_auto_resolve_tdd_resolves_when_source_touched_and_gap_addressed(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _tdd_finding())
        resolved = tdd.auto_resolve_tdd(
            led, "r1", NOW, {"a.py"}, present_ids=set())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == ["f" * 64]
    assert state["f" * 64]["status"] == "fixed"


def test_auto_resolve_tdd_skips_refired_finding(tmp_path):
    """spec 2.4 invariant: same as the source_touched case above, but the id
    IS in present_ids -- auto_resolve runs AFTER record_run, so a still-open
    finding re-fired THIS run must not be resolved out from under itself.
    Must fail if the present_ids guard is dropped."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _tdd_finding())
        resolved = tdd.auto_resolve_tdd(
            led, "r1", NOW, {"a.py"}, present_ids={"f" * 64})
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["f" * 64]["status"] == "open"


def test_auto_resolve_tdd_ignores_unrelated_files(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _tdd_finding())
        resolved = tdd.auto_resolve_tdd(
            led, "r1", NOW, {"b.py"}, present_ids=set())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["f" * 64]["status"] == "open"


def test_auto_resolve_tdd_ignores_other_tools(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        other = Finding(id="r" * 64, tool="ruff", rule="S102", severity_raw="high",
                        severity=Severity.HIGH, verdict=Verdict.WARN, file="a.py",
                        line=1, message="m", evidence="e", gate=Gate.PRE_PUSH)
        _seed(led, other)
        resolved = tdd.auto_resolve_tdd(
            led, "r1", NOW, {"a.py"}, present_ids=set())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["r" * 64]["status"] == "open"


def test_auto_resolve_tdd_skips_malformed_record(tmp_path):
    """A rec with file stored as null must be SKIPPED -- stays open, never
    crashes."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed_raw(led, "d" * 64, {"tool": "tdd", "file": None, "line": 0,
                                  "severity": "medium", "rule": "code-without-test",
                                  "message": "m"})
        resolved = tdd.auto_resolve_tdd(
            led, "r1", NOW, {"a.py"}, present_ids=set())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["d" * 64]["status"] == "open"


# --- the mapped-test rule, shared with mutation_gate ------------------------
#
# This resolver carried its OWN inline copy of `{test_<module>, <module>_test}`
# rather than the shared helper, so the 2026-08-10 widening that taught
# auto_resolve_mutation about subpackage and purpose-suffixed test names missed
# it entirely -- a call-graph query ("callers of _module_tests") cannot see a
# duplicated implementation.
#
# How it was caught, which is the point worth keeping: `test_added` had fired
# ZERO times across 182 FINDING_RESOLVED events in aramid's own ledger, while
# evidence_gone/red_proven/suite_completed_clean had all fired. A resolver that
# has never once fired is either unreachable or unexercised, and the existing
# fire test could not tell you which -- it maps `a.py` to `tests/test_a.py`, an
# input built to satisfy the rule.

def test_auto_resolve_tdd_maps_a_package_qualified_test(tmp_path):
    """The shape this repo actually produces, and could not resolve before."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _tdd_finding(file="src/aramid/consumers/base.py"))
        resolved = tdd.auto_resolve_tdd(
            led, "r1", NOW, {"tests/unit/test_consumers_base.py"},
            present_ids=set())
    finally:
        led.close()
    assert resolved == ["f" * 64]


def test_auto_resolve_tdd_maps_a_purpose_suffixed_test(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _tdd_finding(file="src/aramid/commands/doctor.py"))
        resolved = tdd.auto_resolve_tdd(
            led, "r1", NOW, {"tests/unit/test_doctor_version_parsing.py"},
            present_ids=set())
    finally:
        led.close()
    assert resolved == ["f" * 64]


def test_auto_resolve_tdd_keeps_sibling_subpackages_apart(tmp_path):
    """The boundary: `base` is a stem three source files share, so an
    unanchored rule would clear a finding on a module nobody tested."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _tdd_finding(file="src/aramid/consumers/base.py"))
        resolved = tdd.auto_resolve_tdd(
            led, "r1", NOW, {"tests/unit/test_runners_base.py"},
            present_ids=set())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["f" * 64]["status"] == "open"
