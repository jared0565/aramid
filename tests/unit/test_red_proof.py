"""red_proof (sub-project 3): unit tests for the pre-push red-first-proof
producer. Monkeypatch style mirrors tests/unit/test_tdd.py -- the plumbing
(diff_new_lines/read_blob/_run/run_subprocess) is faked; real-git coverage
lives in tests/integration/test_red_proof_gate.py (Task 3)."""
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import gitutil, red_proof
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Source, Verdict
from aramid.runners.base import RunContext, RunnerResult, ToolState


def _ctx(files, rng="base..HEAD", root=Path("/x")):
    return RunContext(root=root, files=files, rng=rng)


def _cfg(enabled=True, wall_budget_s=120, test_timeout_s=60):
    return SimpleNamespace(red_proof={
        "enabled": enabled, "wall_budget_s": wall_budget_s,
        "test_timeout_s": test_timeout_s})


class _CP:
    def __init__(self, rc=0):
        self.returncode, self.stdout, self.stderr = rc, "", ""


def _plumb(monkeypatch, new_lines, pytest_rcs, worktree_rc=0, blob=None):
    """Fake the full plumbing. pytest_rcs is consumed one rc per subject run;
    returns the list of pytest argv invocations for assertions.

    blob=None (the default) auto-generates a fake head blob with a real
    `def test_x():` test-definition line positioned at the LOWEST changed
    line number across every value in new_lines -- so the T-4 content gate
    (src/aramid/red_proof.py's _new_test_def_lines, which every subject now
    passes through before the subprocess) sees a genuine test-definition
    line among the changed lines, matching what each of these tests already
    assumed before the gate existed. Pass an explicit blob (e.g. "" for the
    unreadable-blob test) to bypass this and use it verbatim -- the gate
    itself is exercised directly by the content-gate tests below, not by
    this default."""
    runs = []
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: new_lines)
    if blob is None:
        first_line = min((min(s) for s in new_lines.values() if s), default=1)
        blob = "\n" * (first_line - 1) + "def test_x():\n    assert True\n"
    monkeypatch.setattr(gitutil, "read_blob", lambda root, ref, rel: blob)
    monkeypatch.setattr(gitutil, "_run", lambda root, *a: _CP(worktree_rc))
    rcs = list(pytest_rcs)

    def fake_run(argv, cwd, timeout_s, env=None):
        runs.append((argv, cwd, env))
        rc = rcs.pop(0)
        if rc == "timeout":
            return RunnerResult("pytest", ToolState.TIMEOUT)
        return RunnerResult("pytest", ToolState.OK, returncode=rc)

    monkeypatch.setattr(red_proof, "run_subprocess", fake_run)
    return runs


def test_never_red_file_yields_finding(monkeypatch, tmp_path):
    runs = _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    findings = red_proof.scan(
        _ctx(["tests/test_foo.py"], root=tmp_path), _cfg())
    assert len(findings) == 1
    f = findings[0]
    assert (f.tool, f.rule, f.severity_raw, f.file, f.line) == \
        ("red-proof", "test-not-red", "medium", "tests/test_foo.py", 0)
    # T-4: the message now names the actual predicate (a CHANGED test
    # DEFINITION line passing on base -- "changed", not "new": a pure
    # reformat of an existing def line satisfies the gate too), not just
    # "new test lines" -- key the assertion on the distinguishing word
    # rather than on "never red", which both the old and new wording share
    # and so cannot tell apart.
    assert "definition" in f.message
    # SP3-M1: assert the actual pytest invocation, not just its outcome --
    # `_plumb`'s docstring always claimed `runs` was captured "for
    # assertions" but no call site ever read it. argv must be the exact
    # in-worktree pytest invocation; the cwd check is STRUCTURAL (not a
    # literal path) because the worktree lives under
    # tempfile.mkdtemp(prefix="aramid-red-")/"wt" (red_proof.py), not under
    # tmp_path, so no literal path is available to assert against.
    assert len(runs) == 1
    argv, cwd, env = runs[0]
    assert argv == [sys.executable, "-m", "pytest", "-q", "tests/test_foo.py"]
    assert Path(cwd).name == "wt" and Path(cwd).parent.name.startswith("aramid-red-")
    # The base run must import the BASE worktree's source, not whatever is
    # installed -- see _base_import_env. Without this the whole producer
    # inverts under a pip editable install.
    assert env["PYTHONPATH"].split(os.pathsep)[:2] == [
        str(Path(cwd) / "src"), str(cwd)]


def test_red_on_base_yields_nothing(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [1])
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_collection_error_counts_as_red(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [2])
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_nothing_collected_yields_nothing(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/helpers_test.py": {3}}, [5])
    assert red_proof.scan(_ctx(["tests/helpers_test.py"], root=tmp_path), _cfg()) == []


def test_timeout_is_fail_open(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, ["timeout"])
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_per_file_verdicts_are_independent(monkeypatch, tmp_path):
    _plumb(monkeypatch,
           {"tests/test_a.py": {1}, "tests/test_b.py": {1}}, [0, 1])
    findings = red_proof.scan(
        _ctx(["tests/test_a.py", "tests/test_b.py"], root=tmp_path), _cfg())
    assert [f.file for f in findings] == ["tests/test_a.py"]


def test_no_new_test_lines_skips_all_plumbing(monkeypatch, tmp_path):
    """Prod-only diff: [] BEFORE any worktree/subprocess (zero-cost guard)."""
    calls = []
    monkeypatch.setattr(gitutil, "diff_new_lines",
                        lambda root, b, h: {"src/foo.py": {1}})
    monkeypatch.setattr(gitutil, "_run",
                        lambda root, *a: calls.append(a) or _CP(0))
    findings = red_proof.scan(_ctx(["src/foo.py"], root=tmp_path), _cfg())
    assert findings == []
    assert calls == []          # no worktree was ever created


def test_subject_outside_ctx_files_is_ignored(monkeypatch, tmp_path):
    """A test file in the diff but ignore-filtered out of ctx.files is not run."""
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    assert red_proof.scan(_ctx(["src/other.py"], root=tmp_path), _cfg()) == []


def test_falsy_rng_skips(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    assert red_proof.scan(
        _ctx(["tests/test_foo.py"], rng="", root=tmp_path), _cfg()) == []
    assert red_proof.scan(
        _ctx(["tests/test_foo.py"], rng=None, root=tmp_path), _cfg()) == []


def test_rangeless_rng_without_base_skips(monkeypatch, tmp_path):
    """rng without '..' gives base None -- no base tree to prove against."""
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    assert red_proof.scan(
        _ctx(["tests/test_foo.py"], rng="HEAD", root=tmp_path), _cfg()) == []


def test_disabled_returns_nothing(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    assert red_proof.scan(
        _ctx(["tests/test_foo.py"], root=tmp_path), _cfg(enabled=False)) == []


def test_exhausted_wall_budget_skips_subjects(monkeypatch, tmp_path):
    """wall_budget_s=-1 makes the budget check true on the first iteration --
    deterministic exhaustion without sleeping."""
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    assert red_proof.scan(
        _ctx(["tests/test_foo.py"], root=tmp_path),
        _cfg(wall_budget_s=-1)) == []


def test_worktree_add_failure_is_fail_open(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0], worktree_rc=1)
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_unreadable_head_blob_skips_file(monkeypatch, tmp_path):
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0], blob="")
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_scan_is_fail_open(monkeypatch, tmp_path):
    def boom(root, b, h):
        raise RuntimeError("git exploded")
    monkeypatch.setattr(gitutil, "diff_new_lines", boom)
    assert red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg()) == []


def test_missing_red_proof_config_defaults_on(monkeypatch, tmp_path):
    """cfg without a red_proof attr: enabled by default, still functions."""
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0])
    findings = red_proof.scan(
        _ctx(["tests/test_foo.py"], root=tmp_path), SimpleNamespace())
    assert [f.file for f in findings] == ["tests/test_foo.py"]


# ---------------------------------------- scan_scoped / auto_resolve (1a-F2) -
# STATUS assertions only -- never membership (see test_tdd.py's identical
# banner; open_findings() returns every materialized record and never
# deletes a key).

NOW = "2026-07-21T12:00:00+00:00"


def _rp_finding(fid="e" * 64, file="tests/test_foo.py"):
    return Finding(id=fid, tool="red-proof", rule="test-not-red", severity_raw="medium",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file,
                   line=0, message="a changed test-definition line passes against the pre-change tree (never red)",
                   evidence="", gate=Gate.PRE_PUSH, source=Source.DETERMINISTIC)


def _seed(led, finding):
    led.record_run("r0", NOW, "drain", set(), set(), [finding])


def test_auto_resolve_red_proof_resolves_proven_red(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _rp_finding())
        resolved = red_proof.auto_resolve_red_proof(
            led, "r1", NOW, {"tests/test_foo.py"}, present_ids=set())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == ["e" * 64]
    assert state["e" * 64]["status"] == "fixed"


def test_auto_resolve_red_proof_ignores_unproven(tmp_path):
    """proven_red=set() is the budget-break / rc-5 / timeout case -- none of
    them prove anything about the file, so nothing may resolve. Must fail if
    the definitive-verdict rule (scan_scoped's rc 1/2 only) is loosened to
    "changed but no finding emitted"."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _rp_finding())
        resolved = red_proof.auto_resolve_red_proof(
            led, "r1", NOW, set(), present_ids=set())
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["e" * 64]["status"] == "open"


def test_auto_resolve_red_proof_skips_refired_finding(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _rp_finding())
        resolved = red_proof.auto_resolve_red_proof(
            led, "r1", NOW, {"tests/test_foo.py"}, present_ids={"e" * 64})
        state = led.open_findings()
    finally:
        led.close()
    assert resolved == []
    assert state["e" * 64]["status"] == "open"


def test_scan_scoped_collects_proven_red(monkeypatch, tmp_path):
    # subjects = sorted(...) -> test_a, test_b, test_c, test_d; _plumb's `_run`
    # fake consumes rcs in that order via rcs.pop(0) per subject run: 0 ->
    # never-red finding, 1 -> proven red, 5 -> nothing collected, "timeout" ->
    # unattributable. rc 5 / TIMEOUT must land in NEITHER out nor proven_red.
    new_lines = {
        "tests/test_a.py": {1},
        "tests/test_b.py": {1},
        "tests/test_c.py": {1},
        "tests/test_d.py": {1},
    }
    _plumb(monkeypatch, new_lines, [0, 1, 5, "timeout"])
    out, proven_red = red_proof.scan_scoped(
        _ctx(list(new_lines), root=tmp_path), _cfg())
    assert [f.file for f in out] == ["tests/test_a.py"]
    assert proven_red == {"tests/test_b.py"}
    assert "tests/test_c.py" not in proven_red
    assert "tests/test_d.py" not in proven_red


def test_scan_is_thin_wrapper(monkeypatch, tmp_path):
    # _plumb's `_run` fake is single-use and stateful: rcs.pop(0) per subject
    # run, so one _plumb(..., [0]) serves exactly ONE producer invocation --
    # pass two rcs so `scan` and `scan_scoped` each get their own real run
    # instead of the second's pop(0) raising IndexError (swallowed by the
    # outer fail-open into [], turning this into a vacuous [] == [] compare).
    _plumb(monkeypatch, {"tests/test_foo.py": {5}}, [0, 0])
    a = red_proof.scan(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg())
    b = red_proof.scan_scoped(_ctx(["tests/test_foo.py"], root=tmp_path), _cfg())[0]
    assert a and a == b


# -------------------------------------------------- T-4 content gate --------
# _new_test_def_lines is the pure AST predicate; scan_scoped's per-subject
# loop gates a subject on (_new_test_def_lines(content) & new_lines[rel])
# immediately after the read_blob/empty-content check and before any
# worktree write or subprocess. Each case below is one row of the prototype
# table T-4 was signed off against -- case_id doubles as the failure label.

_REAL_CASE_CONTENT = (
    "def test_other():\n"
    "    assert True\n"
    "\n"
    "\n"
    "def test_check_writes_config(tmp_path):\n"
    "    p = tmp_path / 'conf.py'\n"
    "    p.write_text(\n"
    '        "def test_x():\\n    assert True\\n", encoding="utf-8")\n'
    "    assert p.exists()\n"
)
# added = {8}: only the write_text(...) call's argument line changed -- a
# STRING LITERAL that CONTAINS "def test_x():" text, not a real def. Both
# real def lines (1 and 5) are pre-existing/untouched context.

_GATE_CASES = [
    ("real_case_string_literal_arg", _REAL_CASE_CONTENT, {8}, False),
    ("genuinely_new_def",
     "def test_old():\n    assert True\n\n\ndef test_new():\n    assert True\n",
     {5, 6}, True),
    ("string_literal_assignment",
     'X = "def test_x():\\n    assert True\\n"\n', {1}, False),
    ("triple_quoted_block",
     "DOC = '''\ndef test_gen():\n    pass\n'''\n", {1, 2, 3, 4}, False),
    ("async_def", "async def test_a():\n    assert True\n", {1, 2}, True),
    ("class_and_indented_method",
     "class TestFoo:\n    def test_m(self):\n        assert True\n",
     {1, 2, 3}, True),
    ("decorated_parametrize",
     "import pytest\n\n\n@pytest.mark.parametrize('x', [1, 2])\n"
     "def test_p(x):\n    assert x\n", {4, 5}, True),
    ("line_inside_existing_body",
     "def test_existing():\n    x = 1\n    assert x == 1\n", {2}, False),
    ("comment_only_line",
     "def test_existing():\n    # a new comment\n    assert True\n", {2}, False),
    ("syntax_error_fails_open", "def test_broken(:\n    pass\n", {1}, False),
]


@pytest.mark.parametrize("case_id,content,added,expected", _GATE_CASES,
                         ids=[c[0] for c in _GATE_CASES])
def test_new_test_def_lines_gate_cases(case_id, content, added, expected):
    assert bool(red_proof._new_test_def_lines(content) & added) is expected


def test_gate_suppresses_string_literal_lookalike_end_to_end(monkeypatch, tmp_path):
    """T-4 acceptance (a): a fixture-repair-shaped change whose only added
    line is a write_text(...) call passing a STRING that merely CONTAINS
    "def test_x():" text must not produce a finding -- and must not even
    reach the subprocess (runs == []), unlike before T-4 where this exact
    shape (no content check at all) produced a false alarm."""
    runs = _plumb(monkeypatch, {"tests/test_check.py": {8}}, [0],
                  blob=_REAL_CASE_CONTENT)
    assert red_proof.scan(
        _ctx(["tests/test_check.py"], root=tmp_path), _cfg()) == []
    assert runs == []          # gate skipped the subprocess entirely


def test_gate_allows_genuine_new_test_def_end_to_end(monkeypatch, tmp_path):
    """T-4 acceptance (b): a genuinely new `def test_new():` among the added
    lines must still reach the subprocess (runs has one entry) and still
    fire when it passes on base."""
    blob = "def test_old():\n    assert True\n\n\ndef test_new():\n    assert True\n"
    runs = _plumb(monkeypatch, {"tests/test_foo.py": {5, 6}}, [0], blob=blob)
    findings = red_proof.scan(
        _ctx(["tests/test_foo.py"], root=tmp_path), _cfg())
    assert [f.file for f in findings] == ["tests/test_foo.py"]
    assert len(runs) == 1
