"""Pins for the numbers in `red_proof.scan_scoped` that nothing else in the
suite tells apart.

FN-21 touched scan_scoped, and the drain mutates whole functions, so every
mutant in it is drawn again. A stage-1 sweep before the commit (2026-10-01)
found four that the function's own test files let survive, all on lines
that predate FN-21:

- the defaults, when `[red_proof]` sets neither: a 120 s wall budget and
  60 s for each test file's run on the base;
- the budget is spent only once elapsed time EXCEEDS it, so a subject
  reached at exactly the budget still runs;
- pytest's rc 2 (interrupted -- a collection error) on the base proves the
  test red, the same as rc 1: a test that imports what the range adds
  cannot even be collected there.
"""
from types import SimpleNamespace

from aramid import gitutil, red_proof
from aramid.runners.base import RunContext, RunnerResult, ToolState

_TEST = "tests/test_foo.py"


class _CP:
    returncode, stdout, stderr = 0, "", ""


def _plumb(monkeypatch, rc=0, clock=(0.0,)):
    """One changed test file adding a test definition; git and the pytest run
    faked. `clock` is what `time.monotonic` returns, in order, its last value
    repeating -- swapped on red_proof's own `time`, never the process clock.
    Returns the timeout each pytest run was given."""
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {_TEST: {1}})
    monkeypatch.setattr(gitutil, "read_blob",
                        lambda root, ref, rel: "def test_x():\n    assert True\n")
    monkeypatch.setattr(gitutil, "_run", lambda root, *a: _CP())
    ticks = list(clock)
    monkeypatch.setattr(red_proof, "time", SimpleNamespace(
        monotonic=lambda: ticks.pop(0) if len(ticks) > 1 else ticks[0]))
    timeouts = []

    def fake_run(argv, cwd, timeout_s, env=None):
        timeouts.append(timeout_s)
        return RunnerResult("pytest", ToolState.OK, returncode=rc)
    monkeypatch.setattr(red_proof, "run_subprocess", fake_run)
    return timeouts


def _scan(tmp_path):
    ctx = RunContext(root=tmp_path, files=[_TEST], rng="base..HEAD")
    return red_proof.scan_scoped(ctx, SimpleNamespace(red_proof={}))


def test_each_test_file_gets_60_seconds_by_default(monkeypatch, tmp_path):
    timeouts = _plumb(monkeypatch)
    _scan(tmp_path)
    assert timeouts == [60.0]


def test_the_default_budget_is_spent_after_120_seconds(monkeypatch, tmp_path):
    timeouts = _plumb(monkeypatch, clock=(0.0, 120.5))
    assert _scan(tmp_path) == ([], set())
    assert timeouts == []                    # skipped, not run


def test_a_subject_reached_at_exactly_the_budget_still_runs(monkeypatch, tmp_path):
    timeouts = _plumb(monkeypatch, clock=(0.0, 120.0))
    findings, _ = _scan(tmp_path)
    assert timeouts == [60.0]
    assert [f.file for f in findings] == [_TEST]     # rc 0 on base: never red


def test_a_collection_error_on_the_base_proves_the_test_red(monkeypatch, tmp_path):
    _plumb(monkeypatch, rc=2)
    assert _scan(tmp_path) == ([], {_TEST})
