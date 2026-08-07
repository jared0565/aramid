"""A blocking gate must say WHY, not just THAT.

Verified against the real runner on 2026-08-07: a failing `[tests]` command
returns `state=OK, returncode=1` with **0 bytes of stderr** and 597 bytes of
stdout naming the failing test. `_write_logs` persisted only stderr, and the
finding carries `message="python exited 1: test suite failed"` with
`evidence=None`.

So the BLOCK-tier gate that stops a push wrote an EMPTY log file and named
nothing. Nothing aramid offers could tell you which test failed.

That is not theoretical. A `windows-latest / py3.14` CI leg failed at exactly
this step, passed on re-run with no code change, and the flake could not be
identified from any artifact -- the one string that would have named it was
collected, held in `RunnerResult.raw`, and thrown away.
"""
from aramid import pipeline
from aramid.runners.base import RunnerResult, ToolState


def _log(tmp_path, result):
    pipeline._write_logs(tmp_path, "run1", [result], [])
    return (tmp_path / ".aramid" / "logs" / f"{result.tool}-run1.log").read_text(
        encoding="utf-8")


def test_a_failing_suites_stdout_reaches_the_log(tmp_path):
    out = ("=" * 20 + " FAILURES " + "=" * 20 + "\n"
           "___ test_boom ___\n"
           "E   AssertionError: the informative detail\n"
           "1 failed, 1 passed\n")
    result = RunnerResult("python", ToolState.OK, raw=out, stderr="", returncode=1)

    body = _log(tmp_path, result)

    assert "test_boom" in body
    assert "the informative detail" in body


def test_a_clean_runners_stdout_is_not_logged(tmp_path):
    """Bloat guard: ruff and semgrep emit their whole JSON report on stdout,
    and it is already surfaced as findings. Writing it on every clean run
    would grow `.aramid/logs` for nothing -- there is no rotation."""
    result = RunnerResult("ruff", ToolState.OK, raw="[]" * 5000, stderr="",
                          returncode=0)

    assert _log(tmp_path, result) == ""


def test_stderr_only_results_keep_their_exact_previous_format(tmp_path):
    """No gratuitous format change: with no stdout to add, the file is
    byte-identical to what it held before -- no headers, no blank lines."""
    result = RunnerResult("clippy", ToolState.MISSING, raw="", stderr="clippy evidence")

    assert _log(tmp_path, result) == "clippy evidence"


def test_both_streams_are_labelled_when_both_are_present(tmp_path):
    result = RunnerResult("python", ToolState.OK, raw="on stdout",
                          stderr="on stderr", returncode=1)

    body = _log(tmp_path, result)

    assert "on stdout" in body and "on stderr" in body
    assert body.index("on stdout") < body.index("on stderr")


def test_a_huge_stdout_is_truncated_from_the_FRONT(tmp_path):
    """pytest prints its short summary LAST, so the tail is the half worth
    keeping. The cap is what stops a giant report filling the disk."""
    tail = "1 failed, 4000 passed"
    result = RunnerResult("python", ToolState.OK,
                          raw=("x" * (pipeline._LOG_STDOUT_CAP * 2)) + tail,
                          stderr="", returncode=1)

    body = _log(tmp_path, result)

    assert tail in body
    assert "truncated" in body
    assert len(body) < pipeline._LOG_STDOUT_CAP * 1.5


def test_stdout_is_scrubbed_exactly_like_stderr(tmp_path):
    """An assertion diff is precisely where a real secret surfaces, and this
    file is written to disk. stderr was already scrubbed; stdout must be too,
    or this change would newly PERSIST secrets that used to be discarded."""
    secret = "AKIAIOSFODNN7EXAMPLE"
    result = RunnerResult("python", ToolState.OK,
                          raw=f"E  assert token == {secret}", stderr="",
                          returncode=1)

    pipeline._write_logs(tmp_path, "run1", [result], [secret])
    body = (tmp_path / ".aramid" / "logs" / "python-run1.log").read_text(
        encoding="utf-8")

    assert secret not in body


def test_a_degraded_runner_logs_its_stdout_too(tmp_path):
    """A CRASHED tool often explains itself on stdout, not stderr."""
    result = RunnerResult("semgrep", ToolState.CRASHED,
                          raw="Traceback: ruleset failed to load", stderr="")

    assert "ruleset failed to load" in _log(tmp_path, result)
