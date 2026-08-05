"""Every fail-safe handler in aramid swallows exceptions ON PURPOSE.

A malformed ledger record must not crash a gate; a provider whose probe raises
must not crash the drain. Skipping is right. Skipping SILENTLY is not: a
systematically corrupt ledger, or a provider that raises on every probe, then
produces output identical to a clean run. That is the failure mode this whole
repo exists to prevent -- a check that reports success for a reason
indistinguishable from a real pass.

These helpers keep the fail-safe behaviour exactly as it was and make the
swallow observable. They are deliberately tiny; what is tested here is the
CONTRACT the eleven call sites depend on.
"""
import pytest

from aramid import diagnostics


def test_a_skip_is_reported_with_its_count(capsys):
    diagnostics.note_skipped("llm-gate", 3)
    err = capsys.readouterr().err
    assert "llm-gate" in err
    assert "3" in err


def test_nothing_is_printed_when_nothing_was_skipped(capsys):
    """THE ONE THAT MATTERS FOR ADOPTION. The clean path is the common path; a
    gate that chatters on every run gets ignored, and then the one run that
    had something to say is ignored too."""
    diagnostics.note_skipped("llm-gate", 0)
    assert capsys.readouterr().err == ""


def test_a_negative_count_is_also_silent(capsys):
    diagnostics.note_skipped("llm-gate", -1)
    assert capsys.readouterr().err == ""


def test_one_line_per_loop_not_one_per_record(capsys):
    """A corrupted ledger holding 500 bad rows must produce ONE line, not 500.
    The counter-then-summarise shape is the reason these helpers exist rather
    than a print inside each handler."""
    diagnostics.note_skipped("llm-gate", 500)
    assert len(capsys.readouterr().err.strip().splitlines()) == 1


def test_the_noun_is_singular_for_one(capsys):
    diagnostics.note_skipped("llm-gate", 1)
    err = capsys.readouterr().err
    assert "1 malformed record" in err
    assert "records" not in err


def test_the_noun_can_be_overridden(capsys):
    """Not every swallow is a malformed record -- an unparseable mutant is
    an expected outcome of mutating an AST, and calling it 'malformed record'
    would send a reader looking for ledger corruption."""
    diagnostics.note_skipped("mutation", 2, "unparseable mutant")
    assert "2 unparseable mutants" in capsys.readouterr().err


def test_a_named_failure_reports_subject_and_exception(capsys):
    """For swallows worth naming individually: a provider that never loads is
    indistinguishable from one that is merely not configured, and that silence
    can disable the entire LLM half of the product indefinitely."""
    diagnostics.note_failed("providers", "openrouter probe", RuntimeError("boom"))
    err = capsys.readouterr().err
    assert "providers" in err
    assert "openrouter probe" in err
    assert "RuntimeError" in err
    assert "boom" in err


def test_diagnostics_go_to_stderr_not_stdout(capsys):
    """stdout carries the gate report that tooling parses; engine telemetry
    about aramid itself must not contaminate it."""
    diagnostics.note_skipped("llm-gate", 1)
    diagnostics.note_failed("providers", "x", ValueError("y"))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err != ""


@pytest.mark.parametrize("exc", [ValueError("v"), OSError("o"), KeyError("k")])
def test_note_failed_never_raises_on_any_exception_type(capsys, exc):
    """These run INSIDE exception handlers. A helper that raised would convert
    a survivable swallow into the crash the handler existed to prevent."""
    diagnostics.note_failed("where", "subject", exc)
    assert capsys.readouterr().err != ""
