"""A configured `[tests].command` holding a shell operator (operator decision
2026-11-22, found beside interop round 340).

The gate's tests runner splits a string command with shlex and runs ONE
program with no shell (`runners.tests._argv`). Measured:
`python -m pytest -q tests/unit && npm test` became one pytest run with
`&&`, `npm`, `test` as its arguments, so `npm test` never ran, at every
pre-push, with no warning. Now the runner refuses such a string and comes
back MISSING -- the BLOCK-tier slot degrades and the push is refused until
the command is a list or names a script -- and doctor's `tests` row fails
naming the key and the operator. A list is an argv, taken as written; an
operator inside quotes is the argument's own text.

Seam: `run_subprocess` in the runner module (the one launcher `run_custom`
reaches). Doctor's row is pinned in test_doctor_configured_argv0.py."""
import pytest

from aramid.runners import tests as tests_runner
from aramid.runners.base import RunContext, RunnerResult, ToolState

PROBLEM = ("[tests].command runs one program without a shell, so `&&` would reach it "
           "as an argument and nothing after it would run -- write the command as a "
           "list, or put the steps in a script and name that")


@pytest.mark.parametrize("command, op", [
    ("a && b", "&&"), ("a || b", "||"), ("a | b", "|"), ("a; b", ";"), ("a > f", ">"),
    ("a 2>f", ">"), ("a >> f", ">>"), ("a < f", "<"), ("a &", "&"), ("a&&b", "&&"),
    ("&& b", "&&"),   # the scan starts at the first character
    # a backslash is literal inside single quotes: the quote closes there
    (r"a 'x\' && b", "&&"),
    # an escaped quote takes one character: the next quote closes the argument
    (r'a "x\"" && b', "&&"),
])
def test_the_first_unquoted_operator_is_named(command, op):
    assert tests_runner.unquoted_operator(command) == op


@pytest.mark.parametrize("command", [
    "python -m pytest -q", 'a -t "x|y"', "a -k 'p and not q; r'", 'a "b&c.py"',
    r'a "x \" && y"', r"a \&\& b", "",
    "'a && b'",   # quoted from the first character
])
def test_quoted_or_escaped_operators_are_text(command):
    assert tests_runner.unquoted_operator(command) is None


def test_a_list_is_never_read_for_operators():
    assert tests_runner.shell_operator_problem("[tests].command", ["a", "&&", "b"]) is None
    assert tests_runner.shell_operator_problem("[tests].command", "a && b") == PROBLEM


def _launches(monkeypatch):
    calls = []

    def fake(argv, cwd, timeout_s, env=None, **kw):
        calls.append(argv)
        return RunnerResult(tool=argv[0], state=ToolState.OK, raw="", returncode=0)
    monkeypatch.setattr(tests_runner, "run_subprocess", fake)
    return calls


def test_a_string_command_with_an_operator_degrades_and_runs_nothing(tmp_path, monkeypatch,
                                                                     capsys):
    calls = _launches(monkeypatch)

    res = tests_runner.run_custom(RunContext(root=tmp_path),
                                  "python -m pytest -q tests/unit && npm test")

    assert (res.tool, res.state, res.stderr) == ("tests", ToolState.MISSING, PROBLEM)
    assert calls == []
    assert capsys.readouterr().err == (
        f"aramid: tests: {PROBLEM}. The tests gate is degraded until then.\n")


def test_a_list_and_a_quoted_operator_still_run(tmp_path, monkeypatch, capsys):
    """Controls: a list is an argv the repo wrote out, and inside quotes the
    characters are the argument's own -- both run as before."""
    calls = _launches(monkeypatch)

    tests_runner.run_custom(RunContext(root=tmp_path), ["python", "-m", "pytest", "&&"])
    tests_runner.run_custom(RunContext(root=tmp_path), "python -m pytest -k 'a or b; c'")

    assert calls == [["python", "-m", "pytest", "&&"],
                     ["python", "-m", "pytest", "-k", "a or b; c"]]
    assert capsys.readouterr().err == ""
