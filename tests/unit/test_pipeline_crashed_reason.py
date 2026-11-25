"""The degraded reason of a CRASHED result that aramid itself refused to
start (interop round 346; operator decision 2026-11-23).

gitleaks' range check (FN-56) and an inline pass that raised stop before any
process exits, so the result carries returncode 0 and aramid's own sentence
on stderr. The reason read "crashed (exit 0)": an exit no program made, and
not why. A tool that did exit keeps its exit code."""
from aramid import pipeline
from aramid.runners.base import RunnerResult, ToolState


def test_a_refusal_of_aramid_s_own_is_named_by_its_sentence():
    rs = [RunnerResult("gitleaks", ToolState.CRASHED,
                       stderr="aramid: HEAD in the range HEAD does not resolve; the secret "
                              "scan did not run"),
          RunnerResult("ruff-inline", ToolState.CRASHED,
                       stderr="aramid: ruff-inline raised ValueError\n")]
    assert pipeline._degraded_reasons(rs) == {
        "gitleaks": "HEAD in the range HEAD does not resolve; the secret scan did not run",
        "ruff-inline": "ruff-inline raised ValueError",
    }


def test_a_tool_that_exited_keeps_its_exit_code():
    """Controls: a tool's own stderr is not aramid's sentence, even one that
    happens to start the same way, once the tool really exited."""
    rs = [RunnerResult("semgrep", ToolState.CRASHED, stderr="Traceback ...", returncode=2),
          RunnerResult("ruff", ToolState.CRASHED, returncode=0),
          RunnerResult("pip-audit", ToolState.CRASHED, stderr="aramid: x", returncode=1)]
    assert pipeline._degraded_reasons(rs) == {
        "semgrep": "crashed (exit 2)",
        "ruff": "crashed (exit 0)",
        "pip-audit": "crashed (exit 1)",
    }


def test_a_crashed_result_that_states_its_reason_is_named_by_it():
    """Opt-in (operator decision 2026-11-25): a pip-audit run that wrote no
    report, twice, carries pip-audit's own line in `RunnerResult.reason`, and
    that is the reason -- over the exit code and over an `aramid: ` sentence.
    Only a CRASHED result's is read: a timeout keeps its measured text."""
    rs = [RunnerResult("pip-audit", ToolState.CRASHED, stderr="aramid: x", returncode=1,
                       reason="crashed (exit 1): no report after a retry -- Failed to "
                              "upgrade `pip`"),
          RunnerResult("semgrep", ToolState.TIMEOUT, duration_s=30.0, reason="ignored"),
          RunnerResult("ruff", ToolState.CRASHED, returncode=2, reason=None)]
    assert pipeline._degraded_reasons(rs) == {
        "pip-audit": "crashed (exit 1): no report after a retry -- Failed to upgrade `pip`",
        "semgrep": "timeout after 30 s",
        "ruff": "crashed (exit 2)",
    }
