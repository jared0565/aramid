"""claude-cli keeps why a call failed in `detail` (operator decision
2026-10-30). With `--output-format json` a failed call can still print its
envelope on stdout, with the error in `result`. The error codes the arm loop
reads are unchanged."""
import json
import shutil

import pytest

from aramid.providers import base, claude_cli, spend


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\claude.cmd")


def _run(monkeypatch, rc, out, err):
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess", lambda *a, **k: (rc, out, err))
    return claude_cli.review("P", "claude-opus-5-5", 240.0)


def test_an_error_envelope_keeps_the_exit_code_and_its_result(monkeypatch):
    out = json.dumps({"type": "result", "subtype": "success", "is_error": True,
                      "result": "API Error: 404 model: claude-opus-4-9 not found"})
    resp = _run(monkeypatch, 1, out, "")
    assert resp.error == base.ERR_ERROR
    assert resp.detail == "exit 1: API Error: 404 model: claude-opus-4-9 not found"


def test_an_envelope_that_is_not_an_error_is_not_read_as_one(monkeypatch):
    out = json.dumps({"type": "result", "is_error": False, "result": "the review text"})
    assert _run(monkeypatch, 1, out, "Invalid API key\n").detail == "exit 1: Invalid API key"


def test_an_envelope_that_is_not_an_error_is_not_kept_either(monkeypatch):
    """Its `result` is a review of the repo's code; with nothing on stderr
    the exit code is all that is kept."""
    out = json.dumps({"type": "result", "is_error": False, "result": "the review text"})
    assert _run(monkeypatch, 1, out, "").detail == "exit 1"


def test_without_an_envelope_the_last_stderr_line_is_kept(monkeypatch):
    resp = _run(monkeypatch, 1, "", "warming up\nInvalid API key - Please run /login\n")
    assert (resp.error, resp.detail) == (base.ERR_ERROR,
                                         "exit 1: Invalid API key - Please run /login")


def test_without_stderr_the_last_stdout_line_is_kept(monkeypatch):
    assert _run(monkeypatch, 1, "not json\nstill not json\n", "").detail == \
        "exit 1: still not json"


def test_a_quota_failure_keeps_its_line(monkeypatch):
    resp = _run(monkeypatch, 1, "", "Claude usage limit reached. Your limit will reset at 5pm.")
    assert resp.error == base.ERR_QUOTA
    assert resp.detail == "exit 1: Claude usage limit reached. Your limit will reset at 5pm."


def test_a_refused_command_line_keeps_the_refusal(monkeypatch, capsys):
    resp = _run(monkeypatch, 1, "", "error: unknown option '--safe-mode'\n")
    assert (resp.error, resp.detail) == (base.ERR_UNAVAILABLE,
                                         "exit 1: error: unknown option '--safe-mode'")


@pytest.mark.parametrize("timeout_s", [float("inf"), float("-inf"), 0.0, 1e300])
def test_an_unusable_timeout_starts_nothing(monkeypatch, timeout_s):
    """The drain's fuzzer: review() raised OverflowError on an infinite
    timeout (row ace833c8ab6c)."""
    started = []
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: started.append(a))
    resp = claude_cli.review("P", "claude-opus-5-5", timeout_s)
    assert (resp.error, started) == (base.ERR_ERROR, [])
    assert resp.detail.startswith("bad timeout: ")


def test_an_answer_has_no_detail(monkeypatch):
    out = json.dumps({"result": '{"findings": []}', "usage": {}})
    resp = _run(monkeypatch, 0, out, "")
    assert (resp.error, resp.detail) == ("", "")
