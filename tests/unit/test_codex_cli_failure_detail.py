"""codex-cli keeps why a call failed in `detail` (operator decision
2026-10-30). On 2026-10-30 a retired model exited 1 with nothing on stderr
and 527 characters of JSON events on stdout, so the reason is looked for in
the event stream first. The error codes the arm loop reads are unchanged."""
import json
import shutil

import pytest

from aramid.providers import base, codex_cli, spend


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")


def _run(monkeypatch, rc, out, err):
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess", lambda *a, **k: (rc, out, err))
    return codex_cli.review("P", "gpt-5.5", 240.0)


def _events(*events):
    return "\n".join(json.dumps(e) for e in events)


def test_a_failed_turn_keeps_the_exit_code_and_its_message(monkeypatch):
    out = _events({"type": "thread.started", "thread_id": "t1"},
                  {"type": "turn.started"},
                  {"type": "error", "message": "stream disconnected"},
                  {"type": "turn.failed",
                   "error": {"message": "The model `gpt-5.5` does not exist"}})
    resp = _run(monkeypatch, 1, out, "")
    assert resp.error == base.ERR_ERROR
    assert resp.detail == "exit 1: The model `gpt-5.5` does not exist"


def test_an_error_event_is_kept_when_no_turn_failed(monkeypatch):
    out = _events({"type": "thread.started", "thread_id": "t1"},
                  {"type": "error", "message": "unexpected status 400 Bad Request"},
                  5, {"type": "error", "message": "  "})
    assert _run(monkeypatch, 1, out, "").detail == "exit 1: unexpected status 400 Bad Request"


def test_without_an_event_the_last_stderr_line_is_kept(monkeypatch):
    resp = _run(monkeypatch, 2, "", "Reading prompt from stdin...\nError: login expired\n")
    assert (resp.error, resp.detail) == (base.ERR_ERROR, "exit 2: Error: login expired")


def test_without_stderr_the_last_stdout_line_is_kept(monkeypatch):
    assert _run(monkeypatch, 1, "a line\nthe last line\n", "").detail == "exit 1: the last line"


def test_a_quota_failure_keeps_its_line(monkeypatch):
    resp = _run(monkeypatch, 1, "", "You've hit your usage limit. Try again at 4pm.")
    assert resp.error == base.ERR_QUOTA
    assert resp.detail == "exit 1: You've hit your usage limit. Try again at 4pm."


def test_a_refused_command_line_keeps_the_refusal(monkeypatch, capsys):
    resp = _run(monkeypatch, 2, "", "error: unexpected argument '--ephemeral' found\n\nUsage: ...")
    assert resp.error == base.ERR_UNAVAILABLE
    assert resp.detail == "exit 2: error: unexpected argument '--ephemeral' found"


def test_a_reply_after_a_tool_keeps_the_tool(monkeypatch, capsys):
    out = _events({"type": "item.completed", "item": {"type": "command_execution"}},
                  {"type": "item.completed",
                   "item": {"type": "agent_message", "text": '{"findings": []}'}})
    resp = _run(monkeypatch, 0, out, "")
    assert (resp.error, resp.detail) == (base.ERR_ERROR, "tool used: command_execution")


def test_an_answer_has_no_detail(monkeypatch):
    out = _events({"type": "item.completed",
                   "item": {"type": "agent_message", "text": '{"findings": []}'}})
    resp = _run(monkeypatch, 0, out, "")
    assert (resp.error, resp.detail) == ("", "")
