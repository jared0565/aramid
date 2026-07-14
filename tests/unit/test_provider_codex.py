import json

import pytest

from aramid.providers import base, codex_cli, spend

JSONL = "\n".join([
    json.dumps({"type": "session.created", "session_id": "s1"}),
    "this line is not json and must be skipped",
    json.dumps({"type": "item.completed",
                "item": {"type": "reasoning", "text": "thinking..."}}),
    json.dumps({"type": "item.completed",
                "item": {"type": "agent_message", "text": '{"findings": []}'}}),
    json.dumps({"type": "turn.completed",
                "usage": {"input_tokens": 1500, "output_tokens": 40}}),
])


@pytest.fixture(autouse=True)
def _isolated_spend(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")


def test_registers_in_providers():
    assert base.PROVIDERS["codex-cli"] is codex_cli


def test_installed_iff_on_path(monkeypatch):
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: r"C:\bin\codex.cmd")
    assert codex_cli.installed() is True
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: None)
    assert codex_cli.installed() is False


def test_review_parses_jsonl(monkeypatch):
    seen = {}

    def fake_run(argv, prompt, timeout_s):
        seen["argv"] = argv
        return 0, JSONL, ""
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess", fake_run)
    resp = codex_cli.review("PACKET", "", 240.0)
    assert resp.text == '{"findings": []}'
    assert (resp.tokens_in, resp.tokens_out) == (1500, 40)
    assert resp.cost_usd == 0.0
    # model "" (CLI default) -> no -m flag; sandboxed read-only one-shot
    assert seen["argv"] == [r"C:\bin\codex.cmd", "exec", "--json",
                            "--sandbox", "read-only", "--skip-git-repo-check", "-"]


def test_review_model_flag_when_set(monkeypatch):
    seen = {}

    def fake_run(argv, prompt, timeout_s):
        seen["argv"] = argv
        return 0, JSONL, ""
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess", fake_run)
    codex_cli.review("PACKET", "o4-mini", 240.0)
    assert "-m" in seen["argv"] and "o4-mini" in seen["argv"]


def test_review_no_agent_message_is_malformed(monkeypatch):
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, json.dumps({"type": "noise"}), ""))
    assert codex_cli.review("P", "", 240.0).error == base.ERR_MALFORMED


def test_review_quota_and_timeout(monkeypatch):
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (1, "", "You've hit your usage limit"))
    assert codex_cli.review("P", "", 240.0).error == base.ERR_QUOTA
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess", lambda *a, **k: None)
    assert codex_cli.review("P", "", 240.0).error == base.ERR_TIMEOUT


def test_review_nonzero_exit_is_error(monkeypatch):
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (1, "", "boom"))
    assert codex_cli.review("P", "", 240.0).error == base.ERR_ERROR


def test_review_unavailable_when_not_on_path(monkeypatch):
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: None)
    assert codex_cli.review("P", "", 240.0).error == base.ERR_UNAVAILABLE


# Extra hardening tests
def test_review_bare_scalar_in_jsonl_is_skipped(monkeypatch):
    """A bare scalar (5) in JSONL should be skipped, not crash."""
    jsonl = "\n".join([
        "5",  # bare scalar
        json.dumps({"type": "item.completed",
                    "item": {"type": "agent_message", "text": "valid reply"}}),
        json.dumps({"type": "turn.completed",
                    "usage": {"input_tokens": 100, "output_tokens": 20}}),
    ])
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, jsonl, ""))
    resp = codex_cli.review("P", "", 240.0)
    assert resp.text == "valid reply"
    assert (resp.tokens_in, resp.tokens_out) == (100, 20)
    assert resp.error == ""


def test_review_item_not_dict_is_skipped(monkeypatch):
    """A line where item is not a dict (e.g. string) should be skipped."""
    jsonl = "\n".join([
        json.dumps({"type": "item.completed", "item": "oops"}),  # item is string, not dict
        json.dumps({"type": "item.completed",
                    "item": {"type": "agent_message", "text": "valid reply"}}),
        json.dumps({"type": "turn.completed",
                    "usage": {"input_tokens": 100, "output_tokens": 20}}),
    ])
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, jsonl, ""))
    resp = codex_cli.review("P", "", 240.0)
    assert resp.text == "valid reply"
    assert (resp.tokens_in, resp.tokens_out) == (100, 20)
    assert resp.error == ""


def test_review_wrong_token_types_zero_out(monkeypatch):
    """Token fields of wrong type should zero out, text kept."""
    jsonl = "\n".join([
        json.dumps({"type": "item.completed",
                    "item": {"type": "agent_message", "text": "valid reply"}}),
        json.dumps({"type": "turn.completed",
                    "usage": {"input_tokens": "bad", "output_tokens": None}}),
    ])
    monkeypatch.setattr(codex_cli.shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, jsonl, ""))
    resp = codex_cli.review("P", "", 240.0)
    assert resp.text == "valid reply"
    assert (resp.tokens_in, resp.tokens_out) == (0, 0)
    assert resp.error == ""
