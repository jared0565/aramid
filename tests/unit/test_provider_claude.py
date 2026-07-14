import json

import pytest

from aramid.providers import base, claude_cli, spend

ENVELOPE = json.dumps({
    "type": "result", "subtype": "success", "is_error": False,
    "duration_ms": 4200, "num_turns": 1, "session_id": "abc",
    "result": "{\"findings\": []}",
    "total_cost_usd": 0.0123,
    "usage": {"input_tokens": 2100, "output_tokens": 60},
})


@pytest.fixture(autouse=True)
def _isolated_spend(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")


def test_registers_in_providers():
    assert base.PROVIDERS["claude-cli"] is claude_cli


def test_available_and_installed_iff_on_path(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    assert claude_cli.available(None) is True
    assert claude_cli.installed() is True
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: None)
    assert claude_cli.available(None) is False
    assert claude_cli.installed() is False


def test_review_parses_envelope_and_logs_zero_cost(monkeypatch, tmp_path):
    seen = {}

    def fake_run(argv, prompt, timeout_s):
        seen["argv"], seen["prompt"] = argv, prompt
        return 0, ENVELOPE, ""
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess", fake_run)
    resp = claude_cli.review("PACKET", "sonnet", 240.0)
    assert resp.text == '{"findings": []}'
    assert (resp.tokens_in, resp.tokens_out) == (2100, 60)
    assert resp.cost_usd == 0.0     # subscription: cost 0.0 regardless of envelope estimate
    assert resp.error == ""
    assert seen["argv"] == [r"C:\bin\claude.exe", "-p", "--model", "sonnet",
                            "--output-format", "json"]
    assert seen["prompt"] == "PACKET"
    logged = (tmp_path / "llm_spend.jsonl").read_text(encoding="utf-8")
    assert json.loads(logged)["provider"] == "claude-cli"


def test_review_timeout(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: None)
    assert claude_cli.review("P", "sonnet", 1.0).error == base.ERR_TIMEOUT


def test_review_quota_error(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (1, "", "Claude usage limit reached|resets 3pm"))
    assert claude_cli.review("P", "sonnet", 240.0).error == base.ERR_QUOTA


def test_review_nonzero_exit_is_error(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (1, "", "boom"))
    assert claude_cli.review("P", "sonnet", 240.0).error == base.ERR_ERROR


def test_review_unparseable_envelope_is_malformed(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, "garbage not json", ""))
    assert claude_cli.review("P", "sonnet", 240.0).error == base.ERR_MALFORMED


def test_review_null_usage_keeps_text_zeroes_tokens(monkeypatch):
    envelope = json.dumps({"result": "ok text", "usage": None})
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, envelope, ""))
    resp = claude_cli.review("P", "sonnet", 240.0)
    assert resp.text == "ok text"
    assert (resp.tokens_in, resp.tokens_out) == (0, 0)
    assert resp.error == ""


def test_review_non_dict_envelope_is_malformed(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, "[1, 2]", ""))
    assert claude_cli.review("P", "sonnet", 240.0).error == base.ERR_MALFORMED


def test_review_unavailable_when_not_on_path(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: None)
    assert claude_cli.review("P", "sonnet", 240.0).error == base.ERR_UNAVAILABLE
