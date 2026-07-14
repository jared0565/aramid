import io
import json

import pytest

from aramid.providers import base, claude_cli, codex_cli, openrouter, spend


@pytest.fixture(autouse=True)
def _spend(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "s.jsonl")


def _capture_argv(monkeypatch, module):
    seen = {}

    def fake_run(argv, prompt, timeout_s):
        seen["argv"] = argv
        # minimal valid envelope per module so review() parses cleanly
        if module is claude_cli:
            out = json.dumps({"result": "{}", "usage": {"input_tokens": 1, "output_tokens": 1}})
        else:  # codex
            out = (json.dumps({"type": "item.completed",
                               "item": {"type": "agent_message", "text": "{}"}}) + "\n" +
                   json.dumps({"type": "turn.completed",
                               "usage": {"input_tokens": 1, "output_tokens": 1}}))
        return (0, out, "")
    monkeypatch.setattr(base, "run_provider_subprocess", fake_run)
    # ensure the exe resolves
    monkeypatch.setattr(module.shutil, "which", lambda name: f"/usr/bin/{name}")
    return seen


def test_claude_effort_appended(monkeypatch):
    seen = _capture_argv(monkeypatch, claude_cli)
    claude_cli.review("P", "opus", 240.0, effort="high")
    assert "--effort" in seen["argv"]
    assert seen["argv"][seen["argv"].index("--effort") + 1] == "high"


def test_claude_effort_omitted_when_unset(monkeypatch):
    seen = _capture_argv(monkeypatch, claude_cli)
    claude_cli.review("P", "opus", 240.0)          # effort=""
    assert "--effort" not in seen["argv"]


def test_codex_effort_appended(monkeypatch):
    seen = _capture_argv(monkeypatch, codex_cli)
    codex_cli.review("P", "gpt-5.6", 240.0, effort="medium")
    assert "-c" in seen["argv"]
    idx = seen["argv"].index("-c")
    assert seen["argv"][idx + 1] == "model_reasoning_effort=medium"


def test_codex_effort_omitted_when_unset(monkeypatch):
    seen = _capture_argv(monkeypatch, codex_cli)
    codex_cli.review("P", "gpt-5.6", 240.0)
    assert "model_reasoning_effort=" not in " ".join(seen["argv"])


def test_openrouter_effort_in_body(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-x")
    seen = {}

    def fake_urlopen(req, timeout):
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return io.BytesIO(json.dumps(
            {"choices": [{"message": {"content": "{}"}}], "usage": {}}).encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)
    openrouter.review("P", "m", 240.0, effort="low", cfg=SimpleNamespace(llm={}))
    assert seen["body"]["reasoning"] == {"effort": "low"}
