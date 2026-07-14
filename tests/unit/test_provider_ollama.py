import io
import json
import urllib.error

import pytest

from aramid.providers import base, ollama_cloud, spend

RESPONSE = json.dumps({
    "message": {"role": "assistant", "content": '{"findings": []}'},
    "prompt_eval_count": 1800, "eval_count": 42,
})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    monkeypatch.setenv("OLLAMA_API_KEY", "ol-test")


def test_registers_in_providers():
    assert base.PROVIDERS["ollama-cloud"] is ollama_cloud


def test_available_requires_key(monkeypatch):
    assert ollama_cloud.installed() is True
    assert ollama_cloud.available(None) is True
    monkeypatch.delenv("OLLAMA_API_KEY")
    assert ollama_cloud.installed() is False
    assert ollama_cloud.available(None) is False


def test_review_posts_native_body_and_parses(monkeypatch, tmp_path):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["auth"] = req.get_header("Authorization")
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return io.BytesIO(RESPONSE.encode("utf-8"))
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", fake_urlopen)
    resp = ollama_cloud.review("PACKET", "deepseek-v4-flash", 240.0)
    assert resp.text == '{"findings": []}'
    assert resp.cost_usd == 0.0
    assert (resp.tokens_in, resp.tokens_out) == (1800, 42)
    assert seen["url"] == "https://ollama.com/api/chat"
    assert seen["auth"] == "Bearer ol-test"
    assert seen["body"]["model"] == "deepseek-v4-flash"
    assert seen["body"]["stream"] is False
    assert seen["body"]["messages"][0]["content"] == "PACKET"
    assert "think" not in seen["body"]          # effort unset -> no think
    logged = (tmp_path / "llm_spend.jsonl").read_text(encoding="utf-8")
    assert json.loads(logged)["cost_usd"] == 0.0


def test_effort_sets_think(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return io.BytesIO(RESPONSE.encode("utf-8"))
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", fake_urlopen)
    ollama_cloud.review("P", "m", 240.0, effort="high")
    assert seen["body"]["think"] is True


def test_missing_key_unavailable(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY")
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_UNAVAILABLE


def test_timeout(monkeypatch):
    def boom(req, timeout):
        raise TimeoutError()
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", boom)
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_TIMEOUT


def test_http_429_is_quota(monkeypatch):
    def boom(req, timeout):
        raise urllib.error.HTTPError("u", 429, "rate", {}, None)
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", boom)
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_QUOTA


def test_http_401_is_unavailable(monkeypatch):
    def boom(req, timeout):
        raise urllib.error.HTTPError("u", 401, "auth", {}, None)
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", boom)
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_UNAVAILABLE


def test_malformed_body_no_message(monkeypatch):
    def fake_urlopen(req, timeout):
        return io.BytesIO(json.dumps({"error": "no such model"}).encode("utf-8"))
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", fake_urlopen)
    resp = ollama_cloud.review("P", "m", 240.0)
    assert resp.error == base.ERR_MALFORMED and resp.text == ""


def test_non_string_content_malformed(monkeypatch):
    def fake_urlopen(req, timeout):
        return io.BytesIO(json.dumps({"message": {"content": 123}}).encode("utf-8"))
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", fake_urlopen)
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_MALFORMED


def test_never_raises_on_garbage(monkeypatch):
    def fake_urlopen(req, timeout):
        return io.BytesIO(b"not json")
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", fake_urlopen)
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_ERROR
