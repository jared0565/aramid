"""ollama-cloud keeps why a call failed in `detail` (operator decision
2026-10-30). The error codes the arm loop reads are unchanged."""
import io
import json
import urllib.error

import pytest

from aramid.providers import base, ollama_cloud, spend

# The body ollama answered for a retired model, probed 2026-10-30 09:01Z.
RETIRED = ("deepseek-v4-flash:0731 was retired on September 25, 2026. "
           "Try glm-5.3-flash:cloud. (ref: 7f0f5855-d655-4a75-8247-124be433a970)")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    monkeypatch.setenv("OLLAMA_API_KEY", "ol-test")


def _raise(exc):
    def boom(req, timeout):
        raise exc
    return boom


def test_a_retired_model_keeps_the_status_and_the_message(monkeypatch):
    body = io.BytesIO(json.dumps({"error": RETIRED}).encode("utf-8"))
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen",
                        _raise(urllib.error.HTTPError("u", 410, "Gone", {}, body)))
    resp = ollama_cloud.review("P", "deepseek-v4-flash", 240.0)
    assert resp.error == base.ERR_ERROR
    assert resp.detail == f"HTTP 410: {RETIRED}"


def test_an_auth_failure_keeps_its_status(monkeypatch):
    body = io.BytesIO(json.dumps({"error": "unauthorized"}).encode("utf-8"))
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen",
                        _raise(urllib.error.HTTPError("u", 401, "auth", {}, body)))
    resp = ollama_cloud.review("P", "m", 240.0)
    assert (resp.error, resp.detail) == (base.ERR_UNAVAILABLE, "HTTP 401: unauthorized")


def test_a_quota_answer_keeps_its_status(monkeypatch):
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen",
                        _raise(urllib.error.HTTPError("u", 429, "Too Many Requests", {}, None)))
    resp = ollama_cloud.review("P", "m", 240.0)
    assert (resp.error, resp.detail) == (base.ERR_QUOTA, "HTTP 429: Too Many Requests")


def test_a_network_failure_keeps_the_exception(monkeypatch):
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen",
                        _raise(urllib.error.URLError("getaddrinfo failed")))
    resp = ollama_cloud.review("P", "m", 240.0)
    assert resp.error == base.ERR_ERROR
    assert resp.detail == "URLError: <urlopen error getaddrinfo failed>"


def test_a_body_that_is_not_json_keeps_the_parse_error(monkeypatch):
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen",
                        lambda req, timeout: io.BytesIO(b"not json"))
    resp = ollama_cloud.review("P", "m", 240.0)
    assert resp.error == base.ERR_ERROR
    assert resp.detail.startswith("JSONDecodeError: Expecting value")


@pytest.mark.parametrize("timeout_s", [float("inf"), float("-inf"), 0.0, 1e300])
def test_an_unusable_timeout_sends_nothing(monkeypatch, timeout_s):
    """The drain's fuzzer: review() raised OverflowError on an infinite
    timeout (row c550e84b6565)."""
    sent = []
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen",
                        lambda req, timeout: sent.append(req))
    resp = ollama_cloud.review("P", "m", timeout_s)
    assert (resp.error, sent) == (base.ERR_ERROR, [])
    assert resp.detail.startswith("bad timeout: ")


def test_an_answer_has_no_detail(monkeypatch):
    ok = json.dumps({"message": {"content": '{"findings": []}'}})
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen",
                        lambda req, timeout: io.BytesIO(ok.encode("utf-8")))
    resp = ollama_cloud.review("P", "m", 240.0)
    assert (resp.error, resp.detail) == ("", "")
