"""openrouter keeps why a call failed in `detail` (operator decision
2026-10-30). Before this, every HTTP status read as a bare `error`: the
provider had no HTTPError branch at all. The error code and the spend log are
unchanged."""
import io
import json
import urllib.error
from types import SimpleNamespace

import pytest

from aramid.providers import base, openrouter, spend


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")


def _cfg():
    return SimpleNamespace(llm={"openrouter_monthly_cap_usd": 5.0})


def _raise(exc):
    def boom(req, timeout):
        raise exc
    return boom


def test_an_http_error_keeps_the_status_and_the_message(monkeypatch, tmp_path):
    body = io.BytesIO(json.dumps({"error": {"code": 402,
                                            "message": "Insufficient credits"}}).encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen",
                        _raise(urllib.error.HTTPError("u", 402, "Payment Required", {}, body)))
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert (resp.error, resp.detail) == (base.ERR_ERROR, "HTTP 402: Insufficient credits")
    assert not (tmp_path / "llm_spend.jsonl").exists(), "a refused call is not spend"


def test_a_network_failure_keeps_the_exception(monkeypatch):
    monkeypatch.setattr(openrouter.urllib.request, "urlopen",
                        _raise(ConnectionResetError("reset by peer")))
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert (resp.error, resp.detail) == (base.ERR_ERROR, "ConnectionResetError: reset by peer")


def test_an_answer_has_no_detail(monkeypatch):
    ok = json.dumps({"choices": [{"message": {"content": '{"findings": []}'}}]})
    monkeypatch.setattr(openrouter.urllib.request, "urlopen",
                        lambda req, timeout: io.BytesIO(ok.encode("utf-8")))
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert (resp.error, resp.detail) == ("", "")
