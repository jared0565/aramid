import io
import json

import pytest

from aramid.providers import base, openrouter, spend

RESPONSE = json.dumps({
    "choices": [{"message": {"content": '{"findings": []}'}}],
    "usage": {"prompt_tokens": 2000, "completion_tokens": 50, "cost": 0.011},
})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")


def _cfg(cap=5.0):
    from types import SimpleNamespace
    return SimpleNamespace(llm={"openrouter_monthly_cap_usd": cap})


def test_registers_in_providers():
    assert base.PROVIDERS["openrouter"] is openrouter


def test_available_requires_key(monkeypatch):
    assert openrouter.available(_cfg()) is True
    assert openrouter.installed() is True
    monkeypatch.delenv("OPENROUTER_API_KEY")
    assert openrouter.available(_cfg()) is False
    assert openrouter.installed() is False


def test_installed_true_even_at_cap():
    spend.append_spend({"at": "2026-07-13T10:00:00+00:00", "provider": "openrouter",
                        "model": "m", "tokens_in": 1, "tokens_out": 1, "cost_usd": 9.0})
    assert openrouter.installed() is True      # installed != available


def test_available_false_when_cap_reached():
    spend.append_spend({"at": "2026-07-13T10:00:00+00:00", "provider": "openrouter",
                        "model": "m", "tokens_in": 1, "tokens_out": 1, "cost_usd": 5.0})
    assert openrouter.available(_cfg(cap=5.0)) is False


def test_available_false_when_spend_unreadable(tmp_path):
    (tmp_path / "llm_spend.jsonl").write_text("CORRUPT\n", encoding="utf-8")
    # fail-closed for money (spec section 6)
    assert openrouter.available(_cfg()) is False


def test_review_posts_and_appends_spend(monkeypatch, tmp_path):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data.decode("utf-8"))
        seen["auth"] = req.get_header("Authorization")
        return io.BytesIO(RESPONSE.encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)
    resp = openrouter.review("PACKET", "anthropic/claude-sonnet-4-5", 240.0, cfg=_cfg())
    assert resp.text == '{"findings": []}'
    assert resp.cost_usd == 0.011
    assert (resp.tokens_in, resp.tokens_out) == (2000, 50)
    assert seen["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert seen["auth"] == "Bearer sk-or-test"
    assert seen["body"]["messages"][0]["content"] == "PACKET"
    assert seen["body"]["usage"] == {"include": True}
    logged = (tmp_path / "llm_spend.jsonl").read_text(encoding="utf-8")
    assert json.loads(logged)["cost_usd"] == 0.011


def test_review_refuses_when_cap_would_breach(monkeypatch):
    spend.append_spend({"at": "2026-07-13T10:00:00+00:00", "provider": "openrouter",
                        "model": "m", "tokens_in": 1, "tokens_out": 1, "cost_usd": 4.99})
    called = []
    monkeypatch.setattr(openrouter.urllib.request, "urlopen",
                        lambda *a, **k: called.append(1))
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg(cap=4.99))
    assert resp.error == base.ERR_QUOTA
    assert called == []          # never sent


def test_review_http_error_is_error(monkeypatch):
    def boom(req, timeout):
        raise OSError("connection refused")
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", boom)
    assert openrouter.review("P", "m", 240.0, cfg=_cfg()).error == base.ERR_ERROR


# Hardening tests: response shape robustness

def test_review_handles_null_usage(monkeypatch):
    """Response with null usage - text kept, tokens/cost default to 0."""
    response = json.dumps({
        "choices": [{"message": {"content": "good text"}}],
        "usage": None,  # null instead of dict
    })

    def fake_urlopen(req, timeout):
        return io.BytesIO(response.encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)

    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.text == "good text"
    assert resp.tokens_in == 0
    assert resp.tokens_out == 0
    assert resp.cost_usd == 0.0
    assert resp.error == ""


def test_review_handles_malformed_response_structure(monkeypatch):
    """Response with valid JSON but wrong structure (e.g., choices not a list)."""
    response = json.dumps({
        "choices": "not_a_list",
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "cost": 0.001},
    })

    def fake_urlopen(req, timeout):
        return io.BytesIO(response.encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)

    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == base.ERR_MALFORMED
    assert resp.text == ""


def test_review_handles_non_dict_response(monkeypatch):
    """Response is valid JSON but not a dict (e.g., a list or scalar)."""
    response = json.dumps(["not", "a", "dict"])

    def fake_urlopen(req, timeout):
        return io.BytesIO(response.encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)

    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == base.ERR_MALFORMED
    assert resp.text == ""


def test_review_handles_non_string_content(monkeypatch):
    """Response content is not a string."""
    response = json.dumps({
        "choices": [{"message": {"content": 123}}],  # int instead of str
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "cost": 0.001},
    })

    def fake_urlopen(req, timeout):
        return io.BytesIO(response.encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)

    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == base.ERR_MALFORMED
    assert resp.text == ""


def test_review_never_raises(monkeypatch):
    """review() must never raise, even on garbage input."""
    def fake_urlopen(req, timeout):
        # Return plain text, not JSON
        return io.BytesIO(b"not json at all")
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)

    # This should not raise - it should return an error response
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == base.ERR_ERROR
    assert resp.text == ""


def test_review_non_numeric_tokens_is_malformed(monkeypatch):
    """usage with non-numeric token strings: int('abc') must not raise out
    of review() -- the widened except tuple (ValueError) maps it to
    ERR_MALFORMED."""
    response = json.dumps({
        "choices": [{"message": {"content": "text"}}],
        "usage": {"prompt_tokens": "abc", "completion_tokens": 5, "cost": 0.001},
    })

    def fake_urlopen(req, timeout):
        return io.BytesIO(response.encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)

    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert isinstance(resp, base.ProviderResponse)
    assert resp.error == base.ERR_MALFORMED
    assert resp.text == ""


def test_review_error_body_without_choices_is_malformed(monkeypatch):
    """An API error body over HTTP 200 (no choices key at all) must surface
    as ERR_MALFORMED -- never a silent empty success on a PAID call."""
    response = json.dumps({
        "error": {"message": "insufficient credits", "code": 402},
    })

    def fake_urlopen(req, timeout):
        return io.BytesIO(response.encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)

    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == base.ERR_MALFORMED
    assert resp.text == ""


def test_timeout_appends_zero_cost_marker(monkeypatch, tmp_path):
    """A timed-out call may have been billed server-side: the spend log gets
    a zero-cost marker so audits see the call happened. cost_usd=0.0 means
    the cap math is unchanged."""
    def boom(req, timeout):
        raise TimeoutError()
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", boom)
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == base.ERR_TIMEOUT
    lines = (tmp_path / "llm_spend.jsonl").read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    assert rec["provider"] == "openrouter" and rec["cost_usd"] == 0.0
    assert "timeout" in rec["note"]
    assert openrouter.available(_cfg()) is True      # marker never trips the cap


def test_spend_write_failure_warns_stderr_success_path(monkeypatch, capsys):
    def fake_urlopen(req, timeout):
        return io.BytesIO(RESPONSE.encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(openrouter.spend, "append_spend",
                        lambda entry: (_ for _ in ()).throw(OSError("disk full")))
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == "" and resp.cost_usd == 0.011   # response still returned
    assert "spend log write failed" in capsys.readouterr().err


def test_spend_write_failure_warns_stderr_timeout_path(monkeypatch, capsys):
    def boom(req, timeout):
        raise TimeoutError()
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", boom)
    monkeypatch.setattr(openrouter.spend, "append_spend",
                        lambda entry: (_ for _ in ()).throw(OSError("disk full")))
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == base.ERR_TIMEOUT
    assert "spend log write failed" in capsys.readouterr().err
