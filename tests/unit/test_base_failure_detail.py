"""providers.base.failure_detail: the one line an attempt keeps about why a
provider call failed (operator decision 2026-10-30). Until then a failed call
was recorded as a bare `error`, and two retired models read as a four-day
outage: ollama answered HTTP 410 "retired on September 25, 2026" and codex
exited 1, and neither reason was kept anywhere."""
import io
import json
import urllib.error

from aramid.providers import base

# Built at runtime: a literal of these shapes would be a finding of this
# repo's own secret scan.
_GH_TOKEN = "ghp_" + "Ab3" * 12
_SK_TOKEN = "sk-" + "x9Y" * 8


def test_the_head_alone_when_there_is_no_text():
    assert base.failure_detail("HTTP 410") == "HTTP 410"
    assert base.failure_detail("exit 1", "  \n \n") == "exit 1"


def test_the_text_becomes_one_line_after_the_head():
    assert base.failure_detail("exit 1", "model\n   not   found\t") == "exit 1: model not found"


def test_it_is_cut_to_the_limit():
    got = base.failure_detail("exit 1", "x" * 500)
    assert base.DETAIL_MAX == 200
    assert len(got) == 200 and got.startswith("exit 1: xxx")


def test_the_provider_keys_in_the_environment_are_masked(monkeypatch):
    ollama_key = "olk" + "7Qz" * 10
    router_key = "ork" + "4Wm" * 10
    monkeypatch.setenv("OLLAMA_API_KEY", ollama_key)
    monkeypatch.setenv("OPENROUTER_API_KEY", router_key)
    got = base.failure_detail("HTTP 401", f"bad key {ollama_key} or {router_key}")
    assert ollama_key not in got and router_key not in got
    assert got.startswith("HTTP 401: bad key ")


def test_secret_shaped_values_are_masked(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    got = base.failure_detail("exit 1", f"rejected {_GH_TOKEN} and {_SK_TOKEN}")
    assert _GH_TOKEN not in got and _SK_TOKEN not in got
    assert got == "exit 1: rejected [REDACTED] and [REDACTED]"


def test_a_key_is_masked_before_the_cut(monkeypatch):
    """Masking after the cut would leave the front of a key that straddles
    the limit."""
    key = "olk" + "7Qz" * 10
    monkeypatch.setenv("OLLAMA_API_KEY", key)
    got = base.failure_detail("exit 1", "y" * 180 + key)
    assert key[:12] not in got


def test_a_key_too_short_to_be_one_does_not_mangle_the_text(monkeypatch):
    """A one-letter value in OLLAMA_API_KEY would otherwise replace that
    letter everywhere in the line."""
    monkeypatch.setenv("OLLAMA_API_KEY", "e")
    assert base.failure_detail("exit 1", "model not found") == "exit 1: model not found"


def test_model_names_survive_the_masking():
    """A masker that ate model names would hide the very thing a retired
    model's error is about."""
    text = "deepseek-v4-flash minimax-m3.1-flash gpt-6.1-sol claude-opus-5-5"
    assert base.failure_detail("HTTP 410", text) == f"HTTP 410: {text}"


def test_last_line_is_the_last_line_with_text():
    assert base.last_line("first\nsecond\n\n  \n") == "second"
    assert base.last_line("") == ""


def _http_error(code, body):
    fp = io.BytesIO(body.encode("utf-8")) if body is not None else None
    return urllib.error.HTTPError("https://example.invalid", code, "the reason", {}, fp)


def test_an_http_error_keeps_the_status_and_the_json_error():
    body = json.dumps({"error": "deepseek-v4-flash:0731 was retired on September 25, 2026. "
                                "Try glm-5.3-flash:cloud."})
    assert base.http_detail(_http_error(410, body)) == (
        "HTTP 410: deepseek-v4-flash:0731 was retired on September 25, 2026. "
        "Try glm-5.3-flash:cloud.")


def test_an_http_error_reads_a_nested_error_message():
    body = json.dumps({"error": {"code": 402, "message": "Insufficient credits"}})
    assert base.http_detail(_http_error(402, body)) == "HTTP 402: Insufficient credits"


def test_an_http_error_without_json_keeps_the_body_on_one_line():
    assert base.http_detail(_http_error(502, "<html>\nBad Gateway\n</html>")) == \
        "HTTP 502: <html> Bad Gateway </html>"


def test_an_http_error_whose_body_cannot_be_read_keeps_the_reason():
    class _Unreadable(urllib.error.HTTPError):
        def read(self, *a):
            raise ConnectionResetError("reset while reading the body")
    exc = _Unreadable("https://example.invalid", 500, "Internal Server Error", {}, None)
    assert base.http_detail(exc) == "HTTP 500: Internal Server Error"


def test_an_http_error_with_no_body_keeps_the_reason():
    assert base.http_detail(_http_error(429, None)) == "HTTP 429: the reason"
    assert base.http_detail(_http_error(503, "")) == "HTTP 503: the reason"
