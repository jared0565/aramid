"""llm_review._call hands `cfg` to openrouter alone: it is the one provider
whose review() takes it (the cap check), and the CLI providers' review() does
not accept it. The drain of 2026-10-30 15:00Z left `module.NAME ==
"openrouter"` -> `!=` alive (row a068e7dfeb40): every unit test reached
`_call` through fakes that take any keyword."""
from types import SimpleNamespace

from aramid.consumers import llm_review
from aramid.providers.base import ProviderResponse

CFG = SimpleNamespace(llm={})


def _openrouter():
    seen = {}

    def review(prompt, model, timeout_s, *, effort="", cfg):
        seen["cfg"] = cfg
        return ProviderResponse(text="ok")
    return SimpleNamespace(NAME="openrouter", review=review), seen


def _cli(name):
    def review(prompt, model, timeout_s, *, effort=""):
        return ProviderResponse(text="ok")
    return SimpleNamespace(NAME=name, review=review)


def test_openrouter_is_handed_the_config():
    module, seen = _openrouter()
    resp, _ = llm_review._call(module, "P", "m", CFG, 240.0)
    assert (resp.error, resp.text) == ("", "ok")
    assert seen["cfg"] is CFG


def test_the_cli_providers_are_not():
    for name in ("codex-cli", "claude-cli", "ollama-cloud"):
        resp, _ = llm_review._call(_cli(name), "P", "m", CFG, 240.0)
        assert (resp.error, resp.detail) == ("", ""), name
