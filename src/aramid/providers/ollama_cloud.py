"""ollama-cloud provider (2026-07-14 model-selection spec): the direct Ollama
Cloud HTTP API on the user's Ollama Cloud subscription. stdlib urllib only.
Flat-rate: cost_usd is ALWAYS 0.0 (no OpenRouter-style money cap). Per the
model-source policy this is a dev-time provider; OpenRouter is in-app only.

HTTPError (a subclass of OSError) is caught BEFORE the generic OSError branch
so a 429 maps to ERR_QUOTA and 401/403 to ERR_UNAVAILABLE, matching the CLI
providers' quota semantics; every other failure is ERR_ERROR, and any
unexpected body shape is ERR_MALFORMED (never a silent empty review)."""
import json
import os
import sys
import urllib.error
import urllib.request

from aramid.providers import base
from aramid.providers.base import ProviderResponse

NAME = "ollama-cloud"
_URL = "https://ollama.com/api/chat"


def installed() -> bool:
    return bool(os.environ.get("OLLAMA_API_KEY"))


def available(cfg) -> bool:
    return installed()


def review(prompt: str, model: str, timeout_s: float, *, effort: str = "") -> ProviderResponse:
    key = os.environ.get("OLLAMA_API_KEY")
    if not key:
        return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
    payload = {"model": model,
               "messages": [{"role": "user", "content": prompt}],
               "stream": False}
    if effort:
        payload["think"] = True
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(_URL, data=body, method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as fh:
            data = json.loads(fh.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            return ProviderResponse(text="", error=base.ERR_QUOTA)
        if exc.code in (401, 403):
            return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
        return ProviderResponse(text="", error=base.ERR_ERROR)
    except TimeoutError:
        return ProviderResponse(text="", error=base.ERR_TIMEOUT)
    except (OSError, ValueError):
        return ProviderResponse(text="", error=base.ERR_ERROR)

    try:
        if not isinstance(data, dict):
            return ProviderResponse(text="", error=base.ERR_MALFORMED)
        text = data["message"]["content"]
        if not isinstance(text, str):
            return ProviderResponse(text="", error=base.ERR_MALFORMED)
        tokens_in = int(data.get("prompt_eval_count", 0) or 0)
        tokens_out = int(data.get("eval_count", 0) or 0)
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return ProviderResponse(text="", error=base.ERR_MALFORMED)

    resp = ProviderResponse(text=text, tokens_in=tokens_in, tokens_out=tokens_out,
                            cost_usd=0.0)
    _log(resp, model)
    return resp


def _log(resp: ProviderResponse, model: str) -> None:
    from datetime import datetime, timezone
    from aramid.providers import spend
    try:
        spend.append_spend({"at": datetime.now(timezone.utc).isoformat(),
                            "provider": NAME, "model": model,
                            "tokens_in": resp.tokens_in, "tokens_out": resp.tokens_out,
                            "cost_usd": resp.cost_usd})
    except OSError:
        pass  # observability only -- never fail a successful call over logging


base.PROVIDERS[NAME] = sys.modules[__name__]
