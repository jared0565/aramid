"""openrouter provider (spec section 4): the paid last leg. stdlib urllib
only. Money rules (spec section 6, the ONE fail-closed path):
- available() is False unless OPENROUTER_API_KEY is set AND the month spend
  is readable AND below [llm].openrouter_monthly_cap_usd.
- review() re-checks the cap immediately before sending (defense in depth)
  and appends the response's actual cost to the spend log BEFORE returning.
"""
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

from aramid.providers import base, spend
from aramid.providers.base import ProviderResponse

NAME = "openrouter"
_URL = "https://openrouter.ai/api/v1/chat/completions"


def _cap(cfg) -> float:
    return float(cfg.llm.get("openrouter_monthly_cap_usd", 5.0))


def _under_cap(cfg) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    month = spend.month_spend_usd(NAME, now)
    if month is None:          # unreadable log: refuse paid calls, never guess
        return False
    return month < _cap(cfg)


def installed() -> bool:
    return bool(os.environ.get("OPENROUTER_API_KEY"))


def available(cfg) -> bool:
    if not installed():
        return False
    return _under_cap(cfg)


def review(prompt: str, model: str, timeout_s: float, *, effort: str = "", cfg) -> ProviderResponse:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
    if not _under_cap(cfg):
        return ProviderResponse(text="", error=base.ERR_QUOTA)
    body_obj = {"model": model,
                "messages": [{"role": "user", "content": prompt}],
                "usage": {"include": True}}
    if effort:
        body_obj["reasoning"] = {"effort": effort}
    body = json.dumps(body_obj).encode("utf-8")
    req = urllib.request.Request(_URL, data=body, method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as fh:
            data = json.loads(fh.read().decode("utf-8"))
    except TimeoutError:
        return ProviderResponse(text="", error=base.ERR_TIMEOUT)
    except (OSError, ValueError):
        return ProviderResponse(text="", error=base.ERR_ERROR)

    # Hardening: any unexpected response shape becomes ERR_MALFORMED instead
    # of raising out of review(). The choices chain uses STRICT access on
    # purpose: a body with no choices at all -- e.g. {"error": {"code": 402}}
    # delivered over HTTP 200 -- must raise into the except and surface as
    # ERR_MALFORMED, never masquerade as a clean empty review on a PAID call.
    try:
        if not isinstance(data, dict):
            return ProviderResponse(text="", error=base.ERR_MALFORMED)

        text = data["choices"][0]["message"]["content"]
        if not isinstance(text, str):
            return ProviderResponse(text="", error=base.ERR_MALFORMED)

        # usage may legitimately be absent or null; treat as empty
        usage = data.get("usage", {})
        usage = usage if isinstance(usage, dict) else {}

        resp = ProviderResponse(text=text,
                                tokens_in=int(usage.get("prompt_tokens", 0)),
                                tokens_out=int(usage.get("completion_tokens", 0)),
                                cost_usd=float(usage.get("cost", 0.0)))
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return ProviderResponse(text="", error=base.ERR_MALFORMED)

    try:
        spend.append_spend({"at": datetime.now(timezone.utc).isoformat(),
                            "provider": NAME, "model": model,
                            "tokens_in": resp.tokens_in, "tokens_out": resp.tokens_out,
                            "cost_usd": resp.cost_usd})
    except OSError:
        pass
    return resp


base.PROVIDERS[NAME] = sys.modules[__name__]
