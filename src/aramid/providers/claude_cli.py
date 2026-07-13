"""claude-cli provider (spec section 4): one-shot `claude -p` review on the
user's Claude subscription. cost_usd is ALWAYS 0.0 -- the envelope's
total_cost_usd is an estimate of what the call would have cost via API and
must not count against the OpenRouter dollar cap; quota burn is the real
currency and is visible via the logged token counts.

Quota detection is pattern-based on stderr/stdout (the CLI's usage-limit
message wording); unknown nonzero exits map to ERR_ERROR so the consumer
falls to the next provider (fail-open, spec section 6)."""
import json
import shutil
import sys

from aramid.providers import base, spend
from aramid.providers.base import ProviderResponse

NAME = "claude-cli"
_QUOTA_MARKERS = ("usage limit", "rate limit", "quota")


def installed() -> bool:
    return shutil.which("claude") is not None


def available(cfg) -> bool:
    return installed()


def review(prompt: str, model: str, timeout_s: float) -> ProviderResponse:
    exe = shutil.which("claude")
    if exe is None:
        return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
    argv = [exe, "-p", "--model", model, "--output-format", "json"]
    got = base.run_provider_subprocess(argv, prompt, timeout_s)
    if got is None:
        return ProviderResponse(text="", error=base.ERR_TIMEOUT)
    rc, out, err = got
    combined = f"{out}\n{err}".lower()
    if rc != 0:
        kind = base.ERR_QUOTA if any(m in combined for m in _QUOTA_MARKERS) else base.ERR_ERROR
        return ProviderResponse(text="", error=kind)
    try:
        envelope = json.loads(out)
        text = envelope["result"]
        usage = envelope.get("usage", {})
        usage = usage if isinstance(usage, dict) else {}
        tokens_in = int(usage.get("input_tokens", 0))
        tokens_out = int(usage.get("output_tokens", 0))
    except (ValueError, KeyError, TypeError, AttributeError):
        return ProviderResponse(text="", error=base.ERR_MALFORMED)
    resp = ProviderResponse(text=text, tokens_in=tokens_in, tokens_out=tokens_out,
                            cost_usd=0.0)
    _log(resp, model)
    return resp


def _log(resp: ProviderResponse, model: str) -> None:
    from datetime import datetime, timezone
    try:
        spend.append_spend({"at": datetime.now(timezone.utc).isoformat(),
                            "provider": NAME, "model": model,
                            "tokens_in": resp.tokens_in, "tokens_out": resp.tokens_out,
                            "cost_usd": resp.cost_usd})
    except OSError:
        pass  # observability only -- never fail a successful call over logging


base.PROVIDERS[NAME] = sys.modules[__name__]
