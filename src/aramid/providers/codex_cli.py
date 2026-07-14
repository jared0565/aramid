"""codex-cli provider (spec section 4): one-shot `codex exec` on the user's
Codex subscription (cost_usd always 0.0). Invoked sandboxed read-only with
`-` so the prompt arrives on stdin; --json gives a JSONL event stream from
which the LAST agent_message item is the reply. The parser is deliberately
lenient (skip unparseable lines) because the event vocabulary evolves
between CLI versions -- only "no agent_message at all" is malformed."""
import json
import shutil
import sys

from aramid.providers import base, spend
from aramid.providers.base import ProviderResponse

NAME = "codex-cli"
_QUOTA_MARKERS = ("usage limit", "rate limit", "quota")


def installed() -> bool:
    return shutil.which("codex") is not None


def available(cfg) -> bool:
    return installed()


def review(prompt: str, model: str, timeout_s: float, *, effort: str = "") -> ProviderResponse:
    exe = shutil.which("codex")
    if exe is None:
        return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
    argv = [exe, "exec", "--json", "--sandbox", "read-only", "--skip-git-repo-check"]
    if model:
        argv += ["-m", model]
    if effort:
        argv += ["-c", f"model_reasoning_effort={effort}"]
    argv.append("-")
    got = base.run_provider_subprocess(argv, prompt, timeout_s)
    if got is None:
        return ProviderResponse(text="", error=base.ERR_TIMEOUT)
    rc, out, err = got
    combined = f"{out}\n{err}".lower()
    if rc != 0:
        kind = base.ERR_QUOTA if any(m in combined for m in _QUOTA_MARKERS) else base.ERR_ERROR
        return ProviderResponse(text="", error=kind)

    text, tokens_in, tokens_out = None, 0, 0
    for line in out.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            # Unparseable line - skip (lenient parsing)
            continue

        # Hardening: skip if event is not a dict (e.g., bare scalar like 5)
        if not isinstance(event, dict):
            continue

        # Check for agent_message item
        if event.get("type") == "item.completed":
            item = event.get("item")
            # Hardening: skip if item is not a dict
            if isinstance(item, dict) and item.get("type") == "agent_message":
                text = item.get("text", "")

        # Check for turn.completed with usage info
        if event.get("type") == "turn.completed":
            usage = event.get("usage")
            # Hardening: skip if usage is not a dict
            if isinstance(usage, dict):
                # Safe int conversion - wrong types zero out
                try:
                    tokens_in = int(usage.get("input_tokens", 0))
                except (ValueError, TypeError):
                    tokens_in = 0
                try:
                    tokens_out = int(usage.get("output_tokens", 0))
                except (ValueError, TypeError):
                    tokens_out = 0

    if text is None:
        return ProviderResponse(text="", error=base.ERR_MALFORMED)

    resp = ProviderResponse(text=text, tokens_in=tokens_in, tokens_out=tokens_out,
                            cost_usd=0.0)
    _log(resp, model or "default")
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
