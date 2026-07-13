"""llm-review consumer (spec sections 2-4): the ONLY place aramid spends
LLM tokens or dollars. Flow per queue item: assemble packet (zero tokens) ->
one review call down the provider chain -> mechanical verification ->
pre-refute dedupe against the ledger -> one cross-provider refute per fresh
CRITICAL -> RawFindings through the drain's normalize/record_run path.

Budget state is per-process: cmd_drain calls begin_drain() once per
invocation (the 4-line drain hook); consume() enforces
[llm].max_items_per_drain by returning DEGRADED ("llm budget exhausted"),
which the 2a drain already interprets as keep-queued -- the *queue holds*
decision. Items are consumed priority-descending, so the highest-risk items
always get the budget first.
"""
import sys

from aramid import review
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.models import EventType, Source
from aramid.normalizer import RawFinding
from aramid.providers import base as providers_base

NAME = "llm-review"
_MALFORMED_GIVE_UP = 3

_reviews_used = 0
_chain_cache: list | None = None


def begin_drain() -> None:
    """Reset per-drain state. Called by cmd_drain once per invocation."""
    global _reviews_used, _chain_cache
    _reviews_used = 0
    _chain_cache = None


def _chain(cfg) -> list:
    global _chain_cache
    if _chain_cache is None:
        _chain_cache = providers_base.chain(cfg)
    return _chain_cache


def _model_for(module, cfg) -> str:
    return {"claude-cli": cfg.llm.get("model_claude", "sonnet"),
            "codex-cli": cfg.llm.get("model_codex", ""),
            "openrouter": cfg.llm.get("model_openrouter", "")}.get(module.NAME, "")


def _call(module, prompt: str, cfg, timeout_s: float):
    kwargs = {"cfg": cfg} if module.NAME == "openrouter" else {}
    try:
        return module.review(prompt, _model_for(module, cfg), timeout_s, **kwargs)
    except Exception:
        return providers_base.ProviderResponse(text="", error=providers_base.ERR_ERROR)


def _malformed_attempts(ledger, item_id: str) -> int:
    n = 0
    for e in ledger.events():
        if (e.type is EventType.CONSUMER_RUN_FINISHED
                and e.payload.get("consumer") == NAME
                and e.payload.get("item_id") == item_id
                and str(e.payload.get("note", "")).startswith("malformed response")):
            n += 1
    return n


def _any_installed(cfg) -> bool:
    for name in cfg.llm.get("provider_order", []):
        module = providers_base.PROVIDERS.get(name)
        if module is None:
            continue
        try:
            if module.installed():
                return True
        except Exception:
            continue
    return False


def consume(item, ctx: DrainContext) -> ConsumerResult:
    global _reviews_used
    cfg = ctx.cfg
    if cfg is None or not cfg.llm.get("enabled", True):
        return ConsumerResult(consumer=NAME, state="ok", note="llm disabled")
    max_items = int(cfg.llm.get("max_items_per_drain", 3))
    if _reviews_used >= max_items:
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="llm budget exhausted")
    if _malformed_attempts(ctx.ledger, item.id) >= _MALFORMED_GIVE_UP:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="llm giving up: repeated malformed output")
    packet = review.build_packet(ctx.root, cfg, item)
    if packet is None:
        return ConsumerResult(consumer=NAME, state="ok", note="empty packet")
    chain = _chain(cfg)
    if not chain:
        if not _any_installed(cfg):
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="llm skipped: no providers installed")
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable")

    timeout_s = float(cfg.llm.get("call_timeout_s", 240))
    prompt = review.render_review_prompt(packet)
    resp, provider = None, None
    for module in chain:
        r = _call(module, prompt, cfg, timeout_s)
        if r.error in ("", providers_base.ERR_MALFORMED):
            resp, provider = r, module
            break                    # call spent (or clean) -- stop the chain
        # unavailable/quota/timeout/error: fall through to the next provider
    if resp is None:
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable")

    _reviews_used += 1
    cost = resp.cost_usd
    tokens_in, tokens_out = resp.tokens_in, resp.tokens_out

    candidates = None if resp.error else review.parse_review_response(resp.text)
    if candidates is None:
        return ConsumerResult(consumer=NAME, state="degraded", cost=cost,
                              note=f"malformed response from {provider.NAME}")

    verified, rejected = review.verify_findings(candidates, packet, ctx.root, item.head)

    # Pre-refute dedupe (spec section 3): never re-refute what the ledger
    # already knows. record_run would drop the duplicate anyway; this check
    # exists to save the refute CALL, not the event.
    state = ctx.ledger.open_findings()
    fresh = []
    for cand in verified:
        rule = f"llm/{cand['owasp']}"
        fid = review.llm_fingerprint(rule, cand["file"], cand["line_content"])
        rec = state.get(fid)
        if rec is not None and rec.get("status") in ("open", "overridden", "historical"):
            continue
        fresh.append((rule, cand))

    refutes = 0
    finals = []
    for rule, cand in fresh:
        if cand["severity"] == "critical":
            refuter = next((m for m in chain if m.NAME != provider.NAME), provider)
            rr = _call(refuter, review.render_refute_prompt(cand, packet), cfg, timeout_s)
            refutes += 1
            cost += rr.cost_usd
            tokens_in += rr.tokens_in
            tokens_out += rr.tokens_out
            parsed = review.parse_refute_response(rr.text) if not rr.error else None
            if parsed is None:      # transport failure OR malformed refute:
                parsed = (True, f"refute unavailable ({rr.error or 'malformed'})")
            cand = review.apply_refute(cand, *parsed)
        finals.append((rule, cand))

    raws = [RawFinding(
        tool=NAME, rule=rule, severity_raw=cand["severity"],
        file=cand["file"], line=cand["line"],
        message=f"{cand['title']}: {cand.get('explanation', '')} "
                f"(fix: {cand.get('fix_hint', 'n/a')})",
        evidence=cand["evidence"], source=Source.LLM,
        confirmed=bool(cand.get("confirmed", False)),
    ) for rule, cand in finals]

    note = (f"provider={provider.NAME} tokens_in={tokens_in} tokens_out={tokens_out} "
            f"refutes={refutes} hallucination_rejected={rejected}"
            + (" truncated" if packet.truncated else ""))
    return ConsumerResult(consumer=NAME, state="ok", findings=raws,
                          cost=cost, note=note)


base.CONSUMERS[NAME] = sys.modules[__name__]
