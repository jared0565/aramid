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
# Provider modules self-register into base.PROVIDERS at import time
# (base.PROVIDERS[NAME] = module), exactly like consumers self-register into
# CONSUMERS. But registration only fires if SOMETHING imports them -- and in
# production nothing did: drain.py imports its consumers, yet no code imported
# the provider modules, so PROVIDERS stayed empty, chain() returned [], and
# every drain reported "no providers installed" even with the CLIs on PATH.
# The consumer that USES the chain is the right place to pull them in.
from aramid.providers import claude_cli, codex_cli, openrouter, ollama_cloud  # noqa: F401

NAME = "llm-review"
_MALFORMED_GIVE_UP = 3

_reviews_used = 0
_refutes_used = 0


def begin_drain() -> None:
    """Reset per-drain state. Called by cmd_drain once per invocation."""
    global _reviews_used, _refutes_used
    _reviews_used = 0
    _refutes_used = 0


def _call(module, prompt: str, model: str, cfg, timeout_s: float, *, effort: str = ""):
    kwargs = {"effort": effort}
    if module.NAME == "openrouter":
        kwargs["cfg"] = cfg
    try:
        return module.review(prompt, model, timeout_s, **kwargs)
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
    global _reviews_used, _refutes_used
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
    arms = review.build_arms(cfg)
    avail = {m.NAME for m in providers_base.chain(cfg)}
    order = review.reviewer_order(arms, item.score, avail)
    if not order:
        if not _any_installed(cfg):
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="llm skipped: no providers installed")
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable")

    timeout_s = float(cfg.llm.get("call_timeout_s", 240))
    prompt = review.render_review_prompt(packet)
    tgt = review.target_arm(arms, item.score)
    resp, reviewer_arm = None, None
    for arm in order:                       # target tier first, then degrade/fallthrough
        r = _call(providers_base.PROVIDERS[arm.provider], prompt, arm.model, cfg,
                  timeout_s, effort=arm.effort)
        if r.error in ("", providers_base.ERR_MALFORMED):
            resp, reviewer_arm = r, arm
            break
        # unavailable/quota/timeout/error: fall through to the next provider
    if resp is None:
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable")
    provider = providers_base.PROVIDERS[reviewer_arm.provider]   # for the refute cross-check

    _reviews_used += 1
    cost = resp.cost_usd
    tokens_in, tokens_out = resp.tokens_in, resp.tokens_out

    candidates = None if resp.error else review.parse_review_response(resp.text)
    if candidates is None:
        return ConsumerResult(consumer=NAME, state="degraded", cost=cost,
                              note=f"malformed response from {provider.NAME}")

    verified, rejected = review.verify_findings(candidates, packet, ctx.root, item.head)

    # Trust boundary (FIX 1): `confirmed` is a privileged flag -- it is the
    # ONLY thing the pre-push ledger gate blocks on. parse_review_response
    # passes through EVERY key in the (untrusted) model JSON, so a prompt-
    # injected `"confirmed": true` on a non-critical finding would otherwise
    # ride straight into RawFinding.confirmed=True with zero refute calls.
    # Strip it here so `confirmed` can become True ONLY via apply_refute on a
    # survived CRITICAL below; everything else defaults False.
    for cand in verified:
        cand.pop("confirmed", None)

    # Pre-refute dedupe (spec section 3): never re-refute what the ledger
    # already knows, AND never refute the same fresh fingerprint twice within
    # one response (a review can surface the same (rule,file,line) more than
    # once). record_run would drop the duplicate at persist time anyway; this
    # check exists to save the refute CALL. Dedupe is fail-safe -- it only ever
    # REMOVES a candidate, so it can never mint a confirmed=True that wouldn't
    # otherwise exist.
    state = ctx.ledger.open_findings()
    seen_fids = set()
    fresh = []
    for cand in verified:
        rule = f"llm/{cand['owasp']}"
        fid = review.llm_fingerprint(rule, cand["file"], cand["line_content"])
        rec = state.get(fid)
        if rec is not None and rec.get("status") in ("open", "overridden", "historical"):
            continue
        if fid in seen_fids:      # duplicate fingerprint already queued this response
            continue
        seen_fids.add(fid)
        fresh.append((rule, cand))

    max_refutes = int(cfg.llm.get("max_refutes_per_drain", 6))
    refutes = 0
    clipped = 0
    finals = []
    for rule, cand in fresh:
        if cand["severity"] == "critical":
            if _refutes_used >= max_refutes:
                # Per-drain refute budget exhausted: do NOT spend a call. Treat
                # identically to a transport-failed refute -- ambiguity defaults
                # to refuted, so the candidate is demoted to high with
                # confirmed=False and can never block, even armed. Fail-safe:
                # the cap only ever WITHHOLDS a confirmation, never grants one.
                # Note the demotion is STICKY: this finding records as open, so
                # the next drain's fresh-vs-ledger check skips its fingerprint
                # and never re-refutes it. Under-blocking is the safe direction;
                # `refute_clipped=N` in the run note surfaces when it happened.
                clipped += 1
                cand = review.apply_refute(
                    cand, True, "refute unavailable (drain refute budget exhausted)")
            else:
                refuter_arm = review.select_refuter(arms, reviewer_arm, avail)
                rr = _call(providers_base.PROVIDERS[refuter_arm.provider],
                          review.render_refute_prompt(cand, packet), refuter_arm.model, cfg,
                          timeout_s, effort=refuter_arm.effort)
                _refutes_used += 1
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

    degraded = (f" degraded_from={tgt.tier}"
                if tgt is not None and reviewer_arm.min_score < tgt.min_score else "")
    note = (f"provider={reviewer_arm.provider} tier={reviewer_arm.tier}{degraded} "
            f"model={reviewer_arm.model} tokens_in={tokens_in} tokens_out={tokens_out} "
            f"refutes={refutes} hallucination_rejected={rejected}"
            + (f" refute_clipped={clipped}" if clipped else "")
            + (" truncated" if packet.truncated else ""))
    return ConsumerResult(consumer=NAME, state="ok", findings=raws,
                          cost=cost, note=note)


base.CONSUMERS[NAME] = sys.modules[__name__]
