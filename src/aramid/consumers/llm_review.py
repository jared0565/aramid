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
import time

from aramid import review
from aramid import autolearn
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
_audits_used = 0


def begin_drain() -> None:
    """Reset per-drain state. Called by cmd_drain once per invocation."""
    global _reviews_used, _refutes_used, _audits_used
    _reviews_used = 0
    _refutes_used = 0
    _audits_used = 0


def _call(module, prompt: str, model: str, cfg, timeout_s: float, *, effort: str = ""):
    """Returns (ProviderResponse, latency_s)."""
    kwargs = {"effort": effort}
    if module.NAME == "openrouter":
        kwargs["cfg"] = cfg
    started = time.monotonic()
    try:
        resp = module.review(prompt, model, timeout_s, **kwargs)
    except Exception:
        resp = providers_base.ProviderResponse(text="", error=providers_base.ERR_ERROR)
    return resp, round(time.monotonic() - started, 3)


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


def _selection(tgt, reviewer_arm, bucket, attempts, uplift_info, cascade_info,
               audit_info, refute_infos, rejected, tokens_in, tokens_out):
    """The structured telemetry payload (autolearn spec section 6), merged
    into the CONSUMER_RUN_FINISHED event via ConsumerResult.extra.
    `bucket` is required by the rollup's posterior key; `target_tier` doubles
    as the band."""
    return {
        "target_tier": tgt.tier if tgt is not None else None,
        "bucket": bucket,
        "served": {"tier": reviewer_arm.tier, "provider": reviewer_arm.provider,
                   "model": reviewer_arm.model, "effort": reviewer_arm.effort},
        "attempts": attempts,
        "uplift": uplift_info,
        "cascade": cascade_info,
        "audit": audit_info,
        "refutes": refute_infos,
        "hallucination_rejected": rejected,
        "tokens": {"in": tokens_in, "out": tokens_out},
    }


def consume(item, ctx: DrainContext) -> ConsumerResult:
    global _reviews_used, _refutes_used, _audits_used
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

    # --- auto-learn uplift consult (autolearn spec section 8.2). Shadow
    # records the pick without changing eff_score; armed application is
    # Task 7. Fail-open: any policy failure -> deterministic ladder,
    # mode="error" on record, never a crashed drain (spec section 11).
    al_cfg = cfg.llm.get("autolearn", {})
    if not isinstance(al_cfg, dict):
        al_cfg = {}
    al_enabled = bool(al_cfg.get("enabled", True))
    al_armed = bool(al_cfg.get("armed", False))
    tgt = review.target_arm(arms, item.score)
    bucket = autolearn.bucket_for(item.reasons)
    uplift_info = {"mode": "off", "pick": None, "applied": False,
                   "sampled_q": None}
    eff_score = item.score
    if al_enabled and tgt is not None:
        try:
            st = autolearn.load_state()
            picked = autolearn.uplift_pick(
                arms, item.score, bucket, st,
                float(al_cfg.get("uplift_threshold", 0.15)),
                autolearn.decision_rng(item.id, st))
            if picked is not None:
                arm_pick, floor_q = picked
                uplift_info = {"mode": "armed" if al_armed else "shadow",
                               "pick": arm_pick.tier, "applied": False,
                               "sampled_q": round(floor_q, 4)}
                if al_armed and arm_pick.min_score > tgt.min_score:
                    eff_score = arm_pick.min_score   # escalate-only: floor raised, never lowered
                    uplift_info["applied"] = True
        except Exception:
            uplift_info = {"mode": "error", "pick": None, "applied": False,
                           "sampled_q": None}

    order = review.reviewer_order(arms, eff_score, avail)
    if not order:
        if not _any_installed(cfg):
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="llm skipped: no providers installed")
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable")

    timeout_s = float(cfg.llm.get("call_timeout_s", 240))
    prompt = review.render_review_prompt(packet)
    resp, reviewer_arm = None, None
    attempts = []
    for arm in order:                       # target tier first, then degrade/fallthrough
        r, lat = _call(providers_base.PROVIDERS[arm.provider], prompt, arm.model,
                       cfg, timeout_s, effort=arm.effort)
        attempts.append({"tier": arm.tier, "provider": arm.provider,
                         "model": arm.model, "error": r.error,
                         "latency_s": lat})
        if r.error in ("", providers_base.ERR_MALFORMED):
            resp, reviewer_arm = r, arm
            break
        # unavailable/quota/timeout/error: fall through to the next provider
    if resp is None:
        # Failed arms still leave their trace (autolearn spec section 6):
        # keep attempts + the shadow decision even on total outage.
        sel = {
            "target_tier": tgt.tier if tgt is not None else None,
            "bucket": bucket,
            "served": None,
            "attempts": attempts,
            "uplift": uplift_info,
            "cascade": {"triggered": False, "trigger": None, "applied": False},
            "audit": None,
            "refutes": [],
            "hallucination_rejected": 0,
            "tokens": {"in": 0, "out": 0},
        }
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable",
                              extra={"selection": sel})
    provider = providers_base.PROVIDERS[reviewer_arm.provider]   # for the refute cross-check

    _reviews_used += 1
    cost = resp.cost_usd
    tokens_in, tokens_out = resp.tokens_in, resp.tokens_out

    candidates = None if resp.error else review.parse_review_response(resp.text)
    if candidates is None:
        sel = _selection(tgt, reviewer_arm, bucket, attempts, uplift_info,
                         {"triggered": False, "trigger": None, "applied": False},
                         None, [], 0, tokens_in, tokens_out)
        sel["malformed"] = True
        return ConsumerResult(consumer=NAME, state="degraded", cost=cost,
                              note=f"malformed response from {provider.NAME}",
                              extra={"selection": sel})

    verified, rejected = review.verify_findings(candidates, packet, ctx.root, item.head)

    # --- cascade (autolearn spec section 9): armed-only re-review by the
    # next-higher arm on danger signs; candidate union feeds the SAME
    # downstream confirmed-strip/dedupe/refute pass. Consumes a normal
    # review slot; budget exhausted -> skip (fail-safe).
    cascade_info = {"triggered": False, "trigger": None, "applied": False}
    if al_enabled and tgt is not None:
        try:
            trig = autolearn.cascade_trigger(
                reviewer_arm, arms, verified, rejected, packet.truncated,
                int(al_cfg.get("cascade_hallucination_min", 3)))
        except Exception:
            trig = None
        if trig is not None:
            cascade_info["triggered"] = True
            cascade_info["trigger"] = trig
            if al_armed and _reviews_used < max_items:
                up_arm = autolearn.next_arm_above(arms, reviewer_arm)
                if up_arm is not None and up_arm.provider in avail:
                    r2, lat2 = _call(providers_base.PROVIDERS[up_arm.provider],
                                     prompt, up_arm.model, cfg, timeout_s,
                                     effort=up_arm.effort)
                    attempts.append({"tier": up_arm.tier,
                                     "provider": up_arm.provider,
                                     "model": up_arm.model, "error": r2.error,
                                     "latency_s": lat2})
                    c2 = None if r2.error else review.parse_review_response(r2.text)
                    if c2 is not None:
                        _reviews_used += 1
                        cost += r2.cost_usd
                        tokens_in += r2.tokens_in
                        tokens_out += r2.tokens_out
                        v2, _rej2 = review.verify_findings(c2, packet,
                                                           ctx.root, item.head)
                        verified = verified + v2
                        cascade_info["applied"] = True

    # --- audit sampling (autolearn spec section 10): the data engine --
    # active in shadow AND armed. One frontier double-review for a hash-
    # sampled below-frontier item; the diff measures what the served arm
    # missed; audit findings are REAL and join the same downstream pass.
    # Own cap (_audits_used), never counted against the review budget.
    audit_info = None
    if al_enabled and tgt is not None:
        try:
            do_audit = (_audits_used < int(al_cfg.get("max_audits_per_drain", 1))
                        and autolearn.should_audit(
                            item.id, reviewer_arm, arms,
                            int(al_cfg.get("audit_every", 8))))
            aud_arm = autolearn.audit_arm(arms, avail) if do_audit else None
            if aud_arm is not None and aud_arm != reviewer_arm:
                ra, lata = _call(providers_base.PROVIDERS[aud_arm.provider],
                                 prompt, aud_arm.model, cfg, timeout_s,
                                 effort=aud_arm.effort)
                attempts.append({"tier": aud_arm.tier,
                                 "provider": aud_arm.provider,
                                 "model": aud_arm.model, "error": ra.error,
                                 "latency_s": lata})
                _audits_used += 1
                ca = None if ra.error else review.parse_review_response(ra.text)
                if ca is not None:
                    cost += ra.cost_usd
                    tokens_in += ra.tokens_in
                    tokens_out += ra.tokens_out
                    va, _reja = review.verify_findings(ca, packet,
                                                       ctx.root, item.head)
                    new_n, missed_n = autolearn.audit_diff(verified, va)
                    audit_info = {"performed": True, "tier": aud_arm.tier,
                                  "new_findings": new_n,
                                  "missed_criticals": missed_n}
                    verified = verified + va
                else:
                    audit_info = {"performed": False, "tier": aud_arm.tier,
                                  "new_findings": 0, "missed_criticals": 0}
        except Exception:
            audit_info = None

    # Trust boundary (FIX 1): `confirmed` is a privileged flag -- it is the
    # ONLY thing the pre-push ledger gate blocks on. parse_review_response
    # passes through EVERY key in the (untrusted) model JSON, so a prompt-
    # injected `"confirmed": true` on a non-critical finding would otherwise
    # ride straight into RawFinding.confirmed=True with zero refute calls.
    # Strip it here so `confirmed` can become True ONLY via apply_refute on a
    # survived CRITICAL below; everything else defaults False.
    for cand in verified:
        cand.pop("confirmed", None)
        # Same trust boundary for the autolearn telemetry marker: `refuted`
        # may only be minted by apply_refute, never by the model JSON.
        cand.pop("refuted", None)

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
    refute_infos = []
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
                refute_infos.append({"refuter_provider": None,
                                     "refuter_tier": None,
                                     "outcome": "unavailable",
                                     "latency_s": 0.0})
                clipped += 1
                cand = review.apply_refute(
                    cand, True, "refute unavailable (drain refute budget exhausted)")
            else:
                refuter_arm = review.select_refuter(arms, reviewer_arm, avail)
                rr, rlat = _call(providers_base.PROVIDERS[refuter_arm.provider],
                                 review.render_refute_prompt(cand, packet),
                                 refuter_arm.model, cfg,
                                 timeout_s, effort=refuter_arm.effort)
                _refutes_used += 1
                refutes += 1
                cost += rr.cost_usd
                tokens_in += rr.tokens_in
                tokens_out += rr.tokens_out
                parsed = review.parse_refute_response(rr.text) if not rr.error else None
                refute_infos.append({
                    "refuter_provider": refuter_arm.provider,
                    "refuter_tier": refuter_arm.tier,
                    "outcome": ("unavailable" if parsed is None
                                else ("refuted" if parsed[0] else "survived")),
                    "latency_s": rlat})
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
        refuted=bool(cand.get("refuted", False)),
    ) for rule, cand in finals]

    degraded = (f" degraded_from={tgt.tier}"
                if tgt is not None and reviewer_arm.min_score < tgt.min_score else "")
    note = (f"provider={reviewer_arm.provider} tier={reviewer_arm.tier}{degraded} "
            f"model={reviewer_arm.model} tokens_in={tokens_in} tokens_out={tokens_out} "
            f"refutes={refutes} hallucination_rejected={rejected}"
            + (f" refute_clipped={clipped}" if clipped else "")
            + (" truncated" if packet.truncated else ""))
    sel = _selection(tgt, reviewer_arm, bucket, attempts, uplift_info,
                     cascade_info, audit_info, refute_infos, rejected,
                     tokens_in, tokens_out)
    return ConsumerResult(consumer=NAME, state="ok", findings=raws,
                          cost=cost, note=note, extra={"selection": sel})


base.CONSUMERS[NAME] = sys.modules[__name__]
