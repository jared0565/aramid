"""tier -- what tier is a ledger finding RIGHT NOW, under the config in force.

The `verdict` stored on a ledger row is a snapshot: `policy.classify` computed
it at detection time and the ledger is append-only, so it never moves again.
Arming is retroactive by design and rules can be demoted, so the stored value
and the truth drift apart with nothing on the row saying so -- a consumer
auditing `ledger filter --status open` reads a frozen tier and has no way to
tell (interop rounds 80, 82, 87 section 6).

WHY THIS IS ITS OWN MODULE. It needs both `policy` and `review`, and `policy`
cannot import `review` -- `review` imports `config`, which imports `policy`,
so the edge would close a cycle. Putting it in a command module would make
every other caller import a command to ask a question about a finding. One
small module with one public function is the shape that lets `override`,
`ledger_cmd` and anything later share a single answer.

THIS IS TRUTH, AND DELIBERATELY NOT A RATCHET -- read this before merging it
with `override._is_block_tier_now`, which looks like a duplicate and is not.
That function answers the neighbouring question "may a machine-local,
gitignored suppression hide this finding", and ORs with the stored verdict so
it can only ever refuse MORE: dropping a rule from `block_rules` must never
make an already-stored BLOCK locally overridable. This function must be free
to report a LOWER tier than the row says, or it is not answering "what is the
tier now" but "what is the worst this has ever been". `override` composes the
ratchet on top of this rather than keeping a parallel copy, so there is one
implementation of the tier question and one explicit `OR` expressing the
safety margin.
"""
from aramid import policy, review
from aramid.models import Gate, Verdict


def verdict_now(cfg, rec: dict) -> Verdict:
    """The tier `rec` would be classified at today's config.

    `rec` is a materialized ledger record (`Ledger.open_findings()` values),
    not a `Finding` -- these rows are plain dicts rebuilt from event payloads.

    The LLM branch is not an optimisation, it is a correctness requirement:
    `policy.classify("llm-review", ...)` ALWAYS returns WARN, because the real
    blocking verdict for a confirmed-CRITICAL LLM finding is computed at gate
    time in `review.llm_gate_findings` from ledger state plus
    `[llm].llm_block_armed`, and is never persisted. A plain classify recompute
    would therefore report `warn` for a finding that genuinely blocks -- the
    same limb this repo has now mis-handled twice, once in `override` (fixed
    with `is_confirmed_critical_llm`) and once in a blast-radius measurement
    whose control never exercised it.

    `severity` is stored post-`_map_severity` and fed back in as `severity_raw`;
    that mapping round-trips on all five levels. PRE_PUSH is passed as the
    strictest gate -- `classify` ignores the argument entirely and policy.py's
    module docstring says why.

    Raises whatever `classify` raises. Callers decide the policy for an
    unreadable config; this function does not invent a verdict to paper over
    one, because a fabricated tier is the defect it exists to remove.
    """
    if review.is_confirmed_critical_llm(rec):
        return Verdict.BLOCK
    _, verdict = policy.classify(str(rec.get("tool", "")), str(rec.get("rule", "")),
                                  str(rec.get("severity", "")), Gate.PRE_PUSH, cfg)
    return verdict
