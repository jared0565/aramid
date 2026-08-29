"""override -- ledger-logged WARN suppression (design doc section 6, "two
tiers"). A BLOCK-tier finding cannot be suppressed here at all: enforcement
requires a reviewed, committed entry in `.aramid-suppressions.toml`
instead, visible in diff review with a reason -- this command actively
refuses and says so rather than silently no-op'ing.

The tiers constrain THIS CHANNEL, not that file. `.aramid/` is gitignored, so
a ledger override is a machine-local, unreviewable decision and is WARN-only
for that reason. The committed file is tier-AGNOSTIC (section 6 amendment,
2026-08-09) -- it accepts a reasoned WARN entry as readily as a BLOCK one, and
carrying the whole judgement there is how it reaches a teammate at all. So the
refusal below is a redirect to a channel that is strictly more capable, not a
dead end; it prints the ready-to-paste entry because the `id` is an opaque
content fingerprint and is the one field an operator cannot retype.

LLM confirmed-critical findings are ALSO BLOCK-tier for this purpose (the
whole-branch adversarial review's must-fix; the parallel fix to check.py's
`_has_genuine_block`, task 13b, closed the same gap for the fresh-ledger
ratchet path but this command never got it). The ledger's STORED verdict
for an LLM finding is ALWAYS "warn" --
`policy.classify("llm-review", ...)` always returns WARN at drain time; the
real BLOCK verdict for a confirmed-critical LLM finding is computed only at
gate time in `review.llm_gate_findings` (from ledger state +
`[llm].llm_block_armed`) and is never persisted. So `rec["verdict"] ==
"block"` alone can never see an LLM finding as BLOCK-tier -- checking only
that would let `aramid override <id>` succeed on an armed+confirmed+critical
LLM finding, flip its status to "overridden", and then have both
`auto_resolve_llm` and `llm_gate_findings` skip it (they require
status=="open") -- permanently and silently defeating the block with no
reviewable artifact (`.aramid/` is gitignored). The refusal below therefore
also fires whenever `source=="llm"` and `confirmed` and `severity==
"critical"`, INDEPENDENT of `[llm].llm_block_armed` -- arming is retroactive
by design, so conditioning the refusal on armed state would let an operator
override the finding while disarmed (gate only WARNs, so the refusal
wouldn't fire) and then arm later, defeating arming after the fact. A
WARN-tier LLM finding (unconfirmed, or confirmed but below critical) is NOT
refused -- it keeps using this legitimate light override path.
"""
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import review, tier
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Verdict


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_TOML_ESCAPES = {"\\": "\\\\", '"': '\\"', "\b": "\\b", "\t": "\\t",
                 "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _toml_str(value: str) -> str:
    """A TOML basic string. `--reason` is free user text pasted straight into
    generated TOML, so a quote or a Windows path's backslash would otherwise
    emit a snippet that fails to parse -- or parses into something other than
    what the operator typed. Remaining control characters are illegal in a
    basic string and go out as \\uXXXX."""
    out = []
    for ch in value:
        if ch in _TOML_ESCAPES:
            out.append(_TOML_ESCAPES[ch])
        elif ch < "\x20" or ch == "\x7f":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _suppression_snippet(finding_id: str, rec: dict, reason: str) -> str:
    """The entry the operator is being told to write. Emitted in full because
    `id` is an opaque content fingerprint -- the one field nobody can retype,
    and the one that makes the difference between a suppression that binds and
    a stale near-miss the gate re-fires. `reason` is mandatory in
    load_suppressions: an entry missing it is DROPPED and suppresses nothing,
    so carrying the already-supplied --reason through keeps the paste
    fail-safe rather than fail-silent."""
    return (
        "[[suppress]]\n"
        f"id = {_toml_str(finding_id)}\n"
        f"tool = {_toml_str(str(rec.get('tool', '')))}\n"
        f"rule = {_toml_str(str(rec.get('rule', '')))}\n"
        f"path = {_toml_str(str(rec.get('file', '')))}\n"
        f"reason = {_toml_str(reason)}\n"
    )


def _is_block_tier_now(cfg, rec: dict) -> bool:
    """Is this finding BLOCK-tier under the config in force RIGHT NOW?

    `rec["verdict"]` is a snapshot, not a property of the finding:
    `policy.classify` computed it when the finding was detected and the ledger
    is append-only, so it never moves again. Every armable tool therefore
    stores "warn" for findings drained while its `*_block_armed` flag was
    false -- and arming is retroactive by design, so those findings ARE
    BLOCK-tier afterwards while the row still reads "warn". Trusting the row
    let `aramid override` grant a machine-local, gitignored suppression of a
    live BLOCK finding. For mutation that is terminal rather than merely
    misleading: `mutation_gate.mutation_gate_findings` skips any rec whose
    status is not "open", so the armed BLOCK never surfaces again. That is the
    defeat the LLM branch below was added to prevent, reached through the one
    door it does not cover -- LLM findings got `is_confirmed_critical_llm`
    precisely BECAUSE their stored verdict is always "warn"; mutation, tdd and
    red-proof have no such guard and the stored value is their only signal.

    ORed with the stored verdict rather than replacing it, so this can only
    ever refuse MORE. Recomputing alone would also WIDEN the command --
    dropping a rule from `block_rules` would make its already-stored BLOCK
    findings locally overridable -- and widening what a gitignored file may
    hide is the one direction this command must never move.

    Delegates the tier question to `tier.verdict_now` rather than calling
    `policy.classify` itself. That module is the single implementation of "what
    tier is this finding now", shared with `ledger`'s read surfaces -- two
    implementations of one question drift, and this repo has paid for that
    lesson more than once.

    WHAT IS *NOT* SHARED IS THE RATCHET, and it is the whole reason this
    wrapper still exists. `tier.verdict_now` reports TRUTH and may answer WARN
    for a row stored `block` (a demoted rule, a disarmed tool). The caller ORs
    this with the stored verdict precisely so this command can only ever refuse
    MORE. Do not "simplify" the call site to `verdict_now(...) is BLOCK`:
    `test_a_stored_block_stays_refused_even_when_its_rule_no_longer_blocks`
    goes red if you do, and the defect it describes is a gitignored file
    silently gaining the power to hide a finding that used to block.

    Failure REFUSES. An earlier draft of this function caught everything and
    returned False, on the reasoning that it "degrades to today's behaviour" --
    which is wrong in the way that matters: it degrades to today's BUG, on a
    path the person wanting the override controls. `aramid.toml` is an ordinary
    writable repo file, so one malformed line makes `load_config` raise, this
    check answer False, and the frozen "warn" become the only gate again. That
    is a documented switch for turning the fix off. An unclassifiable record is
    one we cannot prove is WARN-tier, and a stored "warn" is exactly what this
    function exists not to trust. Refusing costs a legitimate override an error
    message; permitting costs a silently defeated BLOCK.
    """
    try:
        return tier.verdict_now(cfg, rec) is Verdict.BLOCK
    except Exception:
        return True


_CAUSE_TEXT = {
    "recorded_disarmed": "recorded as made while the class was disarmed",
    "arming_state_unrecorded": "arming state was not recorded when they were made",
}


def render_invalidations(invalidated: list[dict]) -> str:
    """The operator-facing notice, broken down BY CAUSE rather than summed.

    "your overrides were invalidated" and "2 override(s) invalidated by
    arming: arming state was not recorded when they were made" are different
    messages, and the difference is whether the reader re-adjudicates or goes
    looking for a bug in aramid. The count and the cause are the two facts
    that decide which (interop round 89).

    Returns "" for an empty sweep so the caller prints nothing at all -- a
    "0 overrides invalidated" line on every gate run is noise that trains
    people to skip the whole notice.
    """
    if not invalidated:
        return ""
    counts: dict[str, int] = {}
    for item in invalidated:
        counts[item["cause"]] = counts.get(item["cause"], 0) + 1
    lines = [f"aramid: check: {len(invalidated)} override(s) invalidated by arming "
             f"-- reopened for re-adjudication:"]
    for cause, count in sorted(counts.items()):
        lines.append(f"aramid: check:   {count} -- {_CAUSE_TEXT.get(cause, cause)}")
    return "\n".join(lines)


def invalidate_stale_overrides(ledger, cfg, *, run_id: str, at: str) -> list[dict]:
    """Revoke overrides that arming has moved out from under, and return what
    was revoked as [{"id", "cause"}] so the caller can report count AND cause.

    Called at GATE START, never from the detection path. Every armed tool's
    gate skips findings whose status is not "open"
    (`mutation_gate.mutation_gate_findings` is the sharpest case), so an
    invalidation that waited for the finding to re-fire would be eaten by the
    exact filter that makes the defeat terminal -- the finding is suppressed,
    so it never re-detects, so it never re-opens.

    The test is the SAME composite `cmd_override` refuses on, deliberately
    reusing it rather than mapping tools to their arming flags. Two reasons.
    The refusal and the revocation answer one question -- "is this finding
    BLOCK-tier under the config in force" -- and two implementations of one
    question drift. And a tool-keyed map gets the LLM case wrong:
    `policy.classify("llm-review", ...)` always returns WARN, so
    `llm_block_armed` does not promote an unconfirmed or sub-critical
    llm-review finding at all, and a map keyed on the flag would revoke
    overrides arming never touched.

    Idempotency is structural rather than guarded: invalidating sets the
    status back to "open", and this only ever examines rows that are
    "overridden", so a revoked row is invisible to every later sweep. It
    cannot be re-overridden either -- it is BLOCK-tier now, which is precisely
    what `cmd_override` refuses.
    """
    state = ledger.open_findings()
    # The WINNING override event per finding -- its last one. A finding may
    # carry several (re-overridden after a re-detect), and only the one that
    # actually granted the live suppression says what was assumed.
    granted: dict[str, dict] = {}
    for e in ledger.events():
        if e.type.value == "finding_overridden":
            granted[e.finding_id] = e.payload

    invalidated: list[dict] = []
    for fid, rec in state.items():
        if rec.get("status") != "overridden":
            continue
        if not (rec.get("verdict") == "block" or _is_block_tier_now(cfg, rec)
                or review.is_confirmed_critical_llm(rec)):
            continue
        # Absent field vs recorded field. Kept distinct because they are
        # different claims: one says "granted while this class was disarmed",
        # the other says "granted by a version that never asked". Collapsing
        # them costs nothing today and makes "were these adjudicated under a
        # wrong assumption, or were they just old?" unanswerable later.
        cause = ("recorded_disarmed" if "arming_state" in granted.get(fid, {})
                 else "arming_state_unrecorded")
        ledger.append(Event(EventType.FINDING_OVERRIDE_INVALIDATED, run_id, at,
                             finding_id=fid, payload={"cause": cause}))
        invalidated.append({"id": fid, "cause": cause})
    return invalidated


def _sweep_context(ledger, finding_id: str) -> tuple[str, int] | None:
    """The sweep that reopened this finding, as (cause, findings it reopened),
    or None when no sweep is responsible for it being open.

    Conditional on purpose. A finding that is BLOCK-tier on FIRST DETECTION
    was never overridden and so was never swept, and telling its operator
    that "your earlier override was revoked" would be a fabricated causal
    claim -- the same defect as asserting a staleness result from an arming
    check (interop round 112). The ledger is the only thing that knows which
    of the two an operator is looking at, so it is what gets asked.

    The LAST invalidation wins: a finding can be re-overridden after a
    re-detect and swept again, and only the most recent sweep is the one the
    operator has just walked into. That sweep's `run_id` is shared by every
    override it revoked, which is what makes the count the REAL batch size
    rather than a number the message asserts.
    """
    last = None
    by_run: dict[str, set[str]] = {}
    for e in ledger.events():
        if e.type.value != EventType.FINDING_OVERRIDE_INVALIDATED.value:
            continue
        by_run.setdefault(e.run_id, set()).add(e.finding_id)
        if e.finding_id == finding_id:
            last = e
    if last is None:
        return None
    return last.payload.get("cause", ""), len(by_run.get(last.run_id, ()))


def render_sweep_reason(cause: str, swept: int) -> str:
    """Why this finding is back, for the refusal to say out loud.

    Shares `_CAUSE_TEXT` with `render_invalidations` deliberately, so the
    gate-start notice and the refusal an operator hits minutes later describe
    one event in one vocabulary instead of two.

    The batch line exists because round 118 section 3's complaint was not that
    the refusal was wrong -- it was that meeting 26 of them on an unrelated
    push reads as 26 isolated denials when it is one re-adjudication, and
    nothing on the surface said so.
    """
    lines = [f"aramid: override: it is back because a gate-start sweep revoked your "
             f"earlier override of it -- {_CAUSE_TEXT.get(cause, cause)}. Arming is "
             f"retroactive, so that judgement is due again in the committed file."]
    if swept > 1:
        lines.append(f"aramid: override: the same sweep reopened {swept} findings -- a "
                     f"run of these refusals is one re-adjudication, not {swept} "
                     f"unrelated denials.")
    return "\n".join(lines)


def cmd_override(root, finding_id: str, reason: str) -> int:
    root = Path(root)
    reason = (reason or "").strip()
    if not reason:
        print("aramid: override: --reason is required", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: override: unknown finding id {finding_id}", file=sys.stderr)
            return 3

        # T-8 section 7.1: override gates on verdict/LLM-confirmed-critical
        # only, never on status -- so open -> unreachable -> override was
        # reachable, granting no NEW capability (anything reachable this
        # way was already overridable directly while open) but costing the
        # resurrection guarantee (overridden findings never re-detect).
        if rec.get("status") == "unreachable":
            print(f"aramid: override: {finding_id} is unreachable -- its tool does not "
                  f"run in this repo, so there is nothing to override", file=sys.stderr)
            return 3
        # Same argument for a REWRITTEN line: its old id is not the row that
        # needs a decision -- the sibling that replaced it is still open --
        # and an override here would stop a revert of the rewrite from
        # re-detecting, since overridden findings never resurrect.
        if rec.get("status") == "superseded":
            print(f"aramid: override: {finding_id} is superseded -- "
                  f"{rec.get('reason') or 'its line was rewritten'}; decide on that "
                  f"finding instead", file=sys.stderr)
            return 3

        # Loaded HERE, and a failure refuses rather than falling through to the
        # stored verdict: whether this finding is BLOCK-tier is a question about
        # the config in force, so being unable to read the config is being
        # unable to answer it -- not licence to trust the frozen row instead.
        try:
            cfg = config_mod.load_config(root)
        except Exception as exc:
            print(f"aramid: override: cannot read the config ({exc}) -- refusing. "
                  f"Whether {finding_id} is BLOCK-tier depends on the config in "
                  f"force, and its stored verdict is not proof of that. Fix "
                  f"aramid.toml and retry.", file=sys.stderr)
            return 3

        is_llm_confirmed_critical = review.is_confirmed_critical_llm(rec)
        if (rec.get("verdict") == "block" or _is_block_tier_now(cfg, rec)
                or is_llm_confirmed_critical):
            print(f"aramid: override: {finding_id} is a BLOCK-tier finding -- a local "
                  f"override is not permitted; add a reasoned entry to "
                  f".aramid-suppressions.toml instead (design doc section 6).",
                  file=sys.stderr)
            # Only when the LEDGER says a sweep is why this row is open again.
            sweep = _sweep_context(ledger, finding_id)
            if sweep is not None:
                print(render_sweep_reason(*sweep), file=sys.stderr)
            print("Append this, review it, and commit it:\n", file=sys.stderr)
            print(_suppression_snippet(finding_id, rec, reason), file=sys.stderr)
            return 3

        # The arming state this decision ASSUMED. An override is a judgement
        # made under a config -- "I accept this as a WARN" -- and until now the
        # ledger recorded the judgement without the premise. A later sweep
        # needs the premise to tell a suppression granted while this class was
        # disarmed from one granted by a version that never asked the question;
        # those two deserve different words in front of an operator, and
        # without this field the distinction is unrecoverable forever after
        # (interop round 89).
        ledger.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, _now(),
                             finding_id=finding_id,
                             payload={"reason": reason,
                                      "arming_state": config_mod.arming_state(cfg)}))
        print(f"aramid: override: {finding_id} overridden ({reason})")
        return 0
    finally:
        ledger.close()
