"""override -- ledger-logged WARN suppression (design doc section 6, "two
tiers"). A BLOCK-tier finding cannot be suppressed here at all: enforcement
requires a reviewed, committed entry in `.aramid-suppressions.toml`
instead, visible in diff review with a reason -- this command actively
refuses and says so rather than silently no-op'ing.

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

from aramid import review
from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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

        is_llm_confirmed_critical = review.is_confirmed_critical_llm(rec)
        if rec.get("verdict") == "block" or is_llm_confirmed_critical:
            print(f"aramid: override: {finding_id} is a BLOCK-tier finding -- a local "
                  f"override is not permitted; add a reasoned entry to "
                  f".aramid-suppressions.toml instead (design doc section 6)", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: override: {finding_id} overridden ({reason})")
        return 0
    finally:
        ledger.close()
