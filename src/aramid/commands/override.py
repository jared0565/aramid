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

from aramid import review
from aramid.ledger import Ledger
from aramid.models import Event, EventType


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

        is_llm_confirmed_critical = review.is_confirmed_critical_llm(rec)
        if rec.get("verdict") == "block" or is_llm_confirmed_critical:
            print(f"aramid: override: {finding_id} is a BLOCK-tier finding -- a local "
                  f"override is not permitted; add a reasoned entry to "
                  f".aramid-suppressions.toml instead (design doc section 6).\n"
                  f"Append this, review it, and commit it:\n", file=sys.stderr)
            print(_suppression_snippet(finding_id, rec, reason), file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: override: {finding_id} overridden ({reason})")
        return 0
    finally:
        ledger.close()
