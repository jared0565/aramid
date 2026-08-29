"""ledger_cmd -- query the findings ledger (`aramid ledger list|show|filter|
mark-rotated|mark-not-a-secret|mark-unreachable`). `mark-rotated`,
`mark-not-a-secret`, and `mark-unreachable` are the three mutating
subcommands: `mark-rotated` appends a `finding_rotated` event and requires
the target finding's materialized status be `historical` OR `not_a_secret`
(design doc section 6 -- rotation applies to init's full-history secret
scan hits, and also to a finding previously marked not-a-secret that
turned out to be a real credential after all). `mark-not-a-secret` appends
a `finding_not_a_secret` event and requires status be EXACTLY `historical`
-- a live (`open`) finding has its own suppression paths, and a `rotated`
finding is a safety assertion that is never downgraded. `mark-unreachable`
(T-8) appends a `finding_unreachable` event and requires status be EXACTLY
`open` AND the finding's tool be in `aramid.toolset.RUNNER_TOOL_NAMES` but
NOT in `aramid.toolset.selected_tool_names(root, cfg)` -- a finding whose
tool has left this repo's live selection (de-selected, disabled, or
genuinely removed), so no future run can ever resolve it the normal way.
All three guards error rather than silently no-op'ing; transitions only
ever move toward more caution, and there is no un-mark."""
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import tier, toolset
from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _config_or_error(root: Path, label: str):
    """`(cfg, None)` or `(None, 3)`, having already explained itself.

    REFUSE RATHER THAN FABRICATE. `verdict_now` is computed from the config in
    force and appears on every row, so a config we cannot read means this
    command cannot deliver what it now promises. Emitting rows with a null or
    omitted tier would invite precisely the misreading the field exists to
    remove -- a reader scanning 121 rows for what is outstanding would take
    silence for "nothing has moved".

    Mirrors `aramid override`, which refuses on the same reasoning. Note it
    deliberately does NOT mirror the suppressions handling below, where a
    malformed file leaves the per-row marker absent: that is a marker whose
    absence carries meaning, this is a value promised on every row.
    """
    try:
        return config_mod.load_config(root), None
    except Exception as exc:
        print(f"aramid: ledger {label}: cannot read the config ({exc}) -- refusing. "
              f"Every row's verdict_now is computed from the config in force, so "
              f"being unable to read it is being unable to answer. Fix aramid.toml "
              f"and retry.", file=sys.stderr)
        return None, 3


def _render_row(finding_id: str, rec: dict, verdict_now: str | None = None) -> str:
    # ASCII `--`, not an em dash. This line carried a literal U+2014, which
    # cp1252 (Windows' encoding for a REDIRECTED stdout) writes as the single
    # byte 0x97 -- not valid UTF-8 in any position, so every programmatic
    # consumer of `ledger list`/`filter` got mojibake or a decode error.
    # Reported from a downstream repo, round 64 item 5b. `cli` now forces
    # UTF-8 on redirected streams, which fixes the general class; this stays
    # ASCII because a separator has no reason not to be, and every other
    # rendered line in this codebase already uses `--`.
    row = (f"[{rec.get('status')}] {finding_id} {rec.get('tool')}:{rec.get('rule')} "
           f"{rec.get('file')}:{rec.get('line')} -- {rec.get('message')}")
    # Annotated ONLY when the tier has actually moved. The unconditional rule
    # applies to `--json`, where a field appearing on some rows and not others
    # invites inference from its absence; this line is for a human, does not
    # print `verdict` at all, and would be pure noise carrying `[now: warn]` on
    # every unchanged row. Here the marker IS the signal: it means the stored
    # tier on this row is misleading.
    if verdict_now is not None and verdict_now != rec.get("verdict"):
        row += f"  [now: {verdict_now}]"
    return row


# ------------------------------------------------------------------- list ---

def cmd_ledger_list(root) -> int:
    root = Path(root)
    cfg, err = _config_or_error(root, "list")
    if err is not None:
        return err
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        if not state:
            print("aramid: ledger: no findings recorded")
            return 0
        for finding_id, rec in state.items():
            print(_render_row(finding_id, rec, str(tier.verdict_now(cfg, rec))))
        return 0
    finally:
        ledger.close()


# ------------------------------------------------------------------- show ---

def cmd_ledger_show(root, finding_id: str) -> int:
    root = Path(root)
    cfg, err = _config_or_error(root, "show")
    if err is not None:
        return err
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: ledger show: unknown finding id {finding_id}", file=sys.stderr)
            return 3

        print(f"id:       {finding_id}")
        for key in ("tool", "rule", "file", "line", "severity", "verdict", "message",
                    "evidence", "historical", "status", "reason"):
            print(f"{key}: {rec.get(key)}")
        # Printed immediately after the block above rather than inside it: the
        # loop renders STORED keys, and this one is computed. Keeping it out of
        # the tuple is what stops a future edit adding it to `_JSON_KEYS` too,
        # where `rec.get("verdict_now")` would silently be None forever.
        print(f"verdict_now: {tier.verdict_now(cfg, rec)}")

        print("events:")
        for e in ledger.events():
            if e.finding_id == finding_id:
                print(f"  {e.at}  {e.type.value}  run={e.run_id}")
        return 0
    finally:
        ledger.close()


# ----------------------------------------------------------------- filter ---

# What `--json` promises a consumer. Mirrors the keys `ledger show` prints,
# plus the id -- so the two commands describe a finding the same way and a
# script does not have to learn a second vocabulary.
#
# `evidence` is included, and that is a checked decision rather than an
# oversight: for a secret finding `normalizer` stores a REDACTED preview plus
# a sha256 (normalizer.py, the `if raw.secret:` branch), never the raw
# credential, so this cannot widen a leak beyond what `show` already prints.
_JSON_KEYS = ("tool", "rule", "file", "line", "severity", "verdict",
              "message", "evidence", "historical", "status", "reason")


def cmd_ledger_filter(root, tool: str | None = None, rule: str | None = None,
                       status: str | None = None, severity: str | None = None,
                       as_json: bool = False) -> int:
    root = Path(root)
    cfg, err = _config_or_error(root, "filter")
    if err is not None:
        return err
    ledger = Ledger(root / ".aramid" / "ledger.db")
    # WHICH OF THESE HAS ANYONE ACTUALLY LOOKED AT.
    #
    # A committed suppression lives in `.aramid-suppressions.toml` and never
    # reaches the ledger row, so an adjudicated finding and one nobody has ever
    # examined are shape-identical here: both `status: open`, both `verdict:
    # block`, both `reason: null`. `check` distinguishes them -- a suppressed
    # finding renders INFO -- but this is the surface a reader uses to ask
    # "what is outstanding", and a consumer found a real never-examined S105
    # camouflaged among nineteen adjudicated rows because of it.
    #
    # Deliberately does NOT rewrite `verdict`. The stored verdict is the
    # finding's own tier and a suppression is a separate decision ABOUT it;
    # collapsing the two would lose the ability to ask "what would this be if
    # the suppression were withdrawn". Additive fields, so a script reading the
    # existing keys is unaffected.
    try:
        suppressed_reasons = {
            rec.id: rec.reason for rec in config_mod.load_suppressions(root)[0]}
    except Exception:
        # An unreadable or malformed suppressions file must not take the query
        # down -- but it must not silently claim nothing is adjudicated either,
        # so the marker simply goes absent rather than reading False.
        suppressed_reasons = {}
    try:
        state = ledger.open_findings()
        matched = {
            finding_id: rec for finding_id, rec in state.items()
            if (tool is None or rec.get("tool") == tool)
            and (rule is None or rec.get("rule") == rule)
            and (status is None or rec.get("status") == status)
            and (severity is None or rec.get("severity") == severity)
        }
        if as_json:
            # An empty match prints `[]`, NOT the prose below. A consumer that
            # has to special-case "no matching findings" is a consumer that
            # starts guessing -- and the text format's unparseability is the
            # defect this flag exists to fix, so it must not survive in the
            # one case where a caller is least likely to test.
            # `verdict_now` is emitted on EVERY row, including the ones whose
            # tier has not moved. graphite withdrew their own `verdict_gate`
            # proposal on exactly this reasoning: a field present on some rows
            # and absent on others invites the reader to infer meaning from the
            # absence, and that inference is unverifiable from the row itself.
            # So the pair is always both -- `verdict` is always the frozen
            # snapshot, `verdict_now` is always the recomputed truth, and which
            # one you are reading is answered structurally rather than by a
            # provenance flag nobody can check.
            print(json.dumps(
                [{"id": fid, **{k: rec.get(k) for k in _JSON_KEYS},
                  "verdict_now": str(tier.verdict_now(cfg, rec)),
                  "suppressed": fid in suppressed_reasons,
                  "suppressed_reason": suppressed_reasons.get(fid)}
                 for fid, rec in matched.items()], indent=2))
            return 0
        if not matched:
            print("aramid: ledger filter: no matching findings")
            return 0
        for finding_id, rec in matched.items():
            row = _render_row(finding_id, rec, str(tier.verdict_now(cfg, rec)))
            if finding_id in suppressed_reasons:
                row += f"  [suppressed: {suppressed_reasons[finding_id]}]"
            print(row)
        return 0
    finally:
        ledger.close()


# ----------------------------------------------------------- mark-rotated ---

def cmd_ledger_mark_rotated(root, finding_id: str, reason: str) -> int:
    root = Path(root)
    reason = (reason or "").strip()
    if not reason:
        print("aramid: ledger mark-rotated: --reason is required", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: ledger mark-rotated: unknown finding id {finding_id}",
                  file=sys.stderr)
            return 3
        status = rec.get("status")
        if status not in ("historical", "not_a_secret"):
            print(f"aramid: ledger mark-rotated: {finding_id} is not a historical or "
                  f"not-a-secret finding (status={status}) -- mark-rotated only applies "
                  f"to historical secrets from init's full-history scan, or to a finding "
                  f"already marked not-a-secret", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_ROTATED, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: ledger: {finding_id} marked rotated ({reason})")
        return 0
    finally:
        ledger.close()


# --------------------------------------------------- mark-not-a-secret ---

def cmd_ledger_mark_not_a_secret(root, finding_id: str, reason: str) -> int:
    root = Path(root)
    reason = (reason or "").strip()
    if not reason:
        print("aramid: ledger mark-not-a-secret: --reason is required", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: ledger mark-not-a-secret: unknown finding id {finding_id}",
                  file=sys.stderr)
            return 3
        status = rec.get("status")
        if status != "historical":
            if status == "open":
                tail = ("mark-not-a-secret only applies to historical secrets from "
                         "init's full-history scan. For a live BLOCK finding use a "
                         "committed .aramid-suppressions.toml entry; for a WARN use "
                         "`aramid override`.")
            elif status == "not_a_secret":
                tail = "already marked not-a-secret."
            elif status == "rotated":
                tail = ("already retired by rotation. A rotated finding is never "
                         "downgraded to not-a-secret.")
            else:
                tail = ("mark-not-a-secret only applies to historical secrets from "
                         "init's full-history scan.")
            print(f"aramid: ledger mark-not-a-secret: {finding_id} is not a historical "
                  f"finding (status={status}) -- {tail}", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_NOT_A_SECRET, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: ledger: {finding_id} marked not-a-secret ({reason})")
        return 0
    finally:
        ledger.close()


# ------------------------------------------------------- mark-unreachable ---

def cmd_ledger_mark_unreachable(root, finding_id: str, reason: str) -> int:
    root = Path(root)
    reason = (reason or "").strip()
    if not reason:
        print("aramid: ledger mark-unreachable: --reason is required", file=sys.stderr)
        return 3

    try:
        cfg = config_mod.load_config(root)
    except Exception as exc:
        print(f"aramid: ledger mark-unreachable: engine error: {exc}", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: ledger mark-unreachable: unknown finding id {finding_id}",
                  file=sys.stderr)
            return 3

        tool = rec.get("tool")
        if tool not in toolset.RUNNER_TOOL_NAMES:
            print(f"aramid: ledger mark-unreachable: {finding_id} is a {tool!r} finding "
                  f"-- producer/consumer findings (tdd, red-proof, mutation, "
                  f"mutation-score, llm-review, js-mutation, fuzz, dast) resolve "
                  f"through their own producer's mechanism, never by hand",
                  file=sys.stderr)
            return 3

        status = rec.get("status")
        if status != "open":
            tails = {
                "unreachable": "already marked unreachable.",
                "fixed": "already fixed -- nothing to retire.",
                "historical": "a historical secret -- use `aramid ledger mark-rotated` "
                              "or `mark-not-a-secret` instead.",
                "overridden": "already overridden.",
                "rotated": "already retired by rotation.",
                "not_a_secret": "already marked not-a-secret.",
                # The line was rewritten; the sibling that replaced it is the
                # row that now needs a decision. `reason` carries its id.
                "superseded": f"{rec.get('reason') or 'rewritten'} -- decide on that finding instead.",
            }
            tail = tails.get(status, "mark-unreachable only applies to an open finding.")
            print(f"aramid: ledger mark-unreachable: {finding_id} is not open "
                  f"(status={status}) -- {tail}", file=sys.stderr)
            return 3

        selected = toolset.selected_tool_names(root, cfg)
        if tool in selected:
            print(f"aramid: ledger mark-unreachable: {finding_id}'s tool ({tool}) still "
                  f"runs in this repo -- not a ghost. If it fails every run, that is "
                  f"`aramid doctor`'s problem, not mark-unreachable's", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_UNREACHABLE, uuid.uuid4().hex, _now(),
                             finding_id=finding_id, payload={"reason": reason}))
        print(f"aramid: ledger: {finding_id} marked unreachable ({reason})")
        return 0
    finally:
        ledger.close()
