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
import shlex
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import gitutil, review, tier, toolset
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Severity, Status


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


def _vocab_or_error(value: str | None, vocab, flag: str):
    """`(canonical, None)` or `(None, 3)`, having already explained itself.

    `--status` and `--severity` draw from fixed vocabularies (`Status`,
    `Severity`) and the ledger stores the underscore form -- but `aramid
    status` PRINTS the hyphen form (`pending-retest: 2`), so the spelling one
    surface teaches was the spelling this one rejected. The miss was silent:
    the raw comparison matched nothing and the command answered "no matching
    findings", which is exactly what a real absence says. Measured on this
    repo's own ledger: `status` reported two pending-retest rows and `filter
    --status pending-retest` reported none; the underscore spelling found both.

    A filter that can answer "none" for a value no row can carry is not a
    filter, it is a guess. So hyphens and case are normalised, and a value
    outside the vocabulary is REFUSED with the vocabulary listed. Exit 3 is
    the config/engine code, matching `_config_or_error`: a caller that could
    not be answered, not one that was answered "nothing".
    """
    if value is None:
        return None, None
    canonical = value.strip().lower().replace("-", "_")
    allowed = [m.value for m in vocab]
    if canonical not in allowed:
        valid = ", ".join(allowed)
        print(f"aramid: ledger filter: unknown {flag} value {value!r} -- refusing rather "
              f"than answering 'no matching findings' for a value no row can carry. "
              f"Valid: {valid} (hyphens and case are accepted).", file=sys.stderr)
        return None, 3
    return canonical, None


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
                for line in _close_evidence(e):
                    print(f"      {line}")
        return 0
    finally:
        ledger.close()


EVIDENCED_CLOSE = "evidenced_close"


def _close_evidence(event) -> list[str]:
    """What a `resolve --fixed` close rests on, for `ledger show` (FN-36):
    the commit, who closed it and why, the test command and the HEAD it
    passed at, and whether the test was also shown to fail without the fix.
    Every other event prints its one line and nothing more.

    This is where a reviewer tells a close that showed the test failing
    from one that did not, so "red proof: not run" is printed rather than
    left out."""
    payload = event.payload or {}
    if event.type.value != "finding_resolved" \
            or payload.get("auto_resolved") != EVIDENCED_CLOSE:
        return []
    proof = payload.get("red_proof")
    if isinstance(proof, dict) and proof.get("at") == "commit":
        # A different claim from a proof at HEAD, so a line of its own: the
        # test caught the bug as the code stood when the fix was made.
        red = (f"red proof at the fix commit (it can no longer be backed out of HEAD: "
               f"{proof.get('head_conflicts')} file(s) in conflict): exit "
               f"{proof.get('pre_fix_rc')} with it backed out against {proof.get('base')} "
               f"-- {proof.get('backed_out')} of its path(s); {proof.get('brought')} test "
               f"file(s) brought in from HEAD")
    elif isinstance(proof, dict):
        red = (f"red proof: exit {proof.get('pre_fix_rc')} with that commit backed out "
               f"against {proof.get('base')} -- {proof.get('backed_out')} of its path(s); "
               f"its tests, the files it added and the files the command names stayed")
    else:
        red = "red proof: not run"
    return [f"closed as fixed in {payload.get('commit')} ({payload.get('via')}): "
            f"{payload.get('reason')}",
            f"test: {shlex.join(payload.get('test_argv') or [])} -- exit "
            f"{payload.get('test_rc')} at {payload.get('head')}",
            red]


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
# The shape version of `ledger filter --json` (1.0 blocker API-3).
# Bumped only by a change an existing reader could trip on -- a key removed,
# renamed or retyped; adding a key is not one. Each `--json` document is
# versioned on its own, so one command's change never moves another's.
FILTER_JSON_SCHEMA_VERSION = 1
# The statuses a `finding_resolved` event produces (`ledger._materialize`).
# A row that was resolved and then raised again, overridden or marked is no
# longer one of them, and its `resolved_by` reads null: the resolution is
# not what the row is showing.
_RESOLVED_STATUSES = ("fixed", "pending_retest", "superseded")


def _resolved_by(events) -> dict[str, str | None]:
    """Finding id -> the `auto_resolved` its LAST resolution carries, for
    the caller to show only on a row whose status is one a resolution
    produces (`_RESOLVED_STATUSES`)."""
    return {e.finding_id: e.payload.get("auto_resolved")
            for e in events if e.type.value == "finding_resolved"}


def cmd_ledger_filter(root, tool: str | None = None, rule: str | None = None,
                       status: str | None = None, severity: str | None = None,
                       as_json: bool = False) -> int:
    root = Path(root)
    cfg, err = _config_or_error(root, "filter")
    if err is not None:
        return err
    status, err = _vocab_or_error(status, Status, "--status")
    if err is not None:
        return err
    severity, err = _vocab_or_error(severity, Severity, "--severity")
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
            # An empty match prints an empty `findings` list, NOT the prose
            # below -- inside an object that carries its version (0.19.0;
            # it was a bare list). A consumer that
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
            # `resolved_by` on EVERY row, like `verdict_now`: the resolver the
            # row's last resolution names (`evidence_gone`, `evidenced_close`,
            # ...). Null on a row no resolution produced, and on one its own
            # tool resolved by no longer reporting it, which names none. It
            # is how a script tells a close a person or an agent recorded on
            # evidence (FN-36) from one aramid made by itself; both read
            # `fixed`.
            resolved_by = _resolved_by(ledger.events())
            print(json.dumps({
                "schema_version": FILTER_JSON_SCHEMA_VERSION,
                "findings": [{"id": fid, **{k: rec.get(k) for k in _JSON_KEYS},
                              "verdict_now": str(tier.verdict_now(cfg, rec)),
                              "suppressed": fid in suppressed_reasons,
                              "suppressed_reason": suppressed_reasons.get(fid),
                              "resolved_by": (resolved_by.get(fid)
                                              if rec.get("status") in _RESOLVED_STATUSES
                                              else None)}
                             for fid, rec in matched.items()]}, indent=2))
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


# -------------------------------------------------------------- consumers ---

# The shape version of `ledger consumers --json` (1.0 blocker API-3).
# Bumped only by a change an existing reader could trip on -- a key removed,
# renamed or retyped; adding a key is not one. Each `--json` document is
# versioned on its own, so one command's change never moves another's.
CONSUMERS_JSON_SCHEMA_VERSION = 1
# The keys the drain writes on every consumer run (commands/drain.py), in
# the order a row carries them. Anything else a consumer recorded goes
# under `extra`, so the row has one shape whatever ran.
CONSUMER_RUN_KEYS = ("consumer", "item_id", "state", "duration_s", "cost",
                     "finding_count", "note")


def cmd_ledger_consumers(root, consumer: str | None = None, last: int | None = None,
                          as_json: bool = False) -> int:
    """The drain's consumer runs (mutation, js_mutation, fuzz, red_proof,
    llm_review, dast), newest first, one line each:
    `[state] <at> <consumer> <duration>s item <item id> -- <note>`.

    `filter` reads findings only. A consumer run is an EVENT, so until
    channel round 244 (2026-09-20) a degraded consumer could be seen in the
    `degraded consumer runs:` block of `status` and nowhere else on the CLI;
    the agent that needed the row's history opened ledger.db by hand.
    `--consumer` is an exact name, `--last N` keeps the newest N after that
    filter, and `--json` emits `{"schema_version": 1, "runs": [...]}`: each
    row is `at`, `run_id`, the CONSUMER_RUN_KEYS (null when an old row
    lacks one) and `extra`, every other key the consumer recorded (an
    empty result is an empty `runs` list, never prose). No config is read: no
    field here is recomputed from the config in force, so there is nothing
    to refuse over."""
    root = Path(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        rows = [e for e in reversed(ledger.events())
                if e.type is EventType.CONSUMER_RUN_FINISHED]
    finally:
        ledger.close()
    if consumer is not None:
        rows = [e for e in rows if str(e.payload.get("consumer", "")) == consumer]
    if last is not None:
        rows = rows[:max(last, 0)]
    if as_json:
        # One shape per row (0.19.0). The old `{at, run_id, **payload}` row
        # was whatever a consumer wrote, and a consumer key named `at` or
        # `run_id` overwrote the event's own.
        print(json.dumps({
            "schema_version": CONSUMERS_JSON_SCHEMA_VERSION,
            "runs": [{"at": e.at, "run_id": e.run_id,
                      **{k: e.payload.get(k) for k in CONSUMER_RUN_KEYS},
                      "extra": {k: v for k, v in e.payload.items()
                                if k not in CONSUMER_RUN_KEYS}}
                     for e in rows]}, indent=2))
        return 0
    if not rows:
        print("aramid: ledger consumers: no consumer runs")
        return 0
    for e in rows:
        p = e.payload
        print(f"[{p.get('state', '?')}] {e.at} {p.get('consumer', '?')} "
              f"{float(p.get('duration_s') or 0.0):.1f}s item {p.get('item_id', '?')}"
              f" -- {p.get('note', '')}")
    return 0


# ----------------------------------------------------------- mark-rotated ---

def _still_in_tree(root: Path, rec: dict) -> bool:
    """Whether a marked secret's file is still in the working tree (FN-35).

    The two marks below write the gitignored ledger, and a ledger mark never
    unblocks a gate, so a value still in its file blocks every whole-tree
    scan, and CI, whatever it is marked. aramid knows only that the FILE is
    there -- the value itself is never stored -- so the note is worded
    conditionally."""
    file = rec.get("file")
    try:
        return bool(file) and (root / file).is_file()
    except (OSError, ValueError):
        return False        # a note is advice; never fail a recorded mark over it


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
        if _still_in_tree(root, rec):
            print(f"aramid: note: {rec['file']} is still in the tree. If the old value is "
                  "still in it, every whole-tree scan (and CI) keeps flagging it: delete it "
                  "(it is dead now), or add the id to .aramid-suppressions.toml with a reason.")
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
        if _still_in_tree(root, rec):
            print(f"aramid: note: {rec['file']} is still in the tree. If the value is still "
                  "in it, every whole-tree scan (and CI) keeps blocking on it: this mark is "
                  "reporting-only. To stop that, add the id to .aramid-suppressions.toml "
                  "with this reason.")
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
                  f"through their own producer's mechanism, not by this mark; an "
                  f"llm-review finding that a commit fixed has `aramid ledger resolve "
                  f"--fixed`", file=sys.stderr)
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
                "out_of_scope": "already resolved as out of scope.",
                "pending_retest": "awaiting a verified re-test -- the mutation consumer "
                                  "closes or re-opens it.",
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


# ---------------------------------------------------------------- resolve ---

def cmd_ledger_resolve(root, finding_id: str, out_of_scope: bool, reason: str) -> int:
    """`aramid ledger resolve <id> --out-of-scope --reason R`: retire an OPEN
    runner finding whose tool still runs here but whose path that runner no
    longer examines, recording WHY as its own event kind.

    The case, interop rounds 139/144/145: the typecheck runner used to hand
    mypy every file in range; scoped to `.py`/`.pyi`, a `mypy:syntax` row
    recorded against `ci.yml` can never resolve -- resolution needs a run
    that EXAMINES the file and this runner never will again -- while
    `mark-unreachable` rightly refuses, because mypy is still selected. The
    consumer chose this shape over widening `mark-unreachable` because the
    ledger must later be able to tell "the tool left" from "the path left
    the tool's scope" without reading payloads.

    The guard that keeps it from becoming a silencer: it refuses while a
    selected runner CAN still examine the path -- decided by the runner's
    own suffix rule (`toolset.examines_path`), and refused outright for a
    tool with no such rule, since "cannot say" is not "no". A tool that is
    not selected at all is `mark-unreachable`'s case and is redirected
    there. Exit 3 on every refusal; a re-detect by the runner re-opens the
    row exactly as it does for `fixed` and `unreachable`."""
    root = Path(root)
    reason = (reason or "").strip()
    if not out_of_scope:
        print("aramid: ledger resolve: give --out-of-scope (a runner finding whose path "
              "left its runner's scope) or --fixed <commit> --test \"<command>\" (an "
              "llm-review finding a commit fixed) -- a finding that is simply gone "
              "resolves on the next run that examines its file", file=sys.stderr)
        return 3
    if not reason:
        print("aramid: ledger resolve: --reason is required", file=sys.stderr)
        return 3

    try:
        cfg = config_mod.load_config(root)
    except Exception as exc:
        print(f"aramid: ledger resolve: engine error: {exc}", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
        rec = state.get(finding_id)
        if rec is None:
            print(f"aramid: ledger resolve: unknown finding id {finding_id}", file=sys.stderr)
            return 3

        tool = str(rec.get("tool"))
        path = str(rec.get("file") or "")
        if tool not in toolset.RUNNER_TOOL_NAMES:
            # llm-review has an exit of its own since FN-36; say so here, where
            # someone holding a fixed llm-review finding lands first.
            how = ("an llm-review finding that a commit fixed closes with `--fixed "
                   "<commit> --test \"<command>\"`, not --out-of-scope"
                   if tool == _LLM_TOOL else
                   "producer/consumer findings resolve through their own producer's "
                   "mechanism, not by --out-of-scope")
            print(f"aramid: ledger resolve: {finding_id} is a {tool!r} finding -- {how}",
                  file=sys.stderr)
            return 3

        status = rec.get("status")
        if status != "open":
            print(f"aramid: ledger resolve: {finding_id} is not open (status={status}) "
                  f"-- resolve --out-of-scope only applies to an open finding",
                  file=sys.stderr)
            return 3

        selected = toolset.selected_tool_names(root, cfg)
        if tool not in selected:
            print(f"aramid: ledger resolve: {finding_id}'s tool ({tool}) no longer runs "
                  f"in this repo at all -- that is `aramid ledger mark-unreachable "
                  f"{finding_id} --reason ...`, not out-of-scope", file=sys.stderr)
            return 3

        examines = toolset.examines_path(tool, path, root=root)
        if examines is None:
            print(f"aramid: ledger resolve: {tool} examines every file it is handed "
                  f"(no suffix scope), so no path is out of its scope -- if the "
                  f"finding is gone, the next run that examines {path} resolves it",
                  file=sys.stderr)
            return 3
        if examines:
            print(f"aramid: ledger resolve: {tool} still examines {path} here -- the "
                  f"next run that looks at it resolves or re-reports {finding_id}; "
                  f"resolving it by hand would be a silencer", file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_OUT_OF_SCOPE, uuid.uuid4().hex, _now(),
                            finding_id=finding_id,
                            payload={"reason": reason, "tool": tool, "file": path}))
        print(f"aramid: ledger: {finding_id} resolved as out of scope -- {tool} no "
              f"longer examines {path} ({reason})")
        return 0
    finally:
        ledger.close()


# ------------------------------------------------------- resolve --fixed ---

_LLM_TOOL = "llm-review"


def cmd_ledger_resolve_selected(root, finding_id: str, commit: str, selectors,
                                reason: str) -> int:
    """The evidenced close as aramid's MCP server makes it (FN-36, spec 9.2).

    The caller names test selectors, never a command: the command is the
    one the repo's committed `aramid.toml` declares
    (`evidenced_close.selected_command`). Red proof is always shown, and the
    event says the close came through MCP. Everything else is
    `cmd_ledger_resolve_fixed`: the same checks, refusals and event."""
    from aramid import evidenced_close

    try:
        argv = evidenced_close.selected_command(Path(root), selectors)
    except evidenced_close.Refused as exc:
        print(f"aramid: ledger resolve: {exc}", file=sys.stderr)
        return 3
    except gitutil.GitTimeout as exc:
        print(f"aramid: ledger resolve: engine error: {exc}", file=sys.stderr)
        return 3
    return cmd_ledger_resolve_fixed(root, finding_id, commit, argv, reason,
                                    red_proof=True, via="mcp")


def cmd_ledger_resolve_fixed(root, finding_id: str, commit: str, test, reason: str,
                             *, red_proof: bool = False, via: str = "cli") -> int:
    """`aramid ledger resolve <id> --fixed <commit> --test "<command>"
    --reason R [--red-proof]`: close an OPEN llm-review finding that is
    fixed although its evidence quote never left its file (FN-36).

    `review.auto_resolve_llm` closes a finding when the quoted line goes. A
    fix that guards the path to that line, or lands in a caller, leaves the
    quote alone, and the finding then stays open for ever. Until this
    command the only exit was `aramid override`, which records a fix as an
    accepted risk and -- unlike a close -- is never re-opened: the consumer
    drops a candidate whose id is `overridden` before it records anything.

    A close writes a plain `finding_resolved`, so the row reads `fixed` and
    a later drain that raises the same finding again RE-OPENS it
    (`Ledger.record_run`). That re-open is the safety net this design rests
    on, and it is why there is no status of its own.

    The evidence, all of it on the event: the commit, the test command as
    split, the HEAD it passed at, and -- with `red_proof` -- that it failed
    once the commit was backed out (`evidenced_close.red_proof`): out of
    HEAD, or at the commit itself when later changes to its lines make that
    impossible. The event's `red_proof.at` says which. A confirmed-critical
    finding closes only with red proof, and either one counts; `override`
    refuses those outright, so before this they had no exit that said
    "fixed".

    Every refusal is exit 3 and writes nothing."""
    from aramid import evidenced_close

    root = Path(root)
    reason = (reason or "").strip()
    if not reason:
        print("aramid: ledger resolve: --reason is required", file=sys.stderr)
        return 3
    try:
        # A string is `--test`, to be split. A list is an argv aramid built
        # itself (`cmd_ledger_resolve_selected`) and is run as it stands.
        argv = list(test) if isinstance(test, list) else evidenced_close.split_command(test)
    except evidenced_close.Refused as exc:
        print(f"aramid: ledger resolve: {exc}", file=sys.stderr)
        return 3
    try:
        cfg = config_mod.load_config(root)
    except Exception as exc:
        print(f"aramid: ledger resolve: engine error: {exc}", file=sys.stderr)
        return 3

    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        rec = ledger.open_findings().get(finding_id)
        if rec is None:
            print(f"aramid: ledger resolve: unknown finding id {finding_id}", file=sys.stderr)
            return 3
        tool = str(rec.get("tool"))
        if tool != _LLM_TOOL:
            print(f"aramid: ledger resolve: {finding_id} is a {tool!r} finding -- --fixed "
                  f"closes an llm-review finding only. A deterministic tool resolves or "
                  f"re-reports its own finding on its next run, and a mutation survivor "
                  f"closes on a verified re-test", file=sys.stderr)
            return 3
        status = rec.get("status")
        if status != "open":
            print(f"aramid: ledger resolve: {finding_id} is not open (status={status}) "
                  f"-- resolve --fixed only applies to an open finding", file=sys.stderr)
            return 3
        if review.is_confirmed_critical_llm(rec) and not red_proof:
            print(f"aramid: ledger resolve: {finding_id} is a confirmed critical finding "
                  f"-- it closes only with red proof. Add --red-proof: the test is then "
                  f"also run with the fix backed out and must fail there",
                  file=sys.stderr)
            return 3

        try:
            sha = gitutil.rev_sha(root, commit or "")
            head = gitutil.rev_sha(root, "HEAD")
            if sha is None:
                print(f"aramid: ledger resolve: --fixed {commit!r} is not a commit in this "
                      f"repo", file=sys.stderr)
                return 3
            if head is None or not gitutil.is_ancestor(root, sha, head):
                print(f"aramid: ledger resolve: {sha[:12]} is not part of HEAD's history "
                      f"-- the fix must be in the tree the test runs on", file=sys.stderr)
                return 3
            raised_at = rec.get("head")
            if raised_at and gitutil.is_ancestor(root, sha, str(raised_at)):
                print(f"aramid: ledger resolve: {sha[:12]} was already in the tree when "
                      f"{finding_id} was raised (at {str(raised_at)[:12]}) -- a fix cannot "
                      f"predate its finding", file=sys.stderr)
                return 3

            timeout_s = evidenced_close.run_timeout(cfg)
            evidenced_close.passes_at_head(root, argv, timeout_s)
            proof = (evidenced_close.red_proof(root, sha, head, argv, timeout_s)
                     if red_proof else None)
        except evidenced_close.Refused as exc:
            print(f"aramid: ledger resolve: {exc}", file=sys.stderr)
            return 3
        except gitutil.GitTimeout as exc:
            print(f"aramid: ledger resolve: engine error: {exc}", file=sys.stderr)
            return 3

        # The test ran for as long as it liked, and another aramid process
        # may have written to this ledger meanwhile (a gate's auto-resolve,
        # an override). A close is recorded against an OPEN finding only.
        now = (ledger.open_findings().get(finding_id) or {}).get("status")
        if now != "open":
            print(f"aramid: ledger resolve: {finding_id} is no longer open (status={now}) "
                  f"-- it changed while the test ran; nothing was recorded",
                  file=sys.stderr)
            return 3

        ledger.append(Event(EventType.FINDING_RESOLVED, uuid.uuid4().hex, _now(),
                            finding_id=finding_id,
                            payload={"auto_resolved": EVIDENCED_CLOSE, "commit": sha,
                                     "test_argv": argv, "test_rc": 0, "reason": reason,
                                     "head": head, "red_proof": proof, "via": via}))
        if not proof:
            shown = "red proof not run"
        elif proof["at"] == "commit":
            shown = (f"failed (exit {proof['pre_fix_rc']}) without the fix as the code "
                     f"stood at {sha[:12]}")
        else:
            shown = f"failed (exit {proof['pre_fix_rc']}) without the fix"
        print(f"aramid: ledger: {finding_id} closed as fixed in {sha[:12]} -- the test "
              f"passes at HEAD, {shown} ({reason})")
        return 0
    finally:
        ledger.close()


def cmd_ledger_resolve_args(root, ids, *, out_of_scope: bool = False,
                            fixed: str | None = None, test: str | None = None,
                            red_proof: bool = False, reason: str = "") -> int:
    """Which of `ledger resolve`'s two resolutions was asked for. They share
    a subcommand and nothing else: `--out-of-scope` retires a runner finding
    whose path left the runner's scope, `--fixed` closes an llm-review
    finding on evidence. A mix of the two is refused rather than guessed."""
    if fixed is None:
        if test is not None or red_proof:
            print("aramid: ledger resolve: --test and --red-proof belong to --fixed "
                  "<commit> -- they are the evidence that an llm-review finding is "
                  "fixed", file=sys.stderr)
            return 3
        return max(cmd_ledger_resolve(root, fid, out_of_scope, reason) for fid in ids)
    if out_of_scope:
        print("aramid: ledger resolve: --fixed and --out-of-scope are two different "
              "resolutions -- give one", file=sys.stderr)
        return 3
    if len(ids) != 1:
        print(f"aramid: ledger resolve: --fixed closes one finding at a time ({len(ids)} "
              f"ids given) -- each needs the test that proves its own fix",
              file=sys.stderr)
        return 3
    return cmd_ledger_resolve_fixed(root, ids[0], fixed, test, reason, red_proof=red_proof)
