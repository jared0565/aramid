"""status -- read-only ledger/config report: last run, open counts,
NEW-since-baseline, aging (>30d), per-tool skip streaks, unrotated
historical secrets, and -- while unarmed -- the WARN-only bake's day count
plus per-rule semgrep hit counts (design doc section 8: this is the bake's
whole functional purpose -- letting the operator spot and demote noisy
rules in `aramid.toml` before `aramid arm`). Pure reporting: never mutates
the ledger, never runs a gate.
"""
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import review
from aramid import toolset
from aramid import yield_report
from aramid.ledger import Ledger
from aramid.models import EventType

_AGING_DAYS = 30


def _parse_at(at: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(at)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _last_run_line(ledger: Ledger) -> str:
    runs = [e for e in ledger.events() if e.type is EventType.RUN_FINISHED]
    if not runs:
        return "last run: none"
    last = runs[-1]
    line = f"last run: {last.at} (run {last.run_id}, {last.payload.get('blocking', 0)} blocking"
    # `finished_at` is newer than `at`; a ledger written before it has none,
    # and that reads as unknown rather than as zero seconds.
    finished = last.payload.get("finished_at")
    if finished:
        try:
            took = (datetime.fromisoformat(finished) - datetime.fromisoformat(last.at)).total_seconds()
            line += f", took {took:.0f}s"
        except (TypeError, ValueError):
            pass
    return line + ")"


def _open_counts_line(state: dict) -> str:
    counts = Counter(rec.get("status") for rec in state.values())
    return (f"open findings: {counts.get('open', 0)} "
            f"(historical: {counts.get('historical', 0)}, "
            f"not-a-secret: {counts.get('not_a_secret', 0)}, "
            f"overridden: {counts.get('overridden', 0)}, "
            f"unreachable: {counts.get('unreachable', 0)}, "
            f"fixed: {counts.get('fixed', 0)}, "
            f"rotated: {counts.get('rotated', 0)})")


def _new_since_baseline_line(ledger: Ledger, state: dict) -> str:
    baseline = ledger.baseline_ids()
    new_ids = [fid for fid, rec in state.items()
               if rec.get("status") == "open" and fid not in baseline]
    return f"NEW since baseline: {len(new_ids)}"


def _detected_at(ledger: Ledger) -> dict[str, str]:
    """Earliest `finding_detected` timestamp per finding id. Ledger's public
    `open_findings()` materialization deliberately doesn't carry this (see
    aramid.reporter's own note on why the console report keeps aging as a
    plain open-count) -- status derives it directly from the raw event
    stream since it, unlike reporter, is allowed to read the wall clock."""
    detected: dict[str, str] = {}
    for e in ledger.events():
        if e.type is EventType.FINDING_DETECTED and e.finding_id and e.finding_id not in detected:
            detected[e.finding_id] = e.at
    return detected


def _aging_line(ledger: Ledger, state: dict) -> str:
    detected = _detected_at(ledger)
    now = datetime.now(timezone.utc)
    aged = 0
    for fid, rec in state.items():
        if rec.get("status") != "open":
            continue
        parsed = _parse_at(detected[fid]) if fid in detected else None
        if parsed is not None and (now - parsed).days > _AGING_DAYS:
            aged += 1
    return f"aging: {aged} finding(s) open > {_AGING_DAYS}d"


def _skip_streak_lines(ledger: Ledger) -> list[str]:
    """For every tool eligible for a gate, how many of that gate's most recent
    consecutive runs it was ABSENT from -- design doc section 8's
    skip-visibility requirement ('semgrep: skipped last N runs').

    SCOPED PER GATE, and that is the whole subtlety. `GATE_RUNNER_KEYS` gives
    each gate a different runner set: ruff is pre-commit only, semgrep and
    tests are pre-push only. A global streak therefore counts ruff as
    "skipped" on every pre-push run, which is not a skip -- it is the gate
    working exactly as designed. Reported to us from a downstream repo as an
    unexplained `ruff: skipped last 1 run(s)` whose `ruff check .` passed by
    hand, and reproduced in aramid's own `status` at the same time.

    One word cannot carry both "ran and failed" and "not part of this gate":
    the first is a hole in the gate, the second is the gate being correct.

    A gate's eligible set is therefore what the gate SHOULD have run, recorded
    on the run itself as `expected` (see the comment at the loop below for how
    it is read, and why an absent key is not an empty one).

    It is deliberately NOT "the tools that have actually appeared at this
    gate". That rule was tried first and it cannot see a scanner that never
    started: misconfigure semgrep before its first run and it never enters the
    universe, so it is never reported skipped, and an absent security control
    reads as a healthy one. Do not reintroduce it -- its appeal is that it
    needs no runner table to keep in sync, and that convenience is exactly the
    blind spot. The tests-runner alias ("tests" the key, "python" the recorded
    label) is handled because `expected` is recorded in the same vocabulary the
    runs report.

    The gate is named in the line for the same reason: it tells the reader
    which set of runs the count is over.
    """
    runs = [e for e in ledger.events() if e.type is EventType.RUN_STARTED]
    if not runs:
        return []

    by_gate: dict[str, list] = defaultdict(list)
    for e in runs:
        by_gate[str(e.payload.get("gate", "?"))].append(e)

    lines = []
    for gate in sorted(by_gate):
        gate_runs = by_gate[gate]
        # WHAT THE GATE SHOULD HAVE RUN, from the newest run that recorded it.
        #
        # Deriving eligibility from tools that have previously APPEARED cannot
        # see a scanner that never started: misconfigure semgrep before its
        # first run and it never enters the universe, so it is never reported
        # skipped and an absent security control reads as a healthy one. That
        # is the shape this whole report exists to prevent, and it survived the
        # fix for the opposite bug.
        #
        # Newest-that-has-it rather than a union across runs, so the report
        # follows config: a tool genuinely removed from a gate stops being
        # expected on the next run instead of being demanded forever.
        #
        # `"expected" in payload` distinguishes ABSENT (a ledger written before
        # this was recorded -- fall back to the old observed-universe rule, or
        # every historical repo suddenly reports nothing) from EMPTY (a
        # positive claim that this gate expects no tools).
        expected: set[str] | None = None
        for e in reversed(gate_runs):
            if "expected" in e.payload:
                expected = {str(t) for t in (e.payload.get("expected") or ())}
                break
        if expected is None:
            expected = set()
            for e in gate_runs:
                expected.update(e.payload.get("tools", []))

        for tool in sorted(expected):
            streak = 0
            for e in reversed(gate_runs):
                if tool in e.payload.get("tools", []):
                    break
                streak += 1
            if streak:
                lines.append(f"  {tool}: skipped last {streak} {gate} run(s)")
    return lines


def _unrotated_historical_lines(state: dict) -> list[str]:
    lines = []
    for fid, rec in state.items():
        if rec.get("historical") and rec.get("status") == "historical":
            lines.append(
                f"  {fid} {rec.get('tool')}:{rec.get('rule')} {rec.get('file')} -- "
                f"real leak? rotate the credential, then "
                f"`aramid ledger mark-rotated {fid} --reason ...`. "
                f"false positive? `aramid ledger mark-not-a-secret {fid} --reason ...`")
    return lines


def _unreachable_candidate_lines(root: Path, cfg, state: dict) -> list[str]:
    """Auto-DETECTED ghost candidates (T-8 section 9 item 2 -- the user's
    chosen auto-detect + manual-retire design): an open finding whose tool
    is in the retireable universe but not currently selected. Mirrors
    _unrotated_historical_lines's shape: one line per candidate, naming the
    exact command. Without this the operator must already suspect a finding
    is a ghost, reproducing the exact discoverability defect T-9 fixed."""
    selected = toolset.selected_tool_names(root, cfg)
    candidates = toolset.ghost_candidates(state, selected)
    return [
        f"  {fid} {rec.get('tool')}:{rec.get('rule')} {rec.get('file')} -- "
        f"tool no longer runs in this repo? "
        f"`aramid ledger mark-unreachable {fid} --reason ...`"
        for fid, rec in candidates.items()
    ]


def _bake_lines(cfg: config_mod.Config, state: dict) -> list[str]:
    if cfg.semgrep_block_armed:
        return []

    lines = []
    if cfg.bake_started:
        try:
            started = date.fromisoformat(cfg.bake_started)
            lines.append(f"bake in progress, day {(date.today() - started).days + 1}")
        except ValueError:
            lines.append("bake in progress, day ? (unparseable bake_started in aramid.toml)")
    else:
        lines.append("bake in progress, day ? (bake_started not set in aramid.toml)")

    hits: Counter = Counter()
    for rec in state.values():
        if rec.get("tool") == "semgrep":
            hits[rec.get("rule", "")] += 1
    if hits:
        lines.append("semgrep per-rule hit counts (demote noisy rules before `aramid arm`):")
        for rule, count in sorted(hits.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"  {rule}: {count}")
    return lines


def _autolearn_line(cfg: config_mod.Config) -> str:
    """One line (autolearn spec section 12): off | armed | shadow with the
    shadow/audit record. Never raises -- status stays read-only-safe."""
    al = cfg.llm.get("autolearn", {})
    if not isinstance(al, dict) or not al.get("enabled", True):
        return "autolearn: off"
    if al.get("armed", False):
        return "autolearn: armed"
    try:
        from aramid import autolearn as al_mod
        st = al_mod.load_state()
        sh, au = st.get("shadow", {}), st.get("audits", {})
        return (f"autolearn: shadow (would-uplift {sh.get('would_uplift', 0)}"
                f"/{sh.get('decisions', 0)}, audits {au.get('performed', 0)}, "
                f"misses {au.get('missed_criticals', 0)})")
    except Exception:
        return "autolearn: shadow (state unreadable)"


def _llm_lines(cfg: config_mod.Config, state: dict) -> list[str]:
    """LLM review status: open count, confirmed critical count, armed state,
    and monthly OpenRouter spend (spec section 7, Phase 2b)."""
    recs = [r for r in state.values()
            if r.get("source") == "llm" and r.get("status") == "open"]
    confirmed = sum(1 for r in recs if review.is_confirmed_critical_llm(r))
    armed = bool(cfg.llm.get("llm_block_armed", False))
    lines = [f"llm: {len(recs)} open ({confirmed} confirmed critical) | "
             f"{'armed' if armed else 'baking'}"]
    try:
        from aramid.providers import spend as spend_mod
        cap = float(cfg.llm.get("openrouter_monthly_cap_usd", 5.0))
        month = spend_mod.month_spend_usd("openrouter",
                                          datetime.now(timezone.utc).isoformat())
        if month is None:
            lines.append("llm spend (openrouter, this month): "
                         "unreadable -- openrouter disabled")
        else:
            lines.append(f"llm spend (openrouter, this month): "
                         f"${month:.2f} / ${cap:.2f}")
    except Exception:
        lines.append("llm spend (openrouter, this month): unknown")
    ladder = cfg.llm.get("ladder", [])
    arms = [a for a in ladder if isinstance(a, dict)]
    if arms:
        tiers = " -> ".join(f"{a.get('tier')}:{a.get('provider')}" for a in arms)
        lines.append(f"llm ladder: {tiers}")
    lines.append(_autolearn_line(cfg))
    return lines


# --- Phase 2a: queue / drain / registry / schedule (spec section 2) ---

def _queue_lines(ledger: Ledger) -> list[str]:
    from aramid import queue as queue_mod

    items = queue_mod.materialize_queue(ledger.events())
    queued = [i for i in items.values() if i.state == queue_mod.QUEUED]
    drained_n = sum(1 for i in items.values() if i.state == queue_mod.DRAINED)
    expired_n = sum(1 for i in items.values() if i.state == queue_mod.EXPIRED)

    if not queued:
        if drained_n or expired_n:
            return [f"queue: empty | {drained_n} drained | {expired_n} expired"]
        return ["queue: empty"]

    q = queued[0]
    age_h = int((datetime.now(timezone.utc)
                 - datetime.fromisoformat(q.created_at)).total_seconds() // 3600)
    lines = [f"queue: {len(queued)} queued (score {q.score}, {age_h}h old) | "
             f"{drained_n} drained | {expired_n} expired"]
    lines.extend(f"  {reason}" for reason in q.reasons)
    return lines


def _last_drain_line(ledger: Ledger) -> str:
    last_consumer = None
    for e in ledger.events():
        if e.type is EventType.CONSUMER_RUN_FINISHED:
            last_consumer = e
    if last_consumer is None:
        return "last drain: never"
    return (f"last drain: {last_consumer.at} "
            f"({last_consumer.payload.get('consumer')}, "
            f"{last_consumer.payload.get('finding_count', 0)} finding(s))")


def _registry_line(root: Path) -> str:
    from aramid import registry as registry_mod
    from aramid.fingerprint import normalize_path

    try:
        this_repo = normalize_path(str(root.resolve()))
        registered = any(normalize_path(e["path"]) == this_repo
                          for e in registry_mod.load_registry())
    except Exception:
        registered = False
    return ("registry: registered" if registered
            else "registry: NOT registered (aramid init to register)")


def _scheduled_drain_line() -> str:
    """Probe whichever scheduler backend this platform actually uses.

    This queried schtasks unconditionally. Once the drain became installable
    via cron on Linux/macOS that turned into a lie by omission: schtasks does
    not exist there, the spawn raises, the except arm swallows it, and a user
    who had just installed the cron entry successfully was told "unknown".
    """
    try:
        import subprocess
        import sys

        from aramid.commands import schedule as schedule_mod

        if sys.platform == "win32":
            # S603 justification: argv comes from schedule._query_argv(), a
            # fixed literal list -- no external input reaches it.
            cp = subprocess.run(schedule_mod._query_argv(), capture_output=True,  # noqa: S603
                                text=True, errors="replace")
            installed = cp.returncode == 0
        else:
            installed = schedule_mod.CRON_MARKER in schedule_mod._read_crontab()
        return ("scheduled drain: installed" if installed
                else "scheduled drain: not installed")
    except Exception:
        return "scheduled drain: unknown"


def _consumer_health_lines(ledger: Ledger) -> list[str]:
    """Consumers currently stuck in `degraded`, as a STREAK.

    `degraded` is load-bearing: the drain marks a queue item drained only when
    every consumer finished cleanly, so a degraded consumer keeps its item
    queued and re-runs the whole set next drain. Until now it appeared in no
    report at all -- `last drain:` prints one consumer's name and finding
    count, and nothing printed state. Measured on this repo: 38 degraded
    mutation runs, invisible from every surface.

    A streak rather than a lifetime total, mirroring `_skip_streak_lines`
    directly above. A lifetime count of a fault that has since been fixed is a
    line that never goes away, and a line that never goes away is one nobody
    reads -- the same reason `_resolver_defect_lines` stays silent when clean.

    The note is carried because "fuzz is degraded" only sends the reader to
    the ledger, while "driver broken @ abc123: no parseable output" tells them
    what to fix without leaving `status`. Never raises.
    """
    try:
        runs: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for e in ledger.events():
            if e.type is EventType.CONSUMER_RUN_FINISHED:
                runs[str(e.payload.get("consumer", "?"))].append(
                    (str(e.payload.get("state", "")),
                     str(e.payload.get("note", ""))))
    except Exception:
        return []

    faults = []
    for name in sorted(runs):
        streak, note = 0, ""
        for state, run_note in reversed(runs[name]):
            if state not in ("degraded", "error"):
                break
            streak += 1
            note = note or run_note
        if streak:
            faults.append(f"    {name}: degraded last {streak} run(s)"
                          + (f" -- {note}" if note else ""))
    return ["  degraded consumer runs:", *faults] if faults else []


# A give-up note's shared marker. Every consumer that stands down says
# "giving up" (mutation, js mutation, llm_review, fuzz, dast), so one marker
# reaches all of them -- and a consumer that invents different wording simply
# goes unreported here rather than breaking anything.
_GIVE_UP_MARK = "giving up"

# A run that finished cleanly and certified nothing. Distinct from a give-up:
# the consumer has NOT stopped, it will run again next drain and burn the same
# time again. Reported because `state` cannot carry it -- `degraded` would pin
# the queue item and stall the drain (measured downstream at 61 hours), so
# these runs are legitimately `ok` and would otherwise be invisible.
_NO_WORK_MARK = "no mutants tested"


def _stood_down_lines(ledger: Ledger) -> list[str]:
    """Consumers that have permanently STOPPED, which `degraded` cannot show.

    A give-up deliberately returns `ok`: `degraded` prevents the drain marking
    the item drained, so standing down as `degraded` would pin the queue item
    and re-run every other consumer on it forever -- trading a wasteful loop
    for a total stall. But `ok` also ends the degraded streak
    `_consumer_health_lines` reports, so the moment a consumer gives up it
    starts reporting exactly like a healthy one.

    That was survivable while give-ups almost never latched. Making the
    baseline-timeout latch actually hold makes standing down the STEADY STATE,
    so this report is not an optional extra -- without it the fix converts a
    loud waste into a silent absence of coverage, which is the failure this
    whole tool exists to catch.

    The cost is stated because it is what makes the line worth acting on: a
    downstream repo spent ~8 minutes every 4 hours for three days here, and
    nothing anywhere named that number. Self-clearing for the same reason the
    degraded streak is: one real run after a give-up means somebody fixed it.

    Never raises.
    """
    try:
        runs: dict[str, list[tuple[str, str, float]]] = defaultdict(list)
        for e in ledger.events():
            if e.type is EventType.CONSUMER_RUN_FINISHED:
                runs[str(e.payload.get("consumer", "?"))].append(
                    (str(e.payload.get("state", "")),
                     str(e.payload.get("note", "")),
                     float(e.payload.get("duration_s") or 0.0)))
    except Exception:
        return []

    faults = []
    for name in sorted(runs):
        seq = runs[name]
        if not seq or _GIVE_UP_MARK not in seq[-1][1]:
            continue        # not currently stood down (or never was)
        # Walk back over everything that produced nothing -- the degraded
        # attempts AND the give-ups -- and stop at the last run that actually
        # worked. That span is the waste, and the give-up run is part of it.
        count, spent = 0, 0.0
        for state, run_note, duration in reversed(seq):
            if state not in ("degraded", "error") and _GIVE_UP_MARK not in run_note:
                break
            count += 1
            spent += duration
        faults.append(f"    {name}: stood down after {count} run(s), "
                      f"{spent:.0f}s spent -- {seq[-1][1]}")
    return ["  consumers stood down:", *faults] if faults else []


def _no_work_lines(ledger: Ledger) -> list[str]:
    """Consumers that keep finishing cleanly while certifying nothing.

    The third instance of this round's defect class, and the one that only
    appeared after the first two were fixed: raising `baseline_timeout_s` lets
    the baseline succeed, the wall budget is then already spent, and mutation
    reports `ok` having generated mutants and tested none. No degraded streak
    (it is `ok`), no stand-down (it has not given up) -- healthy-looking, and
    recurring every drain at full cost.

    A streak, so it self-clears the moment a run does real work, and the cost
    is stated because recurring-cost-for-no-result is the whole point.

    Never raises.
    """
    try:
        runs: dict[str, list[tuple[str, float]]] = defaultdict(list)
        for e in ledger.events():
            if e.type is EventType.CONSUMER_RUN_FINISHED:
                runs[str(e.payload.get("consumer", "?"))].append(
                    (str(e.payload.get("note", "")),
                     float(e.payload.get("duration_s") or 0.0)))
    except Exception:
        return []

    faults = []
    for name in sorted(runs):
        seq = runs[name]
        if not seq or _NO_WORK_MARK not in seq[-1][0]:
            continue
        count, spent = 0, 0.0
        for note, duration in reversed(seq):
            if _NO_WORK_MARK not in note:
                break
            count += 1
            spent += duration
        faults.append(f"    {name}: {count} run(s) certified nothing, "
                      f"{spent:.0f}s spent -- {seq[-1][0]}")
    return ["  consumers doing no work:", *faults] if faults else []


def _resolver_defect_lines(ledger: Ledger) -> list[str]:
    """One line, only when something is wrong, pointing at the full report.

    THE REPORT ITSELF IS NOT THE FIX. Every silent no-op `aramid resolvers`
    grades went unnoticed for weeks with all its evidence sitting in the
    ledger the whole time -- what was missing was anything that SURFACED it.
    Shipping a command that has to be remembered repeats that failure one
    level up, so the grade reaches a command people already type.

    Deliberately not a finding and deliberately not blocking: this is a
    diagnostic about the gate's own machinery, not a verdict on the code being
    pushed, and a false flag that stops a push gets the whole check deleted
    rather than fixed. Silent when healthy, because a line that is always
    there is a line nobody reads.

    Never raises: a broken diagnostic must not take down `status`.
    """
    try:
        flagged = [r for r in yield_report.collect(ledger) if r.flagged]
    except Exception:
        return []
    if not flagged:
        return []
    names = ", ".join(sorted({f"{r.resolver}/{r.tool}" for r in flagged}))
    return [f"  resolver defects: {len(flagged)} (run `aramid resolvers`)",
            f"    {names}"]


def cmd_status(root) -> int:
    root = Path(root)
    try:
        cfg = config_mod.load_config(root)
        ledger = Ledger(root / ".aramid" / "ledger.db")
    except Exception as exc:
        print(f"aramid: status: engine error: {exc}", file=sys.stderr)
        return 3

    try:
        state = ledger.open_findings()

        lines = [
            "aramid status:",
            f"  {_last_run_line(ledger)}",
            f"  {_open_counts_line(state)}",
            f"  {_new_since_baseline_line(ledger, state)}",
            f"  {_aging_line(ledger, state)}",
        ]

        lines.extend(_resolver_defect_lines(ledger))
        lines.extend(_consumer_health_lines(ledger))
        lines.extend(_stood_down_lines(ledger))
        lines.extend(_no_work_lines(ledger))

        streaks = _skip_streak_lines(ledger)
        if streaks:
            lines.append("  per-tool skip streaks:")
            lines.extend(streaks)

        historical = _unrotated_historical_lines(state)
        if historical:
            lines.append("  unrotated historical secrets:")
            lines.extend(historical)

        unreachable_candidates = _unreachable_candidate_lines(root, cfg, state)
        if unreachable_candidates:
            lines.append("  unreachable candidates:")
            lines.extend(unreachable_candidates)

        lines.extend(_bake_lines(cfg, state))

        # --- Phase 2b: LLM review status (spec section 7) ---
        lines.extend(_llm_lines(cfg, state))

        # --- Phase 2a: queue / drain / registry / schedule (spec section 2) ---
        lines.extend(_queue_lines(ledger))
        lines.append(_last_drain_line(ledger))
        lines.append(_registry_line(root))
        lines.append(_scheduled_drain_line())

        print("\n".join(lines))
        return 0
    except Exception as exc:
        print(f"aramid: status: engine error: {exc}", file=sys.stderr)
        return 3
    finally:
        ledger.close()
