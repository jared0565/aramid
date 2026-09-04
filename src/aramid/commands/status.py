"""status -- read-only ledger/config report: last run, open counts,
NEW-since-baseline, aging (>30d), per-tool skip streaks, unrotated
historical secrets, and -- while unarmed -- the WARN-only bake's day count
plus per-rule semgrep hit counts (design doc section 8: this is the bake's
whole functional purpose -- letting the operator spot and demote noisy
rules in `aramid.toml` before `aramid arm`). Pure reporting: never mutates
the ledger, never runs a gate.
"""
import sys
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import health
from aramid import review
from aramid import toolset
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
    events = ledger.events()
    runs = [e for e in events if e.type is EventType.RUN_FINISHED]
    if not runs:
        return "last run: none"
    last = runs[-1]
    # Name the gate: the newest run is whatever ran last, and after `aramid
    # init` that is the full-history scan, not a gate -- read without the
    # label, its line looked like a gate's (interop round 172 s3). The gate
    # sits on the run's RUN_STARTED payload; a ledger without it keeps the
    # old shape rather than inventing one.
    gate = next((e.payload.get("gate") for e in events
                 if e.type is EventType.RUN_STARTED and e.run_id == last.run_id), None)
    label = f"{gate} run {last.run_id}" if gate else f"run {last.run_id}"
    line = f"last run: {last.at} ({label}, {last.payload.get('blocking', 0)} blocking"
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
            f"superseded: {counts.get('superseded', 0)}, "
            f"out-of-scope: {counts.get('out_of_scope', 0)}, "
            f"pending-retest: {counts.get('pending_retest', 0)}, "
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
    """Rendered from `health.snapshot`; the streak rule and its history live
    in aramid.health.skip_streaks."""
    return health.skip_streak_lines(health.snapshot(None, ledger))


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


def _out_of_scope_candidate_lines(root: Path, cfg, state: dict) -> list[str]:
    """The other stranded shape: an open finding whose tool is still selected
    (so it is not a ghost) but whose path that tool's runner will never
    examine again (so no run can resolve it). Interop round 144: two
    `mypy:syntax` rows on `ci.yml`/`README.md` after the runner was scoped
    to .py/.pyi. One line per candidate, naming the exact command."""
    selected = toolset.selected_tool_names(root, cfg)
    candidates = toolset.out_of_scope_candidates(state, selected, root=root)
    return [
        f"  {fid} {rec.get('tool')}:{rec.get('rule')} {rec.get('file')} -- "
        f"{rec.get('tool')} no longer examines this path? "
        f"`aramid ledger resolve {fid} --out-of-scope --reason ...`"
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


def _agent_surfaces_line(root: Path, cfg: config_mod.Config) -> str:
    from aramid import agent_files, agent_mcp, agent_settings
    states = agent_files.agent_block_states(root)
    ok = sum(1 for _, s in states if s == "ok")
    posture = "armed" if cfg.agent_block_armed else "baking"
    return (f"agent surfaces: blocks {ok}/{len(states)}, "
            f"hooks {agent_settings.settings_state(root)}, "
            f"mcp {agent_mcp.mcp_state(root)} | {posture}")


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
    # Why the last drain did not open it, when it did not (round 177): a
    # starved repo's `status` used to read like one nothing had looked at.
    deferral = (f", deferred {q.deferred}x: {q.deferred_reason}"
                if getattr(q, "deferred", 0) else "")
    lines = [f"queue: {len(queued)} queued (score {q.score}, {age_h}h old{deferral}) | "
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
    return health.degraded_consumer_lines(health.snapshot(None, ledger))


def _stood_down_lines(ledger: Ledger) -> list[str]:
    return health.stood_down_lines(health.snapshot(None, ledger))


def _no_work_lines(ledger: Ledger) -> list[str]:
    return health.no_work_lines(health.snapshot(None, ledger))


def _resolver_defect_lines(ledger: Ledger) -> list[str]:
    return health.resolver_defect_lines(health.snapshot(None, ledger))


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

        h = health.snapshot(cfg, ledger)
        lines.extend(health.resolver_defect_lines(h))
        lines.extend(health.degraded_consumer_lines(h))
        lines.extend(health.stood_down_lines(h))
        lines.extend(health.no_work_lines(h))

        streaks = health.skip_streak_lines(h)
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
        out_of_scope_candidates = _out_of_scope_candidate_lines(root, cfg, state)
        if out_of_scope_candidates:
            lines.append("  out-of-scope candidates:")
            lines.extend(out_of_scope_candidates)

        lines.extend(_bake_lines(cfg, state))
        lines.append(_agent_surfaces_line(root, cfg))

        # --- Phase 2b: LLM review status (spec section 7) ---
        lines.extend(_llm_lines(cfg, state))

        # --- Phase 2a: queue / drain / registry / schedule (spec section 2) ---
        lines.extend(_queue_lines(ledger))
        lines.append(_last_drain_line(ledger))
        lines.append(_registry_line(root))
        lines.append(_scheduled_drain_line())

        # --- fleet health (fleet-readiness spec section 8) ---
        from aramid import fleet
        lines.extend(fleet.delivery_lines(root, surface="status",
                                          now=datetime.now(timezone.utc).isoformat()))

        print("\n".join(lines))
        return 0
    except Exception as exc:
        print(f"aramid: status: engine error: {exc}", file=sys.stderr)
        return 3
    finally:
        ledger.close()
