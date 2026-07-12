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
    return f"last run: {last.at} (run {last.run_id}, {last.payload.get('blocking', 0)} blocking)"


def _open_counts_line(state: dict) -> str:
    counts = Counter(rec.get("status") for rec in state.values())
    return (f"open findings: {counts.get('open', 0)} "
            f"(historical: {counts.get('historical', 0)}, overridden: {counts.get('overridden', 0)})")


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
    """For every tool that has ever appeared in a run's recorded scope,
    count how many of the most recent consecutive runs it was ABSENT from
    (skipped/degraded that run) -- design doc section 8's skip-visibility
    requirement ('semgrep: skipped last N runs')."""
    runs = [e for e in ledger.events() if e.type is EventType.RUN_STARTED]
    if not runs:
        return []

    all_tools: set[str] = set()
    for e in runs:
        all_tools.update(e.payload.get("tools", []))

    lines = []
    for tool in sorted(all_tools):
        streak = 0
        for e in reversed(runs):
            if tool in e.payload.get("tools", []):
                break
            streak += 1
        if streak:
            lines.append(f"  {tool}: skipped last {streak} run(s)")
    return lines


def _unrotated_historical_lines(state: dict) -> list[str]:
    lines = []
    for fid, rec in state.items():
        if rec.get("historical") and rec.get("status") == "historical":
            lines.append(
                f"  {fid} {rec.get('tool')}:{rec.get('rule')} {rec.get('file')} -- "
                f"rotate the credential, then `aramid ledger mark-rotated {fid} --reason ...`")
    return lines


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

        streaks = _skip_streak_lines(ledger)
        if streaks:
            lines.append("  per-tool skip streaks:")
            lines.extend(streaks)

        historical = _unrotated_historical_lines(state)
        if historical:
            lines.append("  unrotated historical secrets:")
            lines.extend(historical)

        lines.extend(_bake_lines(cfg, state))

        print("\n".join(lines))
        return 0
    except Exception as exc:
        print(f"aramid: status: engine error: {exc}", file=sys.stderr)
        return 3
    finally:
        ledger.close()
