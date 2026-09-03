"""health -- one snapshot of a repo's gate health, computed once and read
everywhere. Spec: docs/superpowers/specs/2026-09-02-aramid-fleet-readiness-
design.md, sections 4 and 5.

`aramid status` prints skip streaks, degraded / stood-down / no-work consumer
streaks and resolver defects; the fleet health row (aramid.fleet) grades the
same five signals as booleans. Two computations of one fact drift, so both
surfaces read ONE `Health` built here: `status`'s `_x_lines` render from it,
`criteria()` grades it, and tests/unit/test_health.py perturbs a snapshot
and asserts the line and the grade move together.

Pure computation over a ledger plus, optionally, one `GateResult`. Every
ledger-derived signal degrades to "nothing found" on a ledger-shaped fault,
the way `status` already did -- a broken diagnostic must not take down the
report, and must not take down the gate that records the row.
"""
from collections import defaultdict
from dataclasses import dataclass, field

from aramid import config as config_mod
from aramid import yield_report
from aramid.models import EventType, Gate, Verdict
from aramid.pipeline import GATE_RUNNER_KEYS
from aramid.runners.deps import NAME_PIP_AUDIT

CRITERIA = ("no_skip_streak", "consumers_healthy", "resolvers_ok",
            "no_self_inflicted_block", "dep_audit_ran")

# A give-up note's shared marker. Every consumer that stands down says
# "giving up" (mutation, js mutation, llm_review, fuzz, dast), so one marker
# reaches all of them -- and a consumer that invents different wording simply
# goes unreported here rather than breaking anything.
_GIVE_UP_MARK = "giving up"
# A run that finished cleanly and certified nothing. Distinct from a give-up:
# the consumer has NOT stopped, it will run again next drain and burn the same
# time again. `degraded` would pin the queue item, so these runs are
# legitimately `ok` and would otherwise be invisible.
_NO_WORK_MARKS = ("no mutants tested", "no cases run")


@dataclass(frozen=True)
class ConsumerFault:
    name: str
    count: int          # streak length, or runs since the last real one
    spent_s: float
    note: str


@dataclass(frozen=True)
class Health:
    skip_streaks: dict = field(default_factory=dict)   # gate -> {tool: streak}, > 0 only
    degraded_consumers: tuple = ()
    stood_down: tuple = ()
    no_work: tuple = ()
    resolver_defects: tuple = ()                       # (resolver, tool, verdict)
    open: int = 0
    armed: dict = field(default_factory=dict)
    # Per-run facts; meaningful only when built from a GateResult or an
    # engine error.
    gate: str | None = None
    run_id: str | None = None
    exit_code: int | None = None
    blocking: int = 0
    bad_tools: tuple = ()
    degraded_block_tier: bool = False
    engine_error: bool = False
    dep_audit_ran: bool | None = None


# --- the five ledger signals -------------------------------------------------

def skip_streaks(ledger) -> dict[str, dict[str, int]]:
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
        return {}
    by_gate: dict[str, list] = defaultdict(list)
    for e in runs:
        by_gate[str(e.payload.get("gate", "?"))].append(e)
    out: dict[str, dict[str, int]] = {}
    for gate in sorted(by_gate):
        gate_runs = by_gate[gate]
        expected: set[str] | None = None
        for e in reversed(gate_runs):
            if "expected" in e.payload:
                expected = {str(t) for t in (e.payload.get("expected") or ())}
                break
        if expected is None:
            expected = set()
            for e in gate_runs:
                expected.update(e.payload.get("tools", []))
        streaks: dict[str, int] = {}
        for tool in sorted(expected):
            streak = 0
            for e in reversed(gate_runs):
                if tool in e.payload.get("tools", []):
                    break
                streak += 1
            if streak:
                streaks[tool] = streak
        if streaks:
            out[gate] = streaks
    return out


def _consumer_runs(ledger) -> dict[str, list[tuple[str, str, float]]]:
    runs: dict[str, list[tuple[str, str, float]]] = defaultdict(list)
    for e in ledger.events():
        if e.type is EventType.CONSUMER_RUN_FINISHED:
            runs[str(e.payload.get("consumer", "?"))].append(
                (str(e.payload.get("state", "")),
                 str(e.payload.get("note", "")),
                 float(e.payload.get("duration_s") or 0.0)))
    return runs


def _degraded(runs) -> list[ConsumerFault]:
    faults = []
    for name in sorted(runs):
        streak, note = 0, ""
        for state, run_note, _duration in reversed(runs[name]):
            if state not in ("degraded", "error"):
                break
            streak += 1
            note = note or run_note
        if streak:
            faults.append(ConsumerFault(name, streak, 0.0, note))
    return faults


def _stood_down(runs) -> list[ConsumerFault]:
    faults = []
    for name in sorted(runs):
        seq = runs[name]
        if not seq or _GIVE_UP_MARK not in seq[-1][1]:
            continue
        count, spent = 0, 0.0
        for state, run_note, duration in reversed(seq):
            if state not in ("degraded", "error") and _GIVE_UP_MARK not in run_note:
                break
            count += 1
            spent += duration
        faults.append(ConsumerFault(name, count, spent, seq[-1][1]))
    return faults


def _certified_nothing(note: str) -> bool:
    return any(mark in note for mark in _NO_WORK_MARKS)


def _no_work(runs) -> list[ConsumerFault]:
    faults = []
    for name in sorted(runs):
        seq = runs[name]
        if not seq or not _certified_nothing(seq[-1][1]):
            continue
        count, spent = 0, 0.0
        for _state, note, duration in reversed(seq):
            if not _certified_nothing(note):
                break
            count += 1
            spent += duration
        faults.append(ConsumerFault(name, count, spent, seq[-1][1]))
    return faults


def degraded_consumers(ledger) -> list[ConsumerFault]:
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
        return _degraded(_consumer_runs(ledger))
    except Exception:
        return []


def stood_down(ledger) -> list[ConsumerFault]:
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
        return _stood_down(_consumer_runs(ledger))
    except Exception:
        return []


def no_work(ledger) -> list[ConsumerFault]:
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
        return _no_work(_consumer_runs(ledger))
    except Exception:
        return []


def resolver_defects(ledger) -> list[tuple[str, str, str]]:
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
        rows = yield_report.collect(ledger)
    except Exception:
        return []
    return sorted((r.resolver, r.tool, r.verdict) for r in rows if r.flagged)


# --- the snapshot -------------------------------------------------------------

def _dep_audit_ran(gate, result, tools_ran: set[str]) -> bool | None:
    """Tri-state (spec section 4, criterion 5). None: the deps runner is not
    part of this gate, or this is not a Python repo. True: pip-audit
    finished OK -- `runners.deps.run_python` returns MISSING when it finds no
    requirements file, so OK already means at least one file was audited
    (`RunnerResult.examined` is None for this runner; there is nothing
    further to check). False otherwise -- and a pyproject-only Python repo
    lands here on every pre-push, which is the open `aramid doctor` lead
    this criterion exists to keep visible until it is fixed."""
    if gate is None or result is None:
        return None
    try:
        keys = GATE_RUNNER_KEYS.get(Gate(str(gate)), ())
    except ValueError:
        return None
    if "deps" not in keys or "python" not in (getattr(result, "stacks", ()) or ()):
        return None
    return NAME_PIP_AUDIT in tools_ran


def snapshot(cfg, ledger, result=None, *, gate=None, engine_error: bool = False) -> Health:
    """THE health computation. `cfg` None -> no armed flags known; `ledger`
    None -> no ledger signals (the engine-error path where the ledger never
    opened); `result` None -> no per-run facts. `engine_error` marks a run
    that died before it produced a result: every criterion reads red except
    the audit, which reads unknown."""
    armed = config_mod.arming_state(cfg) if cfg is not None else {}
    streaks: dict = {}
    degraded: list = []
    down: list = []
    idle: list = []
    defects: list = []
    open_n = 0
    if ledger is not None:
        try:
            streaks = skip_streaks(ledger)
        except Exception:
            streaks = {}
        try:
            runs = _consumer_runs(ledger)
        except Exception:
            runs = {}
        degraded, down, idle = _degraded(runs), _stood_down(runs), _no_work(runs)
        defects = resolver_defects(ledger)
        try:
            open_n = sum(1 for rec in ledger.open_findings().values()
                         if rec.get("status") == "open")
        except Exception:
            open_n = 0
    base = dict(skip_streaks=streaks, degraded_consumers=tuple(degraded),
                stood_down=tuple(down), no_work=tuple(idle),
                resolver_defects=tuple(defects), open=open_n, armed=armed,
                gate=str(gate) if gate is not None else None,
                engine_error=engine_error)
    if engine_error or result is None:
        return Health(**base, exit_code=3 if engine_error else None)
    tools_ran = {str(t) for t in (getattr(result, "tools_ran", ()) or ())}
    return Health(**base,
                  run_id=str(getattr(result, "run_id", "") or "") or None,
                  exit_code=result.exit_code,
                  blocking=sum(1 for f in result.findings if f.verdict is Verdict.BLOCK),
                  bad_tools=tuple(result.degraded),
                  degraded_block_tier=bool(result.degraded_block_tier),
                  dep_audit_ran=_dep_audit_ran(gate, result, tools_ran))


def criteria(h: Health) -> dict:
    """The five per-row criteria (spec section 4), keyed as the row records
    them. A block on a GENUINE finding is green for criterion 4 -- that is the
    gate working; only aramid's own machinery failing (a BLOCK-tier tool
    missing/crashed/timed out, or an engine error) is red."""
    if h.engine_error:
        return {"no_skip_streak": False, "consumers_healthy": False,
                "resolvers_ok": False, "no_self_inflicted_block": False,
                "dep_audit_ran": None}
    return {
        "no_skip_streak": not h.skip_streaks,
        "consumers_healthy": not (h.degraded_consumers or h.stood_down or h.no_work),
        "resolvers_ok": not h.resolver_defects,
        "no_self_inflicted_block": not h.degraded_block_tier,
        "dep_audit_ran": h.dep_audit_ran,
    }


def row_green(crit: dict) -> bool:
    """Green when criteria 1-4 are true and 5 is true or null."""
    return (all(crit.get(k) is True for k in CRITERIA[:4])
            and crit.get("dep_audit_ran") in (True, None))


# --- rendering, byte-identical to what `status` printed before this module --

def skip_streak_lines(h: Health) -> list[str]:
    return [f"  {tool}: skipped last {streak} {gate} run(s)"
            for gate in sorted(h.skip_streaks)
            for tool, streak in sorted(h.skip_streaks[gate].items())]


def degraded_consumer_lines(h: Health) -> list[str]:
    faults = [f"    {f.name}: degraded last {f.count} run(s)"
              + (f" -- {f.note}" if f.note else "")
              for f in h.degraded_consumers]
    return ["  degraded consumer runs:", *faults] if faults else []


def stood_down_lines(h: Health) -> list[str]:
    faults = [f"    {f.name}: stood down after {f.count} run(s), "
              f"{f.spent_s:.0f}s spent -- {f.note}"
              for f in h.stood_down]
    return ["  consumers stood down:", *faults] if faults else []


def no_work_lines(h: Health) -> list[str]:
    faults = [f"    {f.name}: {f.count} run(s) certified nothing, "
              f"{f.spent_s:.0f}s spent -- {f.note}"
              for f in h.no_work]
    return ["  consumers doing no work:", *faults] if faults else []


def resolver_defect_lines(h: Health) -> list[str]:
    if not h.resolver_defects:
        return []
    names = ", ".join(sorted({f"{r}/{t}" for r, t, _v in h.resolver_defects}))
    return [f"  resolver defects: {len(h.resolver_defects)} (run `aramid resolvers`)",
            f"    {names}"]
