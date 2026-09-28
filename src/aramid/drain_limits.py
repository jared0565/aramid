"""The three clocks a scheduled drain lives under, from one source (FN-14).

    drain deadline  <  task time limit  <  schedule interval

The scheduled drain ran into the task's ExecutionTimeLimit -- a hard-coded
PT1H under a four-hour interval -- in the middle of a consumer (2026-09-25
22Z, and 09-27 02Z inside a mutation run). Task Scheduler's kill runs no
`finally`: no CONSUMER_RUN_FINISHED row, so consumer health (built only
from those rows) never saw the run, and a leaked ~/.aramid/drain.lock.
The order above makes the drain the one that stops itself, at its own
deadline, where it can still write the row and release the lock
(`commands.drain._Watchdog`). The task limit stays as the
backstop for a drain too wedged to do even that; cron has no limit at all,
so on Linux and macOS the deadline is the only one.

Pure arithmetic over config values, no I/O: `schedule` renders the task
limit from it and `drain` arms its watchdog from it, so the two can never
disagree about the order."""
import math

# 90 minutes: one mutation consumer run can take 25 (commands/drain.py's
# budget note), and a drain may carry several items. Operator ruling
# 2026-09-27: "90 min default, configurable" as `[drain].hard_deadline_s`.
DEFAULT_HARD_DEADLINE_S = 5400
_DEFAULT_INTERVAL_HOURS = 4          # defaults.toml [drain].interval_hours
_TASK_MARGIN_MIN = 5                 # task limit sits this far under the interval
_DEADLINE_MARGIN_S = 900             # the deadline sits this far under the interval
_MIN_DEADLINE_S = 60                 # a smaller setting would kill every drain at once
_TASK_LIMIT_MARGIN_S = 300           # the deadline sits this far under an installed task's limit


def _hours(value) -> int:
    """The interval as `schedule` installs it: whole hours, floored at one
    (`render_cron_line` floors the same way). Unusable reads as the default,
    because `load_config` passes a mistyped value through with a warning."""
    if isinstance(value, bool):
        return _DEFAULT_INTERVAL_HOURS
    try:
        return max(1, int(value))
    except (TypeError, ValueError, OverflowError):
        return _DEFAULT_INTERVAL_HOURS


def task_limit_minutes(interval_hours) -> int:
    """The scheduled task's ExecutionTimeLimit: five minutes under the
    interval, so a drain the limit has to kill is gone before the next
    start -- which IgnoreNew would otherwise skip."""
    return _hours(interval_hours) * 60 - _TASK_MARGIN_MIN


def task_limit_iso(interval_hours) -> str:
    """`task_limit_minutes` as the ISO 8601 duration Task Scheduler STORES:
    PT235M registered reads back as PT3H55M (measured 2026-09-28), so
    writing the stored form lets `status` compare like with like."""
    hours, minutes = divmod(task_limit_minutes(interval_hours), 60)
    return f"PT{hours}H{minutes}M" if hours else f"PT{minutes}M"


def _deadline_setting(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if math.isnan(value) or value <= 0:
        return None
    return float(value)


def drain_deadline_s(cfgs, *, task_limit_minutes: int | None = None) -> float:
    """Seconds from the drain's start to its hard deadline, given the
    candidate repos' configs. The widest `[drain].hard_deadline_s` asked
    for wins -- the shape of `wall_clock_budget_s`, the max across
    candidates -- but never past fifteen minutes under the SHORTEST
    interval any candidate is scheduled at. No candidates, or no usable
    setting: the default, under the same ceiling.

    `task_limit_minutes` is the INSTALLED task's own limit when there is
    one (`schedule.installed_task_limit_minutes`), and the deadline also
    sits five minutes under it. The candidates' configs are not what the
    task was installed with, and a task installed before this fix keeps
    its one-hour limit until `schedule install` is re-run: without this,
    Task Scheduler would still kill first there. None or 0 (Task
    Scheduler's "no limit") clamps nothing."""
    cfgs = list(cfgs)
    intervals = [_hours(c.drain.get("interval_hours", _DEFAULT_INTERVAL_HOURS)) for c in cfgs]
    ceiling = min(intervals, default=_DEFAULT_INTERVAL_HOURS) * 3600 - _DEADLINE_MARGIN_S
    if task_limit_minutes:
        ceiling = min(ceiling, task_limit_minutes * 60 - _TASK_LIMIT_MARGIN_S)
    wanted = [s for s in (_deadline_setting(c.drain.get("hard_deadline_s")) for c in cfgs)
              if s is not None]
    return max(float(_MIN_DEADLINE_S), min(max(wanted, default=float(DEFAULT_HARD_DEADLINE_S)),
                                            float(ceiling)))
