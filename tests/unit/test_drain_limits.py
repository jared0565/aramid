"""FN-14: the three clocks a scheduled drain lives under, from one source.

The scheduled drain ran into Task Scheduler's ExecutionTimeLimit (PT1H,
hard-coded) mid-consumer, 2026-09-25 22Z and 09-27 02Z. The kill skipped
every `finally`: no CONSUMER_RUN_FINISHED row, so consumer health never saw
it, and a leaked ~/.aramid/drain.lock. The fix orders the clocks so the drain's own deadline
always fires first, where it can still record what it killed:

    drain deadline  <  task ExecutionTimeLimit  <  schedule interval

These pin that order for every interval, not the one on this machine."""
from types import SimpleNamespace

import pytest

from aramid import drain_limits


def _cfg(**drain):
    return SimpleNamespace(drain=drain)


def test_the_task_limit_sits_five_minutes_under_the_interval():
    assert drain_limits.task_limit_minutes(4) == 235
    assert drain_limits.task_limit_minutes(6) == 355
    assert drain_limits.task_limit_minutes(1) == 55


def test_the_task_limit_floors_the_interval_the_way_the_cron_line_does():
    """`render_cron_line` floors a zero or negative interval at one hour;
    a limit computed from the raw value would be negative."""
    assert drain_limits.task_limit_minutes(0) == 55
    assert drain_limits.task_limit_minutes(-3) == 55


@pytest.mark.parametrize("hours", [1, 2, 3, 4, 6, 8, 12, 24, 48])
def test_deadline_fires_before_the_task_limit_which_fires_before_the_next_start(hours):
    """The order that makes the drain the one that stops itself, for a task
    installed from these same intervals. Checked at the widest deadline a
    config can ask for. A task installed from a DIFFERENT interval is the
    installed-limit clamp's case, below."""
    widest = drain_limits.drain_deadline_s([_cfg(interval_hours=hours,
                                                 hard_deadline_s=10 ** 9)])
    task_limit_s = drain_limits.task_limit_minutes(hours) * 60
    assert widest < task_limit_s < hours * 3600


def test_the_default_deadline_is_ninety_minutes():
    assert drain_limits.DEFAULT_HARD_DEADLINE_S == 5400
    assert drain_limits.drain_deadline_s([_cfg(interval_hours=4)]) == 5400


def test_no_candidates_means_the_default_deadline():
    assert drain_limits.drain_deadline_s([]) == 5400


def test_a_configured_deadline_is_honoured_under_the_interval_ceiling():
    assert drain_limits.drain_deadline_s([_cfg(interval_hours=4, hard_deadline_s=1800)]) == 1800
    assert drain_limits.drain_deadline_s([_cfg(interval_hours=4, hard_deadline_s=7200)]) == 7200


def test_the_ceiling_is_fifteen_minutes_under_the_interval():
    """A one-hour schedule cannot run a ninety-minute drain: the next start
    would find the lock held and the task limit would kill it anyway."""
    assert drain_limits.drain_deadline_s([_cfg(interval_hours=1)]) == 2700
    assert drain_limits.drain_deadline_s([_cfg(interval_hours=1, hard_deadline_s=5400)]) == 2700


def test_the_widest_request_wins_and_the_tightest_interval_bounds_it():
    """Same shape as `wall_clock_budget_s` (the max across candidates): one
    repo asking for longer gets it, but never past the shortest interval
    any candidate is scheduled at."""
    cfgs = [_cfg(interval_hours=4, hard_deadline_s=1800),
            _cfg(interval_hours=4, hard_deadline_s=3600)]
    assert drain_limits.drain_deadline_s(cfgs) == 3600
    cfgs.append(_cfg(interval_hours=1))
    assert drain_limits.drain_deadline_s(cfgs) == 2700


@pytest.mark.parametrize("bad", [0, -5, "soon", None, float("nan"), True])
def test_an_unusable_setting_falls_back_to_the_default(bad):
    """Zero or negative would kill every drain at once; a non-number cannot
    be compared. Neither may take the scheduled drain down, so both read
    as unset. `True` is an int to Python and is refused like the rest."""
    assert drain_limits.drain_deadline_s([_cfg(interval_hours=4, hard_deadline_s=bad)]) == 5400


def test_an_unusable_interval_reads_as_the_default_interval():
    assert drain_limits.drain_deadline_s([_cfg(interval_hours="often")]) == 5400


def test_a_tiny_positive_deadline_is_floored_at_a_minute():
    assert drain_limits.drain_deadline_s([_cfg(interval_hours=4, hard_deadline_s=5)]) == 60


# --- the installed task's own limit -------------------------------------------
# The candidates' configs are not what the task was installed with, and a
# task installed before FN-14 keeps PT1H until `schedule install` is re-run.

def test_a_one_hour_task_pulls_the_deadline_under_it():
    """This machine on the day 0.19.1 is installed, before the re-install:
    the 90-minute default would lose to the task's kill at 60."""
    assert drain_limits.drain_deadline_s([_cfg(interval_hours=4)], task_limit_minutes=60) == 3300


def test_a_current_task_limit_leaves_the_interval_ceiling_in_charge():
    assert drain_limits.drain_deadline_s([_cfg(interval_hours=4)], task_limit_minutes=235) == 5400
    assert drain_limits.drain_deadline_s([_cfg(interval_hours=4, hard_deadline_s=10 ** 9)],
                                         task_limit_minutes=235) == 13500


def test_no_task_or_no_limit_clamps_nothing():
    """PT0S is Task Scheduler's "no limit"; None is no task (cron, or not
    installed)."""
    for limit in (None, 0):
        assert drain_limits.drain_deadline_s([_cfg(interval_hours=4)],
                                             task_limit_minutes=limit) == 5400


@pytest.mark.parametrize("limit", [5, 55, 60, 235, 355, 4320])
@pytest.mark.parametrize("hours", [1, 4, 24])
def test_the_deadline_always_falls_before_the_installed_limit(hours, limit):
    """Whatever the task was installed with and whatever the repos ask for.
    Under the floor the order cannot be kept; a five-minute limit is not
    one `schedule install` writes."""
    widest = drain_limits.drain_deadline_s([_cfg(interval_hours=hours, hard_deadline_s=10 ** 9)],
                                           task_limit_minutes=limit)
    if limit * 60 > 60 + 300:
        assert widest < limit * 60
    else:
        assert widest == 60
