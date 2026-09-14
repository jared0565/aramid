"""`aramid status`'s line renderers at unit scope on a real tmp ledger: the
aging count, the bake-day and per-rule lines, the queue line for a single
queued item, and the command's two engine-error exits.

The drain confirms a mutant against the unit suite alone, and eight of this
module's generator mutants sat on lines the unit suite never executed --
the aging increment, the bake day's `+ 1`, the per-rule hit increment and
the (-count, rule) sort key, the first queued item, both `return 3`s:
tests/integration/test_status*.py cover them and the drain never runs that
directory."""
import uuid
from datetime import date, datetime, timedelta, timezone

from aramid import config as config_mod
from aramid import queue as queue_mod
from aramid.commands import status
from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _ledger(tmp_path):
    return Ledger(tmp_path / ".aramid" / "ledger.db")


def _detect(led, fid, at, tool="semgrep", rule="r"):
    led.append(Event(EventType.FINDING_DETECTED, uuid.uuid4().hex, at, finding_id=fid,
                     payload={"tool": tool, "rule": rule, "file": "a.py", "verdict": "warn",
                              "severity": "high", "line": 1, "message": "m",
                              "evidence": "", "historical": False}))


def _iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


# ------------------------------------------------------------- _aging_line --

def test_aging_line_counts_only_open_findings_past_the_window(tmp_path):
    led = _ledger(tmp_path)
    try:
        _detect(led, "a" * 64, _iso(status._AGING_DAYS + 5))          # old and open
        _detect(led, "b" * 64, _iso(status._AGING_DAYS + 5))          # old but fixed
        led.append(Event(EventType.FINDING_RESOLVED, uuid.uuid4().hex, _iso(1),
                         finding_id="b" * 64))
        _detect(led, "c" * 64, _iso(status._AGING_DAYS - 1))          # young
        state = led.open_findings()
        assert status._aging_line(led, state) == \
            f"aging: 1 finding(s) open > {status._AGING_DAYS}d"
    finally:
        led.close()


# -------------------------------------------------------------- _bake_lines --

def _cfg(**over):
    base = dict(schema_version=1, semgrep_block_armed=False, bake_started=None,
                ignore_paths=[], test_command=None, scope_subpath=None, timeouts={},
                block_rules={}, triage={}, drain={}, pack={}, llm={}, mutation={},
                shadow={}, fuzz={}, js_mutation={})
    base.update(over)
    fields = {f for f in config_mod.Config.__dataclass_fields__}
    return config_mod.Config(**{k: v for k, v in base.items() if k in fields})


def test_bake_lines_day_count_and_per_rule_hits_sorted_by_count_then_name():
    today = date.today().isoformat()
    state = {"1": {"tool": "semgrep", "rule": "z-rule"},
             "2": {"tool": "semgrep", "rule": "a-rule"},
             "3": {"tool": "semgrep", "rule": "m-rule"},
             "4": {"tool": "semgrep", "rule": "m-rule"},
             "5": {"tool": "ruff", "rule": "F401"}}
    assert status._bake_lines(_cfg(bake_started=today), state) == [
        "bake in progress, day 1",
        "semgrep per-rule hit counts (demote noisy rules before `aramid arm`):",
        "  m-rule: 2",
        "  a-rule: 1",
        "  z-rule: 1"]
    week_ago = (date.today() - timedelta(days=7)).isoformat()
    assert status._bake_lines(_cfg(bake_started=week_ago), {}) == ["bake in progress, day 8"]
    assert status._bake_lines(_cfg(bake_started="last tuesday"), {}) == [
        "bake in progress, day ? (unparseable bake_started in aramid.toml)"]
    assert status._bake_lines(_cfg(), {}) == [
        "bake in progress, day ? (bake_started not set in aramid.toml)"]
    assert status._bake_lines(_cfg(semgrep_block_armed=True, bake_started=today), state) == []


# ------------------------------------------------------------- _queue_lines --

def test_queue_line_describes_the_single_queued_item(tmp_path):
    led = _ledger(tmp_path)
    try:
        assert status._queue_lines(led) == ["queue: empty"]
        # 100 whole hours: `// 3600` reads 100h and the derive's `// 3601`
        # would read 99h (a 5h30m age floored the same under both)
        at = (datetime.now(timezone.utc) - timedelta(hours=100)).isoformat()
        queue_mod.enqueue(led, at, "a" * 40, "b" * 40, 75,
                          ["security-path: src/auth.py", "novelty: 1 unseen path(s)"])
        assert status._queue_lines(led) == [
            "queue: 1 queued (score 75, 100h old) | 0 drained | 0 expired",
            "  novelty: 1 unseen path(s)",
            "  security-path: src/auth.py"]
    finally:
        led.close()


# --------------------------------------------------------------- cmd_status --

def test_status_exits_3_on_an_unparseable_config(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("this is = not = toml\n", encoding="utf-8")
    assert status.cmd_status(tmp_path) == 3
    out, err = capsys.readouterr()
    assert out == "" and err.startswith("aramid: status: engine error: ")


def test_status_exits_3_when_the_report_itself_fails(tmp_path, capsys, monkeypatch):
    def boom(self):
        raise RuntimeError("ledger torn")
    monkeypatch.setattr(Ledger, "open_findings", boom)
    assert status.cmd_status(tmp_path) == 3
    assert capsys.readouterr() == ("", "aramid: status: engine error: ledger torn\n")


def test_aging_line_excludes_a_finding_at_exactly_the_window(tmp_path):
    """`> _AGING_DAYS`, not `>=`: a finding detected the window's own
    number of days ago (plus an hour, so the day count is exact) is not
    yet aged. And the open test is `!= "open"`: a fixed one that old is
    not counted either way."""
    led = _ledger(tmp_path)
    try:
        at = (datetime.now(timezone.utc) - timedelta(days=status._AGING_DAYS, hours=1)).isoformat()
        _detect(led, "a" * 64, at)
        _detect(led, "b" * 64, _iso(status._AGING_DAYS + 5))
        led.append(Event(EventType.FINDING_RESOLVED, uuid.uuid4().hex, _iso(1),
                         finding_id="b" * 64))
        assert status._aging_line(led, led.open_findings()) == \
            f"aging: 0 finding(s) open > {status._AGING_DAYS}d"
        _detect(led, "c" * 64, _iso(status._AGING_DAYS + 1))
        assert status._aging_line(led, led.open_findings()) == \
            f"aging: 1 finding(s) open > {status._AGING_DAYS}d"
    finally:
        led.close()


def test_queue_lines_count_drained_and_expired_items_and_age_in_whole_hours(tmp_path):
    """The empty-queue line names the drained and expired counts whenever
    either is non-zero (`or`), one per item; a queued item's age is its
    seconds floored to hours (`// 3600`: 2h and 59 minutes reads 2h)."""
    led = _ledger(tmp_path)
    try:
        old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
        queue_mod.enqueue(led, old, "a" * 40, "b" * 40, 60, ["r"])
        assert len(queue_mod.expire_stale(led, _iso(0), 30)) == 1
        assert status._queue_lines(led) == ["queue: empty | 0 drained | 1 expired"], \
            "one count alone is enough for the counted line (the derive drew or -> and)"
        drained = queue_mod.enqueue(led, _iso(3), "c" * 40, "d" * 40, 60, ["r"])
        queue_mod.mark_drained(led, drained.id, uuid.uuid4().hex, _iso(2))
        assert status._queue_lines(led) == ["queue: empty | 1 drained | 1 expired"]

        at = (datetime.now(timezone.utc) - timedelta(hours=2, minutes=59)).isoformat()
        queue_mod.enqueue(led, at, "e" * 40, "f" * 40, 75, ["security-path: src/auth.py"])
        assert status._queue_lines(led) == [
            "queue: 1 queued (score 75, 2h old) | 1 drained | 1 expired",
            "  security-path: src/auth.py"]
    finally:
        led.close()


def test_scheduled_drain_line_probes_schtasks_on_windows_and_the_crontab_elsewhere(monkeypatch):
    """Both platform branches, faked at their seam, so the line's two
    comparisons run on every CI leg."""
    import subprocess
    import sys
    from types import SimpleNamespace

    from aramid.commands import schedule as schedule_mod
    calls = []
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "run",
                        lambda argv, **kw: calls.append(argv) or SimpleNamespace(returncode=0))
    assert status._scheduled_drain_line() == "scheduled drain: installed"
    assert calls == [schedule_mod._query_argv()]
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: SimpleNamespace(returncode=1))
    assert status._scheduled_drain_line() == "scheduled drain: not installed"

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0))
    monkeypatch.setattr(schedule_mod, "_read_crontab",
                        lambda: "0 3 * * * /x/backup.sh\n"
                                f"0 */4 * * * aramid {schedule_mod.CRON_MARKER}\n")
    assert status._scheduled_drain_line() == "scheduled drain: installed"
    monkeypatch.setattr(schedule_mod, "_read_crontab", lambda: "0 3 * * * /x/backup.sh\n")
    assert status._scheduled_drain_line() == "scheduled drain: not installed"


def test_status_exits_0_on_a_fresh_repo(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    assert status.cmd_status(tmp_path) == 0
    out, err = capsys.readouterr()
    assert err == "" and out.startswith("aramid status")
