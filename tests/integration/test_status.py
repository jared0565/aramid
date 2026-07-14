"""integration: `aramid status` -- read-only ledger/config report. Never
mutates the ledger, never runs a gate.
"""
import subprocess
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from aramid import config as config_mod
from aramid.commands import schedule as schedule_mod
from aramid.commands.status import cmd_status
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Source, Verdict


@pytest.fixture(autouse=True)
def _no_real_schtasks(monkeypatch):
    """cmd_status's `scheduled drain` line queries the host Task Scheduler via
    `schtasks /Query`. Keep the suite off the real scheduler (codebase
    convention: mock `schedule.subprocess.run`, cf. tests/unit/test_schedule.py).
    status.py's `_scheduled_drain_line` uses a bare `subprocess.run`, which is
    the very same stdlib module object as `schedule.subprocess` -- so patching
    `run` here intercepts it too. We branch on argv so only schtasks is faked;
    everything else (notably `_git`) still runs for real."""
    real_run = subprocess.run

    def fake_run(argv, *a, **k):
        if argv and argv[0] == "schtasks":
            class _R:
                returncode = 1  # -> status prints "scheduled drain: not installed"
                stdout = ""
                stderr = ""
            return _R()
        return real_run(argv, *a, **k)

    monkeypatch.setattr(schedule_mod.subprocess, "run", fake_run)


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name="r") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "a.py")
    _git(r, "commit", "-q", "-m", "initial")
    return r


def _no_user_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")


def _f(fid, tool="semgrep", rule="owasp-top-ten.sqli", verdict=Verdict.WARN, file="a.py",
       historical=False):
    return Finding(fid, tool, rule, "ERROR", Severity.HIGH, verdict, file, 1, "m", "e",
                    Gate.PRE_PUSH, historical=historical)


def _write_toml(root, armed, bake_started):
    text = f'schema_version = 1\nsemgrep_block_armed = {"true" if armed else "false"}\n'
    if bake_started:
        text += f'bake_started = "{bake_started}"\n'
    (root / "aramid.toml").write_text(text, encoding="utf-8")


# ------------------------------------------------ bake day-N + rule counts --

def test_status_shows_bake_day_and_semgrep_rule_hit_counts(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    started = (date.today() - timedelta(days=5)).isoformat()
    _write_toml(root, armed=False, bake_started=started)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "pre-push", {"semgrep"}, {"a.py"}, [
        _f("f1", rule="owasp-top-ten.sqli"),
        _f("f2", rule="owasp-top-ten.sqli", file="b.py"),
        _f("f3", rule="owasp-top-ten.xss", file="c.py"),
    ])
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "bake in progress, day 6" in out
    assert "owasp-top-ten.sqli: 2" in out
    assert "owasp-top-ten.xss: 1" in out


def test_status_omits_bake_lines_when_armed(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=date.today().isoformat())

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "pre-push", {"semgrep"}, {"a.py"},
                       [_f("f1")])
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "bake in progress" not in out


# ------------------------------------------------------------ open counts ---

def test_status_reports_open_finding_count(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "pre-push", {"semgrep"},
                       {"a.py", "b.py"}, [_f("f1"), _f("f2", file="b.py")])
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "open findings: 2" in out


# ------------------------------------------------------ NEW since baseline --

def test_status_reports_new_since_baseline(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.write_baseline("base", "2026-01-01T00:00:00+00:00", {"f1"})
    ledger.record_run("run1", "2026-01-02T00:00:00+00:00", "pre-push", {"semgrep"},
                       {"a.py", "b.py"}, [_f("f1"), _f("f2", file="b.py")])
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "NEW since baseline: 1" in out


# -------------------------------------------------------------------- aging -

def test_status_counts_findings_older_than_30_days_as_aging(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    old_at = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.append(Event(EventType.RUN_STARTED, "run1", old_at,
                         payload={"gate": "pre-push", "tools": ["semgrep"]}))
    ledger.append(Event(EventType.FINDING_DETECTED, "run1", old_at, finding_id="old1",
                         payload={"tool": "semgrep", "rule": "r", "file": "a.py", "line": 1,
                                  "verdict": "warn", "severity": "high", "message": "m",
                                  "evidence": "e", "historical": False}))
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "aging: 1 finding" in out


# ------------------------------------------------------- per-tool skip streak

def test_status_reports_per_tool_skip_streak(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    # semgrep ran once, then was skipped (degraded/missing) for the next two runs.
    ledger.append(Event(EventType.RUN_STARTED, "run1", "2026-01-01T00:00:00+00:00",
                         payload={"gate": "pre-push", "tools": ["semgrep", "gitleaks"]}))
    ledger.append(Event(EventType.RUN_STARTED, "run2", "2026-01-02T00:00:00+00:00",
                         payload={"gate": "pre-push", "tools": ["gitleaks"]}))
    ledger.append(Event(EventType.RUN_STARTED, "run3", "2026-01-03T00:00:00+00:00",
                         payload={"gate": "pre-push", "tools": ["gitleaks"]}))
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "semgrep: skipped last 2 run(s)" in out
    assert "gitleaks" not in [l.strip().split(":")[0] for l in out.splitlines()
                               if "skipped" in l]


# ------------------------------------------------- unrotated historical ----

def test_status_lists_unrotated_historical_secrets(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "historical-scan", {"gitleaks"},
                       set(), [_f("hist1", tool="gitleaks", rule="aws-key", verdict=Verdict.BLOCK,
                                   historical=True)])
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "hist1" in out
    assert "rotate" in out.lower()


def test_status_rotated_secret_not_listed_as_unrotated(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "historical-scan", {"gitleaks"},
                       set(), [_f("hist1", tool="gitleaks", rule="aws-key", verdict=Verdict.BLOCK,
                                   historical=True)])
    ledger.append(Event(EventType.FINDING_ROTATED, "run2", "2026-01-02T00:00:00+00:00",
                         finding_id="hist1", payload={"reason": "rotated in AWS"}))
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "hist1" not in out


# ------------------------------------------------ queue / drain / registry --

def test_status_shows_queue_and_drain_sections(tmp_path, capsys, monkeypatch):
    from aramid import queue, registry
    from aramid.models import Event, EventType
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    root = tmp_path / "repo"
    (root / ".aramid").mkdir(parents=True)  # cmd_status needs only config+ledger, no git
    led = Ledger(root / ".aramid" / "ledger.db")
    queue.enqueue(led, "2026-07-13T00:00:00+00:00", "a", "b", 55, ["security-path: auth.py"])
    led.append(Event(EventType.CONSUMER_RUN_FINISHED, "r1", "2026-07-13T01:00:00+00:00",
                     payload={"consumer": "regression_pack", "finding_count": 2}))
    led.close()
    assert cmd_status(root) == 0
    out = capsys.readouterr().out
    assert "queue: 1 queued (score 55" in out
    assert "security-path: auth.py" in out
    assert "last drain: 2026-07-13T01:00:00+00:00 (regression_pack, 2 finding(s))" in out
    assert "registry: NOT registered" in out


def test_status_empty_queue_and_never_drained(tmp_path, capsys, monkeypatch):
    from aramid import registry
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    root = tmp_path / "repo"
    (root / ".aramid").mkdir(parents=True)
    Ledger(root / ".aramid" / "ledger.db").close()  # empty ledger
    assert cmd_status(root) == 0
    out = capsys.readouterr().out
    assert "queue: empty" in out
    assert "last drain: never" in out
    # Driven by the autouse _no_real_schtasks mock (returncode 1), not the host
    # scheduler -- confirms status.py's schtasks query is intercepted.
    assert "scheduled drain: not installed" in out


# ------------------------------------------------ LLM status lines (Phase 2b) -

def test_status_reports_llm_lines(tmp_path, capsys, monkeypatch):
    from aramid.providers import spend as spend_mod
    monkeypatch.setattr(spend_mod, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    _no_user_config(tmp_path, monkeypatch)
    r = _repo(tmp_path)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        f = Finding(id="f" * 64, tool="llm-review", rule="llm/a01",
                    severity_raw="critical", severity=Severity.CRITICAL,
                    verdict=Verdict.WARN, file="src/auth.py", line=2, message="IDOR",
                    evidence="return db.get(order_id)", gate=Gate.ALL,
                    source=Source.LLM, confirmed=True)
        led.record_run("r0", "2026-07-13T12:00:00+00:00", "drain", set(), set(), [f])
    finally:
        led.close()
    spend_mod.append_spend({"at": "2026-07-13T10:00:00+00:00", "provider": "openrouter",
                            "model": "m", "tokens_in": 1, "tokens_out": 1,
                            "cost_usd": 1.25})
    assert cmd_status(r) == 0
    out = capsys.readouterr().out
    assert "llm: 1 open (1 confirmed critical) | baking" in out
    assert "llm spend (openrouter, this month): $1.25 / $5.00" in out
