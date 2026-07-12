"""integration: `aramid status` -- read-only ledger/config report. Never
mutates the ledger, never runs a gate.
"""
import subprocess
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid.commands.status import cmd_status
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict


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
