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
from aramid import ledger as ledger_mod
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


def test_open_counts_line_names_every_status_member():
    """T-8 section 6: the printed buckets must enumerate every Status
    member -- not just the ones known when this line was last touched --
    so the NEXT status added fails this test instead of silently dropping
    out of the printed total (the T-11 move: make the failure mode
    mechanical, not dependent on someone noticing).

    This test is proven to fail against the PRE-T-8 tree for a DIFFERENT
    reason than the one this task fixes: "fixed" and "rotated" are ALSO
    absent from the current line, independent of "unreachable"."""
    from aramid.commands import status as status_mod
    from aramid.models import Status
    line = status_mod._open_counts_line({})
    for member in Status:
        if member is Status.OPEN:
            continue  # the leading bare count IS Status.OPEN; not a named bucket
        label = member.value.replace("_", "-")
        assert label in line, (
            f"Status.{member.name} ({member.value!r}) has no bucket in "
            f"_open_counts_line -- it would silently vanish from the printed total")


def test_status_reports_unreachable_count_in_open_counts_line(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "pre-push", {"ruff"},
                       {"a.py"}, [_f("f1", tool="ruff")])
    ledger.append(Event(EventType.FINDING_UNREACHABLE, "run2", "2026-01-02T00:00:00+00:00",
                        finding_id="f1", payload={"reason": "ruff not selected"}))
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "unreachable: 1" in out
    assert "unreachable candidates" not in out  # already retired, no longer a candidate


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
    assert "gitleaks" not in [ln.strip().split(":")[0] for ln in out.splitlines()
                              if "skipped" in ln]


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
    assert "real leak? rotate the credential" in out
    assert "aramid ledger mark-rotated hist1 --reason ..." in out


def test_status_unrotated_historical_hint_names_both_retirement_exits(
        tmp_path, monkeypatch, capsys):
    """Task 5: the nag is the one place a user sees the problem, so it must
    name BOTH retirement commands, not just `mark-rotated` -- otherwise a
    false positive (this repo's gitleaks generic-api-key hits were 3-for-3)
    has no discoverable way out short of reading the docs."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "historical-scan", {"gitleaks"},
                       set(), [_f("hist1", tool="gitleaks", rule="generic-api-key",
                                   verdict=Verdict.BLOCK, historical=True)])
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "aramid ledger mark-rotated hist1 --reason ..." in out
    assert "aramid ledger mark-not-a-secret hist1 --reason ..." in out


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


def test_status_lists_unreachable_candidate_and_the_exact_retire_command(
        tmp_path, monkeypatch, capsys):
    # A repo with NO .py files at all -- detect_stacks finds no "python"
    # stack, so ruff is never selected (unlike this file's own _repo()
    # fixture, which writes a.py and therefore keeps ruff selected).
    root = tmp_path / "r"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    (root / "README.md").write_text("hello\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-q", "-m", "initial")
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "pre-push", {"ruff"},
                       {"a.py"}, [_f("f1", tool="ruff", rule="F401")])
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "unreachable candidates:" in out
    assert "f1" in out
    assert "aramid ledger mark-unreachable f1 --reason ..." in out


def test_status_omits_unreachable_section_when_no_candidates(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    Ledger(root / ".aramid" / "ledger.db").close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "unreachable candidates" not in out


def test_status_not_a_secret_counted_and_removed_from_unrotated_listing(
        tmp_path, monkeypatch, capsys):
    """A finding marked not-a-secret (Task 2's `mark-not-a-secret`) is counted
    under the new `not-a-secret` bucket on the open-counts line, and -- same
    inherited filter as the mark-rotated case above -- drops out of the
    "unrotated historical secrets" listing because its status is no longer
    "historical"."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "historical-scan", {"gitleaks"},
                       set(), [_f("hist1", tool="gitleaks", rule="aws-key", verdict=Verdict.BLOCK,
                                   historical=True)])
    ledger.append(Event(EventType.FINDING_NOT_A_SECRET, "run2", "2026-01-02T00:00:00+00:00",
                         finding_id="hist1", payload={"reason": "test fixture value"}))
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "not-a-secret: 1" in out
    assert "unrotated historical secrets" not in out
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
    # Current month, NOT a literal: status reports spend MONTH-TO-DATE, so a
    # fixed date silently stops counting the moment the month rolls over --
    # this assertion went red on 2026-08-01 with `2026-07-13` hardcoded. The
    # ledger timestamp above is fine as a literal; it is only an event time and
    # is never compared against the clock.
    spend_at = datetime.now(timezone.utc).replace(
        day=13, hour=10, minute=0, second=0, microsecond=0).isoformat()
    spend_mod.append_spend({"at": spend_at, "provider": "openrouter",
                            "model": "m", "tokens_in": 1, "tokens_out": 1,
                            "cost_usd": 1.25})
    assert cmd_status(r) == 0
    out = capsys.readouterr().out
    assert "llm: 1 open (1 confirmed critical) | baking" in out
    assert "llm spend (openrouter, this month): $1.25 / $5.00" in out


def test_status_llm_spend_unreadable_degrades_without_crash(tmp_path, capsys, monkeypatch):
    """The one deliberate fail-closed money path (spec section 6): when
    month_spend_usd returns None (corrupt/unreadable spend log), status must
    surface 'unreadable -- openrouter disabled' and still exit 0 -- never
    crash, never guess a partial sum."""
    from aramid.providers import spend as spend_mod
    monkeypatch.setattr(spend_mod, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    monkeypatch.setattr(spend_mod, "month_spend_usd", lambda provider, now_iso: None)
    _no_user_config(tmp_path, monkeypatch)
    r = _repo(tmp_path)
    Ledger(r / ".aramid" / "ledger.db").close()  # empty ledger, no findings
    assert cmd_status(r) == 0
    out = capsys.readouterr().out
    assert "llm spend (openrouter, this month): unreadable -- openrouter disabled" in out


def test_status_reports_llm_ladder_line(tmp_path, capsys, monkeypatch):
    _no_user_config(tmp_path, monkeypatch)
    r = _repo(tmp_path)
    text = 'schema_version = 1\nsemgrep_block_armed = true\n'
    text += '\n[llm]\n'
    text += 'ladder = [\n'
    text += '  { tier = "fallback", provider = "openrouter" },\n'
    text += '  { tier = "primary", provider = "ollama-cloud" },\n'
    text += ']\n'
    (r / "aramid.toml").write_text(text, encoding="utf-8")
    Ledger(r / ".aramid" / "ledger.db").close()
    assert cmd_status(r) == 0
    out = capsys.readouterr().out
    assert any(ln.startswith("llm ladder:") for ln in out.splitlines())


def test_status_llm_ladder_skips_non_dict_entry_without_crash(tmp_path, capsys, monkeypatch):
    """Regression test for Fix 1: _llm_lines must not crash on non-dict ladder
    entries. Fail-open to match the convention in review.py's build_arms."""
    _no_user_config(tmp_path, monkeypatch)
    r = _repo(tmp_path)
    text = 'schema_version = 1\nsemgrep_block_armed = true\n'
    text += '\n[llm]\n'
    text += 'ladder = ["not-a-dict", { tier = "primary", provider = "ollama-cloud" }]\n'
    text += 'llm_block_armed = false\n'
    text += 'openrouter_monthly_cap_usd = 5.0\n'
    (r / "aramid.toml").write_text(text, encoding="utf-8")
    Ledger(r / ".aramid" / "ledger.db").close()
    assert cmd_status(r) == 0
    out = capsys.readouterr().out
    # Should complete without crash; may include ladder line with valid entries only
    assert "llm:" in out


def test_status_shows_autolearn_shadow_line(tmp_path, monkeypatch, capsys):
    from aramid import autolearn, config as config_mod
    from aramid.commands.status import cmd_status
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")
    st = autolearn.empty_state()
    st["shadow"] = {"decisions": 17, "would_uplift": 3}
    st["audits"] = {"performed": 5, "missed_criticals": 1}
    autolearn.save_state(st, "2026-07-18T00:00:00+00:00")
    repo = tmp_path / "r"
    repo.mkdir()
    assert cmd_status(repo) == 0
    out = capsys.readouterr().out
    assert "autolearn: shadow (would-uplift 3/17, audits 5, misses 1)" in out


def test_status_shows_autolearn_armed(tmp_path, monkeypatch, capsys):
    from aramid import config as config_mod
    from aramid.commands.status import cmd_status
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "aramid.toml").write_text("[llm.autolearn]\narmed = true\n",
                                      encoding="utf-8")
    assert cmd_status(repo) == 0
    assert "autolearn: armed" in capsys.readouterr().out


# --- the scheduled-drain line must know about the cron backend ---------------

def test_scheduled_drain_line_reads_cron_on_posix(monkeypatch):
    """`_scheduled_drain_line` probed schtasks unconditionally, so once the
    drain became installable via cron a POSIX user could install it
    successfully and still be told "unknown" -- schtasks does not exist there,
    the spawn raises, and the except arm swallows it.
    """
    import sys as _sys

    from aramid.commands import status as status_mod

    monkeypatch.setattr(_sys, "platform", "linux")
    monkeypatch.setattr(
        schedule_mod, "_read_crontab",
        lambda: f"0 */4 * * * /usr/bin/python3 -m aramid drain --all  {schedule_mod.CRON_MARKER}\n")
    assert status_mod._scheduled_drain_line() == "scheduled drain: installed"

    monkeypatch.setattr(schedule_mod, "_read_crontab",
                        lambda: "0 3 * * * /usr/local/bin/backup.sh\n")
    assert status_mod._scheduled_drain_line() == "scheduled drain: not installed"


# ----------------------------------------- resolver defects reach the eye --

def test_status_points_at_a_dead_resolver(tmp_path, monkeypatch, capsys):
    """A report nobody runs is the failure it was built to detect, one level
    up. Every one of the four silent no-ops behind `aramid resolvers` went
    unnoticed for weeks not because the evidence was missing but because
    nothing surfaced it, so the grading has to reach a command people already
    type. One line, non-blocking, pointing at the full report -- `status` is
    a diagnostic, and a diagnostic that grows teeth gets disabled."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    at = datetime.now(timezone.utc).isoformat()
    lg.record_run("r0", at, "pre-push", set(), set(),
                  [_f("a" * 64, tool="mutation", rule="bool-swap")])
    # One unrelated resolver reporting in: that is what makes the ledger
    # instrumented, so the silence of `gap_addressed` becomes meaningful.
    ledger_mod.note_yield(lg, "r1", at, resolver="evidence_gone",
                          tool="llm-review", considered=0, resolved=0)
    lg.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "resolver defects: 2 (run `aramid resolvers`)" in out


def test_status_stays_silent_when_every_resolver_is_healthy(tmp_path, monkeypatch, capsys):
    """The other half. A line that is always present is a line nobody reads."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    at = datetime.now(timezone.utc).isoformat()
    ledger_mod.note_yield(lg, "r1", at, resolver="evidence_gone",
                          tool="llm-review", considered=0, resolved=0)
    lg.close()

    assert cmd_status(root) == 0

    assert "resolver defects" not in capsys.readouterr().out


# ------------------------------------ a degraded consumer reaches the eye --

def _consumer_run(lg, consumer, state, note, run="r", duration_s=0.0):
    lg.append(Event(EventType.CONSUMER_RUN_FINISHED, run,
                    datetime.now(timezone.utc).isoformat(),
                    payload={"consumer": consumer, "state": state, "note": note,
                             "duration_s": duration_s, "finding_count": 0}))


def test_status_shows_a_consumer_stuck_in_degraded(tmp_path, monkeypatch, capsys):
    """`degraded` is load-bearing -- the drain refuses to mark an item drained
    while any consumer is degraded, so the item is being retried every drain
    -- and until now it appeared in no report at all. `last drain:` prints one
    consumer's name and finding count; nothing printed state. Measured on this
    repo: 38 degraded mutation runs, invisible.

    A STREAK, not a lifetime total, and for the same reason `status` already
    reports per-tool skips as streaks: a lifetime count of a fault that has
    since been fixed is a line that never goes away, and a line that never
    goes away is one nobody reads."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    _consumer_run(lg, "fuzz", "ok", "0 crash finding(s)")
    _consumer_run(lg, "fuzz", "degraded", "fuzz driver broken @ abc123456789: boom")
    _consumer_run(lg, "fuzz", "degraded", "fuzz driver broken @ abc123456789: boom")
    lg.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "degraded consumer runs:" in out
    assert "fuzz: degraded last 2 run(s)" in out


def test_status_clears_the_streak_once_a_consumer_recovers(tmp_path, monkeypatch,
                                                            capsys):
    """Self-clearing is the whole reason for a streak. A consumer that failed
    and then succeeded is not a fault worth a line."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    _consumer_run(lg, "fuzz", "degraded", "fuzz driver broken @ abc123456789: boom")
    _consumer_run(lg, "fuzz", "ok", "0 crash finding(s) from 200 case(s)")
    lg.close()

    assert cmd_status(root) == 0

    assert "degraded consumer runs" not in capsys.readouterr().out


def test_the_streak_line_names_the_note_so_it_is_actionable(tmp_path, monkeypatch,
                                                             capsys):
    """"fuzz is degraded" sends the reader to the ledger; the note tells them
    what broke without leaving `status`."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    _consumer_run(lg, "mutation", "degraded", "baseline failing @ 8abc418da153")
    lg.close()

    assert cmd_status(root) == 0

    assert "mutation: degraded last 1 run(s) -- baseline failing @ 8abc418da153" \
        in capsys.readouterr().out


# ---------------------------------- a consumer that STOOD DOWN is visible --
# R64-3/4. A give-up returns `ok` on purpose -- `degraded` would stop the drain
# marking the item drained and stall the queue. But `ok` also ends the degraded
# streak above, so a consumer that has permanently stopped working reports
# exactly like a healthy one. Making the timeout latch actually hold (R64-1)
# turns that from a rare accident into the STEADY STATE, so the latch and this
# report have to ship together: otherwise the fix for a loud waste of 8 minutes
# every 4 hours is a silent no-op forever, which is strictly worse.

def test_status_shows_a_consumer_that_gave_up(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    for _ in range(3):
        _consumer_run(lg, "mutation", "degraded",
                      "baseline timeout: pytest -q did not finish within the 240s budget",
                      duration_s=241.0)
    _consumer_run(lg, "mutation", "ok",
                  "mutation giving up: pytest -q does not fit the 240s baseline "
                  "budget after 3 attempts -- raise [mutation].baseline_timeout_s",
                  duration_s=0.2)
    lg.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "stood down" in out, \
        "a consumer that has permanently stopped must not read as healthy"
    assert "baseline_timeout_s" in out, "the remedy must reach the eye"


def test_stood_down_line_states_what_it_cost(tmp_path, monkeypatch, capsys):
    """Cost is the number that makes it worth acting on. Downstream this was
    ~8 minutes every 4 hours for three days producing nothing, and none of
    that was visible anywhere -- the report said only that a consumer existed.
    """
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    for _ in range(4):
        _consumer_run(lg, "mutation", "degraded", "baseline timeout: x", duration_s=100.0)
    _consumer_run(lg, "mutation", "ok", "mutation giving up: nope", duration_s=0.0)
    lg.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "5 run(s)" in out, "the give-up run counts too -- it is part of the waste"
    assert "400s" in out


def test_a_recovered_consumer_is_not_reported_as_stood_down(tmp_path, monkeypatch,
                                                             capsys):
    """Self-clearing, same contract as the degraded streak. A give-up followed
    by a real run means the operator fixed it -- raised the budget, narrowed
    the suite -- and a line that never goes away is one nobody reads."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    _consumer_run(lg, "mutation", "ok", "mutation giving up: nope")
    _consumer_run(lg, "mutation", "ok", "2 confirmed survivor(s) of 9 mutant(s) tested")
    lg.close()

    assert cmd_status(root) == 0

    assert "stood down" not in capsys.readouterr().out


def test_an_ordinary_healthy_consumer_reports_nothing(tmp_path, monkeypatch, capsys):
    """Falsifiability guard for the two tests above: if `stood down` appeared
    for any `ok` run, they would pass without detecting anything."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    _consumer_run(lg, "mutation", "ok", "3 confirmed survivor(s) of 12 mutant(s) tested")
    lg.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "stood down" not in out
    assert "degraded consumer runs" not in out
