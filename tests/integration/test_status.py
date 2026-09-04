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
    # The gate is named as of R64-8: the streak is now counted over that gate's
    # runs only, so the line has to say which set of runs it counted.
    assert "semgrep: skipped last 2 pre-push run(s)" in out
    assert "gitleaks" not in [ln.strip().split(":")[0] for ln in out.splitlines()
                              if "skipped" in ln]


def test_a_tool_from_another_gates_tier_is_not_called_skipped(tmp_path, monkeypatch,
                                                               capsys):
    """R64-8. `ruff: skipped last 1 run(s)` was reported to us as a puzzle: the
    reporter's `ruff check .` passed when run by hand, and nothing was broken.

    Nothing was. `GATE_RUNNER_KEYS` puts ruff at PRE-COMMIT only and semgrep and
    tests at PRE-PUSH only, so a pre-push run legitimately has no ruff in it --
    and the streak counted that absence as a skip. One word was covering "ran
    and failed" and "not part of this gate", which are opposite things: the
    first is a hole in the gate, the second is the gate working as designed.

    Fixed by scoping the tool universe PER GATE. A tool that has never appeared
    in any run of this gate is not eligible for it, so it cannot be skipped by
    it.
    """
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    # ruff runs at pre-commit; the pre-push runs that follow never include it.
    ledger.append(Event(EventType.RUN_STARTED, "c1", "2026-01-01T00:00:00+00:00",
                         payload={"gate": "pre-commit", "tools": ["gitleaks", "ruff"]}))
    ledger.append(Event(EventType.RUN_STARTED, "p1", "2026-01-02T00:00:00+00:00",
                         payload={"gate": "pre-push", "tools": ["gitleaks", "semgrep"]}))
    ledger.append(Event(EventType.RUN_STARTED, "p2", "2026-01-03T00:00:00+00:00",
                         payload={"gate": "pre-push", "tools": ["gitleaks", "semgrep"]}))
    ledger.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "ruff: skipped" not in out, \
        "ruff is pre-commit tier; its absence from a pre-push run is not a skip"


def test_a_tool_that_really_stopped_running_is_still_reported_with_its_gate(
        tmp_path, monkeypatch, capsys):
    """Control for the test above. Suppressing the false positive must not
    suppress the true one -- a tool that DID run at this gate and then stopped
    is exactly what the streak exists to surface, and naming the gate is what
    tells the two apart at a glance."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.append(Event(EventType.RUN_STARTED, "p1", "2026-01-01T00:00:00+00:00",
                         payload={"gate": "pre-push", "tools": ["gitleaks", "semgrep"]}))
    ledger.append(Event(EventType.RUN_STARTED, "p2", "2026-01-02T00:00:00+00:00",
                         payload={"gate": "pre-push", "tools": ["gitleaks"]}))
    ledger.append(Event(EventType.RUN_STARTED, "p3", "2026-01-03T00:00:00+00:00",
                         payload={"gate": "pre-push", "tools": ["gitleaks"]}))
    ledger.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "semgrep: skipped last 2 pre-push run(s)" in out


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
    # Three resolvers are keyed to the `mutation` producer (`gap_addressed`,
    # `file_departed`, `mutant_killed`), and all three stayed silent here.
    assert "resolver defects: 3 (run `aramid resolvers`)" in out


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


# ------------- a renamed tests slot is not a skipped suite (R80-1) ----------
# Reported from a downstream repo, and it fires on the configuration aramid
# itself recommends. `[tests].command` is labelled by `basename(argv[0])`, so
# pointing it at a venv interpreter -- which a repo MUST do once it stops being
# installed editable, or the machine `pytest` imports the released wheel and
# green-lights changes it never loaded -- renames the slot `pytest` ->
# `python.exe`. Under the observed-universe rule the vanished `pytest` reads as
# a suite that stopped running, and a run that provably executed the suite
# INCREMENTS the skipped counter.
#
# They asked whether the recorded `expected` set already fixes this. These two
# tests are the answer, and the second is what makes the first mean anything:
# without an arm that reproduces the bug, "no phantom streak" is equally
# consistent with the streak logic not running at all.

_OLD_TESTS_EXPECTED = ["gitleaks", "semgrep", "tests", "pytest"]
_CUSTOM_TESTS_EXPECTED = ["gitleaks", "semgrep", "tests", "python.exe"]
_RAN_OLD = ["gitleaks", "pytest", "semgrep"]
_RAN_CUSTOM = ["gitleaks", "python.exe", "semgrep"]


def test_a_renamed_tests_slot_is_not_reported_as_a_skipped_suite(tmp_path, monkeypatch,
                                                                  capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    lg = Ledger(root / ".aramid" / "ledger.db")
    # Two runs under the old label, then the operator repoints [tests].command
    # at a venv interpreter and two more runs record the new one. Every run
    # RAN the suite; only its label changed.
    _run_started(lg, "pre-push", _RAN_OLD, expected=_OLD_TESTS_EXPECTED,
                 at="2026-01-01T00:00:00+00:00")
    _run_started(lg, "pre-push", _RAN_OLD, expected=_OLD_TESTS_EXPECTED,
                 at="2026-01-02T00:00:00+00:00")
    _run_started(lg, "pre-push", _RAN_CUSTOM, expected=_CUSTOM_TESTS_EXPECTED,
                 at="2026-01-03T00:00:00+00:00")
    _run_started(lg, "pre-push", _RAN_CUSTOM, expected=_CUSTOM_TESTS_EXPECTED,
                 at="2026-01-04T00:00:00+00:00")
    lg.close()

    assert cmd_status(root) == 0
    out = capsys.readouterr().out

    assert "pytest: skipped" not in out, (
        "the suite ran on every one of these runs; only the slot's label moved. "
        "A pre-existing streak under the old label must age out, not latch")


def test_without_a_recorded_expected_set_the_rename_does_read_as_a_skip(tmp_path, monkeypatch,
                                                                        capsys):
    """The discriminator, and the state a consumer on an older release is in.

    Identical runs with `expected` ABSENT from every payload, which is how a
    ledger written before that key existed looks. `_skip_streak_lines` falls
    back to the observed-universe rule -- deliberately, so historical repos do
    not suddenly report nothing -- and the bug reappears. This test exists to
    prove the arm above is not passing vacuously.
    """
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    lg = Ledger(root / ".aramid" / "ledger.db")
    _run_started(lg, "pre-push", _RAN_OLD, at="2026-01-01T00:00:00+00:00")
    _run_started(lg, "pre-push", _RAN_OLD, at="2026-01-02T00:00:00+00:00")
    _run_started(lg, "pre-push", _RAN_CUSTOM, at="2026-01-03T00:00:00+00:00")
    _run_started(lg, "pre-push", _RAN_CUSTOM, at="2026-01-04T00:00:00+00:00")
    lg.close()

    assert cmd_status(root) == 0
    out = capsys.readouterr().out

    assert "pytest: skipped last 2 pre-push run(s)" in out, (
        "without `expected` the observed-universe rule still produces the "
        "phantom streak -- if this stops reproducing, the arm above no longer "
        "discriminates and both tests need rewriting")


def test_the_streak_line_names_the_note_so_it_is_actionable(tmp_path, monkeypatch,
                                                             capsys):
    """"fuzz is degraded" sends the reader to the ledger; the note tells them
    what broke without leaving `status`."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    # A real note, not a plausible-looking one: `status` passes it through
    # verbatim, so any string would make this test pass -- which is precisely
    # why the sample should be one production emits.
    from aramid.consumers import mutation as mut_consumer
    note = mut_consumer.failing_note_prefix("8abc418da153")
    _consumer_run(lg, "mutation", "degraded", note)
    lg.close()

    assert cmd_status(root) == 0

    assert f"mutation: degraded last 1 run(s) -- {note}" \
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


def test_status_surfaces_a_consumer_that_certifies_nothing(tmp_path, monkeypatch,
                                                            capsys):
    """R66. `state: ok` with mutants generated and none tested -- no degraded
    streak, no stand-down, full cost every drain. Invisible until now."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    for _ in range(3):
        _consumer_run(lg, "mutation", "ok",
                      "no mutants tested: 18 generated, 0 certified -- the 600s "
                      "wall budget covers the whole item and the baseline alone "
                      "took 686s. Raise [mutation].wall_budget_s, or point "
                      "[mutation].test_command at a narrower suite.",
                      duration_s=690.1)
    lg.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "consumers doing no work:" in out
    assert "3 run(s) certified nothing" in out
    assert "2070s spent" in out, "recurring cost is the reason to act"
    assert "wall_budget_s" in out


def test_a_consumer_that_resumes_real_work_clears_the_no_work_line(
        tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    _consumer_run(lg, "mutation", "ok", "no mutants tested: 18 generated, 0 certified")
    _consumer_run(lg, "mutation", "ok", "2 confirmed survivor(s) of 11 mutant(s) tested")
    lg.close()

    assert cmd_status(root) == 0

    assert "doing no work" not in capsys.readouterr().out


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


# ---------- a scanner that NEVER ran must still be reported (R71 §2) ---------
# The blind spot aramid's own reviewer found in the R64-8 fix. Eligibility was
# derived from tools that had previously APPEARED in a gate's runs, so a
# scanner misconfigured, renamed, or failing from the very first run never
# entered the universe and was never reported skipped. An absent security
# control read as a healthy one -- and this is the report a consumer repo uses
# to notice a missing scanner.
#
# `RUN_STARTED` now records the gate-scoped `expected` set, computed when the
# gate and the config are both in hand. Absent on runs written before that,
# which is why the fallback below has to keep working.

def _run_started(lg, gate, tools, expected=None, at=None):
    payload = {"gate": gate, "tools": tools}
    if expected is not None:
        payload["expected"] = expected
    lg.append(Event(EventType.RUN_STARTED, "r", at or "2026-01-01T00:00:00+00:00",
                    payload=payload))


def test_a_scanner_that_never_ran_is_reported_skipped(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    lg = Ledger(root / ".aramid" / "ledger.db")
    # semgrep is expected at pre-push and has NEVER appeared in a single run.
    for i in range(3):
        _run_started(lg, "pre-push", ["gitleaks"],
                     expected=["gitleaks", "semgrep"],
                     at=f"2026-01-0{i + 1}T00:00:00+00:00")
    lg.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "semgrep: skipped last 3 pre-push run(s)" in out, (
        "a scanner that never started is exactly the case the old report could "
        "not express -- absence of a skip line was reading as presence of a scanner")


def test_a_tool_that_ran_every_time_is_not_reported(tmp_path, monkeypatch, capsys):
    """Control. If `expected` alone drove the report, every healthy tool would
    be listed and the section would be noise."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    lg = Ledger(root / ".aramid" / "ledger.db")
    for i in range(3):
        _run_started(lg, "pre-push", ["gitleaks", "semgrep"],
                     expected=["gitleaks", "semgrep"],
                     at=f"2026-01-0{i + 1}T00:00:00+00:00")
    lg.close()

    assert cmd_status(root) == 0

    assert "skipped" not in capsys.readouterr().out


def test_the_tests_slot_label_does_not_read_as_permanently_skipped(tmp_path,
                                                                    monkeypatch,
                                                                    capsys):
    """The alias trap, end to end. `expected` carries `pytest`, not the `tests`
    registry key -- if it carried the key, a healthy suite would be reported
    skipped on every run forever."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    lg = Ledger(root / ".aramid" / "ledger.db")
    _run_started(lg, "pre-push", ["gitleaks", "pytest"],
                 expected=["gitleaks", "pytest"])
    lg.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "tests: skipped" not in out
    assert "pytest: skipped" not in out


def test_runs_without_expected_still_use_the_observed_universe(tmp_path,
                                                                monkeypatch,
                                                                capsys):
    """Backward compatibility. Ledgers written before `expected` existed must
    keep reporting exactly as they did -- absent means "too old to record",
    not "nothing was expected"."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    lg = Ledger(root / ".aramid" / "ledger.db")
    _run_started(lg, "pre-push", ["gitleaks", "semgrep"], at="2026-01-01T00:00:00+00:00")
    _run_started(lg, "pre-push", ["gitleaks"], at="2026-01-02T00:00:00+00:00")
    lg.close()

    assert cmd_status(root) == 0

    assert "semgrep: skipped last 1 pre-push run(s)" in capsys.readouterr().out


# ------------------------------------------------ last run: how long it took ---

def test_status_last_run_line_says_how_long_the_run_took(tmp_path, monkeypatch, capsys):
    """Round 130 s3: a consumer could not tell a ten-minute gate from a
    one-second one from the ledger. When RUN_FINISHED carries `finished_at`,
    the last-run line says the wall clock in seconds."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-08-29T10:00:00+00:00", "pre-push", {"semgrep"},
                      {"a.py"}, [], finished_at="2026-08-29T10:09:30+00:00")
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "last run: 2026-08-29T10:00:00+00:00 (pre-push run run1, 0 blocking, took 570s)" in out


def test_status_last_run_line_stays_silent_about_duration_on_an_older_ledger(
        tmp_path, monkeypatch, capsys):
    """No `finished_at` recorded means unknown, not zero."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-08-29T10:00:00+00:00", "pre-push", {"semgrep"},
                      {"a.py"}, [])
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "last run: 2026-08-29T10:00:00+00:00 (pre-push run run1, 0 blocking)" in out
    assert "took" not in out.split("last run:")[1].splitlines()[0]


# ----------------------------------------------- out-of-scope candidates ---

def test_status_lists_out_of_scope_candidate_and_the_exact_resolve_command(
        tmp_path, monkeypatch, capsys):
    """Interop round 144: two `mypy:syntax` rows recorded against `ci.yml`
    and `README.md` before the runner was scoped to .py/.pyi. Their tool is
    still selected, so they are not ghosts; their path is one the runner will
    never examine again, so they can never resolve. `status` has to say so
    and name the command, or the operator must already suspect it."""
    root = _repo(tmp_path)                       # writes a.py -> ruff selected
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "pre-commit", {"ruff"},
                      {".github/workflows/ci.yml"},
                      [_f("f1", tool="ruff", rule="syntax", file=".github/workflows/ci.yml")])
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "out-of-scope candidates:" in out
    assert "`aramid ledger resolve f1 --out-of-scope --reason ...`" in out
    assert "unreachable candidates:" not in out, "ruff is still selected -- not a ghost"


def test_status_counts_out_of_scope_findings_in_their_own_bucket(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "pre-commit", {"ruff"},
                      {"ci.yml"}, [_f("f1", tool="ruff", file="ci.yml")])
    ledger.append(Event(EventType.FINDING_OUT_OF_SCOPE, "r2", "2026-01-02T00:00:00+00:00",
                        finding_id="f1", payload={"reason": "scoped", "tool": "ruff", "file": "ci.yml"}))
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "open findings: 0" in out
    assert "out-of-scope: 1" in out


def test_status_counts_pending_retest_findings_in_their_own_bucket(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)

    ledger = Ledger(root / ".aramid" / "ledger.db")
    ledger.record_run("run1", "2026-01-01T00:00:00+00:00", "drain", {"mutation"},
                      {"a.py"}, [_f("m1", tool="mutation", rule="int-bound")])
    ledger.append(Event(EventType.FINDING_RESOLVED, "r2", "2026-01-02T00:00:00+00:00",
                        finding_id="m1", payload={"auto_resolved": "gap_addressed", "pending_retest": True}))
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "open findings: 0" in out
    assert "pending-retest: 1" in out


def test_open_counts_line_on_an_empty_state_reads_zero_in_every_bucket():
    """Every bucket's default is asserted, not just the ones a fixture
    happens to populate: the post-commit drain of 2026-08-30 found the
    `historical`/`not-a-secret` defaults mutable 0 -> 1 with nothing
    noticing."""
    from aramid.commands import status as status_mod
    from aramid.models import Status
    line = status_mod._open_counts_line({})
    assert line.startswith("open findings: 0 (")
    for member in Status:
        if member is Status.OPEN:
            continue
        assert f"{member.value.replace('_', '-')}: 0" in line, line


# ------------- round 155 s1: the streak came back through the KEY -----------
# The R80-1 tests above seed `expected` by hand, so they could not see what
# `expected_tool_names` actually records. This one records what it computes.

def test_two_real_runs_with_a_configured_tests_command_show_no_streak_at_all(
        tmp_path, monkeypatch, capsys):
    """Interop round 155 s1: `tests: skipped last 210 pre-push run(s)` on a
    repo whose suite ran on all 210. `expected` as recorded by the gate carried
    the registry key `tests` beside the label `python.exe`; the runs' `tools`
    never carry the key. Two real runs, `expected` computed the way run_gate
    computes it: the streak section must be empty."""
    from aramid import toolset

    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    (root / "aramid.toml").write_text(
        "schema_version = 1\nsemgrep_block_armed = true\n"
        '[tests]\ncommand = ["C:/venv/Scripts/python.exe", "-m", "pytest"]\n',
        encoding="utf-8")
    cfg = config_mod.load_config(root)
    expected = sorted(toolset.expected_tool_names(root, cfg, Gate.PRE_PUSH))

    lg = Ledger(root / ".aramid" / "ledger.db")
    _run_started(lg, "pre-push", ["gitleaks", "python.exe", "semgrep"], expected=expected,
                 at="2026-01-01T00:00:00+00:00")
    _run_started(lg, "pre-push", ["gitleaks", "python.exe", "semgrep"], expected=expected,
                 at="2026-01-02T00:00:00+00:00")
    lg.close()

    assert cmd_status(root) == 0
    out = capsys.readouterr().out

    assert "tests" not in expected, expected
    assert "skipped last" not in out, out


# ------------- round 155 s2: a fuzz driver that keeps timing out -------------

def test_status_surfaces_a_fuzz_driver_that_keeps_timing_out_with_nothing_run(
        tmp_path, monkeypatch, capsys):
    """Interop round 155 s2: five drains, each `state=ok`, `cases_run=0`,
    `timeouts=1`, ~125 s -- and `status` had no fuzz line at all. The same
    shape mutation's no-work line exists for: finished cleanly, certified
    nothing, will burn the same budget next drain."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    lg = Ledger(root / ".aramid" / "ledger.db")
    for _ in range(5):
        _consumer_run(lg, "fuzz", "ok",
                      "driver timed out in src/graphite/daemon.py:serve (function 1 of 15); "
                      "no cases run to completion (budget did its job) -- exclude it with "
                      "[fuzz].skip_name_patterns", duration_s=125.0)
    lg.close()

    assert cmd_status(root) == 0

    out = capsys.readouterr().out
    assert "consumers doing no work:" in out
    assert "fuzz: 5 run(s) certified nothing" in out
    assert "625s spent" in out
    assert "daemon.py:serve" in out, "the line names what to act on"


# ------------------------------------- last run: the historical scan never blocks ---

def test_status_last_run_line_counts_no_historical_scan_hit_as_blocking(
        tmp_path, monkeypatch, capsys):
    """Interop round 172 s3: after `aramid init`, `last run:` read `3 blocking`
    beside a green gate. The three were the init scan's history hits, which the
    ledger records as historical and non-blocking by contract (init's own exit
    code never sees them) -- but `record_run` counted them by verdict, and a
    secret's verdict is BLOCK. The count must follow the contract."""
    root = _repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_toml(root, armed=True, bake_started=None)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    hits = [_f(f"hist{i}", tool="gitleaks", rule="generic-api-key", verdict=Verdict.BLOCK,
               historical=True) for i in range(3)]
    ledger.record_run("scan1", "2026-09-04T03:02:52+00:00", "historical-scan", {"gitleaks"},
                      set(), hits, finished_at="2026-09-04T03:03:00+00:00")
    ledger.close()

    rc = cmd_status(root)
    out = capsys.readouterr().out

    assert rc == 0
    assert "last run: 2026-09-04T03:02:52+00:00 (historical-scan run scan1, 0 blocking, took 8s)" in out
    assert "not-a-secret" in out or "historical: 3" in out   # the hits are still reported, elsewhere
