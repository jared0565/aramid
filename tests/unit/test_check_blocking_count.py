"""FN-24: the run row's `blocking` counts the findings that actually blocked.

`record_run` wrote RUN_FINISHED with `blocking` counted from the verdicts
`run_gate` handed it, and the pre-push ratchet escalates a new WARN to BLOCK
only afterwards (it needs record_run's `new_ids`); the LLM and mutation ledger
gates are appended after the ratchet. So a push refused by an escalated WARN
recorded `blocking: 0`, and `status`'s `last run:` line -- the count's only
reader -- printed "0 blocking" beside a refused push (two pyjwt advisories
did exactly that on 2026-09-30). `cmd_check` now writes the row once its exit
code is final: after the ratchet, the gate producers and the fresh-ledger
grandfathering, counting with the exit code's own predicate. A refusal that
no finding caused (a ref that moved, a --strict degraded) reads 0 blocking,
and the row says why (`refs_moved`, `degraded`).

Same harness as test_check_hook_stdin.py: a scratch repo whose only pre-push
runner is a fake.
"""
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import config as config_mod
from aramid import pipeline, pushrefs
from aramid.commands.check import cmd_check
from aramid.commands.status import _last_run_line
from aramid.ledger import Ledger
from aramid.models import EventType, Finding, Gate, Severity, Source, Verdict
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState

ZERO = "0" * 40
_WARN = RawFinding(tool="eslint", rule="no-unused-vars", severity_raw="1",
                   file="a.py", line=1, message="unused var")


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout.strip()


def _repo(tmp_path, toml="schema_version = 1\n") -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    (r / "aramid.toml").write_text(toml, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "initial")
    return r


def _arm(tmp_path, monkeypatch, raws=(), toml="schema_version = 1\n"):
    root = _repo(tmp_path, toml)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    monkeypatch.setitem(pipeline.RUNNERS, "fake", SimpleNamespace(
        run=lambda ctx: RunnerResult(tool="fake", state=ToolState.OK, returncode=0),
        parse=lambda result, ctx: list(raws)))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["fake"])
    # the producers would add a code-without-test row for a.py
    monkeypatch.setattr(pipeline.tdd, "scan", lambda ctx, cfg: [])
    monkeypatch.setattr(pipeline.red_proof, "scan_scoped", lambda ctx, cfg: ([], set()))
    sha = _git(root, "rev-parse", "HEAD")
    monkeypatch.setenv(pushrefs.HOOK_ENV, "pre-push")
    monkeypatch.setattr("sys.stdin",
                        io.StringIO(f"refs/heads/main {sha} refs/heads/main {ZERO}\n"))
    return root


def _ledger(root):
    return Ledger(root / ".aramid" / "ledger.db")


def _seed_baseline(root):
    led = _ledger(root)
    try:
        led.write_baseline("seed", "2026-01-01T00:00:00+00:00", set())   # not fresh
    finally:
        led.close()


def _rows(root):
    led = _ledger(root)
    try:
        return [e for e in led.events() if e.type is EventType.RUN_FINISHED]
    finally:
        led.close()


def test_a_push_refused_by_an_escalated_warn_records_one_blocking(tmp_path, monkeypatch, capsys):
    root = _arm(tmp_path, monkeypatch, raws=[_WARN])
    _seed_baseline(root)

    rc = cmd_check(root, Gate.PRE_PUSH, "range", as_json=True)
    report = json.loads(capsys.readouterr().out)

    assert rc == 1
    escalated = [f["id"] for f in report["findings"] if f["escalated_by_ratchet"]]
    assert len(escalated) == 1
    (row,) = _rows(root)
    assert row.payload["blocking"] == 1
    led = _ledger(root)
    try:
        assert "pre-push run" in _last_run_line(led)
        assert ", 1 blocking" in _last_run_line(led)
    finally:
        led.close()


def test_the_escalation_never_reaches_the_stored_verdict(tmp_path, monkeypatch, capsys):
    # The count changes; the finding's recorded verdict does not. An
    # overridden row whose stored verdict is "block" is re-opened by
    # invalidate_stale_overrides at every gate start and cannot be
    # re-overridden -- recording the escalation would brick every accepted
    # WARN on the next push.
    root = _arm(tmp_path, monkeypatch, raws=[_WARN])
    _seed_baseline(root)

    assert cmd_check(root, Gate.PRE_PUSH, "range", as_json=True) == 1
    capsys.readouterr()

    led = _ledger(root)
    try:
        (detected,) = [e for e in led.events() if e.type is EventType.FINDING_DETECTED]
        assert detected.payload["verdict"] == "warn"
    finally:
        led.close()


def test_a_fresh_ledger_that_grandfathers_the_escalation_records_none(tmp_path, monkeypatch, capsys):
    root = _arm(tmp_path, monkeypatch, raws=[_WARN])

    rc = cmd_check(root, Gate.PRE_PUSH, "range", as_json=True)
    report = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert report["grandfathered"], "the fixture must grandfather the escalation"
    (row,) = _rows(root)
    assert row.payload["blocking"] == 0


def test_an_armed_llm_block_from_the_ledger_is_counted(tmp_path, monkeypatch, capsys):
    # The gate producers synthesize their findings from ledger state AFTER
    # the run is recorded, so record_run never saw this one either.
    root = _arm(tmp_path, monkeypatch, toml="schema_version = 1\n[llm]\nllm_block_armed = true\n")
    _seed_baseline(root)
    led = _ledger(root)
    try:
        led.record_run("drain", "2026-01-01T00:00:00+00:00", "drain", set(), set(), [Finding(
            id="f" * 64, tool="llm-review", rule="llm/a01", severity_raw="critical",
            severity=Severity.CRITICAL, verdict=Verdict.WARN, file="a.py", line=1,
            message="m", evidence="x = 1", gate=Gate.ALL, source=Source.LLM,
            confirmed=True)])
    finally:
        led.close()

    rc = cmd_check(root, Gate.PRE_PUSH, "range", as_json=True)
    report = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert [f["tool"] for f in report["findings"]] == ["llm-review"]
    gate_row = _rows(root)[-1]
    assert gate_row.payload["blocking"] == 1


def test_a_clean_push_records_none(tmp_path, monkeypatch, capsys):
    root = _arm(tmp_path, monkeypatch)
    _seed_baseline(root)

    assert cmd_check(root, Gate.PRE_PUSH, "range") == 0
    capsys.readouterr()

    (row,) = _rows(root)
    assert row.payload["blocking"] == 0


def test_a_gate_that_dies_after_recording_still_gets_its_row(tmp_path, monkeypatch, capsys):
    # Before FN-24 record_run wrote the row, so a gate that died later in
    # run_gate still had one. Deferring it must not lose that: the engine
    # error handler flushes it, counted as record_run counted it.
    root = _arm(tmp_path, monkeypatch)
    _seed_baseline(root)

    def boom(*a, **k):
        raise RuntimeError("injected after record_run")
    monkeypatch.setattr(pipeline.review_mod, "auto_resolve_llm", boom)

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 3
    assert "engine error: injected after record_run" in capsys.readouterr().err
    (row,) = _rows(root)
    assert row.payload["blocking"] == 0
