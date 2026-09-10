"""Unit-scope twins of the pre-push hook-stdin contract in `cmd_check`
(tests/integration/test_check_push_drift.py has the full drift story).

They exist because the drain's mutation consumer confirms against
`pytest -q tests/unit` (this repo's `[mutation].test_command`), and the
18:00Z drain of 2026-09-04 reported three survivors on this code that the
integration suite kills and the unit suite did not:

- `return 3` -> `return 4` on the engine-error exit before the gate;
- `hook_text or ""` -> `hook_text and ""`, which turns every real push
  into "nothing to push" and skips the gate;
- `return 0` -> `return 1` on the empty-ref-list exit.
The 2026-09-10 worktree derivation of the pending re-tests added a
fourth, 9e7dc6eb: `exit_code in (2, 3)` -> `(3, 3)` on the --strict
remap, which lets a DEGRADED gate (one tool missing) pass CI's
`--all --strict` run; tests/integration/test_check.py pins it, the
unit suite did not.
The 10:00Z drain of 2026-09-10 (the first over 79113d8) reported two more
in the same function, and the suppression file had carried a third since
2026-09-07 -- all three killed by tests/integration and by nothing in
tests/unit:

- `if not record:` -> `if record:` (79d4ae8f), which prints the no-record
  notice on every recording run and never on a snapshot run;
- `gate is PRE_PUSH and not has_baseline()` -> `or` (177075af), which
  makes every pre-push fresh and every pre-commit write a baseline;
- `exit_code = 2 if result.degraded else 0` -> `else 1` (d05c1a697), which
  turns the fresh-ledger downgrade back into a block.

A worktree derivation of all 19 cmd_check mutants with those three
pinned found three more the unit suite did not kill:

- `exit_code == 1 and not _has_genuine_block(...)` -> `or`, which
  grandfathers a genuine secret on the first push of a fresh clone;
- `exit_code = 1` -> `= 2` on a ref that moved during the gate, which
  turns the failure into a DEGRADED the non-CI shim maps to 0;
- `return 3` -> `return 4` on the mid-run engine-error handler (the
  pre-gate handler was already pinned; the second one was not).

Same harness as the integration file: a scratch repo whose only pre-push
runner is a fake, so the whole pipeline runs in about a second.
"""
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import config as config_mod
from aramid import fleet, pipeline, pushrefs
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import EventType, Gate
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState

ZERO = "0" * 40


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout.strip()


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    (r / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "initial")
    return r


def _arm(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    calls = []

    def run(ctx):
        calls.append("ran")
        return RunnerResult(tool="fake", state=ToolState.OK, returncode=0)

    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                        SimpleNamespace(run=run, parse=lambda result, ctx: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["fake"])
    return root, _git(root, "rev-parse", "HEAD"), calls


def _hook_stdin(monkeypatch, sha, text=None):
    monkeypatch.setenv(pushrefs.HOOK_ENV, "pre-push")
    line = f"refs/heads/main {sha} refs/heads/main {ZERO}\n" if text is None else text
    monkeypatch.setattr("sys.stdin", io.StringIO(line))


def _events(root, kind):
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        return [e for e in led.events() if e.type is kind]
    finally:
        led.close()


def test_an_engine_error_before_the_gate_exits_three(tmp_path, monkeypatch, capsys):
    # A config that will not parse dies before any tool runs: exit 3, never
    # a silent 0 and never the strict-remapped 1 -- 3 is what the shim's
    # exit-code table and `drain --help` name as "engine error".
    root = _repo(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    (root / "aramid.toml").write_text("schema_version = [\n", encoding="utf-8")

    rc = cmd_check(root, Gate.PRE_COMMIT, "staged")

    assert rc == 3
    assert "engine error" in capsys.readouterr().err
    # --strict remaps DEGRADED (2) to 1; an engine error is already a hard
    # failure (3 blocks in the pre-push shim and fails CI) and keeps its
    # own code so the two stay distinguishable. The docs used to promise
    # a 3 -> 1 remap that no path could reach (the handlers return 3
    # before the remap runs); the code was right, the docs were not.
    assert cmd_check(root, Gate.PRE_COMMIT, "staged", strict=True) == 3


def test_an_empty_ref_list_under_the_marker_exits_zero_and_runs_nothing(
        tmp_path, monkeypatch, capsys):
    root, sha, calls = _arm(tmp_path, monkeypatch)
    _hook_stdin(monkeypatch, sha, text="")

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 0
    assert calls == []
    assert "nothing to push" in capsys.readouterr().err
    assert _events(root, EventType.RUN_STARTED) == []


def test_refs_under_the_marker_reach_the_gate(tmp_path, monkeypatch):
    # The lines git hands the hook are the refs the gate certifies. A push
    # that ships something must RUN the gate; a bookkeeping slip that reads
    # those lines as empty would wave every real push through as "nothing
    # to push".
    root, sha, calls = _arm(tmp_path, monkeypatch)
    _hook_stdin(monkeypatch, sha)

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert rc == 0
    assert calls == ["ran"]
    started = _events(root, EventType.RUN_STARTED)[-1].payload
    assert started["hook"] is True
    assert started["refs"] and started["refs"][0]["local_sha"] == sha


def test_strict_turns_a_degraded_gate_into_a_failure(tmp_path, monkeypatch):
    # A missing tool degrades the gate to exit 2; `--strict` (what CI runs)
    # must make that a 1, and a non-strict run must leave it a 2. Both arms
    # in one test: a remap that fires on the wrong code, or never, fails
    # one of them.
    root = _repo(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    led = Ledger(root / ".aramid" / "ledger.db")   # pre-baselined: the
    led.write_baseline("seed", "2026-01-01T00:00:00+00:00", set())  # fresh-
    led.close()                                     # clone rule stays out
    monkeypatch.setitem(pipeline.RUNNERS, "fake", SimpleNamespace(
        run=lambda ctx: RunnerResult(tool="fake", state=ToolState.MISSING),
        parse=lambda result, ctx: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    assert cmd_check(root, Gate.PRE_COMMIT, "staged", strict=False) == 2
    assert cmd_check(root, Gate.PRE_COMMIT, "staged", strict=True) == 1


def test_strict_leaves_a_clean_gate_at_zero(tmp_path, monkeypatch):
    # The remap fires on exactly the degraded code: a clean run under
    # --strict is still a 0 (a remap keyed on `!= 2` would fail every
    # green CI run).
    root, sha, calls = _arm(tmp_path, monkeypatch)
    led = Ledger(root / ".aramid" / "ledger.db")
    led.write_baseline("seed", "2026-01-01T00:00:00+00:00", set())
    led.close()
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    assert cmd_check(root, Gate.PRE_COMMIT, "staged", strict=True) == 0
    assert calls == ["ran"]


def test_the_no_record_notice_belongs_to_a_no_record_run_only(tmp_path, monkeypatch, capsys):
    # `record=False` runs against a SNAPSHOT of the ledger and says so on
    # stderr. A recording run must not print that notice (a CI log would
    # read "nothing was written" beside a run that wrote everything), and a
    # snapshot run must leave the real ledger exactly as the recording run
    # left it. 79d4ae8f: `if not record` -> `if record` swaps the two.
    root, sha, calls = _arm(tmp_path, monkeypatch)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    assert cmd_check(root, Gate.PRE_COMMIT, "staged") == 0
    assert "no-record" not in capsys.readouterr().err
    recorded = [e.run_id for e in _events(root, EventType.RUN_STARTED)]
    assert len(recorded) == 1

    assert cmd_check(root, Gate.PRE_COMMIT, "staged", record=False) == 0
    assert "no-record -- running against a snapshot of the ledger" in capsys.readouterr().err
    assert [e.run_id for e in _events(root, EventType.RUN_STARTED)] == recorded
    assert calls == ["ran", "ran"]


def test_only_a_pre_push_on_a_ledger_with_no_baseline_is_fresh(tmp_path, monkeypatch, capsys):
    # The fresh-ledger rule (write the baseline, grandfather legacy findings)
    # is the CONJUNCTION of two facts: the gate is pre-push AND the ledger
    # has no baseline yet. Either half alone must not fire it: a pre-commit
    # on a new ledger writes no snapshot (the first pre-push owns it), and a
    # pre-push on a baselined ledger neither rewrites the snapshot nor
    # reports itself fresh -- it would grandfather every ratchet escalation
    # on every push. 177075af: `and` -> `or` fires it on either half.
    root, sha, calls = _arm(tmp_path, monkeypatch)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    assert cmd_check(root, Gate.PRE_COMMIT, "staged") == 0
    capsys.readouterr()
    assert _events(root, EventType.BASELINE_SNAPSHOT) == []

    _hook_stdin(monkeypatch, sha)
    assert cmd_check(root, Gate.PRE_PUSH, "range", as_json=True) == 0
    assert json.loads(capsys.readouterr().out)["fresh_ledger_baseline"] is True
    first = [e.run_id for e in _events(root, EventType.BASELINE_SNAPSHOT)]
    assert len(first) == 1

    _hook_stdin(monkeypatch, sha)
    assert cmd_check(root, Gate.PRE_PUSH, "range", as_json=True) == 0
    assert json.loads(capsys.readouterr().out)["fresh_ledger_baseline"] is False
    assert [e.run_id for e in _events(root, EventType.BASELINE_SNAPSHOT)] == first
    assert calls == ["ran", "ran", "ran"]


_LEGACY_WARN = RawFinding(tool="eslint", rule="no-unused-vars", severity_raw="1",
                          file="a.py", line=1, message="unused var")


def _warn_runner():
    # A WARN-tier finding that the pre-push ratchet escalates to BLOCK on a
    # ledger that has never seen it -- which on a brand-new ledger is every
    # finding, so the pipeline answers 1 for a repo whose only defect is a
    # lint warning that predates aramid.
    return SimpleNamespace(run=lambda ctx: RunnerResult(tool="warn", state=ToolState.OK),
                           parse=lambda result, ctx: [_LEGACY_WARN])


def test_a_fresh_ledger_grandfathers_a_ratchet_escalation_to_zero(tmp_path, monkeypatch, capsys):
    # Unit twin of tests/integration/test_check.py
    # ::test_fresh_ledger_downgrade_is_recorded_in_the_json_report. The
    # first pre-push writes the baseline and downgrades the escalated 1 to
    # the code the run earned without the escalation: 0 when every tool
    # ran. d05c1a697: `else 0` -> `else 1` blocks the very first push of
    # every fresh clone on legacy warnings.
    root, sha, calls = _arm(tmp_path, monkeypatch)
    monkeypatch.setitem(pipeline.RUNNERS, "warn", _warn_runner())
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["warn"])
    _hook_stdin(monkeypatch, sha)

    rc = cmd_check(root, Gate.PRE_PUSH, "range", as_json=True)
    report = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert report["exit_code"] == 0
    assert report["fresh_ledger_baseline"] is True
    escalated = [f["id"] for f in report["findings"] if f["escalated_by_ratchet"]]
    assert escalated, "the fixture must produce a ratchet-escalated finding"
    assert sorted(report["grandfathered"]) == sorted(escalated)
    assert report["degraded"] == []


def test_a_fresh_ledger_grandfathers_a_ratchet_escalation_to_two_when_a_tool_is_missing(
        tmp_path, monkeypatch, capsys):
    # Same downgrade, degraded run: a missing WARN-tier tool beside the
    # escalated finding must come out as 2, not 0 (the operator still has
    # to see the degradation) and not 1 (the escalation is still
    # grandfathered). The missing tool is deliberately NOT a block-tier key
    # -- that would be a genuine block and no downgrade at all.
    root, sha, calls = _arm(tmp_path, monkeypatch)
    monkeypatch.setitem(pipeline.RUNNERS, "warn", _warn_runner())
    monkeypatch.setitem(pipeline.RUNNERS, "absent", SimpleNamespace(
        run=lambda ctx: RunnerResult(tool="absent", state=ToolState.MISSING),
        parse=lambda result, ctx: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["warn", "absent"])
    _hook_stdin(monkeypatch, sha)

    rc = cmd_check(root, Gate.PRE_PUSH, "range", as_json=True)
    report = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert report["exit_code"] == 2
    assert report["fresh_ledger_baseline"] is True
    assert report["degraded"] == ["absent"]
    assert report["grandfathered"], "the escalation must still be grandfathered"


def test_a_fresh_ledger_never_grandfathers_a_genuine_block(tmp_path, monkeypatch, capsys):
    # Unit twin of tests/integration/test_check.py
    # ::test_fresh_ledger_prepush_genuine_secret_still_blocks. The downgrade
    # is for the ratchet escalation ONLY -- exit 1 AND no genuine block. A
    # real secret on the first push of a fresh clone blocks; the baseline is
    # still written, nothing is grandfathered and the downgrade notice stays
    # silent. `and` -> `or` on that condition waves the secret through
    # (derived 2026-09-10 in a worktree: unkilled by the full unit suite).
    root, sha, calls = _arm(tmp_path, monkeypatch)
    secret = RawFinding(tool="gitleaks", rule="generic-api-key", severity_raw="high",
                        file="a.py", line=1, message="found a key", secret="AKIA1234567890AB")
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", SimpleNamespace(
        run=lambda ctx: RunnerResult(tool="gitleaks", state=ToolState.OK),
        parse=lambda result, ctx: [secret]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["gitleaks"])
    _hook_stdin(monkeypatch, sha)

    rc = cmd_check(root, Gate.PRE_PUSH, "range", as_json=True)
    out, err = capsys.readouterr()
    report = json.loads(out)

    assert rc == 1
    assert report["exit_code"] == 1
    assert report["fresh_ledger_baseline"] is True
    assert report["grandfathered"] == []
    assert "legacy findings do not block" not in err


def test_a_ref_that_moves_during_the_gate_fails_the_push(tmp_path, monkeypatch, capsys):
    # Unit twin of tests/integration/test_check_push_drift.py
    # ::test_a_commit_during_the_gate_fails_it_and_is_recorded. A certified
    # ref that moved while the gate ran voids the certification, and git
    # will not say so (over smart HTTP it ships the moved tip). That is a
    # FAILURE, 1: a 2 would read as DEGRADED, which the non-CI shim maps to
    # 0 and lets the uncertified tip ship (derived 2026-09-10 in a
    # worktree: `= 1` -> `= 2` unkilled by the full unit suite).
    root, sha, calls = _arm(tmp_path, monkeypatch)

    def run(ctx):
        calls.append("ran")
        (ctx.root / "b.py").write_text("y = 2\n", encoding="utf-8")
        _git(ctx.root, "add", "b.py")
        _git(ctx.root, "commit", "-q", "-m", "landed while the gate ran")
        return RunnerResult(tool="fake", state=ToolState.OK, returncode=0)

    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                        SimpleNamespace(run=run, parse=lambda result, ctx: []))
    _hook_stdin(monkeypatch, sha)

    rc = cmd_check(root, Gate.PRE_PUSH, "range", as_json=True)
    out, err = capsys.readouterr()
    report = json.loads(out)
    new = _git(root, "rev-parse", "HEAD")

    assert rc == 1
    assert report["exit_code"] == 1
    assert report["refs_moved"] == [{"ref": "refs/heads/main", "before": sha, "after": new}]
    assert f"main moved during the gate: {sha[:7]} -> {new[:7]}" in err
    assert calls == ["ran"]


def test_an_engine_error_mid_run_exits_three_and_records_a_red_row(tmp_path, monkeypatch, capsys):
    # Unit twin of tests/integration/test_check_fleet.py
    # ::test_an_engine_error_mid_run_records_a_red_row_and_still_exits_3.
    # cmd_check has TWO engine-error handlers: before the ledger opens
    # (pinned above) and around the gate itself. A gate that dies mid-run is
    # an engine error, 3 -- not 4, which no exit-code table names and the
    # pre-push shim would not block on (derived 2026-09-10 in a worktree:
    # `return 3` -> `return 4` unkilled by the full unit suite). The fleet
    # row says the gate died rather than passed.
    root, sha, calls = _arm(tmp_path, monkeypatch)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    def boom(*a, **k):
        raise RuntimeError("injected")
    monkeypatch.setattr(pipeline, "run_gate", boom)

    rc = cmd_check(root, Gate.PRE_COMMIT, "staged")

    assert rc == 3
    assert "engine error: injected" in capsys.readouterr().err
    assert calls == []
    (row,) = fleet.read_rows()
    assert row["engine_error"] is True
    assert row["exit_code"] == 3
