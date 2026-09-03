"""`aramid check` pushes its repo's health row after printing its report.
The row is evidence, so a `--no-record` snapshot run writes none; the store
is machine state, so a broken one changes nothing about the gate's answer."""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import aramid
from aramid import fleet, pipeline
from aramid.commands.check import cmd_check
from aramid.models import Gate
from aramid.runners.base import RunnerResult, ToolState


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


@pytest.fixture
def clean_gate(monkeypatch):
    fake = SimpleNamespace(run=lambda ctx: RunnerResult("gitleaks", ToolState.OK),
                           parse=lambda result, ctx: [])
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", fake)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["gitleaks"])


def test_a_recording_run_appends_one_row(tmp_path, clean_gate, capsys):
    root = _repo(tmp_path)
    rc = cmd_check(root, Gate.PRE_COMMIT, "staged", as_json=True)
    report = json.loads(capsys.readouterr().out)
    (row,) = fleet.read_rows()
    assert rc == 0
    assert row["repo"] == fleet.repo_key(root)
    assert row["gate"] == "pre-commit"
    assert row["run_id"] == report["run_id"]
    assert row["exit_code"] == 0
    assert row["aramid_version"] == aramid.__version__
    assert row["criteria"]["dep_audit_ran"] is None      # deps never runs at pre-commit


def test_no_record_writes_no_row(tmp_path, clean_gate):
    root = _repo(tmp_path)
    assert cmd_check(root, Gate.PRE_COMMIT, "staged", record=False) == 0
    assert not fleet.health_path().exists()


def test_an_engine_error_mid_run_records_a_red_row_and_still_exits_3(tmp_path, clean_gate,
                                                                     monkeypatch):
    root = _repo(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("injected")
    monkeypatch.setattr(pipeline, "run_gate", boom)
    assert cmd_check(root, Gate.PRE_COMMIT, "staged") == 3
    (row,) = fleet.read_rows()
    assert row["engine_error"] is True and row["exit_code"] == 3
    assert row["criteria"]["no_self_inflicted_block"] is False


def test_a_broken_store_does_not_change_the_exit_code(tmp_path, clean_gate, capsys):
    root = _repo(tmp_path)
    healthy = cmd_check(root, Gate.PRE_COMMIT, "staged")
    capsys.readouterr()
    fleet.health_path().unlink()
    fleet.health_path().mkdir()                       # a directory where the file goes
    broken = cmd_check(root, Gate.PRE_COMMIT, "staged")
    assert broken == healthy == 0
    assert "aramid: fleet: health row not recorded (" in capsys.readouterr().err


def test_subprocess_gate_exits_identically_with_a_broken_store(tmp_path, checkout_env):
    """Spec section 10, as a real child process: the shim's `aramid check`
    with the store unusable must exit exactly as it does with a healthy one.
    Tools are absent from the isolated tools dir, so both arms degrade the
    same way; only the store differs."""
    root = _repo(tmp_path)

    def run(store: Path):
        env = dict(checkout_env)
        env[fleet.FLEET_DIR_ENV] = str(store)
        return subprocess.run([sys.executable, "-P", "-m", "aramid", "check", "--staged"],
                              cwd=root, env=env, capture_output=True, text=True)

    healthy_store = tmp_path / "healthy"
    broken_store = tmp_path / "broken"
    (broken_store / "fleet_health.jsonl").mkdir(parents=True)
    a = run(healthy_store)
    b = run(broken_store)
    assert a.returncode == b.returncode
    assert (healthy_store / "fleet_health.jsonl").is_file()
    assert "aramid: fleet: health row not recorded (" in b.stderr
