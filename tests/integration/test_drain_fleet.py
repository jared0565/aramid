"""Spec section 10, drain integration: two temp repos, a temp registry and
store; after `cmd_drain` the verdict exists, and a seeded green -> red
sequence across two drains yields readiness-reached then readiness-broken.
The drain never opens either repo's ledger for this -- only the rows."""
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aramid import fleet, health, notices, registry
from aramid.commands import drain as drain_mod
from aramid.commands.drain import cmd_drain

NOW_DT = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
NOW = NOW_DT.isoformat()
LATER = (NOW_DT + timedelta(hours=4)).isoformat()


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name) -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "README.md").write_text("hi\n", encoding="utf-8")
    _git(r, "add", "README.md")
    _git(r, "commit", "-q", "-m", "benign")
    return r


@pytest.fixture
def seam(tmp_path, monkeypatch):
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "central" / "drain.lock")
    monkeypatch.setattr(drain_mod, "CONSUMERS", {})


def _row(root, days_ago, version, *, red=(), armed=None, run_id="r"):
    crit = {k: True for k in health.CRITERIA}
    crit["dep_audit_ran"] = None
    for k in red:
        crit[k] = False
    return {"schema_version": 1, "at": (NOW_DT - timedelta(days=days_ago)).isoformat(),
            "repo": fleet.repo_key(root), "name": root.name, "aramid_version": version,
            "gate": "pre-push", "run_id": run_id, "exit_code": 0, "engine_error": False,
            "criteria": crit,
            "evidence": {"skip_streaks": {}, "degraded_consumers": [], "stood_down": [],
                         "no_work": [], "resolver_defects": [], "bad_tools": [],
                         "degraded_block_tier": False, "armed": dict(armed or {}),
                         "open": 0, "blocking": 0}}


def test_drain_judges_the_fleet_and_posts_transitions(tmp_path, seam):
    a, b = _repo(tmp_path, "a"), _repo(tmp_path, "b")
    registry.register(a, "t0")
    registry.register(b, "t0")
    armed = {"semgrep_block_armed": True}
    for row in (_row(a, 20, "0.8.0", armed=armed), _row(b, 20, "0.8.0"),
                _row(a, 10, "0.9.0", armed=armed), _row(b, 10, "0.9.0")):
        fleet.append_row(row)

    assert cmd_drain([], clock=lambda: NOW) == 0
    verdict = fleet.read_verdict()
    assert verdict is not None and verdict["verdict"] == "ready"
    assert [n["notice_kind"] for n in notices.pending()] == ["readiness-reached"]

    fleet.append_row(_row(a, 0.5, "0.9.0", red=("consumers_healthy",), armed=armed,
                          run_id="broke"))
    assert cmd_drain([], clock=lambda: LATER) == 0
    assert fleet.read_verdict()["verdict"] == "not-ready"
    kinds = sorted(n["notice_kind"] for n in notices.pending())
    assert kinds == ["readiness-broken", "readiness-reached"]


def test_a_broken_store_never_fails_the_drain(tmp_path, seam, capsys):
    a = _repo(tmp_path, "a")
    registry.register(a, "t0")
    fleet.verdict_path().mkdir(parents=True)          # unwritable verdict
    assert cmd_drain([], clock=lambda: NOW) == 0
    assert "aramid: fleet: judgement skipped (" in capsys.readouterr().err
