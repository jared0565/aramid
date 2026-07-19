"""aramid autolearn: read-only report + --rebuild from registry ledgers."""
import json

from aramid import autolearn, registry
from aramid.commands.autolearn_cmd import cmd_autolearn
from aramid.ledger import Ledger
from aramid.models import Event, EventType

AT = "2026-07-18T00:00:00+00:00"


def _sel():
    return {"target_tier": "cheap", "bucket": "plain",
            "served": {"tier": "cheap", "provider": "p", "model": "m",
                       "effort": ""},
            "attempts": [], "uplift": {"mode": "shadow", "pick": "frontier",
                                       "applied": False, "sampled_q": 0.3},
            "cascade": {"triggered": False, "trigger": None, "applied": False},
            "audit": {"performed": True, "tier": "frontier",
                      "new_findings": 1, "missed_criticals": 1},
            "refutes": [], "hallucination_rejected": 2,
            "tokens": {"in": 1, "out": 1}}


def test_report_cold_start(tmp_path, capsys):
    assert cmd_autolearn(tmp_path) == 0
    out = capsys.readouterr().out
    assert "aramid autolearn:" in out
    assert "posteriors: none yet" in out
    assert "shadow: would-uplift 0/0" in out


def test_rebuild_replays_registry_ledgers(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    (repo / ".aramid").mkdir(parents=True)
    led = Ledger(repo / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, "r1", AT,
                         payload={"consumer": "llm-review", "item_id": "q1",
                                  "state": "ok", "duration_s": 1.0,
                                  "cost": 0.0, "finding_count": 0,
                                  "note": "x", "selection": _sel()}))
    finally:
        led.close()
    monkeypatch.setattr(registry, "registry_path",
                        lambda: tmp_path / "repos.toml")
    registry.register(repo, AT)

    assert cmd_autolearn(tmp_path, rebuild=True) == 0
    out = capsys.readouterr().out
    assert "1 event(s) replayed" in out
    assert "p/m|cheap|plain: 1/0" in out
    assert "audits: 1 performed, 1 missed critical(s)" in out
    state = json.loads(autolearn.state_path().read_text(encoding="utf-8"))
    assert state["posteriors"]["p/m|cheap|plain"]["misses"] == 1


def test_rebuild_skips_repo_without_ledger(tmp_path, monkeypatch, capsys):
    ghost = tmp_path / "ghost"
    ghost.mkdir()
    monkeypatch.setattr(registry, "registry_path",
                        lambda: tmp_path / "repos.toml")
    registry.register(ghost, AT)
    assert cmd_autolearn(tmp_path, rebuild=True) == 0
    assert "no ledger; skipped" in capsys.readouterr().out
