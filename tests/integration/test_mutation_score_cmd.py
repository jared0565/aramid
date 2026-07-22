import json

from aramid.commands.mutation_score import cmd_mutation_score
from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _seed(led, idx, target, killed_s1, survived_s1, fully):
    led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", "t", payload={
        "consumer": "mutation", "item_id": "q",
        "mutation_scores": {"schema": 1, "targets": {target: {
            "generated": killed_s1 + survived_s1, "killed_s1": killed_s1,
            "survived_s1": survived_s1, "timeouts": 0, "errors": 0,
            "fully_mutated": fully, "killed_fps": [], "survivor_fps": []}}}}))


def test_cmd_reports_scores_and_rate_regression(tmp_path, capsys):
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 3, 0, True)
    _seed(led, 1, "m.py::f", 1, 2, True)
    led.close()
    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "m.py::f" in out
    assert "1.00 -> 0.33" in out


def test_cmd_empty_history(tmp_path, capsys):
    rc = cmd_mutation_score(tmp_path)
    assert rc == 0
    assert "no mutation scores recorded" in capsys.readouterr().out


def test_cmd_json_is_latest_per_target(tmp_path, capsys):
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 3, 0, True)
    _seed(led, 1, "m.py::f", 1, 2, True)
    led.close()
    rc = cmd_mutation_score(tmp_path, as_json=True)
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    ms = [t for t in doc["targets"] if t["target"] == "m.py::f"]
    assert len(ms) == 1, "JSON emits latest-per-target (spec §6), not full history"
    assert ms[0]["killed_s1"] == 1   # the latest run's values, not the first
    assert any(r["kind"] == "rate" for r in doc["regressions"])
