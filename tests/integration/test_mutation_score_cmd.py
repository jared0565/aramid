import json

import pytest

from aramid import config as config_mod
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


# ------------------- an absent measurement is not a bad measurement (R64-4) --
# Reported from a consumer repo: every function printed `kill-rate n/a (0/0)
# (partial)`, which they read as "coverage is poor". It is not a low score, it
# is NO SCORE -- nothing was ever measured, because their mutation baseline
# could not finish. The two demand opposite responses (write tests / fix the
# engine) and the report rendered them alike.

def test_an_unmeasured_target_does_not_render_like_a_low_score(tmp_path, capsys):
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 0, 0, False)      # nothing tested at all
    led.close()

    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out

    assert rc == 0
    assert "not measured" in out
    assert "kill-rate" not in out, \
        "printing a kill-rate for a target with no mutants invites reading 0/0 as bad"


def test_a_real_zero_still_reads_as_a_real_zero(tmp_path, capsys):
    """The control, and the line this whole item turns on. A target where
    mutants WERE tested and none were killed is a genuine 0.00 -- a real
    finding about the tests -- and must NOT be softened into 'not measured'."""
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 0, 5, True)       # 5 tested, 0 killed

    led.close()

    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out

    assert rc == 0
    assert "kill-rate 0.00 (0/5)" in out
    assert "not measured" not in out


def test_nothing_measured_at_all_says_so_once_at_the_top(tmp_path, capsys):
    """With every target unmeasured, the per-target lines are noise and the
    real signal is a single fact about the engine: it produced no measurements.
    That is the sentence that sends someone to `aramid status`, where a
    stood-down or degraded mutation consumer explains why."""
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 0, 0, False)
    _seed(led, 1, "m.py::g", 0, 0, False)
    led.close()

    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out

    assert rc == 0
    assert "no target has been measured" in out
    assert "aramid status" in out, "name where the reason is visible"


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


@pytest.fixture(autouse=True)
def _no_user_config(tmp_path, monkeypatch):
    """cmd_mutation_score reads config on the text path (armed-state line);
    keep every test in this module hermetic against a real
    ~/.aramid/config.toml."""
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")


def test_cmd_text_shows_baking_state(tmp_path, capsys):
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 3, 0, True)
    led.close()
    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "transition regressions: WARN (baking)" in out


def test_cmd_text_shows_armed_state(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text(
        "schema_version = 1\n\n[mutation]\nscore_block_armed = true\n",
        encoding="utf-8")
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 3, 0, True)
    led.close()
    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "transition regressions: BLOCK (armed)" in out


def test_cmd_empty_history_still_shows_arm_state(tmp_path, capsys):
    rc = cmd_mutation_score(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "no mutation scores recorded" in out
    assert "transition regressions: WARN (baking)" in out


def test_cmd_json_output_shape_unchanged(tmp_path, capsys):
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    _seed(led, 0, "m.py::f", 3, 0, True)
    led.close()
    rc = cmd_mutation_score(tmp_path, as_json=True)
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert set(doc) == {"targets", "regressions"}   # no armed key added
