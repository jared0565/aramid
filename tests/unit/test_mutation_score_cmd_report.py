"""`aramid mutation-score` at unit scope on a real tmp ledger: the text
report whole (rates, the partial marker, the unmeasured target and the
once-at-the-top banner, the regressions block, the arming line), the JSON
document whole, and the three exits.

The drain confirms a mutant against the unit suite alone, and seven of the
command's eight generator mutants -- both engine-error `return 3`s, every
`return 0`, the empty-history and nothing-measured guards -- sat on lines
the unit suite never executed: tests/integration/test_mutation_score_cmd.py
covers them and the drain never runs that directory."""
import json

from aramid.commands import mutation_score as cmd_mod
from aramid.commands.mutation_score import cmd_mutation_score
from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _seed(root, idx, target, killed_s1, survived_s1, fully, killed_s2=0):
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", "t", payload={
            "consumer": "mutation", "item_id": "q",
            "mutation_scores": {"schema": 1, "targets": {target: {
                "generated": killed_s1 + survived_s1, "killed_s1": killed_s1,
                "killed_s2": killed_s2, "survived_s1": survived_s1, "timeouts": 0,
                "errors": 0, "fully_mutated": fully, "killed_fps": [],
                "survivor_fps": []}}}}))
    finally:
        led.close()


def _history(root):
    _seed(root, 0, "m.py::f", 3, 0, True)
    _seed(root, 1, "m.py::f", 1, 2, True)                  # a rate regression
    _seed(root, 2, "m.py::g", 2, 1, False, killed_s2=1)    # partial, stage-2 kill counted
    _seed(root, 3, "m.py::h", 0, 0, False)                 # nothing tested


def test_text_report_whole(tmp_path, capsys):
    _history(tmp_path)
    assert cmd_mutation_score(tmp_path) == 0
    assert capsys.readouterr() == (
        "aramid mutation-score:\n"
        "  transition regressions: WARN (baking)\n"
        "  m.py::f: kill-rate 0.33 (1/3)\n"
        "  m.py::g: kill-rate 0.75 (3/4) (partial)\n"
        "  m.py::h: not measured (0 mutants tested)\n"
        "  regressions:\n"
        "    m.py::f [rate]: 1.00 -> 0.33\n", "")


def test_text_report_armed_with_no_regressions(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("[mutation]\nscore_block_armed = true\n",
                                          encoding="utf-8")
    _seed(tmp_path, 0, "m.py::f", 3, 1, True)
    assert cmd_mutation_score(tmp_path) == 0
    assert capsys.readouterr() == (
        "aramid mutation-score:\n"
        "  transition regressions: BLOCK (armed)\n"
        "  m.py::f: kill-rate 0.75 (3/4)\n"
        "  regressions: none\n", "")


def test_text_report_with_nothing_measured_says_so_once_at_the_top(tmp_path, capsys):
    _seed(tmp_path, 0, "m.py::f", 0, 0, False)
    _seed(tmp_path, 1, "m.py::g", 0, 0, False)
    assert cmd_mutation_score(tmp_path) == 0
    assert capsys.readouterr() == (
        "aramid mutation-score:\n"
        "  transition regressions: WARN (baking)\n"
        "  no target has been measured -- mutation recorded scores but tested no "
        "mutants. This is an ABSENT measurement, not a low one; `aramid status` "
        "reports why (look for a degraded or stood-down mutation consumer).\n"
        "  m.py::f: not measured (0 mutants tested)\n"
        "  m.py::g: not measured (0 mutants tested)\n"
        "  regressions: none\n", "")


def test_empty_history_prints_the_arming_line_only(tmp_path, capsys):
    assert cmd_mutation_score(tmp_path) == 0
    assert capsys.readouterr() == (
        "aramid mutation-score: no mutation scores recorded\n"
        "  transition regressions: WARN (baking)\n", "")


def test_json_report_whole(tmp_path, capsys):
    _history(tmp_path)
    assert cmd_mutation_score(tmp_path, as_json=True) == 0
    out, err = capsys.readouterr()
    assert err == ""
    doc = {"targets": [
        {"target": "m.py::f", "run_index": 1, "killed_s1": 1, "killed_s2": 0,
         "survived_s1": 2, "rate": 1 / 3, "fully_mutated": True},
        {"target": "m.py::g", "run_index": 2, "killed_s1": 2, "killed_s2": 1,
         "survived_s1": 1, "rate": 0.75, "fully_mutated": False},
        {"target": "m.py::h", "run_index": 3, "killed_s1": 0, "killed_s2": 0,
         "survived_s1": 0, "rate": None, "fully_mutated": False}],
        "regressions": [{"target": "m.py::f", "kind": "rate", "detail": "1.00 -> 0.33",
                         "baseline_index": 0, "current_index": 1}]}
    assert out == json.dumps(doc, indent=2) + "\n"

    assert cmd_mutation_score(tmp_path / "fresh", as_json=True) == 0
    assert capsys.readouterr().out == json.dumps({"targets": [], "regressions": []},
                                                 indent=2) + "\n"


def test_engine_errors_exit_3_on_one_line(tmp_path, capsys, monkeypatch):
    def refuse(path):
        raise OSError("ledger locked")
    monkeypatch.setattr(cmd_mod, "Ledger", refuse)
    assert cmd_mutation_score(tmp_path) == 3
    assert capsys.readouterr() == ("", "aramid: mutation-score: engine error: ledger locked\n")

    monkeypatch.undo()
    _seed(tmp_path, 0, "m.py::f", 3, 1, True)

    def boom(events):
        raise ValueError("bad score row")
    monkeypatch.setattr(cmd_mod.analyzer, "iter_target_scores", boom)
    assert cmd_mutation_score(tmp_path) == 3
    assert capsys.readouterr() == ("", "aramid: mutation-score: engine error: bad score row\n")
