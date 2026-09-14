"""`aramid autolearn` at unit scope on the isolated state file and
registry: the report whole for an empty and a populated state, the mode
line for every config shape, and `--rebuild` replaying one ledger and
skipping a registered repo without one.

The drain confirms a mutant against the unit suite alone, and five of this
module's generator mutants sat on lines the unit suite never executed --
the no-ledger skip, the two counter defaults, the `return 0`, and the
`or` on the mode line's disabled test (a non-table `[llm.autolearn]`
reported as unreadable rather than off): tests/integration/test_autolearn_cmd.py
covers them and the drain never runs that directory."""
import uuid

import pytest

from aramid import autolearn, registry
from aramid.commands import autolearn_cmd
from aramid.ledger import Ledger
from aramid.models import Event, EventType


@pytest.mark.parametrize("toml, line", [
    ("", "mode: shadow (this repo)"),
    ("[llm.autolearn]\narmed = true\n", "mode: armed (this repo)"),
    ("[llm.autolearn]\nenabled = false\narmed = true\n", "mode: off (this repo)"),
    ("[llm]\nautolearn = \"yes\"\n", "mode: off (this repo)"),      # not a table: off, not a crash
    ("this is = not = toml\n", "mode: unknown (config unreadable)"),
])
def test_mode_line(tmp_path, toml, line):
    if toml:
        (tmp_path / "aramid.toml").write_text(toml, encoding="utf-8")
    assert autolearn_cmd._mode_line(tmp_path) == line


def test_report_on_a_cold_state(tmp_path, capsys):
    assert autolearn_cmd.cmd_autolearn(tmp_path) == 0
    assert capsys.readouterr() == (
        "aramid autolearn:\n"
        "  mode: shadow (this repo)\n"
        f"  state: {autolearn.state_path()} (updated never)\n"
        "  shadow: would-uplift 0/0 decision(s)\n"
        "  audits: 0 performed, 0 missed critical(s)\n"
        "  posteriors: none yet (cold start -- ladder behavior)\n", "")


def test_report_on_a_populated_state_lists_posteriors_sorted(tmp_path, capsys):
    state = autolearn.empty_state()
    state["shadow"] = {"decisions": 9, "would_uplift": 4}
    state["audits"] = {"performed": 3, "missed_criticals": 1}
    state["posteriors"] = {"z|hi|2": {"misses": 1, "clean": 5, "halluc": 1},
                           "a|lo|0": {"misses": 0, "clean": 2, "refuted": 2, "survived": 1,
                                      "overridden": 3, "malformed": 4}}
    autolearn.save_state(state, "2026-09-14T12:00:00+00:00")

    assert autolearn_cmd.cmd_autolearn(tmp_path) == 0
    assert capsys.readouterr() == (
        "aramid autolearn:\n"
        "  mode: shadow (this repo)\n"
        f"  state: {autolearn.state_path()} (updated 2026-09-14T12:00:00+00:00)\n"
        "  shadow: would-uplift 4/9 decision(s)\n"
        "  audits: 3 performed, 1 missed critical(s)\n"
        "  posteriors (arm|band|bucket: misses/clean [halluc malformed refuted survived "
        "overridden]):\n"
        "    a|lo|0: 0/2 [0 4 2 1 3]\n"
        "    z|hi|2: 1/5 [1 0 0 0 0]\n", "")


def test_rebuild_replays_each_registered_ledger_and_skips_the_ledgerless(tmp_path, capsys):
    with_ledger = tmp_path / "with"
    (with_ledger / ".aramid").mkdir(parents=True)
    led = Ledger(with_ledger / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.RUN_FINISHED, uuid.uuid4().hex,
                         "2026-09-14T11:00:00+00:00", payload={"gate": "pre-commit"}))
        led.append(Event(EventType.RUN_FINISHED, uuid.uuid4().hex,
                         "2026-09-14T11:30:00+00:00", payload={"gate": "pre-push"}))
    finally:
        led.close()
    without = tmp_path / "without"
    without.mkdir()
    registry.register(with_ledger, "2026-09-14T00:00:00+00:00")
    registry.register(without, "2026-09-14T00:00:00+00:00")

    assert autolearn_cmd.cmd_autolearn(tmp_path, rebuild=True) == 0
    out, err = capsys.readouterr()
    assert err == ""
    assert out.startswith(
        f"aramid autolearn: {with_ledger}: 2 event(s) replayed\n"
        f"aramid autolearn: {without}: no ledger; skipped\n"
        f"aramid autolearn: state rebuilt -> {autolearn.state_path()}\n"
        "aramid autolearn:\n")
    assert autolearn.load_state()["updated_at"] != ""


def test_report_reads_missing_shadow_audit_and_posterior_counters_as_zero(tmp_path, capsys):
    """Every counter the report prints has a `.get(key, 0)` default;
    `empty_state()` carries them all, so the defaults were never read."""
    state = autolearn.empty_state()
    state["shadow"], state["audits"] = {}, {}
    state["posteriors"] = {"a|lo|0": {"halluc": 1}}
    autolearn.save_state(state, "2026-09-14T12:00:00+00:00")

    assert autolearn_cmd.cmd_autolearn(tmp_path) == 0
    assert capsys.readouterr() == (
        "aramid autolearn:\n"
        "  mode: shadow (this repo)\n"
        f"  state: {autolearn.state_path()} (updated 2026-09-14T12:00:00+00:00)\n"
        "  shadow: would-uplift 0/0 decision(s)\n"
        "  audits: 0 performed, 0 missed critical(s)\n"
        "  posteriors (arm|band|bucket: misses/clean [halluc malformed refuted survived "
        "overridden]):\n"
        "    a|lo|0: 0/0 [1 0 0 0 0]\n", "")
