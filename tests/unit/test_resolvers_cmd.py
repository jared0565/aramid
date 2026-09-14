"""`aramid resolvers` at unit scope with the yield report answered: the
rendered text, the JSON rows whole, and both engine-error exits -- the three
generator mutants tests/integration reached and the unit suite (the suite the
drain confirms a mutant against) never did."""
import json
from types import SimpleNamespace

from aramid.commands import resolvers



ROW = SimpleNamespace(resolver="line_departed", tool="ruff", runs=4, considered=9,
                      resolved=2, volume="low", open_now=1, verdict="ok", flagged=False)


def test_resolvers_prints_the_rendered_report_or_the_rows_as_json(tmp_path, capsys,
                                                                  monkeypatch):
    monkeypatch.setattr(resolvers.yield_report, "collect", lambda ledger: [ROW])
    monkeypatch.setattr(resolvers.yield_report, "render", lambda rows: f"{len(rows)} row(s)")

    assert resolvers.cmd_resolvers(tmp_path) == 0
    assert capsys.readouterr() == ("1 row(s)\n", "")

    assert resolvers.cmd_resolvers(tmp_path, as_json=True) == 0
    assert capsys.readouterr() == (json.dumps([{
        "resolver": "line_departed", "tool": "ruff", "runs": 4, "considered": 9,
        "resolved": 2, "volume": "low", "open_now": 1, "verdict": "ok",
        "flagged": False}], indent=2) + "\n", "")


def test_resolvers_engine_errors_exit_3_on_one_line(tmp_path, capsys, monkeypatch):
    def refuse(path):
        raise OSError("ledger locked")
    monkeypatch.setattr(resolvers, "Ledger", refuse)
    assert resolvers.cmd_resolvers(tmp_path) == 3
    assert capsys.readouterr() == ("", "aramid: resolvers: engine error: ledger locked\n")

    monkeypatch.undo()

    def boom(ledger):
        raise ValueError("torn row")
    monkeypatch.setattr(resolvers.yield_report, "collect", boom)
    assert resolvers.cmd_resolvers(tmp_path) == 3
    assert capsys.readouterr() == ("", "aramid: resolvers: engine error: torn row\n")
