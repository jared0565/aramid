"""`aramid rebaseline` at unit scope on a real tmp ledger with the gate
answered: the dry run's line and exit 3, the rewrite's line, the new
baseline and exit 0 -- the three generator mutants tests/integration reached
and the unit suite (the suite the drain confirms a mutant against) never
did."""
from types import SimpleNamespace

from aramid.commands import rebaseline
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.pipeline import GateResult



def _baseline(root):
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        return sorted(led.baseline_ids())
    finally:
        led.close()


def test_rebaseline_dry_run_says_what_it_would_discard_and_exits_3(tmp_path, capsys,
                                                                   monkeypatch):
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    try:
        led.write_baseline("r" * 32, "2026-09-14T00:00:00+00:00", {"a" * 64, "b" * 64})
    finally:
        led.close()
    monkeypatch.setattr(rebaseline, "run_gate",
                        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("gate ran")))

    assert rebaseline.cmd_rebaseline(tmp_path) == 3
    assert capsys.readouterr() == (
        "aramid: rebaseline: would discard the current baseline (2 grandfathered "
        "finding(s)) and re-snapshot the current gate result. This drops ratchet "
        "grandfathering. Re-run with --yes to proceed.\n", "")
    assert _baseline(tmp_path) == ["a" * 64, "b" * 64]


def test_rebaseline_yes_rewrites_the_baseline_from_a_fresh_gate(tmp_path, capsys, monkeypatch):
    led = Ledger(tmp_path / ".aramid" / "ledger.db")
    try:
        led.write_baseline("r" * 32, "2026-09-14T00:00:00+00:00", {"a" * 64, "b" * 64})
    finally:
        led.close()
    calls = []

    def run_gate(root, gate, mode, cfg, ledger, *a, **kw):
        calls.append((root, gate, mode))
        return GateResult(0, [SimpleNamespace(id="c" * 64)], [], [], [], "n" * 32)
    monkeypatch.setattr(rebaseline, "run_gate", run_gate)

    assert rebaseline.cmd_rebaseline(tmp_path, yes=True) == 0
    assert capsys.readouterr() == (
        "aramid: rebaseline: baseline rewritten (2 -> 1 finding(s) accepted).\n", "")
    assert calls == [(tmp_path, Gate.ALL, "all")]
    assert _baseline(tmp_path) == ["c" * 64]
