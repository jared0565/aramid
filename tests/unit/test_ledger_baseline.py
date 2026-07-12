from aramid.ledger import Ledger

def test_baseline_suppresses_legacy_from_new(tmp_path):
    led = Ledger(tmp_path / "l.db")
    assert not led.has_baseline()
    led.write_baseline("r0", "t", {"legacy1", "legacy2"})
    assert led.has_baseline() and led.baseline_ids() == {"legacy1", "legacy2"}
    assert led.is_new("legacy1") is False
    assert led.is_new("fresh") is True
