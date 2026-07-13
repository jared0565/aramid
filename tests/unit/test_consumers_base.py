from pathlib import Path

from aramid.consumers.base import CONSUMERS, ConsumerResult, DrainContext


def test_protocol_shapes():
    ctx = DrainContext(root=Path("."), cfg=None, ledger=None, clock=lambda: "t")
    res = ConsumerResult(consumer="fake", state="ok", findings=[])
    assert res.cost == 0.0 and res.duration_s == 0.0 and res.note == ""
    assert isinstance(CONSUMERS, dict)
