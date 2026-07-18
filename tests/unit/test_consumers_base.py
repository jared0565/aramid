from pathlib import Path

from aramid.consumers.base import CONSUMERS, ConsumerResult, DrainContext


def test_protocol_shapes():
    ctx = DrainContext(root=Path("."), cfg=None, ledger=None, clock=lambda: "t")
    res = ConsumerResult(consumer="fake", state="ok", findings=[])
    assert res.cost == 0.0 and res.duration_s == 0.0 and res.note == ""
    assert isinstance(CONSUMERS, dict)


def test_consumer_result_extra_defaults_empty():
    r = ConsumerResult(consumer="x", state="ok")
    assert r.extra == {}
