from pathlib import Path

from aramid.consumers.base import CONSUMERS, ConsumerResult, DrainContext


def test_protocol_shapes():
    ctx = DrainContext(root=Path("."), cfg=None, ledger=None, clock=lambda: "t")
    res = ConsumerResult(consumer="fake", state="ok", findings=[])
    # Assert on ctx rather than merely constructing it: the construction was
    # the point (DrainContext accepts these kwargs and stores them), but an
    # unasserted local proves only that __init__ did not raise.
    assert ctx.root == Path(".") and ctx.clock() == "t"
    assert res.cost == 0.0 and res.duration_s == 0.0 and res.note == ""
    assert isinstance(CONSUMERS, dict)


def test_consumer_result_extra_defaults_empty():
    r = ConsumerResult(consumer="x", state="ok")
    assert r.extra == {}
