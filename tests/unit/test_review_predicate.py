"""Unit tests for review.is_confirmed_critical_llm -- the raw-rec BLOCK-tier
predicate shared by the gate (review.llm_gate_findings), the override refusal
(commands.override), and the status count (commands.status). It is deliberately
armed-INDEPENDENT: the override refusal must fire regardless of arming (see
tests/integration/test_override.py::
test_llm_confirmed_critical_is_refused_regardless_of_armed_state), and the gate
ANDs `armed` on top of this predicate itself."""
from aramid.review import is_confirmed_critical_llm


def test_is_confirmed_critical_llm_predicate():
    yes = {"source": "llm", "confirmed": True, "severity": "critical"}
    assert is_confirmed_critical_llm(yes) is True
    # each of the three raw-rec conditions is load-bearing
    assert is_confirmed_critical_llm({**yes, "confirmed": False}) is False
    assert is_confirmed_critical_llm({**yes, "severity": "high"}) is False
    assert is_confirmed_critical_llm({**yes, "source": "gitleaks"}) is False
    # never includes `armed` -- an armed key on the rec is irrelevant
    assert is_confirmed_critical_llm({**yes, "armed": False}) is True
    # truthy-but-non-bool confirmed normalizes to True; result is a strict bool
    assert is_confirmed_critical_llm({**yes, "confirmed": 1}) is True
    # missing keys -> False, never a crash
    assert is_confirmed_critical_llm({}) is False
    assert is_confirmed_critical_llm({"source": "llm"}) is False
