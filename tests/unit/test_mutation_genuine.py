"""_has_genuine_block must treat an armed mutation BLOCK as genuine (so it
survives check.py's fresh-clone downgrade) and must NOT treat it as genuine
when the repo is disarmed -- genuineness is re-derived from cfg via
policy.classify, never from the stored verdict alone (the fresh-clone safety).
"""
from types import SimpleNamespace

from aramid.commands import check
from aramid.models import Finding, Gate, Severity, Source, Verdict


def _mut_block():
    return Finding(id="m" * 64, tool="mutation", rule="flip_comparison",
                   severity_raw="medium", severity=Severity.MEDIUM,
                   verdict=Verdict.BLOCK, file="src/pkg/x.py", line=42,
                   message="mutant survived: flip_comparison", evidence="",
                   gate=Gate.PRE_PUSH, source=Source.DETERMINISTIC)


def test_armed_mutation_block_is_genuine():
    cfg = SimpleNamespace(block_rules={}, mutation={"mutation_block_armed": True})
    result = SimpleNamespace(findings=[_mut_block()], degraded_block_tier=False)
    assert check._has_genuine_block(result, cfg) is True


def test_mutation_block_not_genuine_when_disarmed():
    # A stored BLOCK verdict is re-derived from cfg: not armed -> classify WARN
    # -> not genuine -> would be downgraded on a fresh clone. This is what
    # prevents a stale/forged BLOCK from surviving when the repo is not armed.
    cfg = SimpleNamespace(block_rules={}, mutation={"mutation_block_armed": False})
    result = SimpleNamespace(findings=[_mut_block()], degraded_block_tier=False)
    assert check._has_genuine_block(result, cfg) is False
