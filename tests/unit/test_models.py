from aramid.models import Finding, Verdict, Severity, Gate, Source

def test_finding_is_frozen_and_defaults_deterministic():
    f = Finding(id="x", tool="ruff", rule="S102", severity_raw="high",
                severity=Severity.HIGH, verdict=Verdict.BLOCK, file="a.py",
                line=3, message="exec used", evidence="exec(x)", gate=Gate.PRE_COMMIT)
    assert f.source is Source.DETERMINISTIC
    assert f.historical is False
    import dataclasses
    try:
        f.line = 9  # frozen
        assert False
    except dataclasses.FrozenInstanceError:
        pass
