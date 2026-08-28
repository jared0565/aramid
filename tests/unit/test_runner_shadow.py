"""The shadow runner -- interop round 117(b).

A `python -m aramid` launch puts the CWD on `sys.path[0]`, so a file at a repo
root named after the tool is imported INSTEAD of the tool. It runs before the
real package is ever loaded, which is why a self-check inside aramid cannot
catch it (117 §1): when the shadow wins there is nothing to run the check.
Detection therefore has to be a gate finding about the FILE.

The predicate is graphite's, measured on CPython 3.14 with a firing control,
and the third row is the false positive it excludes: a directory without
`__init__.py` is only a PEP 420 namespace portion, and a namespace portion
loses to a regular package wherever it sits on `sys.path`.
"""
from aramid.runners import shadow
from aramid.runners.base import RunContext, ToolState


def _findings(root, names=("aramid", "graphite")):
    ctx = RunContext(root=root)
    res = shadow.run(ctx, names=names)
    assert res.state is ToolState.OK, "a pure-filesystem check can never be MISSING"
    return shadow.parse(res, ctx)


def test_a_module_named_after_the_tool_is_a_finding(tmp_path):
    (tmp_path / "aramid.py").write_text("import os\n")
    hits = _findings(tmp_path)
    assert len(hits) == 1
    assert hits[0].file == "aramid.py"
    assert hits[0].line == 1, "a file-level hazard is reported at line 1 (pinned: a mutant moved it)"
    assert "aramid" in hits[0].message


def test_a_regular_package_named_after_the_tool_is_a_finding(tmp_path):
    pkg = tmp_path / "aramid"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    hits = _findings(tmp_path)
    assert len(hits) == 1
    assert hits[0].file == "aramid/__init__.py"


def test_a_namespace_portion_is_NOT_a_finding(tmp_path):
    """The measured false positive. A bare directory cannot shadow, so keying
    the detector on 'a directory named aramid exists' would fire on a repo that
    is not at risk at all."""
    (tmp_path / "aramid").mkdir()
    (tmp_path / "aramid" / "helpers.py").write_text("")   # populated, still no __init__
    assert _findings(tmp_path) == []


def test_a_clean_root_is_no_findings(tmp_path):
    (tmp_path / "README.md").write_text("hi")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "aramid.py").write_text("")   # NOT at the root -> not sys.path[0]
    assert _findings(tmp_path) == []


def test_every_configured_name_is_checked_not_just_aramid(tmp_path):
    """117: `<name>` covers any distribution the repo's tooling launches with
    `-m` -- one rule protects both tools."""
    (tmp_path / "graphite.py").write_text("")
    hits = _findings(tmp_path)
    assert len(hits) == 1 and hits[0].file == "graphite.py"


def test_both_shapes_of_both_names_are_found_together(tmp_path):
    (tmp_path / "aramid.py").write_text("")
    gp = tmp_path / "graphite"
    gp.mkdir()
    (gp / "__init__.py").write_text("")
    assert sorted(f.file for f in _findings(tmp_path)) == ["aramid.py", "graphite/__init__.py"]


def test_the_rule_id_is_stable_and_names_the_hazard(tmp_path):
    (tmp_path / "aramid.py").write_text("")
    assert _findings(tmp_path)[0].rule == "module-shadow"


# --------------------------------------------------------------- wiring ---

def test_shadow_runs_on_every_gate_not_just_pre_push():
    """The hazard fires on every commit -- a post-commit hook launches `-m`
    before anything else runs -- so a pre-push-only check would let a shadow
    execute many times before it was ever reported. It costs a few stat calls."""
    from aramid import pipeline
    from aramid.models import Gate
    assert pipeline.RUNNERS.get("shadow") is shadow
    for gate in (Gate.PRE_COMMIT, Gate.PRE_PUSH, Gate.ALL):
        assert "shadow" in pipeline.GATE_RUNNER_KEYS[gate], gate


def test_tier_is_warn_while_disarmed_and_block_once_armed(tmp_path):
    """Ships DISARMED. Arming is retroactive and a new BLOCK-by-default would
    hand every consumer with a vendored `graphite/` an unattended red on
    upgrade -- the precondition-does-not-cover-its-own-deployment shape. The
    reporting is the new capability; the blocking is an operator decision."""
    from aramid import config as config_mod
    from aramid import policy
    from aramid.models import Gate, Verdict

    cfg = config_mod.load_config(tmp_path)
    _, verdict = policy.classify("shadow", "module-shadow", "critical", Gate.PRE_PUSH, cfg)
    assert verdict is Verdict.WARN, "must not block a repo that just upgraded"

    cfg.shadow["shadow_block_armed"] = True
    _, verdict = policy.classify("shadow", "module-shadow", "critical", Gate.PRE_PUSH, cfg)
    assert verdict is Verdict.BLOCK, "arming must actually promote it"


def test_arming_flag_is_recorded_in_arming_state(tmp_path):
    """`arming_state` is WALKED, not listed, so a new flag is picked up with no
    edit there -- but that is a property worth pinning rather than assuming,
    since an unrecorded flag makes every override taken under it unauditable."""
    from aramid import config as config_mod
    cfg = config_mod.load_config(tmp_path)
    cfg.shadow["shadow_block_armed"] = True
    assert "shadow_block_armed" in config_mod.arming_state(cfg)


def test_shadow_is_applicable_even_with_no_detected_stack(tmp_path):
    """It currently rides the `return True` fallthrough in `_is_applicable`.
    Pinned because a future `if key == "shadow"` branch that got the condition
    wrong would silently DESELECT a security check, and a runner that is never
    selected reports a clean gate rather than a degraded one."""
    from aramid import pipeline
    ctx = RunContext(root=tmp_path)          # no stacks, no pkg_manager, no tests
    assert pipeline._is_applicable("shadow", ctx) is True
