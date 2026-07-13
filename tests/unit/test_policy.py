from types import SimpleNamespace

from aramid import policy
from aramid.models import Finding, Gate, Severity, Source, Verdict


def _cfg(armed):
    return SimpleNamespace(semgrep_block_armed=armed,
                            block_rules=policy.load_block_rules())


def _finding(id_, tool, rule, file_, verdict, severity=Severity.MEDIUM,
             gate=Gate.PRE_PUSH):
    return Finding(id=id_, tool=tool, rule=rule, severity_raw="x",
                    severity=severity, verdict=verdict, file=file_, line=1,
                    message="msg", evidence="ev", gate=gate,
                    source=Source.DETERMINISTIC, historical=False)


# --- given by the brief -----------------------------------------------------

def test_secret_always_blocks():
    _, v = policy.classify("gitleaks", "aws-key", "high", Gate.PRE_COMMIT, _cfg(armed=True))
    assert v is Verdict.BLOCK


def test_bake_demotes_semgrep_block():
    _, v = policy.classify("semgrep", "owasp.sqli", "error", Gate.PRE_PUSH, _cfg(armed=False))
    assert v is Verdict.WARN
    _, v2 = policy.classify("semgrep", "owasp.sqli", "error", Gate.PRE_PUSH, _cfg(armed=True))
    assert v2 is Verdict.BLOCK


# --- load_block_rules --------------------------------------------------------

def test_load_block_rules_shape():
    rules = policy.load_block_rules()
    assert "S102" in rules["ruff"]["block"]
    assert rules["deps"]["block_severity"] == "critical"
    assert any("sqli" in p for p in rules["semgrep"]["block"])


# --- classify: secrets ignore armed flag ------------------------------------

def test_secret_blocks_even_when_unarmed():
    _, v = policy.classify("gitleaks", "aws-key", "high", Gate.PRE_PUSH, _cfg(armed=False))
    assert v is Verdict.BLOCK


# --- classify: ruff block-list ----------------------------------------------

def test_ruff_block_list_rule_blocks():
    _, v = policy.classify("ruff", "S102", "error", Gate.PRE_COMMIT, _cfg(armed=True))
    assert v is Verdict.BLOCK


def test_ruff_non_block_list_rule_warns():
    _, v = policy.classify("ruff", "E501", "error", Gate.PRE_COMMIT, _cfg(armed=True))
    assert v is Verdict.WARN


def test_ruff_block_list_rule_blocks_regardless_of_armed():
    _, v = policy.classify("ruff", "S608", "error", Gate.PRE_COMMIT, _cfg(armed=False))
    assert v is Verdict.BLOCK


# --- classify: semgrep non-block rule ---------------------------------------

def test_semgrep_non_block_rule_warns_even_when_armed():
    _, v = policy.classify("semgrep", "style.unused-import", "warning", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.WARN


# --- classify: tests-failed --------------------------------------------------

def test_tests_failed_always_blocks():
    _, v = policy.classify("pytest", "tests-failed", "high", Gate.PRE_PUSH, _cfg(armed=False))
    assert v is Verdict.BLOCK


# --- classify: deps threshold -----------------------------------------------

def test_deps_at_threshold_blocks():
    _, v = policy.classify("pip-audit", "CVE-2024-1", "critical", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.BLOCK


def test_deps_below_threshold_warns():
    _, v = policy.classify("npm", "GHSA-xxx", "high", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.WARN


def test_deps_moderate_maps_below_critical_threshold():
    _, v = policy.classify("pnpm", "GHSA-yyy", "moderate", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.WARN


# --- classify: everything else warns ----------------------------------------

def test_eslint_warns():
    _, v = policy.classify("eslint", "no-unused-vars", "2", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.WARN


def test_typecheck_warns():
    _, v = policy.classify("mypy", "arg-type", "error", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.WARN


# --- classify: regression pack rules -----------------------------------------

def test_pack_block_rule_classifies_block(tmp_path, monkeypatch):
    from aramid import config
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "nouser.toml")
    cfg = config.load_config(tmp_path)
    severity, verdict = policy.classify(
        "semgrep", "aramid-regression.block.deadbeef", "ERROR", Gate.PRE_PUSH, cfg=cfg)
    assert verdict is Verdict.BLOCK


def test_pack_warn_rule_classifies_warn(tmp_path, monkeypatch):
    from aramid import config
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "nouser.toml")
    cfg = config.load_config(tmp_path)
    severity, verdict = policy.classify(
        "semgrep", "aramid-regression.warn.deadbeef", "WARNING", Gate.PRE_PUSH, cfg=cfg)
    assert verdict is Verdict.WARN


# --- OverrideRecord / apply_overrides ---------------------------------------

def test_override_downgrades_matching_warn_finding_to_info():
    f = _finding("id-1", "ruff", "E501", "a.py", Verdict.WARN)
    rec = policy.OverrideRecord(id="id-1", tool="ruff", rule="E501", path="a.py", reason="noisy")
    out, stale = policy.apply_overrides([f], overrides=[rec], suppressions=[])
    assert out[0].verdict is Verdict.INFO
    assert stale == []


def test_suppression_downgrades_matching_block_finding_to_info():
    f = _finding("id-2", "semgrep", "owasp.sqli", "b.py", Verdict.BLOCK)
    rec = policy.OverrideRecord(id="id-2", tool="semgrep", rule="owasp.sqli", path="b.py",
                                 reason="false positive, reviewed")
    out, stale = policy.apply_overrides([f], overrides=[], suppressions=[rec])
    assert out[0].verdict is Verdict.INFO
    assert stale == []


def test_override_does_not_downgrade_block_finding():
    f = _finding("id-3", "gitleaks", "aws-key", "c.py", Verdict.BLOCK)
    rec = policy.OverrideRecord(id="id-3", tool="gitleaks", rule="aws-key", path="c.py", reason="x")
    out, stale = policy.apply_overrides([f], overrides=[rec], suppressions=[])
    assert out[0].verdict is Verdict.BLOCK  # overrides only downgrade WARN, not BLOCK


def test_suppression_does_not_downgrade_warn_finding():
    f = _finding("id-4", "ruff", "E501", "a.py", Verdict.WARN)
    rec = policy.OverrideRecord(id="id-4", tool="ruff", rule="E501", path="a.py", reason="x")
    out, stale = policy.apply_overrides([f], overrides=[], suppressions=[rec])
    assert out[0].verdict is Verdict.WARN  # suppressions only downgrade BLOCK, not WARN


def test_stale_override_near_miss_finding_refires():
    # Same tool+rule+path as the override, but a different id (line content
    # changed) -- the override must NOT apply, and the finding must be
    # flagged stale.
    f = _finding("id-new", "ruff", "E501", "a.py", Verdict.WARN)
    rec = policy.OverrideRecord(id="id-old", tool="ruff", rule="E501", path="a.py", reason="stale reason")
    out, stale = policy.apply_overrides([f], overrides=[rec], suppressions=[])
    assert out[0].verdict is Verdict.WARN  # re-fires at normal tier, not downgraded
    assert stale == [rec]


def test_unmatched_override_with_no_near_miss_is_not_stale():
    # The finding this override once applied to is completely gone (fixed) --
    # not a near-miss, so it is silently dropped, not reported as stale.
    rec = policy.OverrideRecord(id="id-old", tool="ruff", rule="E501", path="gone.py", reason="x")
    out, stale = policy.apply_overrides([], overrides=[rec], suppressions=[])
    assert stale == []


def test_stale_suppression_near_miss_block_finding_refires():
    f = _finding("id-new", "semgrep", "owasp.sqli", "b.py", Verdict.BLOCK)
    rec = policy.OverrideRecord(id="id-old", tool="semgrep", rule="owasp.sqli", path="b.py",
                                 reason="stale reason")
    out, stale = policy.apply_overrides([f], overrides=[], suppressions=[rec])
    assert out[0].verdict is Verdict.BLOCK
    assert stale == [rec]


# --- escalate_degraded -------------------------------------------------------

def test_escalate_degraded_forces_exit_1_at_pre_push():
    assert policy.escalate_degraded(0, True, Gate.PRE_PUSH) == 1


def test_escalate_degraded_not_forced_at_pre_commit():
    assert policy.escalate_degraded(0, True, Gate.PRE_COMMIT) == 0


def test_escalate_degraded_no_degradation_passes_through():
    assert policy.escalate_degraded(2, False, Gate.PRE_PUSH) == 2
