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


def test_dataflow_sqli_rule_stays_warn_even_when_semgrep_block_is_armed():
    """The vendored `injection-dataflow.*` rule must NOT block. R64-9.

    Its tier is decided by its ID, not by the `severity:` in the YAML:
    `block_rules.toml`'s [semgrep].block list is fnmatch, and it contains the
    SUBSTRING glob `*sqli*`. Naming this rule `...-sqli-...` -- the obvious
    name for a SQL-injection rule -- would silently make it BLOCK-tier in every
    repo with `semgrep_block_armed` on.

    That matters because this rule is deliberately broader than the
    high-confidence one beside it, and broader means more false positives: a
    downstream repo audited all 26 hits of the NARROW rule and every one was a
    false positive. Shipping a wider net at blocking tier would stop pushes on
    code that is fine, and a blocking rule people cannot satisfy is one they
    turn off.

    This test is the only thing standing between a well-meaning rename and
    that outcome, which is why it asserts the ARMED case.
    """
    _, v = policy.classify("semgrep", "injection-dataflow.python-query-built-then-executed",
                           "warning", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.WARN, (
        "renaming this rule to contain 'sqli' promotes it to BLOCK via the "
        "*sqli* glob in block_rules.toml -- see the comment above the rule")


def test_the_narrow_sqli_rule_does_still_block_when_armed():
    """Control for the test above. Without it, a change that broke blocking
    for ALL sqli rules would leave that test passing and look like success."""
    _, v = policy.classify("semgrep", "owasp-top-ten.a03-injection.python-sqli-string-concat",
                           "error", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.BLOCK


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


# --- classify: tests-tool-missing (Task 3, review B4) ------------------------

def test_tests_tool_missing_always_blocks():
    """runners/tests.py's dual-suite aggregate emits this for a
    detect_tests()-detected suite whose tool binary could not be run at
    all -- tool="tests" (never "npm"/"pytest", to avoid both a fingerprint
    collision with tests-failed and the _DEPS_TOOLS fallthrough below).
    Unconditional BLOCK, like tests-failed above: a detected suite that
    never ran is exactly as actionable as one that ran and failed."""
    _, v = policy.classify("tests", "tests-tool-missing", "high", Gate.PRE_PUSH, _cfg(armed=False))
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


def test_deps_cargo_audit_gets_same_threshold_treatment_as_other_deps_tools():
    """cargo-audit findings use a constant "medium" severity_raw (see
    runners/deps.py's _CARGO_AUDIT_SEVERITY_RAW docstring), so at the
    default "critical" threshold they warn, not block -- same shape as
    pip-audit's own constant-"low" severity never reaching the default
    threshold either."""
    _, v = policy.classify("cargo-audit", "RUSTSEC-2020-0071", "medium", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.WARN
    _, v = policy.classify("cargo-audit", "RUSTSEC-2020-0071", "critical", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.BLOCK


# --- classify: everything else warns ----------------------------------------

def test_eslint_warns():
    _, v = policy.classify("eslint", "no-unused-vars", "2", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.WARN


def test_typecheck_warns():
    _, v = policy.classify("mypy", "arg-type", "error", Gate.PRE_PUSH, _cfg(armed=True))
    assert v is Verdict.WARN


# --- classify: regression pack rules -----------------------------------------

def test_pack_block_rule_classifies_block(tmp_path, monkeypatch):
    """With DEFAULT config (pack_block_armed defaults true in defaults.toml,
    semgrep_block_armed defaults false), a pack block-tier rule blocks
    immediately -- it rides its own [pack].pack_block_armed gate, NOT the
    OWASP bake's semgrep_block_armed (user decision 2026-07-13)."""
    from aramid import config
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "nouser.toml")
    cfg = config.load_config(tmp_path)
    assert cfg.semgrep_block_armed is False  # sanity: OWASP bake still on
    severity, verdict = policy.classify(
        "semgrep", "aramid-regression.block.deadbeef", "ERROR", Gate.PRE_PUSH, cfg=cfg)
    assert verdict is Verdict.BLOCK


def test_pack_block_rule_warns_when_pack_block_disarmed(tmp_path, monkeypatch):
    """An operator can demote noisy pack rules: [pack].pack_block_armed =
    false in the repo's aramid.toml turns pack block-tier rules into WARN."""
    from aramid import config
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "nouser.toml")
    (tmp_path / "aramid.toml").write_text(
        "[pack]\npack_block_armed = false\n", encoding="utf-8")
    cfg = config.load_config(tmp_path)
    severity, verdict = policy.classify(
        "semgrep", "aramid-regression.block.deadbeef", "ERROR", Gate.PRE_PUSH, cfg=cfg)
    assert verdict is Verdict.WARN


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


def test_suppression_downgrades_a_warn_finding_too():
    # The tracked file is tier-AGNOSTIC. This deliberately reverses the
    # original partition (`suppressions only downgrade BLOCK, not WARN`),
    # which was pinned by this test under its old name. That partition was
    # measured to make a WARN entry here a SILENT NO-OP: it matched neither
    # branch of apply_overrides, and it was not reported stale either,
    # because its id IS among the findings so the stale loop skips it. A
    # team recording a WARN judgement in the reviewable file -- the natural
    # thing to try, and strictly SAFER than the BLOCK entries the file has
    # always accepted -- got no effect and no diagnostic.
    f = _finding("id-4", "ruff", "E501", "a.py", Verdict.WARN)
    rec = policy.OverrideRecord(id="id-4", tool="ruff", rule="E501", path="a.py", reason="x")
    out, stale = policy.apply_overrides([f], overrides=[], suppressions=[rec])
    assert out[0].verdict is Verdict.INFO
    assert stale == []


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


def test_stale_suppression_near_miss_warn_finding_refires():
    # Stale detection took no code change when the tracked file went
    # tier-agnostic -- `matched_ids` was always tier-blind, and the old
    # partition's damage was that a WARN entry landed in the `continue`
    # branch (id present => not stale) while ALSO doing nothing. Pinned
    # here rather than assumed: a WARN entry whose finding has MOVED still
    # re-fires at WARN and is still reported stale.
    f = _finding("id-new", "ruff", "E501", "a.py", Verdict.WARN)
    rec = policy.OverrideRecord(id="id-old", tool="ruff", rule="E501", path="a.py",
                                 reason="stale reason")
    out, stale = policy.apply_overrides([f], overrides=[], suppressions=[rec])
    assert out[0].verdict is Verdict.WARN
    assert stale == [rec]


def test_a_ledger_override_still_cannot_hide_a_block_finding_when_both_channels_carry_it():
    # The dangerous collapse of apply_overrides' two branches is
    # `if f.id in suppress_ids or f.id in override_ids`. The single-channel
    # guard above catches it, but this pins the mixed case too: the id is in
    # BOTH lists, for DIFFERENT findings. Only the file-suppressed one may
    # go INFO.
    blocked = _finding("id-block", "gitleaks", "aws-key", "c.py", Verdict.BLOCK)
    suppressed = _finding("id-supp", "semgrep", "owasp.sqli", "b.py", Verdict.BLOCK)
    ledger_rec = policy.OverrideRecord(id="id-block", tool="gitleaks", rule="aws-key",
                                        path="c.py", reason="x")
    file_rec = policy.OverrideRecord(id="id-supp", tool="semgrep", rule="owasp.sqli",
                                      path="b.py", reason="reviewed")
    out, _ = policy.apply_overrides([blocked, suppressed], overrides=[ledger_rec],
                                     suppressions=[file_rec])
    by_id = {f.id: f.verdict for f in out}
    assert by_id["id-block"] is Verdict.BLOCK
    assert by_id["id-supp"] is Verdict.INFO


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


# --- classify: llm-review (Phase 2b) ----------------------------------------

def test_llm_review_always_warns_at_drain_time():
    sev, verdict = policy.classify("llm-review", "llm/a01", "critical", Gate.ALL, _cfg(armed=False))
    assert sev is Severity.CRITICAL
    assert verdict is Verdict.WARN


def test_llm_review_warns_even_when_semgrep_armed():
    sev, verdict = policy.classify("llm-review", "llm/logic", "high", Gate.PRE_PUSH, _cfg(armed=True))
    assert sev is Severity.HIGH
    assert verdict is Verdict.WARN


# --- classify: tdd (sub-project 1a) ------------------------------------------

def _tdd_cfg(armed: bool):
    # classify reads cfg.block_rules early, then the tool branch; a minimal
    # namespace with the attributes classify touches is enough.
    return SimpleNamespace(block_rules={}, semgrep_block_armed=False,
                           pack={}, tdd_block_armed=armed)


def test_tdd_disarmed_is_warn():
    sev, verdict = policy.classify("tdd", "code-without-test", "medium",
                                   Gate.PRE_PUSH, _tdd_cfg(armed=False))
    assert sev is Severity.MEDIUM
    assert verdict is Verdict.WARN


def test_tdd_armed_is_block():
    sev, verdict = policy.classify("tdd", "code-without-test", "medium",
                                   Gate.PRE_PUSH, _tdd_cfg(armed=True))
    assert sev is Severity.MEDIUM
    assert verdict is Verdict.BLOCK


# --- classify: mutation (sub-project 1b) ------------------------------------

def _mut_cfg(armed: bool):
    # classify reads cfg.block_rules early, then the tool branch; a minimal
    # namespace with the attributes classify touches is enough.
    return SimpleNamespace(block_rules={}, mutation={"mutation_block_armed": armed})


def test_mutation_disarmed_is_warn():
    sev, verdict = policy.classify("mutation", "flip_comparison", "medium",
                                   Gate.PRE_PUSH, _mut_cfg(armed=False))
    assert sev is Severity.MEDIUM
    assert verdict is Verdict.WARN


def test_mutation_armed_is_block():
    sev, verdict = policy.classify("mutation", "flip_comparison", "medium",
                                   Gate.PRE_PUSH, _mut_cfg(armed=True))
    assert sev is Severity.MEDIUM       # assert severity in BOTH (1a T2a lesson)
    assert verdict is Verdict.BLOCK


# --- classify: mutation-score (sub-project 2b) -------------------------------

def _msc_cfg(armed: bool):
    # classify reads cfg.block_rules early, then the tool branch; a minimal
    # namespace with the attributes classify touches is enough.
    return SimpleNamespace(block_rules={},
                           mutation={"score_block_armed": armed})


def test_mutation_score_transition_armed_is_block():
    sev, verdict = policy.classify("mutation-score", "transition", "high",
                                   Gate.PRE_PUSH, _msc_cfg(armed=True))
    assert sev is Severity.HIGH         # assert severity in BOTH (1a T2a lesson)
    assert verdict is Verdict.BLOCK


def test_mutation_score_transition_disarmed_is_warn():
    sev, verdict = policy.classify("mutation-score", "transition", "high",
                                   Gate.PRE_PUSH, _msc_cfg(armed=False))
    assert sev is Severity.HIGH
    assert verdict is Verdict.WARN


def test_mutation_score_rate_is_warn_even_armed():
    sev, verdict = policy.classify("mutation-score", "rate", "low",
                                   Gate.PRE_PUSH, _msc_cfg(armed=True))
    assert sev is Severity.LOW
    assert verdict is Verdict.WARN


# --- classify: red-proof (sub-project 3) ------------------------------------

def _rp_cfg(armed: bool):
    # classify reads cfg.block_rules early, then the tool branch; a minimal
    # namespace with the attributes classify touches is enough.
    return SimpleNamespace(block_rules={},
                           red_proof={"red_proof_block_armed": armed})


def test_red_proof_disarmed_is_warn():
    sev, verdict = policy.classify("red-proof", "test-not-red", "medium",
                                   Gate.PRE_PUSH, _rp_cfg(armed=False))
    assert sev is Severity.MEDIUM
    assert verdict is Verdict.WARN


def test_red_proof_armed_is_block():
    sev, verdict = policy.classify("red-proof", "test-not-red", "medium",
                                   Gate.PRE_PUSH, _rp_cfg(armed=True))
    assert sev is Severity.MEDIUM       # assert severity in BOTH (1a T2a lesson)
    assert verdict is Verdict.BLOCK


# --- cargo-audit informational warnings: guarantees 1 and 2 (round 20) ------

def test_cargo_audit_warnings_never_block_however_the_operator_tunes_deps():
    """Guarantee 1: the warnings tool is deliberately absent from
    `_DEPS_TOOLS`, so the operator-tunable `block_rules.deps.block_severity`
    comparison cannot reach it.

    The adversarial arm is the point. `block_severity` defaults to "critical",
    which would make a low severity look safe for the wrong reason -- so this
    drives it to the FLOOR ("info"), the setting a supply-chain-conscious
    operator would actually choose to catch more real CVEs. cargo-audit
    proper escalates under that setting; the warnings tool must not.
    """
    from aramid.runners import deps

    cfg = _cfg(armed=True)
    cfg.block_rules = {**cfg.block_rules, "deps": {"block_severity": "info"}}

    _, real = policy.classify(deps.NAME_CARGO_AUDIT, "RUSTSEC-2021-0003",
                              "info", Gate.PRE_PUSH, cfg)
    _, warn = policy.classify(deps.NAME_CARGO_AUDIT_WARNINGS,
                              "unmaintained/RUSTSEC-2021-0139",
                              "info", Gate.PRE_PUSH, cfg)

    assert real is Verdict.BLOCK      # the tunable reaches the real path...
    assert warn is Verdict.WARN       # ...and cannot reach this one


def test_cargo_audit_warnings_resist_block_rules_promotion():
    """Guarantee 2: WARN is returned unconditionally, ahead of every
    promotion path. Round 20 asked for these never to be in the block path
    "ever, including via `block_rules` promotion" -- an operator who wants an
    unmaintained crate to block has cargo-audit's real advisory path.

    Driven at every severity, since a promotion bug would most likely show up
    only at the high end.
    """
    from aramid.runners import deps

    cfg = _cfg(armed=True)
    cfg.block_rules = {
        **cfg.block_rules,
        "deps": {"block_severity": "info"},
        deps.NAME_CARGO_AUDIT_WARNINGS: {"block": ["*", "unmaintained/*"]},
    }
    for severity_raw in ("info", "low", "medium", "high", "critical"):
        _, verdict = policy.classify(deps.NAME_CARGO_AUDIT_WARNINGS,
                                     "unmaintained/RUSTSEC-2021-0139",
                                     severity_raw, Gate.PRE_PUSH, cfg)
        assert verdict is Verdict.WARN, f"promoted at severity {severity_raw!r}"
