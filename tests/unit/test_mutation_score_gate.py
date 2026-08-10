"""mutation_score_gate (2b): zero-persistence PRE_PUSH seam over the 2a
analyzer. Seeded-ledger tests mirror test_mutation_score.py's _crf pattern;
cfg fakes mirror test_mutation_gate.py's SimpleNamespace pattern."""
from types import SimpleNamespace

from aramid import mutation_score_gate, policy
from aramid.fingerprint import compute_fingerprint
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Gate, Severity, Source, Verdict

FP = "deadbeef"


def _crf(idx, target, killed_s1, survived_s1, fully,
         killed_fps=(), survivor_fps=()):
    return Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", "t", payload={
        "consumer": "mutation", "item_id": "q",
        "mutation_scores": {"schema": 1, "targets": {target: {
            "generated": killed_s1 + survived_s1, "killed_s1": killed_s1,
            "survived_s1": survived_s1, "timeouts": 0, "errors": 0,
            "fully_mutated": fully, "killed_fps": list(killed_fps),
            "survivor_fps": list(survivor_fps)}}}})


def _transition_ledger(base, target="src/calc.py::is_adult"):
    """Baseline kills FP; current run has FP as a confirmed survivor.
    NOTE: the current run's rate (0.33) is also below baseline (1.00), so
    this history yields BOTH a transition and a rate regression -- tests
    filter by rule."""
    led = Ledger(base / "l.db")
    led.append(_crf(0, target, 2, 0, True, killed_fps=[FP, "other"]))
    led.append(_crf(1, target, 1, 2, True, killed_fps=["other"],
                    survivor_fps=[FP]))
    return led


def _rate_ledger(base, target="src/calc.py::is_adult"):
    """Rate drop 1.00 -> 0.33 with NO fps seeded: rate-only regression."""
    led = Ledger(base / "l.db")
    led.append(_crf(0, target, 3, 0, True))
    led.append(_crf(1, target, 1, 2, True))
    return led


def _cfg(armed, enabled=True):
    return SimpleNamespace(mutation={"enabled": enabled,
                                     "score_block_armed": armed})


def _findings(led, cfg, gate=Gate.PRE_PUSH, changed_files=None):
    try:
        return mutation_score_gate.mutation_score_gate_findings(
            cfg, led, gate, changed_files)
    finally:
        led.close()


def test_armed_transition_blocks(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True))
    trans = [f for f in got if f.rule == "transition"]
    assert len(trans) == 1
    f = trans[0]
    assert f.tool == "mutation-score"
    assert f.verdict is Verdict.BLOCK
    assert f.severity is Severity.HIGH and f.severity_raw == "high"
    assert f.file == "src/calc.py" and f.line == 0
    assert "is_adult" in f.message
    assert "1 previously-killed mutant(s) now survive" in f.message
    assert FP in f.evidence
    assert f.gate is Gate.PRE_PUSH and f.source is Source.DETERMINISTIC


def test_baking_transition_warns(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=False))
    trans = [f for f in got if f.rule == "transition"]
    assert [f.verdict for f in trans] == [Verdict.WARN]


def test_rate_warns_even_when_armed(tmp_path):
    got = _findings(_rate_ledger(tmp_path), _cfg(armed=True))
    assert [f.rule for f in got] == ["rate"]
    f = got[0]
    assert f.verdict is Verdict.WARN
    assert f.severity is Severity.LOW and f.severity_raw == "low"
    assert "1.00 -> 0.33" in f.message
    assert f.evidence == ""


def test_mapped_test_suppresses_transition_not_rate(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True),
                    changed_files={"tests/test_calc.py"})
    assert [f.rule for f in got] == ["rate"]   # transition ephemeral-suppressed


def test_module_test_suffix_variant_suppresses(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True),
                    changed_files={"src/calc_test.py"})
    assert "transition" not in [f.rule for f in got]


def test_source_touch_does_not_suppress(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True),
                    changed_files={"src/calc.py"})
    trans = [f for f in got if f.rule == "transition"]
    assert [f.verdict for f in trans] == [Verdict.BLOCK]


def test_unrelated_test_does_not_suppress(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True),
                    changed_files={"tests/test_other.py"})
    assert "transition" in [f.rule for f in got]


def test_none_changed_files_never_suppresses(tmp_path):
    got = _findings(_transition_ledger(tmp_path), _cfg(armed=True),
                    changed_files=None)
    assert "transition" in [f.rule for f in got]


def test_empty_outside_pre_push(tmp_path):
    assert _findings(_transition_ledger(tmp_path / "a"), _cfg(True),
                     gate=Gate.PRE_COMMIT) == []
    assert _findings(_transition_ledger(tmp_path / "b"), _cfg(True),
                     gate=Gate.ALL) == []


def test_disabled_engine_returns_empty(tmp_path):
    """[mutation].enabled=false disables the seam entirely: the drain stops
    measuring, so no re-drain could ever clear a stale regression -- teeth
    without the measuring engine would be an inescapable block (spec s9)."""
    got = _findings(_transition_ledger(tmp_path),
                    _cfg(armed=True, enabled=False))
    assert got == []


def test_missing_mutation_config_defaults_to_baking(tmp_path):
    got = _findings(_transition_ledger(tmp_path), SimpleNamespace())
    trans = [f for f in got if f.rule == "transition"]
    assert [f.verdict for f in trans] == [Verdict.WARN]


def test_malformed_target_key_skipped_wellformed_surfaces(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.append(_crf(0, "nosep", 2, 0, True, killed_fps=[FP]))
    led.append(_crf(1, "nosep", 0, 1, True, survivor_fps=[FP]))
    led.append(_crf(2, "src/ok.py::f", 2, 0, True, killed_fps=[FP]))
    led.append(_crf(3, "src/ok.py::f", 0, 1, True, survivor_fps=[FP]))
    got = _findings(led, _cfg(armed=True))
    assert {f.file for f in got} == {"src/ok.py"}


def test_empty_rel_target_key_skipped(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.append(_crf(0, "::func", 2, 0, True, killed_fps=[FP]))
    led.append(_crf(1, "::func", 0, 1, True, survivor_fps=[FP]))
    got = _findings(led, _cfg(armed=True))
    assert got == []


def test_fail_open_broken_ledger():
    class Boom:
        def events(self):
            raise RuntimeError("boom")
    got = mutation_score_gate.mutation_score_gate_findings(
        _cfg(armed=True), Boom(), Gate.PRE_PUSH)
    assert got == []


def test_id_deterministic_and_never_finding_id_shaped(tmp_path):
    got1 = _findings(_transition_ledger(tmp_path / "a"), _cfg(True))
    got2 = _findings(_transition_ledger(tmp_path / "b"), _cfg(True))
    t1 = [f for f in got1 if f.rule == "transition"][0]
    t2 = [f for f in got2 if f.rule == "transition"][0]
    assert t1.id == t2.id
    assert t1.id == compute_fingerprint("mutation-score", "transition",
                                        "src/calc.py", "is_adult", 0)


def test_twin_rule_seam_and_classify_agree(tmp_path):
    """The seam's inline verdict and policy.classify's tool=="mutation-score"
    branch encode the SAME rule (the 1b dual-rule discipline). Red-first:
    fails while classify lacks the branch (it falls through to the default
    WARN while the armed seam says BLOCK)."""
    for armed in (True, False):
        cfg = SimpleNamespace(
            block_rules={},
            mutation={"enabled": True, "score_block_armed": armed})
        led = _transition_ledger(tmp_path / ("armed" if armed else "baking"))
        try:
            got = mutation_score_gate.mutation_score_gate_findings(
                cfg, led, Gate.PRE_PUSH)
        finally:
            led.close()
        assert got, "fixture must yield findings for the twin comparison"
        for f in got:
            _sev, verdict = policy.classify(f.tool, f.rule, f.severity_raw,
                                            Gate.PRE_PUSH, cfg)
            assert f.verdict is verdict, (f.rule, armed)


# --- id stability, which is what makes these SUPPRESSIBLE -------------------
#
# These findings are EPHEMERAL: unlike its two siblings, this producer writes
# nothing to the ledger, so the id is recomputed from scratch every run. Since
# `.aramid-suppressions.toml` binds on ID, an id that moved with the score
# would make an entry against a mutation-score regression a silent no-op --
# valid on the run it was written, dead on the next. That is precisely the
# defect the suppressions work exists to remove, so it is pinned rather than
# read off `compute_fingerprint(TOOL, r.kind, rel, func, 0)` and assumed.
#
# Deliberately NOT asserting a literal digest: that would pin the hash and
# force an edit here whenever fingerprinting changes, while proving nothing
# about stability. What matters is that the id does not MOVE when the things
# that legitimately vary between runs vary.

def _transition_ledger_worse(base, target="src/calc.py::is_adult"):
    """Same file, same function, same rule -- WORSE score. Two previously
    killed mutants now survive instead of one, so message and evidence both
    differ from _transition_ledger's."""
    led = Ledger(base / "l.db")
    led.append(_crf(0, target, 3, 0, True, killed_fps=[FP, "other", "third"]))
    led.append(_crf(1, target, 1, 2, True, killed_fps=["third"],
                    survivor_fps=[FP, "other"]))
    return led


def _only(findings, rule):
    got = [f for f in findings if f.rule == rule]
    assert len(got) == 1, f"expected exactly one {rule} finding, got {len(got)}"
    return got[0]


def test_a_mutation_score_finding_id_does_not_move_when_the_score_does(tmp_path):
    mild = _only(_findings(_transition_ledger(tmp_path / "mild"),
                           _cfg(armed=True)), "transition")
    worse = _only(_findings(_transition_ledger_worse(tmp_path / "worse"),
                            _cfg(armed=True)), "transition")

    assert mild.message != worse.message, (
        "the two fixtures must actually differ in score, or this test compares "
        "a run with itself and proves determinism instead of stability")
    assert mild.id == worse.id, (
        "the id moved with the score -- a suppression written against a "
        "mutation-score regression would be dead on the next run")


def test_a_mutation_score_finding_id_does_not_move_with_the_changed_file_scope(
        tmp_path):
    """`changed_files` is passed only for a genuine push delta, so the SAME
    regression is graded with it on one push and without it on the next
    (`check --all`, or a rangeless range). An id keyed on scope would give one
    finding two identities.

    WEAKER THAN ITS SIBLING, measured rather than assumed. Perturbing the id to
    vary with the score turns the sibling above red and leaves this one GREEN
    -- `changed_files` only filters today, so nothing short of deliberately
    threading it into the fingerprint can move this. It is a forward guard on a
    property that currently holds by construction; its only live protection is
    `_only`, which fails if the fixture stops producing the finding at all."""
    unscoped = _only(_findings(_transition_ledger(tmp_path / "a"),
                               _cfg(armed=True)), "transition")
    # A changed set that does NOT contain the mapped test, so the finding
    # survives rather than being scope-suppressed.
    scoped = _only(_findings(_transition_ledger(tmp_path / "b"),
                             _cfg(armed=True),
                             changed_files={"src/unrelated.py"}), "transition")

    assert unscoped.id == scoped.id
