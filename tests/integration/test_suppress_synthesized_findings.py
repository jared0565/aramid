"""`.aramid-suppressions.toml` must reach the findings the gate SYNTHESIZES.

Three producers do not emit a RunnerResult -- they are materialized from the
ledger inside run_gate itself, AFTER `policy.apply_overrides` has already run:

    llm-review      review.llm_gate_findings
    mutation        mutation_gate.mutation_gate_findings
    mutation-score  mutation_score_gate.mutation_score_gate_findings

So a suppression entry naming one of them bound NOTHING, and -- because stale
detection needs a "near miss" among the findings apply_overrides was given --
it was not even reported as dead. The operator wrote a reviewed, reason-bearing
entry, committed it, and got silence in both directions. That combination is
worse than either half: a suppression that fails loudly is a bug, one that
fails quietly is a false sense of having decided something.

THE TOOL STRINGS ARE `llm-review`, `mutation`, `mutation-score`. Not `llm`.
This file's own CHANGELOG entry said "llm" and would have sent the next reader
to write a second silent no-op -- the same NAME != TOOL trap already documented
on `consumers.base.Repaired` (`js_mutation` emits `tool="js-mutation"`). The
gate matches on ID, so a wrong `tool` here does not break BINDING -- it breaks
the STALE report, which is the only thing that would have told you.

WHAT THIS CHANGES, STATED PLAINLY: a tracked suppression can now downgrade an
armed, confirmed-critical LLM BLOCK. That is a security-gate semantic and it is
deliberate -- design doc section 6 gives the committed file ANY tier ("the team
decided this"), which it already exercises over gitleaks and semgrep BLOCKs.
What does NOT change is the other channel: `.aramid/` ledger overrides stay
WARN-only, so a machine-local, unreviewable entry still cannot hide a BLOCK.
That asymmetry is `policy.apply_overrides`'s `elif f.verdict is Verdict.WARN`
branch, guarded by tests/unit/test_policy.py::
test_override_does_not_downgrade_block_finding -- NOT duplicated here.

Not reachable through this path at all, and deliberately not tested here: the
ledger-override channel never gets as far as apply_overrides for these three,
because both synthesizers skip a record whose `status` is not "open" -- an
override drops the finding before it is ever built. `commands/override.py`
refuses that at the CLI for a confirmed-critical LLM finding, armed or not.
"""
import subprocess

from aramid import config as config_mod
from aramid import pipeline
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Source, Verdict

NOW = "2026-08-10T12:00:00+00:00"

MUTANT_ID = "w" * 64
LLM_ID = "f" * 64
LLM_EVIDENCE = "return db.get(order_id)"


def _no_runners(monkeypatch):
    """Isolate the real subprocess runners out so the exit code reflects ONLY
    the synthesized ledger gates -- never a stray lint/tests BLOCK from the
    fixture repo. Same device as test_mutation_gate_e2e.py."""
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})


def _run(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


def _repo_with_upstream(tmp_path):
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    r = tmp_path / "repo"
    r.mkdir()
    _run(r, "init", "-q", "-b", "main")
    _run(r, "config", "user.email", "t@t")
    _run(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "src" / "widget.py").write_text("def add(a, b):\n    return a + b\n",
                                         encoding="utf-8")
    # The LLM finding's evidence quote must still exist at HEAD, or
    # review.auto_resolve_llm clears the finding before the gate ever
    # materializes it and the test would pass by having nothing to suppress.
    (r / "src" / "auth.py").write_text(
        f"def get_order(order_id):\n    {LLM_EVIDENCE}\n", encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "c1")
    _run(r, "remote", "add", "origin", str(remote))
    _run(r, "push", "-q", "-u", "origin", "main")
    return r


def _commit_unrelated(r):
    """Put something in @{u}..HEAD WITHOUT touching widget.py or a mapped
    test, so auto_resolve_mutation does not resolve the survivor."""
    (r / "src" / "other.py").write_text("y = 2\n", encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "unrelated change")


def _seed_mutation_survivor(r):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("r0", NOW, "drain", set(), set(), [Finding(
            id=MUTANT_ID, tool="mutation", rule="flip_arith",
            severity_raw="medium", severity=Severity.MEDIUM,
            verdict=Verdict.WARN, file="src/widget.py", line=2,
            message="mutant survived: a - b", evidence="",
            gate=Gate.ALL, source=Source.DETERMINISTIC)])
    finally:
        led.close()


def _seed_confirmed_critical_llm(r):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("r0", NOW, "drain", set(), set(), [Finding(
            id=LLM_ID, tool="llm-review", rule="llm/a01",
            severity_raw="critical", severity=Severity.CRITICAL,
            verdict=Verdict.WARN, file="src/auth.py", line=2,
            message="IDOR: no ownership check", evidence=LLM_EVIDENCE,
            gate=Gate.ALL, source=Source.LLM, confirmed=True)])
    finally:
        led.close()


def _arm(r, section):
    (r / "aramid.toml").write_text(
        f"schema_version = 1\n\n[{section}]\n{section}_block_armed = true\n",
        encoding="utf-8")


def _suppress(r, *, fid, tool, rule, path, reason="team decided: accepted risk"):
    (r / ".aramid-suppressions.toml").write_text(
        "schema_version = 1\n\n[[suppress]]\n"
        f'id = "{fid}"\ntool = "{tool}"\nrule = "{rule}"\n'
        f'path = "{path}"\nreason = "{reason}"\n',
        encoding="utf-8")


# --- the two BLOCKs a tracked suppression must be able to reach --------------

def test_a_suppression_downgrades_an_armed_mutation_block(tmp_path, monkeypatch):
    """The armed BLOCK is asserted FIRST. Without that half the test could
    pass against a gate that never blocked at all, which is exactly how a
    suppression that binds nothing looks from the outside."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm(r, "mutation")
    _seed_mutation_survivor(r)
    _commit_unrelated(r)

    assert cmd_check(r, Gate.PRE_PUSH, "range") == 1, (
        "the armed mutation survivor did not block -- this test's premise is "
        "gone and everything below it would pass vacuously")

    _suppress(r, fid=MUTANT_ID, tool="mutation", rule="flip_arith",
              path="src/widget.py")

    assert cmd_check(r, Gate.PRE_PUSH, "range") != 1, (
        "a tracked, reason-bearing suppression naming the mutation finding's "
        "exact id did not reach it -- it is synthesized after apply_overrides")


def test_a_suppression_downgrades_an_armed_confirmed_critical_llm_block(
        tmp_path, monkeypatch):
    """The named semantic change, given its own test so it can never be
    mistaken for a side effect of the mutation one. `llm_block_armed` +
    confirmed + critical is the ONLY combination review.llm_gate_findings
    renders as BLOCK."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm(r, "llm")
    _seed_confirmed_critical_llm(r)
    _commit_unrelated(r)

    assert cmd_check(r, Gate.PRE_PUSH, "range") == 1, (
        "the armed confirmed-critical LLM finding did not block -- premise "
        "gone (check auto_resolve_llm did not clear it: the evidence quote "
        "must still exist at HEAD)")

    _suppress(r, fid=LLM_ID, tool="llm-review", rule="llm/a01",
              path="src/auth.py")

    assert cmd_check(r, Gate.PRE_PUSH, "range") != 1, (
        "a tracked suppression did not reach the LLM BLOCK")


# --- the stale report, which is the half that told nobody -------------------

def test_a_suppression_that_binds_a_synthesized_finding_is_not_reported_stale(
        tmp_path, monkeypatch):
    """The obvious wrong composition is to concatenate the two passes' stale
    lists; the right one is to recompute over their union, so `matched_ids`
    covers both.

    MEASURED, AND WEAKER THAN IT LOOKS: swapping the union for a concatenation
    leaves this test -- and the two above -- GREEN. Near-miss requires TOOL
    equality, and the two lists carry disjoint tool namespaces today (no runner
    emits `mutation`, `mutation-score` or `llm-review`), so no record can ever
    near-miss in one list and match in the other. Union is kept because it is
    correct by construction rather than by that coincidence, but this test does
    NOT discriminate the two and must not be cited as if it did. A runner that
    ever emits one of those three tool names is what would make the difference
    real.

    What it does pin, which nothing else does: a suppression that BINDS is not
    also announced as dead. Report-only today (reporter.py is the sole
    consumer, no exit code reads it) -- a wrong-message bug, not a
    wrong-verdict one, but one that reads as "delete me" to an operator."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm(r, "mutation")
    _seed_mutation_survivor(r)
    _commit_unrelated(r)
    _suppress(r, fid=MUTANT_ID, tool="mutation", rule="flip_arith",
              path="src/widget.py")

    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        res = pipeline.run_gate(r, Gate.PRE_PUSH, "range", cfg, led)
    finally:
        led.close()

    assert [f.verdict for f in res.findings if f.id == MUTANT_ID] == [Verdict.INFO], (
        "premise: the suppression must actually bind for 'not stale' to mean "
        "anything")
    assert [s.id for s in res.stale_overrides] == [], (
        f"a suppression that BOUND was reported stale: {res.stale_overrides}")


def test_a_stale_mutation_suppression_is_now_reported_instead_of_silent(
        tmp_path, monkeypatch):
    """The OTHER half of the original defect, and the one that actually needed
    the second pass to exist.

    An entry with the right tool, rule and path but a DEAD id (the mutant it
    named was killed and a different one now survives) is exactly what the
    stale report is for -- `.aramid-suppressions.toml`'s own docstring promises
    "aramid reports it as a stale suppression rather than silently covering
    nothing". For the three synthesized producers that promise was false: no
    `mutation` finding was ever in the list stale detection saw, so there was
    no near miss and no warning, forever.

    Red before the fix -- and unlike the three tests above, this one is red
    for the STALE path specifically, not the binding path."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm(r, "mutation")
    _seed_mutation_survivor(r)
    _commit_unrelated(r)
    # Same tool + rule + path as the open survivor, different id: a near miss.
    dead_id = "d" * 64
    _suppress(r, fid=dead_id, tool="mutation", rule="flip_arith",
              path="src/widget.py")

    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        res = pipeline.run_gate(r, Gate.PRE_PUSH, "range", cfg, led)
    finally:
        led.close()

    assert any(f.id == MUTANT_ID for f in res.findings), (
        "premise: the synthesized mutation finding must be present for the "
        "near-miss comparison to have anything to compare against")
    assert [s.id for s in res.stale_overrides] == [dead_id], (
        "a suppression naming a mutation finding that no longer exists was "
        f"not reported stale: {res.stale_overrides}")
