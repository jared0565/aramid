"""One snapshot, two readers. `aramid status` renders these signals and the
fleet health row grades them; if they were computed twice they would drift.
Every criterion is exercised in BOTH directions from a real ledger, and the
last test perturbs the snapshot by ADDING a member and asserts the rendered
line and the graded criterion move together."""
import dataclasses
from datetime import datetime, timezone

from aramid import health
from aramid import ledger as ledger_mod
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict
from aramid.pipeline import GateResult

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc).isoformat()


def _f(fid, tool="semgrep", rule="r", verdict=Verdict.WARN, file="a.py"):
    return Finding(fid, tool, rule, "high", Severity.HIGH, verdict, file, 1, "m", "e",
                   Gate.PRE_PUSH)


def _run(lg, run_id, tools, gate="pre-push", expected=None):
    payload = {"gate": gate, "tools": list(tools)}
    if expected is not None:
        payload["expected"] = list(expected)
    lg.append(Event(EventType.RUN_STARTED, run_id, NOW, payload=payload))


def _consumer(lg, name, state, note, duration_s=0.0):
    lg.append(Event(EventType.CONSUMER_RUN_FINISHED, "d", NOW,
                    payload={"consumer": name, "state": state, "note": note,
                             "duration_s": duration_s, "finding_count": 0}))


def _result(**kw):
    base = dict(exit_code=0, findings=[], degraded=[], new_ids=[], stale_overrides=[],
                run_id="run-1")
    base.update(kw)
    return GateResult(**base)


def _crit(lg, **kw):
    return health.criteria(health.snapshot(None, lg, **kw))


# ------------------------------------------------------ 1. no_skip_streak ---

def test_skip_streak_present_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    _run(lg, "p1", ["gitleaks", "semgrep"], expected=["gitleaks", "semgrep"])
    _run(lg, "p2", ["gitleaks"], expected=["gitleaks", "semgrep"])
    h = health.snapshot(None, lg)
    assert h.skip_streaks == {"pre-push": {"semgrep": 1}}
    assert health.criteria(h)["no_skip_streak"] is False
    assert health.skip_streak_lines(h) == ["  semgrep: skipped last 1 pre-push run(s)"]
    lg.close()


def test_every_expected_tool_ran_reads_green(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    _run(lg, "p1", ["gitleaks", "semgrep"], expected=["gitleaks", "semgrep"])
    _run(lg, "p2", ["gitleaks", "semgrep"], expected=["gitleaks", "semgrep"])
    h = health.snapshot(None, lg)
    assert h.skip_streaks == {}
    assert health.criteria(h)["no_skip_streak"] is True
    assert health.skip_streak_lines(h) == []
    lg.close()


# --------------------------------------------------- 2. consumers_healthy ---

def test_degraded_streak_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    _consumer(lg, "fuzz", "ok", "0 crash finding(s)")
    _consumer(lg, "fuzz", "degraded", "fuzz driver broken @ abc: boom")
    _consumer(lg, "fuzz", "degraded", "fuzz driver broken @ abc: boom")
    h = health.snapshot(None, lg)
    assert h.degraded_consumers == (health.ConsumerFault("fuzz", 2, 0.0,
                                                         "fuzz driver broken @ abc: boom"),)
    assert health.criteria(h)["consumers_healthy"] is False
    assert health.degraded_consumer_lines(h) == [
        "  degraded consumer runs:",
        "    fuzz: degraded last 2 run(s) -- fuzz driver broken @ abc: boom"]
    lg.close()


def test_stood_down_reads_red_and_counts_the_give_up_run(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    for _ in range(3):
        _consumer(lg, "mutation", "degraded", "baseline timeout: x", duration_s=100.0)
    _consumer(lg, "mutation", "ok", "mutation giving up: nope", duration_s=0.0)
    h = health.snapshot(None, lg)
    assert h.stood_down == (health.ConsumerFault("mutation", 4, 300.0,
                                                 "mutation giving up: nope"),)
    assert health.criteria(h)["consumers_healthy"] is False
    assert health.stood_down_lines(h) == [
        "  consumers stood down:",
        "    mutation: stood down after 4 run(s), 300s spent -- mutation giving up: nope"]
    lg.close()


def test_no_work_streak_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    for _ in range(2):
        _consumer(lg, "mutation", "ok", "no mutants tested: 18 generated, 0 certified",
                  duration_s=10.0)
    h = health.snapshot(None, lg)
    assert h.no_work == (health.ConsumerFault(
        "mutation", 2, 20.0, "no mutants tested: 18 generated, 0 certified"),)
    assert health.criteria(h)["consumers_healthy"] is False
    assert health.no_work_lines(h) == [
        "  consumers doing no work:",
        "    mutation: 2 run(s) certified nothing, 20s spent -- "
        "no mutants tested: 18 generated, 0 certified"]
    lg.close()


def test_recovered_consumer_reads_green(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    _consumer(lg, "fuzz", "degraded", "boom")
    _consumer(lg, "mutation", "ok", "no mutants tested: 1 generated, 0 certified")
    _consumer(lg, "fuzz", "ok", "0 crash finding(s) from 200 case(s)")
    _consumer(lg, "mutation", "ok", "2 confirmed survivor(s) of 11 mutant(s) tested")
    h = health.snapshot(None, lg)
    assert (h.degraded_consumers, h.stood_down, h.no_work) == ((), (), ())
    assert health.criteria(h)["consumers_healthy"] is True
    lg.close()


# -------------------------------------------------------- 3. resolvers_ok ---

def test_never_ran_resolver_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    lg.record_run("r0", NOW, "pre-push", set(), set(),
                  [_f("a" * 64, tool="mutation", rule="bool-swap")])
    ledger_mod.note_yield(lg, "r1", NOW, resolver="evidence_gone", tool="llm-review",
                          considered=0, resolved=0)
    h = health.snapshot(None, lg)
    assert ("gap_addressed", "mutation", "NEVER RAN") in h.resolver_defects
    assert health.criteria(h)["resolvers_ok"] is False
    assert health.resolver_defect_lines(h) == [
        "  resolver defects: 3 (run `aramid resolvers`)",
        "    file_departed/mutation, gap_addressed/mutation, mutant_killed/mutation"]
    lg.close()


def test_blind_resolver_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    lg.record_run("r0", NOW, "pre-push", set(), set(),
                  [_f("b" * 64, tool="mutation", rule="bool-swap")])
    for resolver in ("gap_addressed", "file_departed", "mutant_killed"):
        ledger_mod.note_yield(lg, "r1", NOW, resolver=resolver, tool="mutation",
                              considered=0, resolved=0)
    h = health.snapshot(None, lg)
    assert all(v == "BLIND" for _r, _t, v in h.resolver_defects)
    assert health.criteria(h)["resolvers_ok"] is False
    lg.close()


def test_healthy_resolvers_read_green(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    ledger_mod.note_yield(lg, "r1", NOW, resolver="evidence_gone", tool="llm-review",
                          considered=0, resolved=0)
    h = health.snapshot(None, lg)
    assert h.resolver_defects == ()
    assert health.criteria(h)["resolvers_ok"] is True
    assert health.resolver_defect_lines(h) == []
    lg.close()


# ------------------------------------------ 4. no_self_inflicted_block ------

def test_a_crashed_block_tier_tool_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    h = health.snapshot(None, lg, _result(exit_code=1, degraded=["semgrep"],
                                          degraded_block_tier=True), gate=Gate.PRE_PUSH)
    assert h.bad_tools == ("semgrep",)
    assert health.criteria(h)["no_self_inflicted_block"] is False
    lg.close()


def test_a_block_on_a_genuine_finding_reads_green(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    h = health.snapshot(None, lg, _result(exit_code=1,
                                          findings=[_f("s1", tool="gitleaks",
                                                       verdict=Verdict.BLOCK)]),
                        gate=Gate.PRE_PUSH)
    assert h.blocking == 1 and h.exit_code == 1
    assert health.criteria(h)["no_self_inflicted_block"] is True
    lg.close()


def test_engine_error_reads_every_criterion_red_and_audit_null(tmp_path):
    h = health.snapshot(None, None, None, gate=Gate.PRE_PUSH, engine_error=True)
    assert health.criteria(h) == {"no_skip_streak": False, "consumers_healthy": False,
                                  "resolvers_ok": False, "no_self_inflicted_block": False,
                                  "dep_audit_ran": None}
    assert h.exit_code == 3 and h.engine_error is True


# ---------------------------------------------------------- 5. dep_audit_ran

def test_pip_audit_ran_on_a_python_repo_at_pre_push_reads_true(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    res = _result(tools_ran=("gitleaks", "pip-audit", "semgrep"), stacks=("python",))
    assert _crit(lg, result=res, gate=Gate.PRE_PUSH)["dep_audit_ran"] is True
    lg.close()


def test_pip_audit_missing_on_a_python_repo_at_pre_push_reads_false(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    res = _result(tools_ran=("gitleaks", "semgrep"), stacks=("python",))
    assert _crit(lg, result=res, gate=Gate.PRE_PUSH)["dep_audit_ran"] is False
    lg.close()


def test_pip_audit_not_expected_reads_null(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    py = _result(tools_ran=("gitleaks", "ruff"), stacks=("python",))
    js = _result(tools_ran=("gitleaks", "semgrep"), stacks=("js",))
    assert _crit(lg, result=py, gate=Gate.PRE_COMMIT)["dep_audit_ran"] is None
    assert _crit(lg, result=js, gate=Gate.PRE_PUSH)["dep_audit_ran"] is None
    assert _crit(lg)["dep_audit_ran"] is None
    lg.close()


# ------------------------------------------------------------ row_green -----

def test_row_green_table():
    green = {k: True for k in health.CRITERIA}
    assert health.row_green(green) is True
    assert health.row_green({**green, "dep_audit_ran": None}) is True
    assert health.row_green({**green, "dep_audit_ran": False}) is False
    for key in health.CRITERIA[:4]:
        assert health.row_green({**green, key: False}) is False
    assert health.row_green({}) is False


# ------------------------------------- two computations that must agree -----

def test_status_line_and_criterion_move_together(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    clean = health.snapshot(None, lg)
    assert health.criteria(clean)["consumers_healthy"] is True
    assert health.stood_down_lines(clean) == []

    # Perturb by ADDING a member, never by breaking one.
    perturbed = dataclasses.replace(
        clean, stood_down=(health.ConsumerFault("dast", 3, 9.0, "dast giving up: x"),))
    assert health.criteria(perturbed)["consumers_healthy"] is False
    assert health.stood_down_lines(perturbed) == [
        "  consumers stood down:",
        "    dast: stood down after 3 run(s), 9s spent -- dast giving up: x"]
    lg.close()
