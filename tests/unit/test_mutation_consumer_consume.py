"""`consumers.mutation.consume` at unit scope: every counter, budget, exit-code
tuple, note and claim, one exact assertion each.

The drain confirms a mutant against the UNIT suite alone, and until this
file the only unit test that reached `consume` was the disabled-section
early return: the 109 mutants the generator emits for its body were held by
tests/integration/test_mutation_consumer.py, which the drain never runs, so
every one of them was a survivor waiting to be reported three at a time.

The harness is the seam the integration tests use and nothing more: a real
tmp git repo (the worktree `consume` cuts is real), a real ledger, and
`run_subprocess` replaced by an ORACLE that reads which mutant is applied
in the worktree and answers from a script -- so a run of fourteen mutants
with every verdict takes a second, and the counters can be asserted to the
digit. The fixture module has one mutant per function (`x + N`), so an
outcome is scripted by function name."""
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from aramid import config as config_mod
from aramid import mutation
from aramid.consumers import mutation as mut_consumer
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict
from aramid.queue import QueueItem
from aramid.runners.base import RunnerResult, ToolState

N = 14
SRC = "".join(f"def f{i}(x):\n    return x + {i}\n\n\n" for i in range(1, N + 1)).rstrip("\n") + "\n"
LINES = SRC.splitlines()
MUTANTS = mutation.generate_mutants(SRC, set(range(1, len(LINES) + 1)))
assert len(MUTANTS) == N and [m.func for m in MUTANTS] == [f"f{i}" for i in range(1, N + 1)]
ONE = "def g(x):\n    return x + 1\n"
DESC = {m.func: m.description for m in MUTANTS}
TOML = ("schema_version = 1\n[mutation]\nmax_mutants = 20\nconfirm_cap = 3\n"
        "wall_budget_s = 600\nmutant_timeout_s = 120\nbaseline_timeout_s = 480\n"
        "retest_cap = 3\n")
TEST = "from calc import f1\ndef test_one():\n    assert isinstance(f1(1), int)\n"


def _git(root, *a):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a],
                   cwd=root, check=True, capture_output=True, text=True)


def _sha(root):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


def _repo(tmp_path, toml=TOML, head_src=SRC):
    """calc.py empty at base, `head_src` at head: every line is in range."""
    r = tmp_path / "r"
    (r / "tests").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    (r / "aramid.toml").write_text(toml, encoding="utf-8")
    (r / "conftest.py").write_text("", encoding="utf-8")
    (r / "tests" / "test_calc.py").write_text(TEST, encoding="utf-8")
    (r / "calc.py").write_text("", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "calc.py").write_text(head_src, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "head")
    return r, base, _sha(r)


def _commit(r, rel, body):
    (r / rel).parent.mkdir(parents=True, exist_ok=True)
    (r / rel).write_text(body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", rel)
    return _sha(r)


def fp(func):
    m = next(x for x in MUTANTS if x.func == func)
    return mut_consumer._mutant_fp("calc.py", m.op, m.line, LINES)


def _record_survivors(r, funcs, *, pending=()):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("seed", "2026-09-01T00:00:00+00:00", "drain", {"mutation"}, {"calc.py"},
                       [Finding(id=fp(f), tool="mutation", rule="int-bound", severity_raw="medium",
                                severity=Severity.MEDIUM, verdict=Verdict.WARN, file="calc.py",
                                line=next(m.line for m in MUTANTS if m.func == f),
                                message="mutant survived", evidence="", gate=Gate.ALL)
                        for f in funcs])
        for k, f in enumerate(pending):
            led.append(Event(EventType.FINDING_RESOLVED, "gate", f"2026-09-01T00:01:{k:02d}+00:00",
                             finding_id=fp(f),
                             payload={"auto_resolved": "gap_addressed", "pending_retest": True}))
    finally:
        led.close()


def _seed_notes(r, n, note):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for k in range(n):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"d{k}",
                             f"2026-09-01T0{k}:00:00+00:00",
                             payload={"consumer": "mutation", "item_id": f"old{k}",
                                      "state": "degraded", "note": note, "duration_s": 1.0}))
    finally:
        led.close()


@dataclass
class Out:
    rc: int = 0
    state: ToolState = ToolState.OK
    raw: str = ""
    stderr: str = ""
    dur: float = 0.5


OK1, OK2, PASS = Out(rc=1), Out(rc=2), Out(rc=0)
TIMEOUT = Out(state=ToolState.TIMEOUT)


class Oracle:
    """`run_subprocess` for a worktree whose calc.py the script names.
    `outcomes[(kind, label)]` is an Out or a callable(cwd) -> Out (side
    effects, or raise); kind is "full" (the configured suite: baseline and
    every confirm) or "s1"; label is "BASE", "f<n>", "DIR" or "?"."""

    def __init__(self, full_argv, outcomes, default=PASS, original=SRC):
        self.full = list(full_argv)
        self.outcomes = dict(outcomes)
        self.default = default
        self.original = original
        lines = original.splitlines()
        self.by_source = {m.source: m.func for m in
                          mutation.generate_mutants(original, set(range(1, len(lines) + 1)))}
        self.calls = []

    def __call__(self, argv, cwd, timeout_s, env=None, **kw):
        p = Path(cwd) / "calc.py"
        if p.is_dir():
            label = "DIR"
        elif p.exists():
            src = p.read_text(encoding="utf-8")
            label = "BASE" if src == self.original else self.by_source.get(src, "?")
        else:
            label = "NONE"
        kind = "full" if list(argv) == self.full else "s1"
        self.calls.append((kind, label, timeout_s))
        # the default is for MUTANTS; an unscripted baseline passes
        spec = self.outcomes.get((kind, label), PASS if label == "BASE" else self.default)
        if callable(spec):
            spec = spec(Path(cwd))
        return RunnerResult(tool=str(argv[0]), state=spec.state, raw=spec.raw,
                            stderr=spec.stderr, duration_s=spec.dur, returncode=spec.rc)


def _run(r, base, head, monkeypatch, outcomes, *, default=PASS, item_id="q1",
         reasons=("t",), original=SRC):
    cfg = config_mod.load_config(r)
    oracle = Oracle(mut_consumer._full_argv(cfg, r), outcomes, default, original)
    monkeypatch.setattr(mut_consumer, "run_subprocess", oracle)
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id=item_id, base=base, head=head, score=55, reasons=tuple(reasons),
                     state="queued", created_at="t", updated_at="t")
    try:
        res = mut_consumer.consume(item, DrainContext(root=r, cfg=cfg, ledger=led,
                                                      clock=lambda: "t"))
    finally:
        led.close()
    return res, oracle


def _stats(res, **expect):
    """Every counter `consume` reports, exactly; unnamed ones are zero."""
    zero = {"generated": 0, "tested": 0, "killed_s1": 0, "killed_s2": 0, "survived": 0,
            "confirmed": 0, "timeouts": 0, "errors": 0, "unconfirmed_kills": 0,
            "capped_kills": 0, "unselected_s1": 0, "truncated": False,
            "retest_candidates": 0, "retested": 0, "retest_killed": 0,
            "retest_truncated": False, "retest_skipped": 0, "claimed": 0,
            "claimed_retested": 0, "retested_ids": []}
    want = {**zero, **expect}
    got = {k: res.extra[k] for k in want}
    assert got == want, {k: (got[k], want[k]) for k in want if got[k] != want[k]}


def _target(res, func, **expect):
    t = res.extra["mutation_scores"]["targets"][f"calc.py::{func}"]
    zero = {"generated": 1, "killed_s1": 0, "killed_s2": 0, "survived_s1": 0,
            "unconfirmed": 0, "timeouts": 0, "errors": 0}
    want = {**zero, **expect}
    got = {k: t[k] for k in want}
    assert got == want, (func, {k: (got[k], want[k]) for k in want if got[k] != want[k]})
    return t


def _ids(res):
    return {f.message.split(" in ")[1].split(" ")[0] for f in res.findings}


def _no_worktrees(r):
    out = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                         capture_output=True, text=True).stdout
    return len([ln for ln in out.splitlines() if ln.strip()]) == 1


# ----------------------------------------------------------- every verdict --

def _dir_trick(cwd):
    """The oracle's side effect for the last mutant: calc.py becomes a
    directory, so the restore after this run raises OSError."""
    p = cwd / "calc.py"
    p.unlink()
    p.mkdir()
    return OK1


def _boom(cwd):
    raise RuntimeError("the runner itself blew up")


MIXED = {
    ("full", "BASE"): Out(rc=0, dur=3.5),
    ("s1", "f1"): OK1,                                   # killed at stage 1
    ("s1", "f2"): OK2,                                   # collection error = kill
    ("s1", "f3"): PASS, ("full", "f3"): OK1,             # killed by the full suite
    ("s1", "f4"): PASS, ("full", "f4"): OK2,
    ("s1", "f5"): PASS, ("full", "f5"): PASS,            # confirmed survivor
    ("s1", "f6"): TIMEOUT,                               # unattributable
    ("s1", "f7"): _boom,                                 # the runner raised
    ("s1", "f8"): Out(rc=5), ("full", "f8"): PASS,       # nothing selected, then confirmed
    ("s1", "f9"): PASS, ("full", "f9"): TIMEOUT,
    ("s1", "f10"): Out(rc=3),                            # usage error: argv's fault
    ("s1", "f11"): Out(rc=1, state=ToolState.CRASHED),   # rc 1 but not OK: not a kill
    ("full", "f11"): PASS,
    ("s1", "f12"): PASS, ("full", "f12"): Out(rc=1, state=ToolState.CRASHED),
    ("s1", "f13"): PASS,                                 # the 8th confirm: cap is 7
    ("s1", "f14"): _dir_trick,                           # killed, then the restore fails
}


def test_every_stage_1_and_full_suite_verdict_lands_in_its_own_counter(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, TOML.replace("confirm_cap = 3", "confirm_cap = 7"))

    res, oracle = _run(r, base, head, monkeypatch, MIXED)

    assert res.state == "ok", res.note
    _stats(res, generated=14, tested=14, killed_s1=3, killed_s2=2, survived=8, confirmed=3,
           timeouts=2, errors=4, unselected_s1=1, truncated=True)
    assert res.note == ("3 confirmed survivor(s) of 14 mutant(s) tested (truncated: budget/cap"
                        " hit, remainder dropped); stage 1 selected no test for 1 mutant(s)")
    assert _ids(res) == {"f5", "f8", "f11"}
    assert {f.message for f in res.findings} == {
        f"mutant survived: {DESC[f]} (unkilled by: pytest -q)" for f in ("f5", "f8", "f11")}
    # a full-suite kill is its own confirmation and is claimed whether or
    # not the id is on the books; a stage-1 kill of an unrecorded id is
    # a score only
    assert res.repaired is not None and res.repaired.examined == ()
    assert res.repaired.ids == tuple(sorted((fp("f3"), fp("f4"))))
    assert res.extra["baseline_s"] == 3.5
    # the whole-suite budget for the baseline and every confirm, the
    # per-mutant one for every stage-1 run
    assert oracle.calls[0] == ("full", "BASE", 480.0)
    assert {t for k, _, t in oracle.calls if k == "s1"} == {120.0}
    assert {t for k, _, t in oracle.calls if k == "full"} == {480.0}
    assert [lab for k, lab, _ in oracle.calls if k == "full"][1:] == \
        ["f3", "f4", "f5", "f8", "f9", "f11", "f12"], "seven confirms, then the cap"
    _target(res, "f1", killed_s1=1)
    _target(res, "f2", killed_s1=1)
    _target(res, "f3", killed_s2=1)
    _target(res, "f4", killed_s2=1)
    t5 = _target(res, "f5", survived_s1=1)
    assert t5["survivor_fps"] == [fp("f5")] and t5["fully_mutated"] is True
    t6 = _target(res, "f6", timeouts=1)
    assert t6["fully_mutated"] is False
    _target(res, "f7")                       # the exception is the run's, not the target's
    _target(res, "f8", survived_s1=1)
    _target(res, "f9", timeouts=1)
    _target(res, "f10", errors=1)
    _target(res, "f11", survived_s1=1)
    _target(res, "f12", errors=1)
    _target(res, "f13", unconfirmed=1)
    t14 = _target(res, "f14", killed_s1=1, errors=1)
    assert t14["killed_fps"] == [fp("f14")]
    assert _no_worktrees(r)


def test_a_file_that_cannot_be_read_is_one_error_and_no_mutants(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, head_src=ONE)

    def swap(cwd):
        p = cwd / "calc.py"
        p.unlink()
        p.mkdir()
        return PASS
    res, _ = _run(r, base, head, monkeypatch, {("full", "BASE"): swap}, original=ONE)

    assert res.state == "ok"
    _stats(res, errors=1)
    assert res.note == "0 confirmed survivor(s) of 0 mutant(s) tested"


# --------------------------------------------------------------- budgets --

def test_max_mutants_cuts_the_range_and_the_note_says_so(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, TOML.replace("max_mutants = 20", "max_mutants = 3"))

    res, _ = _run(r, base, head, monkeypatch, {}, default=OK1)

    _stats(res, generated=14, tested=3, killed_s1=3, truncated=True)
    assert res.note == ("0 confirmed survivor(s) of 3 mutant(s) tested "
                        "(truncated: budget/cap hit, remainder dropped)")


def _clock(monkeypatch, *ticks):
    seq = list(ticks)

    def monotonic():
        if len(seq) > 1:
            return seq.pop(0)
        return seq[0]
    monkeypatch.setattr(mut_consumer, "time", SimpleNamespace(monotonic=monotonic))


def test_the_wall_budget_stops_between_mutants_strictly_after_it_is_spent(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    # started, then one check per mutant: at exactly the budget the next
    # mutant still runs; past it the rest are dropped.
    _clock(monkeypatch, 0.0, 0.0, 600.0, 600.001)

    res, _ = _run(r, base, head, monkeypatch, {}, default=OK1)

    _stats(res, generated=14, tested=2, killed_s1=2, truncated=True)
    assert res.note == ("0 confirmed survivor(s) of 2 mutant(s) tested "
                        "(truncated: budget/cap hit, remainder dropped)")


def test_a_baseline_that_ate_the_whole_budget_certifies_nothing_and_says_so(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, head_src=ONE)
    _clock(monkeypatch, 0.0, 600.001)

    res, _ = _run(r, base, head, monkeypatch, {("full", "BASE"): Out(rc=0, dur=590.0)},
                  original=ONE)

    _stats(res, generated=1, tested=0, truncated=True)
    assert res.note == ("no mutants tested: 1 generated, 0 certified -- the 600s wall budget"
                        " covers the whole item and the baseline alone took 590s. Raise"
                        " [mutation].wall_budget_s, or point [mutation].test_command at a"
                        " narrower suite.")


# -------------------------------------------------------------- baseline --

def test_a_missing_suite_command_is_degraded_and_names_the_cwd(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)

    res, oracle = _run(r, base, head, monkeypatch, {("full", "BASE"): Out(state=ToolState.MISSING)})

    assert res.state == "degraded"
    assert res.note.startswith(mut_consumer.missing_note_prefix(oracle.full[0]) + " (resolved from ")
    assert res.note.endswith("or a repo-relative path)")
    assert res.findings == [] and res.repaired is None
    assert len(oracle.calls) == 1, "nothing ran after the baseline"
    assert _no_worktrees(r)


def test_a_baseline_that_collects_no_tests_is_a_skip_not_a_failure(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)

    res, oracle = _run(r, base, head, monkeypatch, {("full", "BASE"): Out(rc=5)})

    assert res.state == "ok"
    assert res.note == ("no python test stack (mutation skipped: pytest collected no tests at"
                        " this head)")
    assert len(oracle.calls) == 1


def test_a_baseline_timeout_is_degraded_with_the_budget_and_the_head(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    cfg = config_mod.load_config(r)
    suite = mut_consumer._suite_label(mut_consumer._full_argv(cfg, r))

    # rc 5 on the timeout: a timed-out run is a timeout whatever code it left
    res, _ = _run(r, base, head, monkeypatch,
                  {("full", "BASE"): Out(rc=5, state=ToolState.TIMEOUT)})

    assert res.state == "degraded"
    assert res.note == (f"{mut_consumer.timeout_note_prefix(480.0, suite)}"
                        f" (last seen @ {head[:12]})")


def test_a_red_baseline_is_degraded_with_the_rc_and_the_last_line_and_a_log(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)

    res, _ = _run(r, base, head, monkeypatch,
                  {("full", "BASE"): Out(rc=1, raw="....F\nFAILED tests/test_calc.py::t\n"
                                                  "1 failed, 4 passed in 0.2s\n")})

    assert res.state == "degraded"
    assert res.note == (f"{mut_consumer.failing_note_prefix(head)} -- rc 1: "
                        f"1 failed, 4 passed in 0.2s")
    assert (r / ".aramid" / "logs" / f"mutation-baseline-q1-{head[:12]}.log").exists()


def test_a_baseline_that_did_not_finish_cleanly_is_degraded_even_at_rc_0(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)

    res, _ = _run(r, base, head, monkeypatch,
                  {("full", "BASE"): Out(rc=0, state=ToolState.CRASHED, stderr="Killed")})

    assert res.state == "degraded"
    assert res.note == f"{mut_consumer.failing_note_prefix(head)} -- rc 0: Killed"


def test_a_missing_command_seen_three_times_gives_up_before_cutting_a_worktree(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    cfg = config_mod.load_config(r)
    argv0 = mut_consumer._full_argv(cfg, r)[0]
    _seed_notes(r, 3, mut_consumer.missing_note_prefix(argv0) + " (resolved from x)")

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert res.state == "ok"
    assert res.note == (f"mutation giving up: {argv0} not found after 3 attempts -- fix"
                        f" [mutation].test_command or [tests].command")
    assert oracle.calls == []


def test_a_worktree_that_cannot_be_added_is_an_error_with_200_chars_of_stderr(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    real = mut_consumer.gitutil._run

    def failing(root, *args, **kw):
        if args[:2] == ("worktree", "add"):
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="x" * 250)
        return real(root, *args, **kw)
    monkeypatch.setattr(mut_consumer.gitutil, "_run", failing)

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert res.state == "error"
    assert res.note == "worktree add failed: " + "x" * 200
    assert oracle.calls == []


# ------------------------------------------------- recorded survivors --

def _claimed_repo(tmp_path, retest_cap=6):
    """Survivors f1..f6 on the books; the item changes only the test that
    NAMES calc.py, so all six are claimed and run first."""
    r, base, head = _repo(tmp_path, TOML.replace("retest_cap = 3", f"retest_cap = {retest_cap}"))
    _record_survivors(r, ["f1", "f2", "f3", "f4", "f5", "f6"])
    head2 = _commit(r, "tests/test_calc.py", TEST + "def test_two():\n    assert f1(2) == 3\n")
    return r, head, head2


CLAIMED = {
    ("s1", "f1"): OK1, ("full", "f1"): OK1,                            # claimed
    ("s1", "f2"): PASS, ("full", "f2"): PASS,                          # still surviving
    ("s1", "f3"): OK2, ("full", "f3"): OK2,                            # claimed
    ("s1", "f4"): OK1, ("full", "f4"): Out(rc=1, state=ToolState.CRASHED),  # unconfirmed
    ("s1", "f5"): OK1, ("full", "f5"): TIMEOUT,                        # unconfirmed
    ("s1", "f6"): PASS, ("full", "f6"): OK1,                           # claimed by the suite
}


def test_named_survivors_run_first_and_only_a_confirmed_kill_is_claimed(tmp_path, monkeypatch):
    r, head, head2 = _claimed_repo(tmp_path)

    res, oracle = _run(r, head, head2, monkeypatch, CLAIMED, item_id="q2")

    assert res.state == "ok", res.note
    _stats(res, tested=6, killed_s1=4, killed_s2=1, survived=2, confirmed=1,
           unconfirmed_kills=2, retest_candidates=6, retested=6, retest_killed=3, claimed=6,
           claimed_retested=6, retested_ids=[fp(f) for f in ("f1", "f2", "f3", "f4", "f5", "f6")])
    assert res.note == ("1 confirmed survivor(s) of 6 mutant(s) tested; re-tested 6 of 6 open"
                        " survivor(s), 3 killed; 6 of 6 survivor(s) named by a changed test"
                        " re-tested first")
    assert res.repaired is not None
    # a stage-1 kill claims after its confirm; a full-suite kill IS the confirm
    assert res.repaired.ids == tuple(sorted((fp("f1"), fp("f3"), fp("f6"))))
    assert res.repaired.examined == tuple(sorted(fp(f) for f in
                                                 ("f1", "f2", "f3", "f4", "f5", "f6")))
    assert _ids(res) == {"f2"}, "the survivor re-reports; the unconfirmed kills report nothing"
    assert res.extra["mutation_scores"]["targets"] == {}, "re-tests never score a target"
    assert [lab for k, lab, _ in oracle.calls] == \
        ["BASE", "f1", "f1", "f2", "f2", "f3", "f3", "f4", "f4", "f5", "f5", "f6", "f6"]
    assert _no_worktrees(r)


def test_retest_cap_ends_the_claimed_pass_and_the_shortfall_is_said(tmp_path, monkeypatch):
    r, head, head2 = _claimed_repo(tmp_path, retest_cap=3)

    res, _ = _run(r, head, head2, monkeypatch, CLAIMED, item_id="q2")

    _stats(res, tested=3, killed_s1=2, survived=1, confirmed=1, retest_candidates=6,
           retested=3, retest_killed=2, retest_truncated=True, claimed=6, claimed_retested=3,
           retested_ids=[fp(f) for f in ("f1", "f2", "f3")])
    assert res.note == ("1 confirmed survivor(s) of 3 mutant(s) tested; re-tested 3 of 6 open"
                        " survivor(s), 2 killed; 3 of 6 survivor(s) named by a changed test"
                        " re-tested first")


def test_a_test_that_names_no_survivor_leaves_them_to_the_hygiene_pass(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, TOML.replace("retest_cap = 3", "retest_cap = 2"))
    _record_survivors(r, ["f1", "f2", "f3"])
    head2 = _commit(r, "tests/test_other.py", "def test_x():\n    assert True\n")

    res, oracle = _run(r, head, head2, monkeypatch, CLAIMED, item_id="q2")

    _stats(res, tested=2, killed_s1=1, survived=1, confirmed=1, retest_candidates=3,
           retested=2, retest_killed=1, retest_truncated=True,
           retested_ids=[fp("f1"), fp("f2")])
    assert res.note == ("1 confirmed survivor(s) of 2 mutant(s) tested; re-tested 2 of 3 open"
                        " survivor(s), 1 killed")
    assert res.repaired is not None and res.repaired.ids == (fp("f1"),)
    assert [lab for k, lab, _ in oracle.calls] == ["BASE", "f1", "f1", "f2", "f2"]


def test_a_recorded_survivor_killed_in_the_range_needs_a_confirm_the_cap_can_refuse(
        tmp_path, monkeypatch):
    """f13 and f14 are on the books; the range re-mutates every function.
    f13 survives stage 1 and spends the ONE confirm; f14 dies at stage 1,
    but a kill of a recorded id is a claim and needs the full suite --
    capped, so it is counted and never claimed."""
    r, base, head = _repo(tmp_path, TOML.replace("confirm_cap = 3", "confirm_cap = 1"))
    _record_survivors(r, ["f13", "f14"])

    res, _ = _run(r, base, head, monkeypatch,
                  {("s1", "f13"): PASS, ("full", "f13"): PASS}, default=OK1)

    _stats(res, generated=14, tested=14, killed_s1=13, survived=1, confirmed=1,
           capped_kills=1, truncated=True)
    assert res.note == ("1 confirmed survivor(s) of 14 mutant(s) tested (truncated: budget/cap"
                        " hit, remainder dropped); 1 kill(s) of a recorded survivor"
                        " unconfirmed at confirm_cap=1")
    assert res.repaired is not None and res.repaired.ids == ()
    assert res.repaired.examined == tuple(sorted((fp("f13"), fp("f14"))))
    assert _ids(res) == {"f13"}


def test_a_recorded_survivor_confirmed_dead_in_the_range_is_claimed(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    _record_survivors(r, ["f1"], pending=["f1"])

    res, _ = _run(r, base, head, monkeypatch, {("full", "f1"): OK1}, default=OK1)

    _stats(res, generated=14, tested=14, killed_s1=14)
    assert res.repaired is not None and res.repaired.ids == (fp("f1"),)
    assert res.repaired.examined == (fp("f1"),)


def test_a_two_occurrence_survivor_that_does_not_fit_is_skipped_unspent(tmp_path, monkeypatch):
    twice = SRC + "\n\ndef f1_again(x):\n    return x + 1\n"
    # one slot in EACH pass: the claimed pass skips it, and so does the
    # hygiene pass on the range budget
    r, base, head = _repo(tmp_path, TOML.replace("retest_cap = 3", "retest_cap = 1")
                          .replace("max_mutants = 20", "max_mutants = 1"), head_src=twice)
    lines = twice.splitlines()
    m = mutation.generate_mutants(twice, {2})[0]
    fid = mut_consumer._mutant_fp("calc.py", m.op, m.line, lines)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("seed", "2026-09-01T00:00:00+00:00", "drain", {"mutation"}, {"calc.py"},
                       [Finding(id=fid, tool="mutation", rule=m.op, severity_raw="medium",
                                severity=Severity.MEDIUM, verdict=Verdict.WARN, file="calc.py",
                                line=m.line, message="mutant survived", evidence="", gate=Gate.ALL)])
    finally:
        led.close()
    head2 = _commit(r, "tests/test_calc.py", TEST + "def test_two():\n    assert f1(2) == 3\n")
    cfg = config_mod.load_config(r)
    oracle = Oracle(mut_consumer._full_argv(cfg, r), {}, OK1, twice)
    monkeypatch.setattr(mut_consumer, "run_subprocess", oracle)
    monkeypatch.setattr(mut_consumer, "_stage1_argv", lambda *a, **k: ["never"])
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id="q2", base=head, head=head2, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")
    try:
        res = mut_consumer.consume(item, DrainContext(root=r, cfg=cfg, ledger=led,
                                                      clock=lambda: "t"))
    finally:
        led.close()

    _stats(res, retest_candidates=1, retest_truncated=True, retest_skipped=1, claimed=1)
    assert [lab for k, lab, _ in oracle.calls] == ["BASE"], "nothing spent on it"
    assert res.repaired is not None and res.repaired.ids == () and res.repaired.examined == (fid,)
    assert res.note == ("0 confirmed survivor(s) of 0 mutant(s) tested; re-tested 0 of 1 open"
                        " survivor(s), 0 killed; 0 of 1 survivor(s) named by a changed test"
                        " re-tested first; 1 survivor(s) not re-tested: occurrences exceed"
                        " the remaining re-test budget")
