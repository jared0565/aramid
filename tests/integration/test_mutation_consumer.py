"""Integration: the mutation consumer against real git worktrees + real
pytest on tiny fixture repos. Budgets are tightened via aramid.toml so each
scenario runs a handful of pytest invocations, not hundreds.

Fixture-design note: the mutated function must have NO equivalent mutants
for its operator set, or the strong-suite test cannot pass. A clamp-style
function is the classic trap (x > 10 -> x >= 10 is behaviorally identical
at the clamp point). is_adult(age >= 18) is boundary-observable: cmp-flip
(>= -> >) and int-bound (18 -> 19) BOTH flip is_adult(18) -- killable by
any test that pins the boundary. (Real repos WILL produce occasionally-
equivalent mutants; that inherent noise is why 2c-1 is WARN-only.)"""
import os
import subprocess

import pytest

from aramid import config as config_mod
from aramid.consumers import mutation as mut_consumer
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.queue import QueueItem
from aramid.runners import tests as tests_runner


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root) -> str:
    cp = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                         capture_output=True, text=True)
    return cp.stdout.strip()


ADULT = ("def is_adult(age):\n"
         "    if age >= 18:\n"
         "        return True\n"
         "    return False\n")
WEAK_TEST = ("from calc import is_adult\n"
             "def test_type():\n"
             "    assert isinstance(is_adult(5), bool)\n")
STRONG_TEST = ("from calc import is_adult\n"
               "def test_boundary():\n"
               "    assert is_adult(18) is True\n"
               "    assert is_adult(17) is False\n"
               "    assert is_adult(19) is True\n")


def _repo(tmp_path, test_body, extra_files=()):
    r = tmp_path / "r"
    (r / "tests").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\n", encoding="utf-8")
    (r / "conftest.py").write_text("import sys, pathlib\n"
                                   "sys.path.insert(0, str(pathlib.Path(__file__).parent))\n",
                                   encoding="utf-8")
    (r / "calc.py").write_text("def is_adult(age):\n    return False\n",
                               encoding="utf-8")
    (r / "tests" / "test_calc.py").write_text(test_body, encoding="utf-8")
    for name, content in extra_files:
        (r / name).write_text(content, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "calc.py").write_text(ADULT, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)


def _consume(r, base, head, monkeypatch, tmp_path, item_id="q1"):
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id=item_id, base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")
    try:
        return mut_consumer.consume(item, DrainContext(root=r, cfg=cfg,
                                                        ledger=led, clock=lambda: "t"))
    finally:
        led.close()


def _no_worktrees(r):
    cp = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                         capture_output=True, text=True)
    return len([ln for ln in cp.stdout.splitlines() if ln.strip()]) == 1


def test_weak_suite_survivor_confirmed_and_reported(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "a survivor must be reported against a weak suite"
    f = res.findings[0]
    assert f.tool == "mutation" and f.file == "calc.py"
    assert "mutant survived" in f.message
    assert res.extra["confirmed"] >= 1
    assert _no_worktrees(r), "throwaway worktree must be removed"


def test_strong_suite_kills_no_findings(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, STRONG_TEST)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["killed_s1"] >= 1   # strong targeted suite kills at stage 1
    assert _no_worktrees(r)


def test_stage2_rescue_prevents_false_survivor(tmp_path, monkeypatch):
    # Stage-1 selection runs tests/test_calc.py (weak). A DIFFERENT test file
    # -- never selected by the test_<module>.py heuristic -- pins the boundary
    # and kills every mutant at the full-suite confirmation, so no finding
    # may be reported.
    other = ("from calc import is_adult\n"
             "def test_cross_file_boundary():\n"
             "    assert is_adult(18) is True\n"
             "    assert is_adult(17) is False\n")
    r, base, head = _repo(tmp_path, WEAK_TEST,
                          extra_files=[("tests/test_other.py", other)])
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == [], "full-suite confirmation must kill what stage 1 missed"
    assert res.extra["killed_s2"] >= 1   # cross-file test only runs at stage 2


def test_no_pytest_stack_skips_ok_with_loud_note(tmp_path, monkeypatch):
    # JS-only / test-less repo: PERMANENT structural absence must be an OK
    # skip with a loud note (the 2c-1b seam), NOT degraded -- the drain
    # refuses to mark items drained while any consumer is degraded, so
    # degraded here would pin queue items forever on non-Python repos
    # (caught live by test_llm_review's no-providers drain e2e).
    import shutil as _shutil
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _shutil.rmtree(r / "tests")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "drop tests")
    # The item must reference the commit that actually reflects the removed
    # tests: `consume()` checks out a worktree at `item.head` (gitutil
    # worktree add --detach), and a worktree pinned to the PRE-drop `head`
    # still has tests/test_calc.py in its git tree -- the "test-less repo"
    # this test claims to construct would never actually exist on disk
    # where consume() looks for it. Recapturing head here is what makes the
    # worktree's contents match the scenario the test above describes; it
    # was silently irrelevant before Task 1 only because the old
    # detect_tests(ctx.root) check returned empty and consume() returned at
    # line ~110, before a worktree was ever created.
    head = _sha(r)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert "no python test stack" in res.note


def test_baseline_rc5_is_ok_skip_not_degraded(tmp_path, monkeypatch):
    """Unit-style sibling of the E2E test above: pins the BASELINE rc==5
    branch directly (mutation.py's `base_res.state is ToolState.OK and
    base_res.returncode == 5` check) via a scripted run_subprocess, so the
    proof doesn't depend on real pytest's exit code or on constructing a
    real worktree whose tree has no test files.

    rc 5 = pytest collected no tests -- PERMANENT structural absence, the
    same condition the detect_tests() skip earlier in consume() exists for,
    not a transiently failing baseline. Must be an OK-skip (never
    "degraded"), and the note must NOT start with "baseline failing @ " --
    that literal prefix is what base.prior_note_count's give-up counter
    matches, and conflating the two note families would let a permanent
    no-tests repo silently count toward the 3-strikes give-up alongside a
    genuinely red baseline."""
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)

    def scripted(argv, cwd, timeout, **kw):
        return RunnerResult(tool="pytest", state=ToolState.OK, returncode=5)

    monkeypatch.setattr(mut_consumer, "run_subprocess", scripted)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert "no python test stack" in res.note
    assert "baseline failing" not in res.note
    assert _no_worktrees(r), "throwaway worktree must be removed"


def test_baseline_red_degrades_no_findings(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, "def test_always_fails():\n    assert False\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    assert "baseline" in res.note
    assert res.findings == []
    assert _no_worktrees(r)


def test_no_python_files_is_ok_noop(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    (r / "notes.md").write_text("hi\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "docs")
    res = _consume(r, head, _sha(r), monkeypatch, tmp_path)
    assert res.state == "ok" and res.findings == []
    assert "no python files" in res.note


def test_budget_truncation_visible(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 1\nconfirm_cap = 1\n",
        encoding="utf-8")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.extra["truncated"] is True
    assert "truncated" in res.note


def test_worktree_removed_on_midloop_exception(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    monkeypatch.setattr(mut_consumer.mutation, "generate_mutants",
                         lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        _consume(r, base, head, monkeypatch, tmp_path)
    assert _no_worktrees(r), "finally must remove the worktree even on a crash"


def test_drain_e2e_records_mutation_run(tmp_path, monkeypatch, recent_iso):
    from aramid import registry
    from aramid.commands import drain as drain_mod
    from aramid.commands.drain import cmd_drain
    from aramid.models import EventType
    from aramid import queue as queue_mod

    r, base, head = _repo(tmp_path, WEAK_TEST)
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "drain.lock")
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    registry.register(r, "2026-07-20T10:00:00+00:00")
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        queue_mod.enqueue(led, recent_iso, base, head, 55, ["seed"])
    finally:
        led.close()

    rc = cmd_drain([str(r)])
    assert rc in (0, 2)  # 2 allowed: llm consumer may degrade w/o providers

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        events = led.events()
        runs = [e for e in events if e.type is EventType.CONSUMER_RUN_FINISHED
                and e.payload.get("consumer") == "mutation"]
        assert runs, "drain must have run the mutation consumer"
        assert "confirmed" in runs[-1].payload  # extra payload merged
        state = led.open_findings()
        assert any(rec.get("tool") == "mutation" for rec in state.values()), \
            "confirmed survivor must land in the ledger as a finding"
    finally:
        led.close()


def test_stage1_narrowing_actually_ran(tmp_path, monkeypatch):
    # Pin that stage 1 uses the targeted tests/test_<module>.py argv, not the
    # full suite -- a silent regression to full-suite-always would only show
    # as slowness. Spy wraps the REAL run_subprocess.
    r, base, head = _repo(tmp_path, WEAK_TEST)
    calls = []
    real = mut_consumer.run_subprocess

    def spy(argv, cwd, timeout, **kw):
        calls.append([str(a) for a in argv])
        return real(argv, cwd, timeout, **kw)

    monkeypatch.setattr(mut_consumer, "run_subprocess", spy)
    _consume(r, base, head, monkeypatch, tmp_path)
    targeted = [c for c in calls if any(a.endswith("test_calc.py") for a in c)]
    assert targeted, "stage 1 must have invoked the targeted test file"
    assert not any("-k" in c for c in calls), \
        "with tests/test_calc.py present the -k fallback must not fire"


def test_stage1_argv_unsafe_stem_falls_back_to_full_suite(tmp_path):
    # pytest -k chokes on expression keywords and non-word chars (exit 4 =
    # usage error, which previously scored as a KILL). Unsafe stems must use
    # the always-correct full-suite argv instead.
    for fname in ("not.py", "and.py", "or.py", "my-mod.py", "weird mod.py"):
        argv = mut_consumer._stage1_argv(tmp_path, fname)
        assert "-k" not in argv, fname
    safe = mut_consumer._stage1_argv(tmp_path, "calc.py")
    assert safe[-2:] == ["-k", "calc"]


def test_stage1_usage_error_counts_error_not_kill(tmp_path, monkeypatch):
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    seq = {"n": 0}

    def scripted(argv, cwd, timeout, **kw):
        seq["n"] += 1
        if seq["n"] == 1:      # baseline full suite: green
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        return RunnerResult(tool="pytest", state=ToolState.OK, returncode=4)

    monkeypatch.setattr(mut_consumer, "run_subprocess", scripted)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.extra["errors"] >= 1
    assert res.extra["killed_s1"] == 0, "usage error is not a kill"
    assert res.findings == []


def test_stage2_usage_error_never_reports_survivor(tmp_path, monkeypatch):
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    fulls = {"n": 0}

    def scripted(argv, cwd, timeout, **kw):
        joined = " ".join(str(a) for a in argv)
        if "test_calc.py" in joined:   # stage-1 targeted: mutant survives
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        fulls["n"] += 1
        if fulls["n"] == 1:            # baseline: green
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        return RunnerResult(tool="pytest", state=ToolState.OK, returncode=4)

    monkeypatch.setattr(mut_consumer, "run_subprocess", scripted)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.findings == [], "survivor is only reported when the full suite PASSES"
    assert res.extra["confirmed"] == 0
    assert res.extra["errors"] >= 1


def _seed_baseline_failures(r, n, head):
    from aramid.models import Event, EventType
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for i in range(n):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"seed{i}", "t",
                             payload={"consumer": "mutation", "item_id": "q1",
                                      "state": "degraded",
                                      "note": mut_consumer.failing_note_prefix(head)}))
    finally:
        led.close()


def test_baseline_giveup_after_three_failures(tmp_path, monkeypatch):
    # 3 prior "baseline failing" runs for this item AT THIS HEAD -> OK
    # give-up, and NO pytest invocation at all (run_subprocess poisoned to
    # prove it): the give-up check must fire BEFORE the worktree/baseline
    # work.
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _seed_baseline_failures(r, 3, head)
    monkeypatch.setattr(mut_consumer, "run_subprocess",
                         lambda *a, **kw: (_ for _ in ()).throw(
                             AssertionError("give-up path must not run pytest")))
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "giving up" in res.note
    assert res.findings == []
    assert _no_worktrees(r)


def test_baseline_two_failures_still_degrades(tmp_path, monkeypatch):
    # Below the give-up threshold the transient-retry contract stands.
    r, base, head = _repo(tmp_path,
                          "def test_always_fails():\n    assert False\n")
    _seed_baseline_failures(r, 2, head)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    assert "baseline failing" in res.note


def test_baseline_giveup_is_head_scoped(tmp_path, monkeypatch):
    # Review I2: queue coalescing advances item.head under a stable item.id.
    # 3 failures recorded at an OLD head must NOT give up the CURRENT head --
    # new commits always deserve a fresh baseline attempt.
    r, base, head = _repo(tmp_path,
                          "def test_always_fails():\n    assert False\n")
    _seed_baseline_failures(r, 3, "0" * 40)   # stale head
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded", "stale-head failures must not trigger give-up"
    assert "baseline failing" in res.note


# ------------------------------------ a TIMEOUT is not a FAILURE (R64-1) ---
# Reported from a downstream repo: 11 consecutive baseline runs at
# 482.8-486.6s -- under 1% spread, which is the shape of a budget, not of a
# failing test -- every one of them reporting "baseline failing @ <sha>".
# The reader went looking for a broken test. There wasn't one: the suite
# passes in 985s and simply cannot fit a 483s budget.
#
# The two states demand OPPOSITE responses (fix a test / raise a budget), so
# reporting them with one string is the whole defect. Fixing only the wording
# would leave mutation dead; fixing only the budget would leave the next
# timeout equally illegible.

TIMEOUT_BUDGET = 240.0          # _repo sets mutant_timeout_s = 60; 60 * 4


def _timeout_baseline(monkeypatch):
    """Make the baseline (and only the baseline) time out."""
    from aramid.runners.base import RunnerResult, ToolState
    monkeypatch.setattr(mut_consumer, "run_subprocess",
                         lambda *a, **kw: RunnerResult(tool="pytest",
                                                        state=ToolState.TIMEOUT))


def _seed_notes(r, n, note, item_id="q1"):
    from aramid.models import Event, EventType
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for i in range(n):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"seed{i}", "t",
                             payload={"consumer": "mutation", "item_id": item_id,
                                      "state": "degraded", "note": note}))
    finally:
        led.close()


def test_baseline_timeout_is_not_reported_as_a_failure(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _timeout_baseline(monkeypatch)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "degraded"
    assert not res.note.startswith("baseline failing"), \
        "a timeout must not join the failing-baseline note family"
    assert "timeout" in res.note
    # The budget is the actionable number: it is the thing the operator
    # changes. Without it the note says a run was too slow but not too slow
    # for WHAT.
    assert "240s" in res.note


def test_baseline_failure_still_reports_as_a_failure(tmp_path, monkeypatch):
    """The other half of the split. A genuinely red suite must still land in
    the failing-baseline family -- and carry the head-scoped note the give-up
    counter keys on, whatever that note's current spelling is."""
    r, base, head = _repo(tmp_path, "def test_always_fails():\n    assert False\n")

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "degraded"
    assert res.note.startswith(mut_consumer.failing_note_prefix(head))
    assert "timeout" not in res.note


# ------------------------------- one grammar down the status column (R66-3) ---
# The timeout family says "(last seen @ <sha>)"; the failing family said
# "@ <sha>". Both land in the same `status` column, one under the other, and a
# reader learns the grammar from whichever they meet first -- so the bare "@"
# reads as the causal claim the timeout reword exists to avoid. The sha is
# honest for a red baseline (that IS where the suite was red); this is about
# the two notes agreeing, not about either being wrong.
#
# The string is load-bearing -- the head-scoped give-up counter matches it --
# so `failing_note_prefix` is the single definition both the counter and the
# emit site use. These three tests are what makes a PARTIAL change impossible
# to land green: one pins the wording, one pins that the counter follows it,
# and one pins the one-time cost of moving it.


def test_note_families_are_pinned_to_their_literal_wording():
    """The only test here that knows what the words actually are.

    Every other assertion in this area compares `res.note` against
    `failing_note_prefix(head)` -- both sides read from one function, so they
    prove the producer is deterministic and would hold just as well if that
    function returned "potato". Something has to pin the literal, and this is
    it.

    Worth pinning rather than leaving to the contract functions, because the
    wording is load-bearing in two directions at once: it is what a downstream
    reader sees in `status`, and it is what the give-up counters match against
    ledger rows written by EARLIER versions. A silent reword is a silent latch
    reset in every consumer's repo, which is why this change is deliberate and
    announced rather than incidental.

    The 12-character truncation is pinned here too -- the full sha is passed in
    and must not survive into the note.
    """
    from aramid.consumers import js_mutation as jsc

    head = "8abc418da153ffffffffffffffffffffffffffff"

    assert mut_consumer.failing_note_prefix(head) == \
        "baseline failing (last seen @ 8abc418da153)"
    assert jsc.link_note_prefix(head) == \
        "node_modules link failing (last seen @ 8abc418da153)"
    # The family this grammar was borrowed FROM, pinned alongside so the three
    # cannot drift into two grammars again.
    assert mut_consumer.timeout_note_prefix(480.0, "pytest -q") == \
        "baseline timeout: pytest -q did not finish within the 480s budget"
    # The fourth family (interop round 174): the command never resolved, so
    # nothing ran -- neither red nor slow. argv[0] is in the prefix on
    # purpose: it is the release valve, like the timeout family's inputs.
    assert mut_consumer.missing_note_prefix("./nope/python") == \
        "baseline command not found: ./nope/python"


def test_failing_baseline_note_uses_the_last_seen_grammar(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, "def test_always_fails():\n    assert False\n")

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "degraded"
    # Prefix, not equality: the note now carries ` -- rc N: <last line>`
    # after the prefix, and the give-up counter matches on the prefix.
    assert res.note.startswith(mut_consumer.failing_note_prefix(head) + " -- rc ")
    # The discriminator. Asserting only `startswith("baseline failing")` --
    # which is what tests/unit/test_ledger_compact.py does, correctly, because
    # it is testing compaction and not wording -- passes on BOTH spellings and
    # so cannot witness this change at all.
    assert not res.note.startswith(f"baseline failing @ {head[:12]}"), \
        "the bare '@ <sha>' spelling must be gone, not merely accompanied"


def test_failing_giveup_counts_the_new_note_format(tmp_path, monkeypatch):
    """The counter has to move WITH the wording or the latch silently dies."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _seed_notes(r, 3, mut_consumer.failing_note_prefix(head))
    monkeypatch.setattr(mut_consumer, "run_subprocess",
                         lambda *a, **kw: (_ for _ in ()).throw(
                             AssertionError("give-up path must not run pytest")))

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok"
    assert "giving up" in res.note


def test_failing_giveup_ignores_the_old_note_format(tmp_path, monkeypatch):
    """The one-time cost of the reword, pinned rather than discovered.

    Notes already in a live ledger keep the old spelling, and the counter no
    longer matches them -- so an item that had accumulated 3 strikes starts
    again from zero and gets 3 more DEGRADED retries before standing down.
    Bounded, one-time, and per-item; recorded here so the next reader meets it
    as a decision instead of as a latch that looks broken.
    """
    r, base, head = _repo(tmp_path,
                          "def test_always_fails():\n    assert False\n")
    _seed_notes(r, 3, f"baseline failing @ {head[:12]}")   # pre-reword spelling

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "degraded", \
        "old-format notes no longer satisfy the counter -- this is the reset"
    # Prefix, not equality: the note now carries ` -- rc N: <last line>`
    # after the prefix, and the give-up counter matches on the prefix.
    assert res.note.startswith(mut_consumer.failing_note_prefix(head) + " -- rc ")


def test_timeout_giveup_survives_an_advancing_head(tmp_path, monkeypatch):
    """Latch reset path A.

    The failing-baseline give-up is head-scoped on purpose: new commits
    deserve a fresh attempt because new code can fix a red suite. A TIMEOUT is
    not like that -- "this suite does not fit this budget" is a property of the
    repo and the config, and no commit changes it. Head-scoping the timeout
    give-up is what let a downstream repo burn ~8 minutes every 4 hours for
    three days: its head advanced between drains, so the counter never reached
    three.
    """
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _seed_notes(r, 3, mut_consumer.timeout_note_prefix(TIMEOUT_BUDGET,
                                                        "pytest -q") + " (last seen @ 000000000000)")
    monkeypatch.setattr(mut_consumer, "run_subprocess",
                         lambda *a, **kw: (_ for _ in ()).throw(
                             AssertionError("give-up path must not run pytest")))

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok"
    assert "giving up" in res.note
    assert _no_worktrees(r)


def test_timeout_giveup_survives_a_new_queue_item(tmp_path, monkeypatch):
    """Latch reset path B, and the one that made the give-up event appear
    exactly once downstream before the burn resumed.

    `prior_note_count` filters on item_id. Giving up returns `ok`, so the drain
    marks the item drained -- and the NEXT drain is a different item_id, whose
    count starts at zero. A per-item latch therefore grants a fresh 3 x budget
    allowance forever, which is not a latch at all.
    """
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _seed_notes(r, 3, mut_consumer.timeout_note_prefix(TIMEOUT_BUDGET,
                                                        "pytest -q") + " (last seen @ 000000000000)",
                 item_id="an-older-queue-item")
    monkeypatch.setattr(mut_consumer, "run_subprocess",
                         lambda *a, **kw: (_ for _ in ()).throw(
                             AssertionError("give-up path must not run pytest")))

    res = _consume(r, base, head, monkeypatch, tmp_path, item_id="a-brand-new-item")

    assert res.state == "ok"
    assert "giving up" in res.note


def test_timeout_giveup_stays_ok_so_the_item_can_drain(tmp_path, monkeypatch):
    """Deliberately NOT `degraded`, unlike the fuzz driver fix.

    The drain refuses to mark an item drained while any consumer is degraded,
    so degrading here would pin the queue item forever and re-run every OTHER
    consumer on it each drain -- converting a wasteful loop into a total stall.
    Visibility is `status`'s job (R64-4), not the drain state's.
    """
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _seed_notes(r, 3, mut_consumer.timeout_note_prefix(TIMEOUT_BUDGET,
                                                        "pytest -q") + " (last seen @ 000000000000)")
    _timeout_baseline(monkeypatch)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok", "degraded would pin the queue item and stall the drain"
    assert res.findings == []


def test_timeout_giveup_names_the_knob_that_clears_it(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _seed_notes(r, 3, mut_consumer.timeout_note_prefix(TIMEOUT_BUDGET,
                                                        "pytest -q") + " (last seen @ 000000000000)")
    _timeout_baseline(monkeypatch)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert "baseline_timeout_s" in res.note, \
        "a permanent give-up must name the setting that un-does it"


def test_raising_the_budget_clears_the_timeout_latch(tmp_path, monkeypatch):
    """The latch is repo-scoped, so it needs its own release valve or it is a
    one-way door: a suite that later fits (bigger budget, narrower command)
    would never be retried. Keying the note on the budget makes changing the
    budget the release.

    TWO ARMS ON PURPOSE. The second arm alone passes vacuously -- a repo where
    the latch never engaged also reports `ok` with no "giving up". Only the
    contrast shows the seeded notes were capable of latching and that the
    budget change is what released them.
    """
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _seed_notes(r, 3, mut_consumer.timeout_note_prefix(TIMEOUT_BUDGET,
                                                        "pytest -q") + " (last seen @ 000000000000)")

    # Arm 1 -- unchanged budget: the latch holds.
    latched = _consume(r, base, head, monkeypatch, tmp_path)
    assert "giving up" in latched.note, "control: these notes must latch at 240s"

    # Arm 2 -- budget raised: the same notes no longer match, so it retries.
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\nbaseline_timeout_s = 900\n",
        encoding="utf-8")

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok", "a raised budget must let the baseline run again"
    assert "giving up" not in res.note


def test_baseline_timeout_budget_is_configurable(tmp_path, monkeypatch):
    """`mutant_timeout_s * 4` is a per-mutant number pressed into service as a
    whole-suite budget. A repo whose suite legitimately exceeds it needs a
    setting it can point at, which is what the note now names."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\nbaseline_timeout_s = 777\n",
        encoding="utf-8")
    _timeout_baseline(monkeypatch)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert "777s" in res.note


def test_successful_baseline_records_its_measured_duration(tmp_path, monkeypatch):
    """You cannot measure a suite by timing it out -- the only number a
    timeout yields is the budget you already knew. The one run that CAN
    measure it is a successful one, so that is where the number is recorded."""
    r, base, head = _repo(tmp_path, WEAK_TEST)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok"
    assert isinstance(res.extra.get("baseline_s"), float)
    assert res.extra["baseline_s"] > 0


# ------------------------- generated 18, tested 0, reported ok (R66) --------
# Reported after the timeout fix landed: raising `baseline_timeout_s` let the
# baseline SUCCEED, and then the wall budget -- whose clock starts BEFORE the
# baseline -- was already spent, so 18 mutants were generated and 0 were tested.
# `state: ok`, `finding_count: 0`, and `status` showed neither a degraded streak
# nor a stand-down. 690s per drain, certifying nothing, looking healthy.
#
# That is the SAME defect class as the timeout-reported-as-failure this round
# began with: a condition wearing a label that belongs to a different condition.
# Raising the default budget without fixing this would move every affected repo
# from a loud stand-down to a silent no-op -- strictly worse.

def _tiny_wall_budget(r):
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 3\n"
        "wall_budget_s = 0.001\nmutant_timeout_s = 60\n", encoding="utf-8")


def test_a_run_that_tested_nothing_does_not_read_as_success(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _tiny_wall_budget(r)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.extra["generated"] > 0, "fixture must actually generate mutants"
    assert res.extra["tested"] == 0, "fixture must exhaust the wall budget first"
    # The note is what a human and `status` both read.
    assert "0 confirmed survivor(s)" not in res.note, \
        "'0 survivors of 0 tested' reads as a clean result; it certified nothing"
    assert "no mutants tested" in res.note.lower()
    # Name the knob, same contract as the timeout note.
    assert "wall_budget_s" in res.note


def test_a_run_that_tested_nothing_still_drains(tmp_path, monkeypatch):
    """Deliberately still `ok`, and this is the half that is easy to get wrong.

    `degraded` would stop the drain marking the item drained -- the reporting
    repo measured a queue item stuck for 61 HOURS from exactly that. So the
    drain state stays drainable and the VISIBILITY is the report's job. Drain
    state and report are different questions; conflating them is what produced
    both this bug and item 3's.
    """
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _tiny_wall_budget(r)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok", "degraded here would pin the queue item and stall the drain"


def test_a_run_that_did_test_mutants_keeps_the_ordinary_note(tmp_path, monkeypatch):
    """Control. The new wording must not leak onto healthy runs, or it becomes
    the noise that teaches an operator to stop reading the report."""
    r, base, head = _repo(tmp_path, WEAK_TEST)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.extra["tested"] > 0
    assert "no mutants tested" not in res.note.lower()
    assert "confirmed survivor(s)" in res.note


def test_pin_occurrence_declared_only_on_variable_set_consumers():
    from aramid.consumers import fuzz as fz
    import aramid.consumers.regression_pack as rp
    assert mut_consumer.PIN_OCCURRENCE is True
    assert fz.PIN_OCCURRENCE is True
    assert getattr(rp, "PIN_OCCURRENCE", False) is False, \
        "regression-pack fingerprints must keep exact gate parity"


def test_drain_passes_pin_flag_per_consumer(tmp_path, monkeypatch, recent_iso):
    # Flag-flow teeth: spy on drain's normalize and record the kwarg each
    # consumer's batch was normalized with.
    from aramid import registry
    from aramid.commands import drain as drain_mod
    from aramid.commands.drain import cmd_drain
    from aramid import queue as queue_mod

    r, base, head = _repo(tmp_path, WEAK_TEST)
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "drain.lock")
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    registry.register(r, "2026-07-20T10:00:00+00:00")
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        queue_mod.enqueue(led, recent_iso, base, head, 55, ["seed"])
    finally:
        led.close()

    seen = {}
    real_norm = drain_mod.normalize

    def spy(raws, root, ref_for, salt, gate, classify, *, pin_occurrence=False):
        seen[raws[0].tool] = pin_occurrence
        return real_norm(raws, root, ref_for, salt, gate, classify,
                         pin_occurrence=pin_occurrence)

    monkeypatch.setattr(drain_mod, "normalize", spy)
    cmd_drain([str(r)])
    assert seen.get("mutation") is True, \
        "mutation batch must normalize with pin_occurrence=True"


def test_mutation_scores_recorded_for_strong_suite(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, STRONG_TEST)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    ms = res.extra["mutation_scores"]
    assert ms["schema"] == 1
    t = ms["targets"]["calc.py::is_adult"]
    assert t["killed_s1"] >= 1
    assert t["survived_s1"] == 0
    assert t["fully_mutated"] is True
    assert t["killed_fps"]           # non-empty
    assert t["survivor_fps"] == []


def test_mutation_scores_records_confirmed_survivor_fps(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    t = res.extra["mutation_scores"]["targets"]["calc.py::is_adult"]
    assert t["survived_s1"] >= 1
    assert t["survivor_fps"]         # confirmed survivor fingerprints present
    assert t["fully_mutated"] is True


def test_mutation_scores_partial_run_not_fully_mutated(tmp_path, monkeypatch):
    # Budget truncation (max_mutants=1) leaves is_adult's >=2 mutants partly
    # untested -> generated > killed_s1 + survived_s1 -> fully_mutated False.
    # Guards spec §11 + the Step 7b "count generated for ALL muts up front"
    # requirement: a mis-wire that counted only tested muts would falsely
    # report fully_mutated True and corrupt baseline selection.
    r, base, head = _repo(tmp_path, WEAK_TEST)
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 1\nconfirm_cap = 1\n",
        encoding="utf-8")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    t = res.extra["mutation_scores"]["targets"]["calc.py::is_adult"]
    assert t["fully_mutated"] is False
    assert t["generated"] > t["killed_s1"] + t["survived_s1"]


def test_mutation_scores_stage1_error_attributed_and_excluded(tmp_path, monkeypatch):
    # A stage-1 usage error (returncode 4) must land in the function's errors
    # bucket, never killed_s1/survived_s1 -> excluded from the rate and
    # fully_mutated False. Guards the 7e/7i error-attribution wiring.
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    seq = {"n": 0}

    def scripted(argv, cwd, timeout, **kw):
        seq["n"] += 1
        if seq["n"] == 1:      # baseline full suite: green
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        return RunnerResult(tool="pytest", state=ToolState.OK, returncode=4)

    monkeypatch.setattr(mut_consumer, "run_subprocess", scripted)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    t = res.extra["mutation_scores"]["targets"]["calc.py::is_adult"]
    assert t["errors"] >= 1
    assert t["killed_s1"] == 0 and t["survived_s1"] == 0
    assert t["fully_mutated"] is False


def test_mutation_findings_classify_warn_never_block(tmp_path, monkeypatch):
    from aramid.models import Gate
    from aramid import policy
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(tmp_path)
    severity, verdict = policy.classify("mutation", "cmp-flip", "medium",
                                        Gate.ALL, cfg=cfg)
    assert str(verdict) != "block"
    assert not any("mutation" in key for key in cfg.block_rules), \
        "block_rules must have no mutation entry (spec invariant 3)"


# ---------------------------------------------------------------------------
# WHAT EVERY TEST ABOVE IS BLIND TO, and why the bugs below survived 44 runs.
#
# `_repo` builds a FLAT-layout fixture with a conftest.py that manually
# inserts the repo root on sys.path. aramid itself is SRC-layout and installed
# editable. So the fixture can reach its own source with no help, while the
# real repo cannot -- every scenario above passes whether or not the worktree
# runs are import-isolated, and whether or not they honour `[tests].command`.
# Two production defects lived entirely inside that blind spot:
#
#   * the baseline ran a hardcoded bare `pytest -q` -- the WHOLE 1595-test
#     tree, ~1141 s -- against `mutant_timeout_s * 4` = 480 s, so it timed out
#     on every attempt (38 degraded runs of 44, zero findings ever) and
#     reported "baseline failing", which reads as "your tests are red".
#   * no worktree run passed `env=`, so a mutant written into the worktree was
#     never the code under test and every mutant would read as SURVIVED.
#
# These assert on the CALLS rather than the outcome, because the outcome is
# exactly what cannot distinguish them here.

def _capture_runs(monkeypatch):
    """Record every run_subprocess the consumer makes, and answer each one so
    the loop proceeds: baseline green, stage 1 green (putative survivor),
    stage 2 green (confirmed)."""
    from aramid.runners.base import RunnerResult, ToolState
    calls = []

    def fake(argv, cwd, timeout_s, env=None):
        calls.append({"argv": list(argv), "cwd": cwd,
                      "timeout_s": timeout_s, "env": env})
        return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)

    monkeypatch.setattr(mut_consumer, "run_subprocess", fake)
    return calls


def _with_test_command(r, command_toml):
    txt = (r / "aramid.toml").read_text(encoding="utf-8")
    (r / "aramid.toml").write_text(f"{txt}\n[tests]\ncommand = {command_toml}\n",
                                   encoding="utf-8")


def test_the_baseline_runs_the_repo_s_configured_test_command(tmp_path, monkeypatch):
    """`[tests].command` is the repo's own statement of what its suite IS.
    Ignoring it is what made the baseline unrunnable here."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _with_test_command(r, '["python", "-m", "pytest", "-q", "tests/unit"]')
    calls = _capture_runs(monkeypatch)
    _consume(r, base, head, monkeypatch, tmp_path)

    assert calls, "consumer made no subprocess calls at all"
    assert calls[0]["argv"] == ["python", "-m", "pytest", "-q", "tests/unit"], (
        f"baseline ignored [tests].command; ran {calls[0]['argv']}")


def test_every_worktree_run_is_import_isolated_to_the_worktree(tmp_path, monkeypatch):
    """THE INVISIBLE ONE. Without `env`, the worktree runs import the INSTALLED
    package -- under an editable install, the live tree -- so the mutant is
    never the code under test and every mutant reads as survived. Asserting on
    the outcome cannot see this; asserting on the env can."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    calls = _capture_runs(monkeypatch)
    _consume(r, base, head, monkeypatch, tmp_path)

    assert calls
    for c in calls:
        env = c["env"] or {}
        assert "PYTHONPATH" in env, (
            f"worktree run with no import isolation: {c['argv']}")
        first = env["PYTHONPATH"].split(os.pathsep)[0]
        assert first == str(c["cwd"] / "src"), (
            f"PYTHONPATH does not lead with the worktree's own src: {first}")


def test_a_whole_command_run_never_gets_the_per_mutant_budget(tmp_path, monkeypatch):
    """The trap in fixing the above. The confirm run executes the SAME whole
    command as the baseline; giving it `mutant_timeout_s` (120 s) while the
    command needs ~305 s moves the timeout from the baseline into stage 2 --
    where it is counted as an unattributable timeout and emits NO finding. The
    consumer would flip from `degraded` to `ok` with permanently zero
    findings: healthy-looking and silent, strictly worse than the bug."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _with_test_command(r, '["python", "-m", "pytest", "-q", "tests/unit"]')
    calls = _capture_runs(monkeypatch)
    _consume(r, base, head, monkeypatch, tmp_path)

    whole = ["python", "-m", "pytest", "-q", "tests/unit"]
    whole_runs = [c for c in calls if c["argv"] == whole]
    assert len(whole_runs) >= 2, (
        "expected at least a baseline and one stage-2 confirm running the "
        f"whole command; got {len(whole_runs)}")
    # aramid.toml in _repo sets mutant_timeout_s = 60, so the whole-command
    # budget is 240 and the per-mutant one is 60.
    for c in whole_runs:
        assert c["timeout_s"] == pytest.approx(240.0), (
            f"whole-command run given {c['timeout_s']}s; the per-mutant "
            "budget here is 60s and this command needs the larger one")


# --- closing the loop: a mutant a newly written test now kills --------------
#
# Until now a mutation finding could never resolve, for any reason. The drain
# records consumer findings with an EMPTY scope on purpose (a narrow ruleset
# must not clear findings it never looks for), and `resolve_departed` only
# covers a file LEAVING the repo. So "someone wrote the missing test" -- the
# entire point of the tier -- produced no state change at all, and the WARN
# list grew monotonically. Measured on aramid's own ledger: three survivors in
# `doctor._version_of`, two of them since genuinely fixed, all three still
# open with nothing in the product able to change that.
#
# The consumer already had the evidence and threw it away: `killed_fps` is the
# exact fingerprint each killed mutant WOULD have carried as a finding.

def _fps(res, key: str) -> set:
    out = set()
    for t in res.extra["mutation_scores"]["targets"].values():
        out |= set(t[key])
    return out


def test_the_identity_that_survives_a_weak_suite_is_the_one_a_strong_suite_kills(
        tmp_path, monkeypatch):
    """Cross-run STABILITY of the fingerprint: the id recorded for a survivor
    under a weak suite is the same id recorded as killed under a strong one.
    Both repos hold byte-identical `calc.py` and differ only in their tests --
    exactly the change an operator makes when closing a test gap. Without
    this, a repair claim could never match a finding from an earlier drain.

    Deliberately NOT claiming more than it checks. It does not pin that the
    fingerprint equals the id `normalize` gives the finding: measured by
    perturbing `_mutant_fp`, this test stays GREEN (both sides shift together)
    while `test_a_drained_repair_flips_the_open_finding_to_fixed` goes red.
    That test is what holds the two computations together; this one holds the
    fingerprint stable across runs. Two different properties, one each."""
    weak_r, wb, wh = _repo(tmp_path / "weak", WEAK_TEST)
    weak = _consume(weak_r, wb, wh, monkeypatch, tmp_path)
    survived = _fps(weak, "survivor_fps")
    assert survived, f"fixture produced no survivor: {weak.note}"

    strong_r, sb, sh = _repo(tmp_path / "strong", STRONG_TEST)
    strong = _consume(strong_r, sb, sh, monkeypatch, tmp_path)

    assert survived <= _fps(strong, "killed_fps"), (
        "the mutant that survived the weak suite was not reported killed by "
        "the strong one, so no repair could ever be proved")


def test_a_consumer_reports_the_identities_it_proved_repaired(tmp_path, monkeypatch):
    """The whole scenario in ONE repo, with real pytest throughout: a weak
    suite leaves a survivor, that identity is open in the ledger, someone
    writes the test that kills it, and the next run hands the identity back as
    a repair claim -- tagged with the tool the FINDINGS carry (not the
    consumer's NAME, which for `js_mutation` is a different string) and the
    reason that reaches the audit trail.

    The claim is deliberately NOT compared to `killed_fps`: it is a strict
    subset of it, since a kill is only claimed when it is confirmed by the
    full suite AND matches something actually open."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    weak = _consume(r, base, head, monkeypatch, tmp_path)
    survived = sorted(_fps(weak, "survivor_fps"))
    assert survived, f"fixture produced no survivor: {weak.note}"
    _seed_open(r, survived[0])

    (r / "tests" / "test_calc.py").write_text(STRONG_TEST, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "close the test gap")

    res = _consume(r, base, _sha(r), monkeypatch, tmp_path)

    assert res.repaired is not None, "the newly written test proved nothing"
    assert res.repaired.tool == "mutation"
    assert res.repaired.reason == "mutant_killed"
    assert survived[0] in set(res.repaired.ids)
    assert set(res.repaired.ids) <= _fps(res, "killed_fps")


def test_a_run_that_kills_nothing_claims_no_repair_but_says_what_it_examined(tmp_path, monkeypatch):
    """The safe direction, pinned: proving nothing must clear nothing. But an
    empty claim used to be indistinguishable from a consumer that never ran,
    and a consumer's resolver census graded `mutant_killed` NEVER RAN after a
    completed mutation run (interop round 180). The claim now names the
    recorded survivors the run examined, so the ledger can write "looked,
    proved 0" -- an outcome, not a defect."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    weak = _consume(r, base, head, monkeypatch, tmp_path)
    assert weak.repaired is not None and weak.repaired.ids == ()
    assert weak.repaired.examined == (), "nothing was recorded before the first run"
    survived = sorted(_fps(weak, "survivor_fps"))
    assert survived, f"fixture produced no survivor: {weak.note}"
    _seed_open(r, survived[0])

    res = _consume(r, base, head, monkeypatch, tmp_path)   # same weak suite: nothing dies

    assert res.repaired is not None
    assert res.repaired.ids == ()
    assert survived[0] in set(res.repaired.examined)


def test_a_drained_repair_flips_the_open_finding_to_fixed(tmp_path, monkeypatch):
    """End to end through the REAL drain, one shared ledger, nothing
    replicated: the weak repo records a genuine finding (id computed by
    `normalize`, not by the test), then the strong repo proves that same id
    repaired and the ledger says `fixed`.

    Passing both roots through `_consume_item` is what makes this a wiring
    test -- the consumer being right is worth nothing if the drain drops the
    claim on the floor, and every other test here stops at the consumer's
    return value."""
    from aramid.commands import drain as drain_mod

    weak_r, wb, wh = _repo(tmp_path / "weak", WEAK_TEST)
    strong_r, sb, sh = _repo(tmp_path / "strong", STRONG_TEST)
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"mutation": mut_consumer})
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")

    led = Ledger(tmp_path / "shared.db")
    try:
        drain_mod._consume_item(
            weak_r, config_mod.load_config(weak_r), led,
            QueueItem(id="q1", base=wb, head=wh, score=55, reasons=("t",),
                      state="queued", created_at="t", updated_at="t"),
            lambda: "2026-08-10T00:00:00+00:00")

        open_now = {fid: rec for fid, rec in led.open_findings().items()
                    if rec.get("tool") == "mutation" and rec["status"] == "open"}
        assert open_now, "the weak suite recorded no open mutation finding"

        drain_mod._consume_item(
            strong_r, config_mod.load_config(strong_r), led,
            QueueItem(id="q2", base=sb, head=sh, score=55, reasons=("t",),
                      state="queued", created_at="t", updated_at="t"),
            lambda: "2026-08-10T01:00:00+00:00")

        after = led.open_findings()
        assert all(after[fid]["status"] == "fixed" for fid in open_now), (
            "a mutant killed by a newly written test stayed open: "
            f"{ {fid: after[fid]['status'] for fid in open_now} }")
    finally:
        led.close()


# --- a repair claim is not the same thing as a kill -------------------------
#
# Stage 2 exists so that narrow stage-1 selection "can never manufacture a
# false test-gap finding" -- it guards SURVIVAL. Nothing guarded the KILL
# direction, because until repair claims existed a false kill was free: it
# only meant no finding was emitted. Now a stage-1 kill can resolve an open
# finding, so a false one writes a false REPAIR into an append-only audit
# ledger -- the exact class the drain's empty-scope comment exists to prevent,
# arriving through the door that comment does not cover.
#
# It does not take a flake. `s1.returncode in (1, 2)` counts 2 = collection
# error as a kill, and stage 1 selects `tests/**/test_<module>.py` -- so a test
# file that merely fails to IMPORT reads as "the suite killed this mutant" for
# every mutant in that module.
#
# So: a kill may be claimed as a repair only if the FULL suite confirms it,
# exactly as a survivor may only be reported if the full suite confirms that.
# Symmetric, and cheap -- the confirm runs only when a kill matches an id
# that is actually open, which is almost never.

def _script_runs(monkeypatch, *, targeted_rc, full_rc):
    """Answer each subprocess by SHAPE: the baseline and any confirm run the
    whole command, a targeted stage-1 run does not. The baseline is forced
    green so the consumer gets past it."""
    from aramid.runners.base import RunnerResult, ToolState
    calls = []
    full = mut_consumer._full_argv(None)

    def fake(argv, cwd, timeout_s, env=None):
        calls.append(list(argv))
        is_full = list(argv) == full
        rc = 0 if len(calls) == 1 else (full_rc if is_full else targeted_rc)
        return RunnerResult(tool="pytest", state=ToolState.OK, returncode=rc)

    monkeypatch.setattr(mut_consumer, "run_subprocess", fake)
    return calls, full


def _seed_open(r, fp):
    from aramid.models import Finding, Gate, Severity, Verdict
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("seed", "2026-08-10T00:00:00+00:00", "drain", set(), set(),
                       [Finding(id=fp, tool="mutation", rule="bool-swap",
                                severity_raw="medium", severity=Severity.MEDIUM,
                                verdict=Verdict.WARN, file="calc.py", line=2,
                                message="mutant survived", evidence="",
                                gate=Gate.ALL)])
    finally:
        led.close()


def _a_killed_fp(r, base, head, monkeypatch, tmp_path):
    """One fingerprint the consumer really does report as killed here."""
    calls, _ = _script_runs(monkeypatch, targeted_rc=1, full_rc=1)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    fps = sorted(_fps(res, "killed_fps"))
    assert fps, f"scripted kill produced no killed fingerprints: {res.note}"
    return fps[0]


def test_a_kill_matching_no_open_finding_costs_no_confirmation(tmp_path, monkeypatch):
    """The property that makes this affordable. Almost every killed mutant was
    never reported in the first place -- there is nothing to repair, so there
    is nothing to confirm, and the full suite runs exactly once (the
    baseline). Asserted on the CALLS: an outcome-level assertion cannot tell a
    skipped confirm from a cheap one."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    calls, full = _script_runs(monkeypatch, targeted_rc=1, full_rc=0)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert [c for c in calls if c == full] == [full], (
        f"a kill nobody had reported still paid for a full-suite run: {calls}")
    assert not (res.repaired and res.repaired.ids)


def test_a_stage1_kill_of_an_open_finding_is_confirmed_before_being_claimed(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    fp = _a_killed_fp(r, base, head, monkeypatch, tmp_path)
    _seed_open(r, fp)
    calls, full = _script_runs(monkeypatch, targeted_rc=1, full_rc=1)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.repaired is not None and fp in set(res.repaired.ids)
    assert len([c for c in calls if c == full]) >= 2, (
        f"the repair was claimed with no full-suite confirmation: {calls}")


def test_a_kill_the_full_suite_does_not_reproduce_claims_no_repair(
        tmp_path, monkeypatch):
    """THE BUG, pinned. Stage 1 says killed; the full suite passes on the same
    mutant, so the narrow selection -- not a new test -- produced that exit
    code. Claiming repair here would record a fix that never happened, and the
    ledger is append-only. The finding must stay open, which is also the
    direction that keeps a real test gap visible."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    fp = _a_killed_fp(r, base, head, monkeypatch, tmp_path)
    _seed_open(r, fp)
    _script_runs(monkeypatch, targeted_rc=1, full_rc=0)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert not (res.repaired and fp in set(res.repaired.ids)), (
        "an unconfirmed stage-1 kill was written to the ledger as a repair")


# --- mutation's baseline is not the gate's suite ----------------------------
#
# `[tests].command` answers "what does the gate run before letting a push
# through", and the honest answer is CI's whole tree. Mutation's baseline is a
# different question with a hard budget: it runs the suite ONCE to establish
# green and then once more per stage-2 confirm, all inside
# `mutant_timeout_s * 4`. Pointing that at the whole tree is precisely the bug
# that left mutation testing degraded for 44 consecutive drains with zero
# findings, so the two are now separable.

def test_mutation_prefers_its_own_test_command(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _with_test_command(r, '["python", "-m", "pytest", "-q"]')
    # Inserted INTO the existing [mutation] table -- a second `[mutation]`
    # header is a duplicate-table TOML error, not an override.
    txt = (r / "aramid.toml").read_text(encoding="utf-8")
    (r / "aramid.toml").write_text(
        txt.replace("[mutation]\n",
                    '[mutation]\ntest_command = '
                    '["python", "-m", "pytest", "-q", "tests/unit"]\n', 1),
        encoding="utf-8")
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")

    argv = mut_consumer._full_argv(config_mod.load_config(r))

    assert argv[-1] == "tests/unit", (
        f"mutation inherited the gate's whole-tree command: {argv}")


def test_mutation_still_falls_back_to_the_tests_command(tmp_path, monkeypatch):
    """The behaviour that must survive: a repo that declares only
    `[tests].command` keeps getting it, so nothing is broken by not opting in."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _with_test_command(r, '["python", "-m", "pytest", "-q", "tests/fast"]')
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")

    argv = mut_consumer._full_argv(config_mod.load_config(r))

    assert argv[-1] == "tests/fast"


def test_this_repos_mutation_baseline_is_not_the_whole_tree(monkeypatch, tmp_path):
    """A CONFIG regression guard, asserted behaviourally rather than as a
    literal: whatever aramid's own aramid.toml says, mutation must not end up
    running the same command the gate does. The gate's is the whole tree
    (~19 min); mutation's budget is `mutant_timeout_s * 4`. If these ever
    converge again, mutation silently stops finding anything -- which is
    exactly how it failed before, reporting "baseline failing" while the truth
    was "we never let it finish".
    """
    from pathlib import Path

    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")
    root = Path(__file__).resolve().parents[2]
    cfg = config_mod.load_config(root)

    gate_argv = tests_runner._argv(cfg.tests.get("command"))
    mutation_argv = mut_consumer._full_argv(cfg)

    assert gate_argv, "this repo must declare [tests].command"
    assert mutation_argv != gate_argv, (
        "mutation's baseline is the gate's whole-tree suite again; its budget "
        f"cannot fit it: {mutation_argv}")


# --- re-test OPEN survivors when a test file changes -------------------------
#
# A survivor is recorded at head N. At head N+1 the only change is a NEW TEST
# that kills it. Nothing in the item's range is a python source file, so before
# this the item returned "no python files in range" and the survivor stayed
# open for good: `mutant_killed` never got a chance, and the gate's
# `gap_addressed` needs a test-stem mapping that ordinary test names do not
# satisfy (this repo: `test_runner_shadow.py` vs `runners/shadow.py`, killed
# by perturbation on 2026-08-28 and unclosable). THE SUITE IS THE MAPPING:
# regenerate the recorded mutant from its fingerprint and put it through the
# same stage-1 / full-suite confirmation path a fresh mutant gets. A kill
# claimed here is exactly the claim stage 2 already makes.

KILLER = ("from calc import is_adult\n"
          "def test_boundary_elsewhere():\n"
          "    assert is_adult(18) is True\n"
          "    assert is_adult(17) is False\n"
          "    assert is_adult(19) is True\n")
HARMLESS = ("from calc import is_adult\n"
            "def test_still_weak():\n"
            "    assert is_adult(50) in (True, False)\n")


def _ids_of(r, findings) -> set[str]:
    lines = (r / "calc.py").read_text(encoding="utf-8").splitlines()
    return {mut_consumer._mutant_fp(f.file, f.rule, f.line, lines) for f in findings}


def _record_open_survivors(r, res) -> set[str]:
    """Write the run's confirmed survivors into the ledger as OPEN findings
    under the ids the drain would give them (`_mutant_fp` is the same
    `compute_fingerprint` call `normalize` makes), and return those ids."""
    from aramid.models import Finding, Gate, Severity, Verdict
    lines = (r / "calc.py").read_text(encoding="utf-8").splitlines()
    found = [Finding(id=mut_consumer._mutant_fp(f.file, f.rule, f.line, lines),
                     tool="mutation", rule=f.rule, severity_raw="medium",
                     severity=Severity.MEDIUM, verdict=Verdict.WARN, file=f.file,
                     line=f.line, message=f.message, evidence="", gate=Gate.ALL)
             for f in res.findings]
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("seed", "2026-08-28T00:00:00+00:00", "drain",
                       {"mutation"}, {"calc.py"}, found)
    finally:
        led.close()
    return {f.id for f in found}


def _commit_file(r, rel, body) -> str:
    (r / rel).write_text(body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", f"add {rel}")
    return _sha(r)


def _with_recorded_survivors(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    ids = _record_open_survivors(r, res)
    assert ids, "the weak suite must leave a confirmed survivor to re-test"
    return r, head, ids


def test_a_new_test_that_kills_a_recorded_survivor_claims_it(tmp_path, monkeypatch):
    r, head, ids = _with_recorded_survivors(tmp_path, monkeypatch)
    head2 = _commit_file(r, "tests/test_other.py", KILLER)

    res = _consume(r, head, head2, monkeypatch, tmp_path, item_id="q2")

    assert res.state == "ok", res.note
    assert res.repaired is not None and set(res.repaired.ids) == ids, (res.repaired, ids)
    assert res.extra["retested"] == len(ids)
    assert res.extra["retest_killed"] == len(ids)
    assert f"re-tested {len(ids)} of {len(ids)} open survivor(s), {len(ids)} killed" in res.note
    assert _no_worktrees(r)


def test_a_new_test_that_kills_nothing_claims_nothing_and_reconfirms(tmp_path, monkeypatch):
    r, head, ids = _with_recorded_survivors(tmp_path, monkeypatch)
    head2 = _commit_file(r, "tests/test_other.py", HARMLESS)

    res = _consume(r, head, head2, monkeypatch, tmp_path, item_id="q2")

    assert res.repaired is not None and res.repaired.ids == (), "nothing died: no claim"
    assert set(res.repaired.examined) == ids, "but the run says which survivors it re-tested"
    assert res.extra["retested"] == len(ids)
    assert res.extra["retest_killed"] == 0
    assert _ids_of(r, res.findings) == ids, "still surviving: re-reported under the same ids"


def test_a_push_that_touches_no_test_spends_nothing_on_retests(tmp_path, monkeypatch):
    """Docs-only push with survivors on the books: no baseline, no mutants,
    and the note is the one the item always had."""
    r, head, ids = _with_recorded_survivors(tmp_path, monkeypatch)
    head2 = _commit_file(r, "README.md", "docs only\n")
    calls = []
    real = mut_consumer.run_subprocess

    def spy(*a, **k):
        calls.append(a)
        return real(*a, **k)
    monkeypatch.setattr(mut_consumer, "run_subprocess", spy)

    res = _consume(r, head, head2, monkeypatch, tmp_path, item_id="q2")

    assert res.note == "no python files in range"
    assert calls == [], "nothing changed that could kill anything, so nothing runs"


def test_retest_cap_bounds_the_hygiene_pass_and_says_so(tmp_path, monkeypatch):
    r, head, ids = _with_recorded_survivors(tmp_path, monkeypatch)
    assert len(ids) >= 2, "fixture must leave at least two survivors for a cap of 1 to bite"
    toml = r / "aramid.toml"
    toml.write_text(toml.read_text(encoding="utf-8") + "retest_cap = 1\n", encoding="utf-8")
    head2 = _commit_file(r, "tests/test_other.py", KILLER)

    res = _consume(r, head, head2, monkeypatch, tmp_path, item_id="q2")

    assert res.extra["retested"] == 1
    assert res.extra["retest_truncated"] is True
    assert f"re-tested 1 of {len(ids)} open survivor(s), 1 killed" in res.note


def test_retests_can_be_switched_off(tmp_path, monkeypatch):
    r, head, ids = _with_recorded_survivors(tmp_path, monkeypatch)
    toml = r / "aramid.toml"
    toml.write_text(toml.read_text(encoding="utf-8") + "retest_open_survivors = false\n",
                    encoding="utf-8")
    head2 = _commit_file(r, "tests/test_other.py", KILLER)

    res = _consume(r, head, head2, monkeypatch, tmp_path, item_id="q2")

    assert res.note == "no python files in range"
    assert res.repaired is None


def test_a_suppressed_survivor_is_not_retested(tmp_path, monkeypatch):
    """An `equivalent mutant` suppression says "unkillable"; re-testing it
    would burn a full-suite run per drain forever and could never claim."""
    r, head, ids = _with_recorded_survivors(tmp_path, monkeypatch)
    fid = sorted(ids)[0]
    (r / ".aramid-suppressions.toml").write_text(
        f'[[suppress]]\nid = "{fid}"\ntool = "mutation"\nrule = "x"\n'
        'path = "calc.py"\nreason = "equivalent mutant"\n', encoding="utf-8")
    head2 = _commit_file(r, "tests/test_other.py", KILLER)

    res = _consume(r, head, head2, monkeypatch, tmp_path, item_id="q2")

    assert res.extra["retested"] == len(ids) - 1
    assert res.repaired is not None and fid not in res.repaired.ids
    assert set(res.repaired.ids) == ids - {fid}


def test_a_survivor_whose_line_changed_is_left_to_the_gate_resolvers():
    """The fingerprint is keyed on the line's CONTENT, not its number. So a
    pure shift (a comment added above) still regenerates the SAME mutant --
    the id follows the content, as the ledger's `finding_moved` already
    assumes -- while a line that now says something else fingerprints to
    nothing and the retest skips it: `gap_addressed` / `file_departed` own
    that case. The first draft of this test asserted the opposite of the
    shift and was refuted by the real fingerprint."""
    from aramid import mutation
    lines = ADULT.splitlines()
    m = mutation.generate_mutants(ADULT, {2})[0]
    fid = mut_consumer._mutant_fp("calc.py", m.op, m.line, lines)

    assert mut_consumer._survivor_mutant("calc.py", m.line, fid, ADULT) is not None
    shifted = "# a comment shifts every line\n" + ADULT
    found = mut_consumer._survivor_mutant("calc.py", m.line, fid, shifted)
    assert found is not None and found.line == m.line + 1, "same mutant, one line down"
    rewritten = ADULT.replace("age >= 18", "age >= 21")
    assert mut_consumer._survivor_mutant("calc.py", m.line, fid, rewritten) is None


def test_retest_candidates_include_a_pending_retest_survivor(tmp_path):
    """`gap_addressed` at the gate now leaves a survivor `pending_retest`
    instead of `fixed`, precisely so the verified re-test can find it. A
    candidate predicate that reads only `open` would make that state a dead
    end -- the exact hole the state exists to close."""
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict
    root = tmp_path
    (root / ".aramid").mkdir()
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        f = Finding(id="p" * 64, tool="mutation", rule="int-bound", severity_raw="medium",
                    severity=Severity.MEDIUM, verdict=Verdict.WARN, file="calc.py",
                    line=3, message="mutant survived", evidence="", gate=Gate.ALL)
        led.record_run("r1", "2026-08-30T00:00:00+00:00", "drain", {"mutation"}, {"calc.py"}, [f])
        led.append(Event(EventType.FINDING_RESOLVED, "r2", "2026-08-30T00:01:00+00:00",
                         finding_id="p" * 64,
                         payload={"auto_resolved": "gap_addressed", "pending_retest": True}))
        got = mut_consumer._retest_candidates(led, root)
    finally:
        led.close()
    assert got == [("p" * 64, "calc.py", 3)]


# --------------- a repo-relative command in the drain (interop round 174) ---
#
# graphite's `[tests].command` names its dev-venv interpreter by a
# repo-relative path. At the gate that resolved by accident (the gate's cwd
# IS the repo root); in the scheduled drain (no Start In) it resolved against
# nothing, `run_subprocess` said MISSING, and the consumer reported it as
# `baseline failing` -- 43 rows over three weeks, none of which ran a test.

def _repo_relative_launcher(r):
    """A launcher script inside the repo, the shape a dev-venv interpreter
    takes. Delegates to whatever `python` is on PATH, so the real pytest
    runs through it."""
    d = r / "tools"
    d.mkdir()
    if os.name == "nt":
        p = d / "py.cmd"
        p.write_text("@echo off\r\npython %*\r\n", encoding="utf-8")
    else:
        p = d / "py"
        p.write_text("#!/bin/sh\nexec python \"$@\"\n", encoding="utf-8")
        p.chmod(0o755)
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "launcher")
    return "tools/" + p.name


def test_repo_relative_test_command_runs_from_any_drain_cwd(tmp_path, monkeypatch):
    r, base, _ = _repo(tmp_path, WEAK_TEST)
    rel = _repo_relative_launcher(r)
    head = _sha(r)
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\n"
        f"[tests]\ncommand = [\"{rel}\", \"-m\", \"pytest\", \"-q\"]\n", encoding="utf-8")
    # The scheduled drain's cwd is never the repo root.
    monkeypatch.chdir(tmp_path)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert not res.note.startswith("baseline"), res.note
    assert res.state == "ok" and res.extra["tested"] >= 1, res.note


# ---------------- the baseline that never started (round 174, s1 and s4) ---
#
# `baseline failing` covered two things that demand opposite responses: a red
# suite (fixed at a commit) and a command that does not resolve (fixed in
# aramid.toml). The second gets its own family, repo-scoped like the timeout
# family because no commit ever fixes a path. And a genuinely red baseline
# now says WHY: rc and the last output line on the note, the tails in a log.

def _with_missing_command(r):
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\n"
        "[tests]\ncommand = [\"./nope/python\", \"-m\", \"pytest\"]\n", encoding="utf-8")


def test_missing_baseline_command_is_named_not_reported_as_failing(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _with_missing_command(r)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    assert res.note.startswith(mut_consumer.missing_note_prefix("./nope/python")), res.note
    assert "baseline failing" not in res.note
    assert "[mutation].test_command" in res.note, "the remedy must be named"
    assert _no_worktrees(r)


def test_missing_command_gives_up_after_three_across_items(tmp_path, monkeypatch):
    """Repo-scoped: three MISSING notes on ANY items latch the give-up, the
    way the timeout family does -- a path is a property of the config, and
    a new commit never resolves one. The drain writes the notes the counter
    reads, so they are seeded here the way the other give-up tests do, one
    per item to prove the scope."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _with_missing_command(r)
    prefix = mut_consumer.missing_note_prefix("./nope/python")
    for i in range(3):
        _seed_notes(r, 1, f"{prefix} (resolved from /somewhere; set ...)", item_id=f"q{i}")
    monkeypatch.setattr(mut_consumer, "run_subprocess",
                         lambda *a, **kw: (_ for _ in ()).throw(
                             AssertionError("give-up path must not run anything")))

    res = _consume(r, base, head, monkeypatch, tmp_path, item_id="q9")

    assert res.state == "ok"
    assert res.note.startswith("mutation giving up: ./nope/python not found after 3 attempts"), res.note
    assert "[tests].command" in res.note


def test_missing_command_give_up_releases_when_the_command_changes(tmp_path, monkeypatch):
    """The release valve: argv[0] is in the prefix, so three strikes against
    one path say nothing about the next one."""
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _with_missing_command(r)
    _seed_notes(r, 3, mut_consumer.missing_note_prefix("./old/python") + " (resolved from x)")

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "degraded"
    assert res.note.startswith(mut_consumer.missing_note_prefix("./nope/python")), res.note


# ------------- a confirm without a verdict is not a survivor (round 174, Q3) ---
#
# `survived_s1` was incremented when a mutant passed stage 1 and never undone:
# a confirm that timed out, errored, or was skipped by `confirm_cap` left the
# mutant counted as a survivor in the per-target score, and a full-suite KILL
# counted it as both killed and survived. `mutation-score` then read those
# rows as low kill rates on targets that had none.

def _scripted(monkeypatch, confirm_result):
    """Same shape as `test_stage2_usage_error_never_reports_survivor`: a
    targeted stage-1 run names test_calc.py and passes (putative survivor);
    the first full run is the baseline (green); every later full run is a
    confirm and returns `confirm_result`."""
    from aramid.runners.base import RunnerResult, ToolState
    fulls = {"n": 0}

    def scripted(argv, cwd, timeout, **kw):
        joined = " ".join(str(a) for a in argv)
        if "test_calc.py" in joined:
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        fulls["n"] += 1
        if fulls["n"] == 1:
            return RunnerResult(tool="pytest", state=ToolState.OK, returncode=0)
        return confirm_result
    monkeypatch.setattr(mut_consumer, "run_subprocess", scripted)


def _target(res, key="calc.py::is_adult"):
    return res.extra["mutation_scores"]["targets"][key]


def test_confirm_timeout_moves_the_mutant_out_of_survived(tmp_path, monkeypatch):
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _scripted(monkeypatch, RunnerResult(tool="pytest", state=ToolState.TIMEOUT, duration_s=60.0))

    res = _consume(r, base, head, monkeypatch, tmp_path)

    t = _target(res)
    assert t["survived_s1"] == 0, t
    assert t["timeouts"] >= 1 and t["fully_mutated"] is False, t
    assert res.extra["confirmed"] == 0 and res.findings == []


def test_confirm_error_moves_the_mutant_out_of_survived(tmp_path, monkeypatch):
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _scripted(monkeypatch, RunnerResult(tool="pytest", state=ToolState.OK, returncode=4))

    res = _consume(r, base, head, monkeypatch, tmp_path)

    t = _target(res)
    assert t["survived_s1"] == 0, t
    assert t["errors"] >= 1 and t["fully_mutated"] is False, t


def test_confirm_kill_is_counted_as_killed_s2_not_survived(tmp_path, monkeypatch):
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _scripted(monkeypatch, RunnerResult(tool="pytest", state=ToolState.OK, returncode=1))

    res = _consume(r, base, head, monkeypatch, tmp_path)

    t = _target(res)
    assert t["killed_s2"] >= 1, t
    assert t["survived_s1"] == 0, t
    assert t["fully_mutated"] is True, "a full-suite kill IS a verdict"


def test_confirm_cap_leaves_the_unconfirmed_out_of_the_score(tmp_path, monkeypatch):
    """`confirm_cap = 0`: every putative survivor is skipped, none confirmed.
    Not a survivor, not a kill -- and not a measurement either."""
    from aramid.runners.base import RunnerResult, ToolState
    r, base, head = _repo(tmp_path, WEAK_TEST)
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 0\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\n", encoding="utf-8")
    _scripted(monkeypatch, RunnerResult(tool="pytest", state=ToolState.OK, returncode=0))

    res = _consume(r, base, head, monkeypatch, tmp_path)

    t = _target(res)
    assert t["survived_s1"] == 0, t
    assert t["unconfirmed"] >= 1 and t["fully_mutated"] is False, t
    assert res.extra["truncated"] is True


def test_failing_baseline_note_carries_rc_and_last_line_and_a_log(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, "def test_always_fails():\n    assert False\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    # The prefix is byte-identical (the give-up counter matches on it); the
    # suffix is where the diagnosis lives.
    assert res.note.startswith(mut_consumer.failing_note_prefix(head) + " -- rc 1: "), res.note
    assert "1 failed" in res.note, res.note
    log = r / ".aramid" / "logs" / f"mutation-baseline-q1-{head[:12]}.log"
    assert log.is_file(), sorted(p.name for p in (r / ".aramid" / "logs").glob("*")) \
        if (r / ".aramid" / "logs").exists() else "no logs dir"
    assert "test_always_fails" in log.read_text(encoding="utf-8")
