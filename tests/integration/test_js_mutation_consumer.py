import shutil
import subprocess

import pytest

from aramid import config as config_mod
from aramid.consumers import js_mutation as jsc
from aramid.consumers import mutation as py_mutation
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.queue import QueueItem
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


# A JS repo whose test SCRIPT exists (so detect_tests -> "npm"); the calc source
# has a mutable `>=` on the changed line.
def _js_repo(tmp_path, with_node_modules=True, wire_pkg=False):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "package.json").write_text(
        '{"name":"x","scripts":{"test":"node test.js"}}\n', encoding="utf-8")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[js_mutation]\nmax_mutants = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\n", encoding="utf-8")

    # calc.js has a mutable `>=` on the changed line. When wire_pkg is set, calc.js
    # also require()s a hand-written package that ONLY resolves through the
    # node_modules junction, and test.js require()s calc.js -- so if the junction is
    # not wired, `node test.js` throws MODULE_NOT_FOUND and the baseline fails
    # (never a survivor). The require line is in BOTH commits so the diff stays the
    # `return` line and the mutant target is unchanged. (D4)
    req = "const { bump } = require('isadult-helper');\n" if wire_pkg else ""
    calc_base = f"{req}function isAdult(age) {{\n  return true;\n}}\nmodule.exports = {{ isAdult }};\n"
    calc_feat = f"{req}function isAdult(age) {{\n  return age >= 18;\n}}\nmodule.exports = {{ isAdult }};\n"
    test_js = ("const { isAdult } = require('./calc.js');\nprocess.exit(0);\n"
               if wire_pkg else "process.exit(0);\n")
    (r / "calc.js").write_text(calc_base, encoding="utf-8")
    (r / "test.js").write_text(test_js, encoding="utf-8")
    # node_modules must never be a tracked path: `git worktree add` would then
    # check it out into the worktree, and a real `mklink /J` / os.symlink
    # cannot land on top of an already-existing (non-empty) directory.
    (r / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    if with_node_modules:
        (r / "node_modules").mkdir()
        (r / "node_modules" / ".marker").write_text("real deps", encoding="utf-8")
        if wire_pkg:
            pkg = r / "node_modules" / "isadult-helper"
            pkg.mkdir()
            (pkg / "package.json").write_text(
                '{"name":"isadult-helper","main":"index.js"}\n', encoding="utf-8")
            (pkg / "index.js").write_text(
                "module.exports = { bump: (n) => n + 1 };\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "calc.js").write_text(calc_feat, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)


def _consume(r, base, head, monkeypatch, tmp_path, item_id="q1"):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id=item_id, base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")
    try:
        return jsc.consume(item, DrainContext(root=r, cfg=cfg, ledger=led, clock=lambda: "t"))
    finally:
        led.close()


def test_disabled_returns_ok_note(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    (r / "aramid.toml").write_text("schema_version = 1\n[js_mutation]\nenabled = false\n",
                                   encoding="utf-8")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok" and res.note == "disabled"


def test_no_js_test_stack_ok_skip(tmp_path, monkeypatch):
    # package.json WITHOUT a test script -> detect_tests has no "npm" -> OK-skip,
    # never degraded (else the queue item pins forever).
    r, base, head = _js_repo(tmp_path)
    (r / "package.json").write_text('{"name":"x","scripts":{}}\n', encoding="utf-8")
    _git(r, "commit", "-q", "-am", "drop test script")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "no js test stack" in res.note


def test_node_modules_absent_ok_skip(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path, with_node_modules=False)
    # Force the pm gate to pass regardless of whether npm is on PATH (CI is
    # Node-free), so the node_modules check is the one that fires.
    monkeypatch.setattr(jsc, "_pm_test_argv", lambda pm: ["npm", "test"])
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "node_modules not installed" in res.note


def test_link_and_unlink_node_modules_preserves_target(tmp_path):
    # Invariant #7: unlinking the junction/symlink must NEVER delete the real
    # node_modules it points at.
    src = tmp_path / "src"
    (src / "node_modules").mkdir(parents=True)
    (src / "node_modules" / "keep.txt").write_text("keep", encoding="utf-8")
    wt = tmp_path / "wt"
    wt.mkdir()
    linked = jsc._link_node_modules(src, wt)
    assert linked is True
    assert (wt / "node_modules" / "keep.txt").read_text() == "keep"
    jsc._unlink_node_modules(wt)
    assert not (wt / "node_modules").exists()
    assert (src / "node_modules" / "keep.txt").read_text() == "keep", \
        "the real node_modules must survive the unlink"


def _scripted(monkeypatch, seq):
    """Replace run_subprocess with a scripted sequence of (state, returncode).
    Also force the pm gate to pass (CI is Node-free, so shutil.which('npm') is
    None) and stub the junction helpers so no real link is created. call 0 is
    the baseline run; calls 1+ are the per-mutant runs."""
    calls = {"n": 0}

    def fake(argv, cwd, timeout, **kw):
        i = calls["n"]
        calls["n"] += 1
        state, rc = seq[i] if i < len(seq) else seq[-1]
        return RunnerResult(tool="npm", state=state, returncode=rc)

    monkeypatch.setattr(jsc, "run_subprocess", fake)
    monkeypatch.setattr(jsc, "_pm_test_argv", lambda pm: ["npm", "test"])
    monkeypatch.setattr(jsc, "_link_node_modules", lambda src, wt: True)
    monkeypatch.setattr(jsc, "_unlink_node_modules", lambda wt: None)
    return calls


def test_survivor_reported_when_suite_passes_the_mutant(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    # baseline green (rc 0), then every mutant run green (rc 0) -> survivor(s)
    _scripted(monkeypatch, [(ToolState.OK, 0)])
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "a mutant the suite cannot kill must be reported"
    f = res.findings[0]
    assert f.tool == "js-mutation" and f.file == "calc.js"
    assert "mutant survived" in f.message
    assert res.extra["survived"] >= 1


def test_killed_when_suite_fails_the_mutant(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    # baseline green, then every mutant fails (rc 1) -> killed, no findings
    _scripted(monkeypatch, [(ToolState.OK, 0), (ToolState.OK, 1)])
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["killed"] >= 1


def test_baseline_red_degrades_with_loadbearing_note(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    _scripted(monkeypatch, [(ToolState.OK, 1)])   # baseline itself fails
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    # Shared with the Python consumer -- one definition, so the two paths
    # cannot drift into different spellings of the same condition.
    assert res.note.startswith(py_mutation.failing_note_prefix(head))


def test_timeout_counts_not_killed_not_survived(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    _scripted(monkeypatch, [(ToolState.OK, 0), (ToolState.TIMEOUT, 0)])
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.extra["timeouts"] >= 1
    assert res.findings == []


def test_give_up_after_three_baseline_failures_head_scoped(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for i in range(3):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}", "t",
                             payload={"consumer": "js_mutation", "item_id": "q1",
                                      "note": py_mutation.failing_note_prefix(head)}))
    finally:
        led.close()
    _scripted(monkeypatch, [(ToolState.OK, 0)])   # would pass, but give-up first
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "giving up" in res.note


def test_baseline_timeout_is_not_reported_as_a_failure(tmp_path, monkeypatch):
    """Parity with the Python consumer (R64-1).

    This module was cloned from consumers/mutation.py and inherited its exact
    defect: `state is not ToolState.OK` swallows TIMEOUT into the
    failing-baseline branch. Only the Python path was exercised downstream, so
    without this test the same bug ships alive on the JS path with nothing
    that would ever find it.
    """
    r, base, head = _js_repo(tmp_path)
    _scripted(monkeypatch, [(ToolState.TIMEOUT, 0)])   # baseline times out

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "degraded"
    assert not res.note.startswith("baseline failing"), \
        "a timeout must not join the failing-baseline note family"
    assert "timeout" in res.note


def test_js_timeout_giveup_is_repo_scoped_not_item_scoped(tmp_path, monkeypatch):
    from aramid.consumers import mutation as py_mutation
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType

    r, base, head = _js_repo(tmp_path)
    # 240.0 = the fixture's `mutant_timeout_s = 60` x 4, i.e. the default
    # budget. Getting this wrong makes the prefix miss and the test pass for
    # the wrong reason -- it would simply run normally and report ok.
    prefix = py_mutation.timeout_note_prefix(240.0, "npm test")
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for i in range(3):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}", "t",
                             payload={"consumer": "js_mutation",
                                      "item_id": "some-older-item",
                                      "state": "degraded",
                                      "note": prefix + " (last seen @ 000000000000)"}))
    finally:
        led.close()
    _scripted(monkeypatch, [(ToolState.OK, 0)])   # would pass, but give-up first

    res = _consume(r, base, head, monkeypatch, tmp_path, item_id="a-new-item")

    assert res.state == "ok"
    assert "giving up" in res.note
    assert "baseline_timeout_s" in res.note


def _link_raises(src, wt):
    raise OSError("mklink /J failed: simulated persistent link failure")


def test_node_modules_link_failure_degrades_with_head_scoped_prefix(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    _scripted(monkeypatch, [(ToolState.OK, 0)])          # pm gate + stubs
    monkeypatch.setattr(jsc, "_link_node_modules", _link_raises)   # link fails
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    # note must START with the head-scoped prefix so prior_note_count can match it
    assert res.note.startswith(jsc.link_note_prefix(head))


def test_give_up_after_three_node_modules_link_failures_head_scoped(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for i in range(3):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}", "t",
                             payload={"consumer": "js_mutation", "item_id": "q1",
                                      "note": jsc.link_note_prefix(head)}))
    finally:
        led.close()
    _scripted(monkeypatch, [(ToolState.OK, 0)])
    monkeypatch.setattr(jsc, "_link_node_modules", _link_raises)   # would fail, but give-up first
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "giving up" in res.note


_HAS_NODE = shutil.which("node") is not None and shutil.which("npm") is not None


def _no_worktrees(r):
    cp = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                        capture_output=True, text=True)
    return len([ln for ln in cp.stdout.splitlines() if ln.strip()]) == 1


@pytest.mark.skipif(not _HAS_NODE, reason="node+npm not on PATH (Python-only CI)")
def test_real_npm_weak_suite_reports_survivor(tmp_path, monkeypatch):
    # End-to-end with a REAL `npm test`. wire_pkg=True makes test.js -> calc.js ->
    # require('isadult-helper'), which ONLY resolves through the node_modules
    # junction. So the baseline passing (and the weak suite then reporting the
    # `>= -> >` survivor) PROVES resolution went through the junction (D4).
    # DoD sanity check (manual, not committed): stub jsc._link_node_modules to a
    # no-op returning True and this test goes red (MODULE_NOT_FOUND -> baseline
    # fails -> no findings).
    r, base, head = _js_repo(tmp_path, wire_pkg=True)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "the weak suite cannot kill the mutant -> survivor"
    assert res.findings[0].tool == "js-mutation"
    assert res.extra["survived"] >= 1
    assert _no_worktrees(r)


def test_is_test_file_case_insensitive():
    # `.test.`/`.spec.` detection must be case-insensitive so an uppercase
    # `Foo.TEST.JS` is treated as a test file, not mutated as production code.
    assert jsc._is_test_file("src/Foo.TEST.JS")
    assert jsc._is_test_file("src/Bar.Spec.ts")
    assert jsc._is_test_file("__tests__/x.js")
    assert not jsc._is_test_file("src/calc.js")


def test_consumer_is_registered():
    # Importing the module must register it in the consumer registry (the drain
    # loop dispatches via base.CONSUMERS).
    from aramid.consumers import base
    assert base.CONSUMERS["js_mutation"] is jsc


# --- js-mutation can prove a repair -----------------------------------------
#
# js-mutation had no resolver of any kind: nothing matched tool="js-mutation",
# record_run cannot reach it (runner labels only) and drain._consume_item
# passes empty scopes deliberately. Its findings never resolved for ANY reason,
# not even a deletion -- so writing the killing test changed nothing.
#
# Single-stage is an ADVANTAGE here: `<pm> test` IS the full suite, so a
# non-zero exit is already a full-suite verdict and needs no second stage (the
# python consumer has to go and buy that confirmation).
#
# The residual risk is different, and it is the environment. If the junction or
# node itself breaks mid-run, EVERY subsequent mutant exits non-zero and reads
# as killed -- mass false repair from one broken link. The initial baseline
# proves health at the start; a final clean-tree baseline proves it at the end,
# and is only paid for when there is actually something to claim.

def _seed_open(r, fid, file="calc.js", line=2):
    from aramid.models import Finding, Gate, Severity, Verdict
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("seed", "2026-08-10T00:00:00+00:00", "drain", set(), set(),
                       [Finding(id=fid, tool="js-mutation", rule="cmp-flip",
                                severity_raw="medium", severity=Severity.MEDIUM,
                                verdict=Verdict.WARN, file=file, line=line,
                                message="mutant survived", evidence="",
                                gate=Gate.ALL)])
    finally:
        led.close()


def _scripted_by_tree(monkeypatch, *, mutant_rc, baseline_rcs=(0,)):
    """Answer each run by WHAT IS ON DISK, not by call index.

    `_scripted` above indexes a sequence and repeats its last entry, which
    makes any test that needs a DIFFERENT answer for a later run impossible to
    write correctly -- the confirming baseline silently inherited the mutant's
    exit code, and the first version of these tests read that as a bug in the
    consumer rather than in the script.

    The pristine feature line is `return age >= 18;`; every mutant of it
    changes that text. So the tree itself says which run this is, which is the
    same distinction the consumer is making and is robust to however many
    mutants the generator emits. `baseline_rcs` indexes successive PRISTINE
    runs (clamped to the last), so "green at the start, broken at the end" is
    expressible.
    """
    from pathlib import Path
    calls = {"n": 0, "baselines": 0, "mutants": 0}

    def fake(argv, cwd, timeout, **kw):
        calls["n"] += 1
        src = (Path(cwd) / "calc.js").read_text(encoding="utf-8")
        if "age >= 18" in src:                      # pristine tree
            i = min(calls["baselines"], len(baseline_rcs) - 1)
            calls["baselines"] += 1
            rc = baseline_rcs[i]
        else:
            calls["mutants"] += 1
            rc = mutant_rc
        return RunnerResult(tool="npm", state=ToolState.OK, returncode=rc)

    monkeypatch.setattr(jsc, "run_subprocess", fake)
    monkeypatch.setattr(jsc, "_pm_test_argv", lambda pm: ["npm", "test"])
    monkeypatch.setattr(jsc, "_link_node_modules", lambda src, wt: True)
    monkeypatch.setattr(jsc, "_unlink_node_modules", lambda wt: None)
    return calls


def _a_killed_fp(r, base, head, monkeypatch, tmp_path):
    """One fingerprint this repo really does report as killed."""
    _scripted_by_tree(monkeypatch, mutant_rc=1)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    fps = sorted(res.extra.get("killed_fps", []))
    assert fps, f"scripted kill produced no fingerprints: {res.note}"
    return fps[0]


def test_a_killed_mutant_matching_an_open_finding_is_claimed_repaired(
        tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    fp = _a_killed_fp(r, base, head, monkeypatch, tmp_path)
    _seed_open(r, fp)
    _scripted_by_tree(monkeypatch, mutant_rc=1)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.repaired is not None, "a killed mutant proved nothing"
    assert fp in set(res.repaired.ids)
    assert res.repaired.reason == "mutant_killed"


def test_the_claim_names_the_tool_the_findings_carry_not_the_consumer(
        tmp_path, monkeypatch):
    """NAME is "js_mutation"; the findings are tool="js-mutation". Inferring
    the tool from NAME would make every claim a silent no-op -- it would match
    no open finding and report success doing it."""
    r, base, head = _js_repo(tmp_path)
    fp = _a_killed_fp(r, base, head, monkeypatch, tmp_path)
    _seed_open(r, fp)
    _scripted_by_tree(monkeypatch, mutant_rc=1)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.repaired.tool == "js-mutation"
    assert res.repaired.tool != jsc.NAME


def test_a_kill_matching_nothing_open_buys_no_confirming_run(tmp_path, monkeypatch):
    """The affordability property. Almost every killed mutant was never
    reported, so there is nothing to confirm and no second baseline is run.
    Asserted on the CALLS -- an outcome assertion cannot tell a skipped
    confirmation from a cheap one."""
    r, base, head = _js_repo(tmp_path)
    calls = _scripted_by_tree(monkeypatch, mutant_rc=1)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert not (res.repaired and res.repaired.ids)
    assert calls["baselines"] == 1, (
        f"a kill that resolves nothing still paid for a confirmation: {calls}")

    _seed_open(r, sorted(res.extra["killed_fps"])[0])
    calls2 = _scripted_by_tree(monkeypatch, mutant_rc=1)
    _consume(r, base, head, monkeypatch, tmp_path)

    assert calls2["baselines"] == 2, (
        f"a claimable kill must buy exactly one confirming baseline: {calls2}")


def test_no_repair_is_claimed_when_the_environment_is_broken_at_the_end(
        tmp_path, monkeypatch):
    """THE ATTACK. The junction (or node) dies mid-run, so every subsequent
    `<pm> test` exits non-zero and every mutant reads as killed. Those are not
    repairs, they are one broken link -- and claiming them writes fixes that
    never happened into an append-only ledger, for every open finding at once.

    Green at the start (so the run proceeds at all), broken by the time the
    confirming baseline runs on the restored tree."""
    r, base, head = _js_repo(tmp_path)
    fp = _a_killed_fp(r, base, head, monkeypatch, tmp_path)
    _seed_open(r, fp)
    _scripted_by_tree(monkeypatch, mutant_rc=1, baseline_rcs=(0, 1))

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert not (res.repaired and res.repaired.ids), (
        "a broken environment was allowed to resolve findings as repaired")
    assert res.extra.get("unconfirmed_kills", 0) >= 1, (
        "the refusal must be counted, not silent")


def test_a_drained_js_repair_flips_the_open_finding_to_fixed(tmp_path, monkeypatch):
    """End to end through the REAL drain, one shared ledger, nothing
    replicated: a surviving mutant is recorded as a finding (id computed by
    `normalize`, not by this test), the suite is then strong enough to kill it,
    and the ledger says `fixed`.

    This is the ONLY test here that holds `_mutant_fp` == the id `normalize`
    gives the finding. Every other test in this block reads both sides from
    `_mutant_fp`, so they would all stay green if it drifted -- measured
    exactly that way on the python consumer earlier, where a perturbed
    fingerprint left the "identity" test passing and only the drain test red.
    """
    from aramid.commands import drain as drain_mod

    r, base, head = _js_repo(tmp_path)
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"js_mutation": jsc})
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)
    item = QueueItem(id="q1", base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        # Survivor: the suite passes with the mutant applied.
        _scripted_by_tree(monkeypatch, mutant_rc=0)
        drain_mod._consume_item(r, cfg, led, item, lambda: "2026-08-10T00:00:00+00:00")

        opened = {fid for fid, rec in led.open_findings().items()
                  if rec.get("tool") == "js-mutation" and rec["status"] == "open"}
        assert opened, "the weak suite recorded no open js-mutation finding"

        # Someone writes the test: the same mutant now fails the suite.
        _scripted_by_tree(monkeypatch, mutant_rc=1)
        drain_mod._consume_item(r, cfg, led, item, lambda: "2026-08-10T01:00:00+00:00")

        after = led.open_findings()
        assert all(after[fid]["status"] == "fixed" for fid in opened), (
            "a killed js mutant stayed open: "
            f"{ {fid: after[fid]['status'] for fid in opened} }")
    finally:
        led.close()
