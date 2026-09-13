"""`consumers.js_mutation.consume` at unit scope: every knob default, skip,
give-up, budget cut, verdict, counter, note and claim, one exact assertion
each.

The drain confirms a mutant against the unit suite alone, and until this
file nothing in it reached `consume` -- the 49 mutants the generator emits
for its body were held by tests/integration/test_js_mutation_consumer.py,
which the drain never runs. The harness is that file's seams and nothing
more: a real tmp git repo (the worktree `consume` cuts is real), a real
ledger, the node_modules link and `<pm> test` resolution faked, and
`run_subprocess` replaced by an ORACLE that reads which mutant the
worktree's calc.js holds and answers a script. The fixture module has one
`&&` per function, so `jsmutate` emits exactly one mutant per function and
an outcome is scripted by function name. `time` is a fixed clock (or a
scripted sequence) so the budget arithmetic is exact."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import jsmutate
from aramid.consumers import js_mutation as jsc
from aramid.consumers import mutation as pymut
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict
from aramid.queue import QueueItem
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a],
                   cwd=root, check=True, capture_output=True, text=True)


def _sha(root):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


def _module(n):
    # distinct operands per function: a mutation id is the LINE CONTENT, so
    # identical `return a && b;` lines would share one id
    body = "".join(f"function f{i}(a{i}, b{i}) {{\n  return a{i} && b{i};\n}}\n"
                   for i in range(1, n + 1))
    return body + "module.exports = { " + ", ".join(f"f{i}" for i in range(1, n + 1)) + " };\n"


def _labels(src):
    """mutant source -> function name, for a module `_module` wrote."""
    lines = src.splitlines()
    out = {}
    for m in jsmutate.generate_mutants(src, set(range(1, len(lines) + 1))):
        out[m.source] = lines[m.line - 2].split("(")[0].replace("function ", "")
    return out


def _repo(tmp_path, n=3, *, node_modules=True, lock=False, test_script=True, extra=None):
    """calc.js is new at head (every line in range); package.json is at base."""
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    pkg = {"name": "x", "scripts": {"test": "node test.js"}} if test_script else {"name": "x"}
    (r / "package.json").write_text(json.dumps(pkg) + "\n", encoding="utf-8")
    (r / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    if lock:
        (r / "package-lock.json").write_text("{}\n", encoding="utf-8")
    if node_modules:
        (r / "node_modules").mkdir()
        (r / "node_modules" / ".marker").write_text("deps", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "calc.js").write_text(_module(n), encoding="utf-8")
    for rel, body in (extra or {}).items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_text(body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "head")
    return r, base, _sha(r)


PASS = RunnerResult(tool="npm", state=ToolState.OK, returncode=0)
FAIL = RunnerResult(tool="npm", state=ToolState.OK, returncode=1)
TIMEOUT = RunnerResult(tool="npm", state=ToolState.TIMEOUT)
CRASHED = RunnerResult(tool="npm", state=ToolState.CRASHED, returncode=0)


class Oracle:
    """`run_subprocess` for `npm test` in the worktree: labels calc.js (BASE,
    f<n>, or ?), answers `outcomes[label]` -- a RunnerResult, a list of them
    consumed in order (the baseline and the final confirm are both BASE),
    or a callable(wt) for a side effect or a raise -- and records
    (label, timeout_s, argv)."""

    def __init__(self, original, outcomes, default=FAIL):
        self.labels = _labels(original)
        self.original = original
        self.outcomes = {k: (list(v) if isinstance(v, list) else v) for k, v in outcomes.items()}
        self.default = default
        self.calls = []

    def __call__(self, argv, cwd, timeout_s, env=None):
        p = Path(cwd) / "calc.js"
        try:
            src = p.read_text(encoding="utf-8")
            label = "BASE" if src == self.original else self.labels.get(src, "?")
        except OSError:
            label = "DIR"
        self.calls.append((label, timeout_s, list(argv)))
        spec = self.outcomes.get(label, PASS if label == "BASE" else self.default)
        if isinstance(spec, list):
            spec = spec.pop(0)
        if callable(spec):
            spec = spec(Path(cwd))
        return spec


def _run(r, base, head, monkeypatch, cfg, outcomes=None, *, default=FAIL, clock=(100.0,),
         item_id="q1", link=True):
    original = (r / "calc.js").read_text(encoding="utf-8") if (r / "calc.js").exists() else ""
    oracle = Oracle(original, outcomes or {}, default)
    monkeypatch.setattr(jsc, "run_subprocess", oracle)
    monkeypatch.setattr(jsc, "_pm_test_argv", lambda pm: [pm, "test"] if pm == "npm" else None)
    if link is True:
        monkeypatch.setattr(jsc, "_link_node_modules", lambda src, wt: True)
    else:
        monkeypatch.setattr(jsc, "_link_node_modules", link)
    monkeypatch.setattr(jsc, "_unlink_node_modules", lambda wt: None)
    seq = list(clock)

    def monotonic():
        return seq.pop(0) if len(seq) > 1 else seq[0]
    monkeypatch.setattr(jsc, "time", SimpleNamespace(monotonic=monotonic))
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id=item_id, base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")
    try:
        res = jsc.consume(item, DrainContext(root=r, cfg=SimpleNamespace(js_mutation=cfg,
                                                                         ignore_paths=[]),
                                             ledger=led, clock=lambda: "t"))
    finally:
        led.close()
    return res, oracle


ZERO = {"generated": 0, "tested": 0, "killed": 0, "survived": 0, "timeouts": 0, "errors": 0,
        "unconfirmed_kills": 0, "killed_fps": [], "truncated": False}


def _stats(res, **expect):
    want = {**ZERO, **expect}
    assert res.extra == want, {k: (res.extra.get(k), want[k]) for k in want
                               if res.extra.get(k) != want[k]}


def fp(r, func, rel="calc.js"):
    lines = (r / rel).read_text(encoding="utf-8").splitlines()
    line = next(i for i, ln in enumerate(lines) if ln.startswith(f"function {func}(")) + 2
    return jsc._mutant_fp(rel, "logical-swap", line, lines)


def _seed_open(r, fid):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("seed", "2026-08-10T00:00:00+00:00", "drain", set(), set(),
                       [Finding(id=fid, tool="js-mutation", rule="logical-swap",
                                severity_raw="medium", severity=Severity.MEDIUM,
                                verdict=Verdict.WARN, file="calc.js", line=2,
                                message="mutant survived", evidence="", gate=Gate.ALL)])
    finally:
        led.close()


def _seed_notes(r, n, note, item_id="q1"):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for k in range(n):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"d{k}",
                             f"2026-08-10T0{k}:00:00+00:00",
                             payload={"consumer": "js_mutation", "item_id": item_id,
                                      "state": "degraded", "note": note, "duration_s": 1.0}))
    finally:
        led.close()


def _no_worktrees(r):
    out = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                         capture_output=True, text=True).stdout
    return len([ln for ln in out.splitlines() if ln.strip()]) == 1


# --------------------------------------------------------------- skips --

def test_disabled_says_so_before_git_is_asked(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    monkeypatch.setattr(jsc.gitutil, "diff_new_lines",
                        lambda *a: (_ for _ in ()).throw(AssertionError("git was asked")))

    res, oracle = _run(r, base, head, monkeypatch, {"enabled": False})

    assert (res.state, res.note) == ("ok", "disabled") and oracle.calls == []


def test_a_range_of_only_tests_and_non_js_files_is_an_ok_skip(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 0, extra={"calc.test.js": _module(2),
                                              "__tests__/x.js": _module(1),
                                              "a.spec.ts": _module(1), "calc.py": "a >= 1\n"})
    (r / "calc.js").unlink()
    _git(r, "commit", "-q", "-a", "-m", "drop calc")
    head = _sha(r)

    res, oracle = _run(r, base, head, monkeypatch, None)

    assert (res.state, res.note) == ("ok", "no js files in range") and oracle.calls == []


def test_a_repo_without_an_npm_test_script_is_an_ok_skip(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, test_script=False)

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert (res.state, res.note) == ("ok", "no js test stack (mutation skipped)")
    assert oracle.calls == []


def test_a_package_manager_that_is_not_on_path_is_an_ok_skip(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    (r / "pnpm-lock.yaml").write_text("", encoding="utf-8")

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert (res.state, res.note) == ("ok", "js package manager not found (mutation skipped)")
    assert oracle.calls == []


def test_missing_node_modules_is_an_ok_skip(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, node_modules=False)

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert (res.state, res.note) == ("ok", "node_modules not installed (js mutation skipped)")
    assert oracle.calls == []


# ------------------------------------------------------------- give-ups --

def test_three_baseline_timeouts_on_any_item_give_up_with_the_budget_named(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    _seed_notes(r, 3, pymut.timeout_note_prefix(480.0, "npm test") + " (last seen @ x)",
                item_id="older")

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert (res.state, res.note) == (
        "ok", "js mutation giving up: npm test does not fit the 480s baseline budget after"
              " 3 attempts -- raise [js_mutation].baseline_timeout_s")
    assert oracle.calls == []


def test_three_failing_baselines_at_this_item_give_up(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    _seed_notes(r, 3, pymut.failing_note_prefix(head))

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert (res.state, res.note) == ("ok", "js mutation giving up: baseline persistently failing")
    assert oracle.calls == []


def test_three_link_failures_at_this_item_give_up(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    _seed_notes(r, 3, jsc.link_note_prefix(head) + ": mklink /J failed")

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert (res.state, res.note) == (
        "ok", "js mutation giving up: node_modules link persistently failing")
    assert oracle.calls == []


def test_two_of_each_do_not_give_up(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    _seed_notes(r, 2, pymut.timeout_note_prefix(480.0, "npm test"), item_id="older")
    _seed_notes(r, 2, pymut.failing_note_prefix(head))
    _seed_notes(r, 2, jsc.link_note_prefix(head))

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert res.state == "ok" and len(oracle.calls) == 4, "baseline + 3 mutants"


# ------------------------------------------------- worktree and baseline --

def test_a_worktree_that_cannot_be_added_degrades_with_200_chars_of_stderr(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    real = jsc.gitutil._run

    def failing(root, *args, **kw):
        if args[:2] == ("worktree", "add"):
            return subprocess.CompletedProcess(args, 1, stdout="", stderr=" " + "x" * 250)
        return real(root, *args, **kw)
    monkeypatch.setattr(jsc.gitutil, "_run", failing)

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert (res.state, res.note) == ("degraded", "worktree add failed: " + "x" * 200)
    assert oracle.calls == []


def test_a_worktree_failure_with_no_stderr_still_reads(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)
    real = jsc.gitutil._run

    def failing(root, *args, **kw):
        if args[:2] == ("worktree", "add"):
            return subprocess.CompletedProcess(args, 128, stdout="", stderr=None)
        return real(root, *args, **kw)
    monkeypatch.setattr(jsc.gitutil, "_run", failing)

    res, _ = _run(r, base, head, monkeypatch, {})

    assert res.note == "worktree add failed: "


def test_a_link_failure_degrades_with_150_chars_of_the_error(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)

    def boom(src, wt):
        raise OSError("m" * 200)

    res, oracle = _run(r, base, head, monkeypatch, {}, link=boom)

    assert (res.state, res.note) == ("degraded", jsc.link_note_prefix(head) + ": " + "m" * 150)
    assert oracle.calls == [] and _no_worktrees(r)


def test_a_baseline_timeout_degrades_with_the_budget_the_suite_and_the_head(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)

    res, oracle = _run(r, base, head, monkeypatch, {}, {"BASE": TIMEOUT})

    assert res.state == "degraded"
    assert res.note == f"{pymut.timeout_note_prefix(480.0, 'npm test')} (last seen @ {head[:12]})"
    assert oracle.calls == [("BASE", 480.0, ["npm", "test"])], "mutant_timeout_s x 4"
    assert _no_worktrees(r)


def test_a_red_baseline_degrades_with_the_shared_prefix(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)

    res, oracle = _run(r, base, head, monkeypatch, {}, {"BASE": FAIL})

    assert (res.state, res.note) == ("degraded", pymut.failing_note_prefix(head))
    assert len(oracle.calls) == 1


def test_a_baseline_that_crashed_at_rc_0_is_failing_too(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)

    res, _ = _run(r, base, head, monkeypatch, {}, {"BASE": CRASHED})

    assert (res.state, res.note) == ("degraded", pymut.failing_note_prefix(head))


def test_the_configured_baseline_budget_wins_over_the_multiple(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path)

    _, oracle = _run(r, base, head, monkeypatch, {"mutant_timeout_s": 10, "baseline_timeout_s": 7})

    assert [t for _, t, _ in oracle.calls] == [7.0, 10.0, 10.0, 10.0]


# -------------------------------------------------------------- verdicts --

def test_every_mutant_verdict_lands_in_its_own_counter(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 6, extra={"other.js": _module(1)})

    def dir_trick(wt):
        p = wt / "calc.js"
        p.unlink()
        p.mkdir()
        return FAIL

    def boom(wt):
        raise RuntimeError("runner blew up")
    res, oracle = _run(r, base, head, monkeypatch, {},
                       {"f1": PASS, "f2": FAIL, "f3": TIMEOUT, "f4": CRASHED, "f5": boom,
                        "f6": dir_trick})

    assert res.state == "ok", res.note
    # f6's restore left calc.js a directory: one error, and other.js's mutant
    # then runs against a tree the oracle labels DIR and fails (a kill)
    _stats(res, generated=7, tested=7, killed=3, survived=1, timeouts=1, errors=3,
           killed_fps=[fp(r, "f2"), fp(r, "f6"), fp(r, "f1", "other.js")])
    assert res.note == "1 survivor(s) of 7 mutant(s) tested"
    assert [(f.tool, f.rule, f.file, f.line, f.message) for f in res.findings] == [
        ("js-mutation", "logical-swap", "calc.js", 2, "mutant survived: && -> ||")]
    assert res.cost == 0.0
    assert res.repaired is not None
    assert (res.repaired.tool, res.repaired.reason, res.repaired.ids, res.repaired.examined) == (
        "js-mutation", "mutant_killed", (), ())
    assert [lab for lab, _, _ in oracle.calls] == ["BASE", "f1", "f2", "f3", "f4", "f5", "f6", "DIR"]
    assert {t for lab, t, _ in oracle.calls if lab != "BASE"} == {120.0}, "mutant_timeout_s"
    assert _no_worktrees(r)


def test_an_unreadable_file_and_a_generator_that_throws_are_errors_not_stops(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 1, extra={"bad.js": "x\n", "zed.js": _module(1)})
    real = jsc.jsmutate.generate_mutants

    def gen(source, lines):
        if source == "x\n":
            raise ValueError("cannot parse")
        return real(source, lines)
    monkeypatch.setattr(jsc.jsmutate, "generate_mutants", gen)

    def swap(wt):
        p = wt / "zed.js"
        p.unlink()
        p.mkdir()
        return PASS

    res, oracle = _run(r, base, head, monkeypatch, {}, {"BASE": [swap, PASS]})

    _stats(res, generated=1, tested=1, killed=1, errors=2, killed_fps=[fp(r, "f1")])
    assert [lab for lab, _, _ in oracle.calls] == ["BASE", "f1"]


# --------------------------------------------------------------- budgets --

def test_max_mutants_defaults_to_20_and_the_21st_is_dropped_with_a_note(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 21)

    res, oracle = _run(r, base, head, monkeypatch, {})

    _stats(res, generated=21, tested=20, killed=20, truncated=True,
           killed_fps=[fp(r, f"f{i}") for i in range(1, 21)])
    assert res.note == "0 survivor(s) of 20 mutant(s) tested (truncated: budget/cap hit, remainder dropped)"
    assert len(oracle.calls) == 21


def test_an_exact_fit_is_not_a_truncation(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 2)

    res, _ = _run(r, base, head, monkeypatch, {"max_mutants": 2})

    _stats(res, generated=2, tested=2, killed=2, killed_fps=[fp(r, "f1"), fp(r, "f2")])
    assert res.note == "0 survivor(s) of 2 mutant(s) tested"


def test_the_wall_budget_stops_between_mutants_strictly_after_it_is_spent(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 3)
    # started, then one check per mutant: at exactly the (default 600 s)
    # budget the next mutant still runs; past it the rest are dropped
    res, oracle = _run(r, base, head, monkeypatch, {}, clock=(0.0, 600.0, 600.001, 600.001))

    _stats(res, generated=3, tested=1, killed=1, truncated=True, killed_fps=[fp(r, "f1")])
    assert res.duration_s == 600.001


# ---------------------------------------------------------------- claims --

def test_a_recorded_survivor_killed_and_confirmed_on_the_restored_tree_is_claimed(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 2)
    _seed_open(r, fp(r, "f1"))

    res, oracle = _run(r, base, head, monkeypatch, {}, {"BASE": [PASS, PASS]})

    _stats(res, generated=2, tested=2, killed=2, killed_fps=[fp(r, "f1"), fp(r, "f2")])
    assert res.repaired is not None
    assert (res.repaired.ids, res.repaired.examined) == ((fp(r, "f1"),), (fp(r, "f1"),))
    assert [(lab, t) for lab, t, _ in oracle.calls] == [
        ("BASE", 480.0), ("f1", 120.0), ("f2", 120.0), ("BASE", 480.0)], "one confirm, x4"


def test_a_confirm_that_fails_withholds_the_claim_and_counts_it(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 2)
    _seed_open(r, fp(r, "f1"))
    _seed_open(r, fp(r, "f2"))

    res, _ = _run(r, base, head, monkeypatch, {}, {"BASE": [PASS, FAIL]})

    _stats(res, generated=2, tested=2, killed=2, unconfirmed_kills=2,
           killed_fps=[fp(r, "f1"), fp(r, "f2")])
    assert res.repaired is not None and res.repaired.ids == ()
    assert res.repaired.examined == tuple(sorted((fp(r, "f1"), fp(r, "f2"))))


def test_a_confirm_that_crashed_at_rc_0_withholds_too(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 1)
    _seed_open(r, fp(r, "f1"))

    res, _ = _run(r, base, head, monkeypatch, {}, {"BASE": [PASS, CRASHED]})

    _stats(res, generated=1, tested=1, killed=1, unconfirmed_kills=1, killed_fps=[fp(r, "f1")])
    assert res.repaired is not None and res.repaired.ids == ()


def test_a_kill_of_an_unrecorded_id_buys_no_confirm(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 1)

    res, oracle = _run(r, base, head, monkeypatch, {})

    assert [lab for lab, _, _ in oracle.calls] == ["BASE", "f1"]
    assert res.repaired is not None and res.repaired.ids == () and res.repaired.examined == ()


def test_a_recorded_survivor_that_survives_again_is_re_reported_not_claimed(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, 1)
    _seed_open(r, fp(r, "f1"))

    res, oracle = _run(r, base, head, monkeypatch, {}, {"f1": PASS})

    _stats(res, generated=1, tested=1, survived=1)
    assert [f.file for f in res.findings] == ["calc.js"]
    assert res.repaired is not None and res.repaired.ids == ()
    assert [lab for lab, _, _ in oracle.calls] == ["BASE", "f1"]
