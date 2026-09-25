"""`consumers.fuzz.consume` at unit scope: every knob default, budget cut,
driver verdict, counter, note and claim, one exact assertion each.

The drain confirms a mutant against the unit suite alone, and until this
file nothing in it reached `consume` -- the 49 mutants the generator emits
for its body were held by tests/integration/test_fuzz_consumer.py, which
the drain never runs. The harness is that file's seams and nothing more: a
real tmp git repo (the worktree `consume` cuts is real, and `_reported_ids`
reads it), a real ledger, and the driver subprocess replaced by a fake that
reads the spec it was handed, records what it was asked, and answers a
script. `time` is a fixed clock so the budget arithmetic is exact."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid.consumers import fuzz as fc
from aramid.consumers.base import DrainContext
from aramid.fingerprint import compute_fingerprint
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


def _fns(names):
    return "".join(f"def {n}(x: int) -> int:\n    return x + 1\n\n\n" for n in names)


def _repo(tmp_path, head_files):
    """Every file in `head_files` is new at head, so every line is in range."""
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "README.md").write_text("base\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    for rel, body in head_files.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_text(body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "head")
    return r, base, _sha(r)


class Driver:
    """`run_subprocess` for `python -m aramid.fuzzdriver <spec>`: records the
    call and the spec, optionally writes the progress file, answers `out`
    (a dict -> JSON on stdout, rc 0) or a RunnerResult verbatim."""

    def __init__(self, out=None, progress=None):
        self.out = out if out is not None else {}
        self.progress = progress
        self.calls = []
        self.spec = None

    def __call__(self, argv, cwd, timeout_s, env=None):
        self.spec = json.loads(Path(argv[-1]).read_text(encoding="utf-8"))
        self.calls.append((list(argv[:-1]), Path(cwd), timeout_s, dict(env or {})))
        if self.progress is not None:
            Path(self.spec["progress"]).write_text(json.dumps(self.progress), encoding="utf-8")
        if isinstance(self.out, RunnerResult):
            return self.out
        return RunnerResult(tool="python", state=ToolState.OK, raw=json.dumps(self.out),
                            returncode=0)


def _run(r, base, head, monkeypatch, fuzz, driver=None, *, item_id="q1", clock=100.0):
    driver = driver if driver is not None else Driver()
    monkeypatch.setattr(fc, "run_subprocess", driver)
    monkeypatch.setattr(fc, "time", SimpleNamespace(monotonic=lambda: clock))
    cfg = SimpleNamespace(fuzz=fuzz, ignore_paths=[])
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id=item_id, base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")
    try:
        res = fc.consume(item, DrainContext(root=r, cfg=cfg, ledger=led, clock=lambda: "t"))
    finally:
        led.close()
    return res, driver


ZERO = {"functions_seen": 0, "functions_fuzzed": 0, "skipped_unhinted": 0,
        "skipped_name": 0, "skipped_async": 0, "cases_run": 0, "crashes": 0,
        "contract_exceptions": 0, "findings": 0, "timeouts": 0, "import_failures": 0,
        "truncated": False}


def _no_worktrees(r):
    out = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                         capture_output=True, text=True).stdout
    return len([ln for ln in out.splitlines() if ln.strip()]) == 1


def _seed_notes(r, n, note, item_id="q1"):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for k in range(n):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"d{k}",
                             f"2026-08-10T0{k}:00:00+00:00",
                             payload={"consumer": "fuzz", "item_id": item_id,
                                      "state": "degraded", "note": note, "duration_s": 1.0}))
    finally:
        led.close()


def _seed_open(r, fid, file, message, line=2):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("seed", "2026-08-10T00:00:00+00:00", "drain", set(), set(),
                       [Finding(id=fid, tool="fuzz", rule="crash-zerodivisionerror",
                                severity_raw="medium", severity=Severity.MEDIUM,
                                verdict=Verdict.WARN, file=file, line=line,
                                message=message, evidence="", gate=Gate.ALL)])
    finally:
        led.close()


def _fid(r, rel, line, rule="crash-zerodivisionerror"):
    """The id `_reported_ids` gives a crash at `line` of `rel` at head."""
    content = (r / rel).read_text(encoding="utf-8").splitlines()[line - 1]
    return compute_fingerprint("fuzz", rule, rel, content, 0)


# --------------------------------------------------------------- skips --

def test_disabled_says_so_before_anything(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})

    res, driver = _run(r, base, head, monkeypatch, {"enabled": False})

    assert (res.state, res.note) == ("ok", "disabled")
    assert driver.calls == [] and _no_worktrees(r)


def test_a_range_of_only_tests_and_non_python_files_is_an_ok_skip(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"tests/test_x.py": _fns(["t"]), "notes.txt": "x\n",
                                     "x_test.py": _fns(["u"])})

    res, driver = _run(r, base, head, monkeypatch, {})

    assert (res.state, res.note) == ("ok", "no python files in range")
    assert driver.calls == []


def test_a_range_whose_python_has_no_candidate_is_an_ok_skip_with_zero_stats(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": "X = 1\n\n\nasync def a(x: int) -> int:\n"
                                               "    return x\n\n\ndef _hide(x: int) -> int:\n"
                                               "    return x\n"})

    res, driver = _run(r, base, head, monkeypatch, {"skip_name_patterns": ["_*"]})

    assert (res.state, res.note) == ("ok", "no fuzzable functions in range")
    assert res.extra == {**ZERO, "functions_seen": 2, "skipped_name": 1, "skipped_async": 1}
    assert res.duration_s == 0.0, "a fixed clock: started == now"
    assert driver.calls == [] and _no_worktrees(r)


# --------------------------------------------------------- the driver --

def test_the_driver_gets_the_targets_the_default_cases_and_batch_timeout(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f", "g"]), "tests/test_l.py": _fns(["t"]),
                                     "data.txt": "def z(x: int) -> int:\n    return x\n"})

    res, driver = _run(r, base, head, monkeypatch, {}, Driver({"cases_run": 100, "fuzzed": []}))

    assert res.state == "ok"
    assert res.note == "0 crash finding(s) from 100 case(s) over 2 function(s)"
    assert driver.spec["targets"] == [{"file": "lib.py", "functions": ["f", "g"], "cases": 50}]
    (argv, cwd, timeout, env), = driver.calls
    assert argv[1:] == ["-m", "aramid.fuzzdriver"] and cwd == Path(driver.spec["root"])
    assert timeout == 120.0, "batch_timeout_s default, under the 300 s wall budget"
    assert env["PYTHONHASHSEED"] == "0" and env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert res.extra == {**ZERO, "functions_seen": 2, "functions_fuzzed": 2, "cases_run": 100,
                         "import_failed": {}}
    assert res.cost == 0.0 and res.repaired is None
    assert _no_worktrees(r)


def test_the_wall_budget_bounds_the_batch_when_it_is_the_smaller(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})

    _, driver = _run(r, base, head, monkeypatch, {"batch_timeout_s": 1000})

    assert driver.calls[0][2] == 300.0, "wall_budget_s default"


def test_configured_knobs_reach_the_spec_and_the_timeout(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})

    _, driver = _run(r, base, head, monkeypatch,
                     {"cases_per_function": 7, "batch_timeout_s": 9, "wall_budget_s": 50})

    assert driver.spec["targets"][0]["cases"] == 7
    assert driver.calls[0][2] == 9.0


def test_every_candidate_reaches_the_driver_with_the_budget_default_10(
        tmp_path, monkeypatch):
    """FN-3: only the driver knows which candidates it can call, so the
    budget travels with the spec and the driver charges it. `over_budget`
    is its count of callable functions left unfuzzed."""
    names = [f"f{i}" for i in range(11)]
    r, base, head = _repo(tmp_path, {"lib.py": _fns(names)})

    res, driver = _run(r, base, head, monkeypatch, {}, Driver({"over_budget": 1}))

    assert driver.spec["targets"] == [{"file": "lib.py", "functions": names, "cases": 50}]
    assert driver.spec["max_functions"] == 10
    assert res.extra["truncated"] is True and res.extra["functions_seen"] == 11
    assert res.extra["functions_fuzzed"] == 10
    assert res.note == ("0 crash finding(s) from 0 case(s) over 10 function(s)"
                        " (truncated: max_functions cap hit)")


def test_nothing_left_over_is_not_a_truncation(tmp_path, monkeypatch):
    names = [f"f{i}" for i in range(10)]
    r, base, head = _repo(tmp_path, {"lib.py": _fns(names)})

    res, driver = _run(r, base, head, monkeypatch, {"max_functions": 4})

    assert driver.spec["max_functions"] == 4
    assert res.extra["truncated"] is False
    assert res.note == "0 crash finding(s) from 0 case(s) over 10 function(s)"


def test_every_file_with_candidates_reaches_the_driver_whatever_the_budget(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"a.py": _fns(["a1", "a2"]), "b.py": _fns(["b1"]),
                                     "c.py": "X = 1\n"})

    res, driver = _run(r, base, head, monkeypatch, {"max_functions": 1})

    assert driver.spec["targets"] == [{"file": "a.py", "functions": ["a1", "a2"], "cases": 50},
                                      {"file": "b.py", "functions": ["b1"], "cases": 50}]
    assert res.extra["functions_seen"] == 3


# ------------------------------------------------------------ verdicts --

def test_a_timed_out_driver_names_where_it_hung(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f", "g"])})
    driver = Driver(RunnerResult(tool="python", state=ToolState.TIMEOUT),
                    progress={"file": "lib.py", "function": "g", "functions_started": 2})

    res, _ = _run(r, base, head, monkeypatch, {}, driver)

    assert res.state == "ok"
    assert res.note == ("driver timed out in lib.py:g (function 2 of 2); no cases run to"
                        " completion (budget did its job) -- a target that blocks forfeits"
                        " the batch; exclude it with [fuzz].skip_name_patterns")
    assert res.extra == {**ZERO, "functions_seen": 2, "timeouts": 1, "hung_in": "lib.py:g"}
    assert res.repaired is None and _no_worktrees(r)


def test_a_timed_out_driver_that_never_called_says_so(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})

    res, _ = _run(r, base, head, monkeypatch, {},
                  Driver(RunnerResult(tool="python", state=ToolState.TIMEOUT)))

    assert res.note.startswith("driver timed out before its first call; no cases run")
    assert res.extra == {**ZERO, "functions_seen": 1, "timeouts": 1}


def test_a_driver_that_exited_non_zero_degrades_with_100_chars_of_stderr(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})

    res, _ = _run(r, base, head, monkeypatch, {},
                  Driver(RunnerResult(tool="python", state=ToolState.OK, raw="{}",
                                      stderr="  " + "e" * 150 + "\n", returncode=1)))

    assert res.state == "degraded"
    assert res.note == f"fuzz driver broken @ {head[:12]}: " + "e" * 100
    assert res.extra == {**ZERO, "functions_seen": 1} and res.repaired is None


def test_a_driver_that_crashed_at_rc_0_is_still_broken(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})

    res, _ = _run(r, base, head, monkeypatch, {},
                  Driver(RunnerResult(tool="python", state=ToolState.CRASHED, raw="{}",
                                      stderr="Killed", returncode=0)))

    assert (res.state, res.note) == ("degraded", f"fuzz driver broken @ {head[:12]}: Killed")


def test_a_driver_whose_output_does_not_parse_is_broken(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})

    res, _ = _run(r, base, head, monkeypatch, {},
                  Driver(RunnerResult(tool="python", state=ToolState.OK, raw="not json",
                                      returncode=0)))

    assert (res.state, res.note) == ("degraded",
                                     f"fuzz driver broken @ {head[:12]}: no parseable output")


def test_three_broken_notes_at_this_head_give_up_before_git_is_asked(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})
    _seed_notes(r, 3, f"fuzz driver broken @ {head[:12]}: whatever")
    monkeypatch.setattr(fc.gitutil, "diff_new_lines",
                        lambda *a: (_ for _ in ()).throw(AssertionError("git was asked")))

    res, driver = _run(r, base, head, monkeypatch, {})

    assert (res.state, res.note) == ("ok", "fuzz giving up: driver persistently broken")
    assert driver.calls == []


def test_a_config_with_no_fuzz_table_still_reads_the_give_up_counter(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})
    _seed_notes(r, 3, f"fuzz driver broken @ {head[:12]}: whatever")

    res, _ = _run(r, base, head, monkeypatch, None)

    assert res.note == "fuzz giving up: driver persistently broken"


def test_two_broken_notes_or_notes_at_another_head_do_not_give_up(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})
    _seed_notes(r, 2, f"fuzz driver broken @ {head[:12]}: whatever")
    _seed_notes(r, 3, f"fuzz driver broken @ {'f' * 12}: whatever")

    res, driver = _run(r, base, head, monkeypatch, {})

    assert res.state == "ok" and len(driver.calls) == 1


def test_a_worktree_that_cannot_be_added_is_an_error_with_200_chars_of_stderr(
        tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})
    real = fc.gitutil._run

    def failing(root, *args, **kw):
        if args[:2] == ("worktree", "add"):
            return subprocess.CompletedProcess(args, 1, stdout="", stderr=" " + "x" * 250)
        return real(root, *args, **kw)
    monkeypatch.setattr(fc.gitutil, "_run", failing)

    res, driver = _run(r, base, head, monkeypatch, {})

    assert (res.state, res.note) == ("error", "worktree add failed: " + "x" * 200)
    assert driver.calls == []


def test_a_worktree_failure_with_no_stderr_still_reads(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})
    real = fc.gitutil._run

    def failing(root, *args, **kw):
        if args[:2] == ("worktree", "add"):
            return subprocess.CompletedProcess(args, 128, stdout="", stderr=None)
        return real(root, *args, **kw)
    monkeypatch.setattr(fc.gitutil, "_run", failing)

    res, _ = _run(r, base, head, monkeypatch, {})

    assert res.note == "worktree add failed: "


# ------------------------------------------------------------- records --

CRASH = {"file": "lib.py", "func": "f", "exc": "ZeroDivisionError", "msg": "division by zero",
         "args_repr": "x=0", "line": 2}


def test_records_become_findings_and_the_counters_read_the_verdict(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f", "g"]), "bad.py": _fns(["h"])})
    out = {"cases_run": 150, "crashes": 1, "contract_exceptions": 4, "unfuzzable": 1,
           "import_failures": ["bad.py"], "import_errors": {"bad.py": "ModuleNotFoundError"},
           "records": [CRASH, {"file": "lib.py", "func": "g", "exc": "KeyError", "msg": "k"}],
           "fuzzed": [["lib.py", "f"]]}

    res, _ = _run(r, base, head, monkeypatch, {}, Driver(out))

    assert res.state == "ok"
    assert res.note == ("2 crash finding(s) from 150 case(s) over 1 function(s); "
                        "1 skipped (unhinted)")
    assert res.extra == {**ZERO, "functions_seen": 3, "functions_fuzzed": 1, "cases_run": 150,
                         "crashes": 1, "contract_exceptions": 4, "skipped_unhinted": 1,
                         "import_failures": 1, "import_failed": {"bad.py": "ModuleNotFoundError"},
                         "findings": 2}
    assert [(f.tool, f.rule, f.severity_raw, f.file, f.line, f.message) for f in res.findings] == [
        ("fuzz", "crash-zerodivisionerror", "medium", "lib.py", 2,
         "fuzz crash: f(x=0) raised ZeroDivisionError: division by zero"),
        ("fuzz", "crash-keyerror", "medium", "lib.py", 1, "fuzz crash: g() raised KeyError: k")]
    assert res.repaired is None


def test_a_verdict_with_nothing_in_it_reads_as_zeros(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})

    res, _ = _run(r, base, head, monkeypatch, {}, Driver({}))

    assert res.note == "0 crash finding(s) from 0 case(s) over 1 function(s)"
    assert res.extra == {**ZERO, "functions_seen": 1, "functions_fuzzed": 1, "import_failed": {}}


# -------------------------------------------------------------- claims --

def test_an_open_crash_whose_function_was_fuzzed_clean_is_claimed(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f", "g"])})
    fid = _fid(r, "lib.py", 2)
    _seed_open(r, fid, "lib.py", "fuzz crash: f(x=0) raised ZeroDivisionError: division by zero")

    res, _ = _run(r, base, head, monkeypatch, {}, Driver({"fuzzed": [["lib.py", "f"]]}))

    assert res.repaired is not None
    assert (res.repaired.tool, res.repaired.reason, res.repaired.ids) == (
        "fuzz", "crash_not_reproduced", (fid,))


def test_a_crash_that_still_reproduces_is_not_claimed(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})
    fid = _fid(r, "lib.py", 2)
    _seed_open(r, fid, "lib.py", "fuzz crash: f(x=0) raised ZeroDivisionError: division by zero")

    res, _ = _run(r, base, head, monkeypatch, {},
                  Driver({"records": [CRASH], "fuzzed": [["lib.py", "f"]]}))

    assert [f.file for f in res.findings] == ["lib.py"]
    assert res.repaired is None


def test_a_crash_in_a_function_the_driver_did_not_fuzz_stays_open(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f", "g"])})
    fid = _fid(r, "lib.py", 2)
    _seed_open(r, fid, "lib.py", "fuzz crash: f(x=0) raised ZeroDivisionError: division by zero")

    res, _ = _run(r, base, head, monkeypatch, {}, Driver({"fuzzed": [["lib.py", "g"]]}))

    assert res.repaired is None


def test_only_well_formed_fuzzed_pairs_count(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f", "g"])})
    fid = _fid(r, "lib.py", 2)
    _seed_open(r, fid, "lib.py", "fuzz crash: f(x=0) raised ZeroDivisionError: division by zero")

    res, _ = _run(r, base, head, monkeypatch, {},
                  Driver({"fuzzed": [["lib.py", "f", "extra"], {"file": "lib.py", "function": "f"},
                                     "lib.py", ["lib.py"]]}))

    assert res.repaired is None, "a triple, a dict, a string and a single are not (file, func)"


def test_a_pair_is_file_then_function(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, {"lib.py": _fns(["f"])})
    fid = _fid(r, "lib.py", 2)
    _seed_open(r, fid, "lib.py", "fuzz crash: f(x=0) raised ZeroDivisionError: division by zero")

    res, _ = _run(r, base, head, monkeypatch, {}, Driver({"fuzzed": [["f", "lib.py"]]}))

    assert res.repaired is None


def test_candidate_functions_on_unparseable_source_is_empty_with_zero_skips():
    """The drain confirms a mutant against the unit suite alone, and the
    SyntaxError exit's `[], 0, 0` was reached only through tests/integration."""
    assert fc._candidate_functions("def broken(:\n", {1}, []) == ([], 0, 0)
    assert fc._candidate_functions("def ok(a: int):\n    return a\n", {1, 2}, []) \
        == (["ok"], 0, 0)


def test_candidate_functions_span_is_the_def_through_its_last_line_only():
    """A change inside the body (not on the def line) selects the function
    -- the span is `lineno..end_lineno` (the derive drew `end_lineno or
    lineno` -> `and`, which shrinks it to the def line); a change on the line
    right after the function does not (`end + 1` -> `end + 2` would)."""
    src = "def f(a: int):\n    return a\n\ndef g(b: int):\n    return b\n"
    assert fc._candidate_functions(src, {2}, []) == (["f"], 0, 0)
    assert fc._candidate_functions(src, {3}, []) == ([], 0, 0)
    assert fc._candidate_functions(src, {5}, []) == (["g"], 0, 0)
