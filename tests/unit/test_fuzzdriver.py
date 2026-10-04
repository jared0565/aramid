import json
import subprocess
import sys
import textwrap

from aramid.fuzzdriver import ALLOWLIST, main, run_spec


def _module(tmp_path, name, body):
    p = tmp_path / f"{name}.py"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def _spec(tmp_path, rel, funcs, cases=30):
    return {"root": str(tmp_path),
            "targets": [{"file": rel, "functions": funcs, "cases": cases}]}


def test_allowlist_is_deep_crash_set():
    assert IndexError in ALLOWLIST and KeyError in ALLOWLIST
    assert ValueError not in ALLOWLIST and TypeError not in ALLOWLIST


def test_seeded_indexerror_is_recorded(tmp_path):
    _module(tmp_path, "buggy", """
        def head(xs: list[int]) -> int:
            return xs[0]   # IndexError on []
    """)
    out = run_spec(_spec(tmp_path, "buggy.py", ["head"]))
    assert out["crashes"] >= 1
    rec = next(r for r in out["records"] if r["func"] == "head")
    assert rec["exc"] == "IndexError"
    assert rec["file"] == "buggy.py"
    assert rec["line"] >= 1


def test_contract_valueerror_not_recorded(tmp_path):
    _module(tmp_path, "safe", """
        def validate(a: int) -> int:
            if a < 0:
                raise ValueError("must be non-negative")
            return a
    """)
    out = run_spec(_spec(tmp_path, "safe.py", ["validate"]))
    assert out["records"] == []
    assert out["contract_exceptions"] >= 1


def test_custom_exception_not_recorded(tmp_path):
    _module(tmp_path, "cust", """
        class MyError(Exception):
            pass
        def go(a: int) -> int:
            raise MyError("nope")
    """)
    out = run_spec(_spec(tmp_path, "cust.py", ["go"]))
    assert out["records"] == []
    assert out["contract_exceptions"] >= 1


def test_dedupe_one_record_per_func_exc(tmp_path):
    _module(tmp_path, "dd", """
        def boom(a: int) -> int:
            return [][a]   # IndexError for every input
    """)
    out = run_spec(_spec(tmp_path, "dd.py", ["boom"], cases=20))
    idx = [r for r in out["records"] if r["exc"] == "IndexError"]
    assert len(idx) == 1
    assert out["crashes"] >= 1


def test_import_failure_counted(tmp_path):
    _module(tmp_path, "broken", "this is not valid python :\n")
    out = run_spec(_spec(tmp_path, "broken.py", ["whatever"]))
    assert "broken.py" in out["import_failures"]


def test_unfuzzable_function_skipped(tmp_path):
    _module(tmp_path, "mix", """
        def unhinted(a):
            return a
    """)
    out = run_spec(_spec(tmp_path, "mix.py", ["unhinted"]))
    assert out["records"] == [] and out["cases_run"] == 0
    assert out["unfuzzable"] >= 1


def test_poison_annotation_does_not_abort_batch(tmp_path):
    # An unhashable annotation makes supported_params' `hint in SUPPORTED_ATOMS`
    # hash() raise -- it must be swallowed to None, not propagate out of the
    # batch and discard head's genuine IndexError finding.
    _module(tmp_path, "mix2", """
        def head(xs: list[int]) -> int:
            return xs[0]
        def poison(a: {1: 2}) -> int:
            return a
    """)
    out = run_spec(_spec(tmp_path, "mix2.py", ["head", "poison"]))
    assert any(r["func"] == "head" and r["exc"] == "IndexError"
               for r in out["records"]), "sibling finding must survive a poison peer"
    assert out["unfuzzable"] >= 1  # poison counted skipped, not crashed


def test_systemexit_is_contract_not_crash(tmp_path):
    _module(tmp_path, "cli", """
        import sys
        def run(a: int) -> int:
            sys.exit(2)
    """)
    out = run_spec(_spec(tmp_path, "cli.py", ["run"]))
    assert out["records"] == []


def test_subprocess_entrypoint_emits_json(tmp_path):
    _module(tmp_path, "buggy2", """
        def head(xs: list[int]) -> int:
            return xs[0]
    """)
    spec = _spec(tmp_path, "buggy2.py", ["head"])
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    cp = subprocess.run([sys.executable, "-m", "aramid.fuzzdriver", str(spec_path)],
                        cwd=tmp_path, capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    out = json.loads(cp.stdout)
    assert out["crashes"] >= 1



def test_run_spec_records_where_it_is_before_each_call(tmp_path):
    """Interop round 155 s2: the driver prints once, at the end, so a kill at
    the budget discards everything and the consumer cannot say which function
    it was in. With a `progress` path in the spec it writes its position before
    every call; a timeout leaves the last one behind."""
    _module(tmp_path, "m", """
        def f(x: int) -> int:
            return x

        def g(y: str) -> str:
            return y
    """)
    spec = _spec(tmp_path, "m.py", ["f", "g"], cases=3)
    spec["progress"] = str(tmp_path / "progress.json")

    run_spec(spec)

    progress = json.loads((tmp_path / "progress.json").read_text(encoding="utf-8"))
    assert progress == {"file": "m.py", "function": "g", "functions_started": 2}


# --- the in-process entrypoint and the two silent skips ---------------------
#
# The drain confirms a mutant against the unit suite alone; `main` was reached
# only through the subprocess arm above (a child process cannot carry a
# mutant verdict back), and the missing-function skip only through
# tests/integration/test_fuzz_consumer.py.

def test_main_prints_the_verdict_as_json_and_exits_0(tmp_path, capsys):
    _module(tmp_path, "okmod", """
        def f(a: int) -> int:
            return a
    """)
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_spec(tmp_path, "okmod.py", ["f"], cases=3)),
                         encoding="utf-8")

    assert main([str(spec_path)]) == 0
    out, err = capsys.readouterr()
    assert err == ""
    verdict = json.loads(out)
    assert verdict["cases_run"] == 3 and verdict["fuzzed"] == [["okmod.py", "f"]]


# --- a target that writes to stdout must not corrupt the verdict ------------
#
# The verdict is ONE JSON object on the driver's stdout, and the targets run in
# the same process. promote_live.main() (fuzzed as a zero-argument function at
# 645617b) printed "live now: ..." before it, three drains read "no parseable
# output", and the consumer stood down (fleet notice 4b572e60a018). A child
# process the target launches inherits the same stdout, so redirecting only
# sys.stdout is not enough -- the child arm is the one that tells them apart.

def _run_driver_from_source(tmp_path, spec):
    """The driver under test, not the installed wheel: a child does not inherit
    pytest's pythonpath, so the source dir is pinned explicitly and checked."""
    import os
    from pathlib import Path

    import aramid
    src = Path(aramid.__file__).resolve().parents[1]
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(src)}
    which = subprocess.run(
        [sys.executable, "-c", "import aramid.fuzzdriver as d; print(d.__file__)"],
        cwd=tmp_path, capture_output=True, text=True, env=env)
    assert Path(which.stdout.strip()).resolve().parents[1] == src, which
    return subprocess.run([sys.executable, "-m", "aramid.fuzzdriver", str(spec_path)],
                          cwd=tmp_path, capture_output=True, text=True, env=env)


def test_a_quiet_target_leaves_stdout_as_the_verdict_alone(tmp_path):
    _module(tmp_path, "quiet", """
        def f(a: int) -> int:
            return a
    """)
    cp = _run_driver_from_source(tmp_path, _spec(tmp_path, "quiet.py", ["f"], cases=3))
    assert cp.returncode == 0, cp.stderr
    assert json.loads(cp.stdout)["cases_run"] == 3


def test_a_target_that_prints_does_not_corrupt_the_verdict(tmp_path):
    _module(tmp_path, "chatty", """
        def f(a: int) -> int:
            print("chatty says hi")
            return a
    """)
    cp = _run_driver_from_source(tmp_path, _spec(tmp_path, "chatty.py", ["f"], cases=3))
    assert cp.returncode == 0, cp.stderr
    assert json.loads(cp.stdout)["cases_run"] == 3
    assert "chatty says hi" in cp.stderr, "the target's output is moved, not lost"


def test_a_child_process_writing_to_stdout_does_not_corrupt_the_verdict(tmp_path):
    _module(tmp_path, "spawner", """
        import subprocess
        import sys
        def f(a: int) -> int:
            subprocess.run([sys.executable, "-c", "print('child-noise')"])
            return a
    """)
    cp = _run_driver_from_source(tmp_path, _spec(tmp_path, "spawner.py", ["f"], cases=2))
    assert cp.returncode == 0, cp.stderr
    assert json.loads(cp.stdout)["cases_run"] == 2
    assert "child-noise" in cp.stderr


def test_main_in_process_keeps_a_printing_target_off_the_verdict(tmp_path, capsys):
    _module(tmp_path, "chatty2", """
        def f(a: int) -> int:
            print("in-process chatter")
            return a
    """)
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_spec(tmp_path, "chatty2.py", ["f"], cases=2)),
                         encoding="utf-8")

    assert main([str(spec_path)]) == 0
    out, err = capsys.readouterr()
    assert json.loads(out)["cases_run"] == 2
    assert "in-process chatter" in err


def test_a_function_with_no_parameters_is_counted_unfuzzable_and_never_called(tmp_path):
    marker = tmp_path / "called.txt"
    _module(tmp_path, "entry", f"""
        from pathlib import Path
        def main() -> int:
            Path({str(marker)!r}).write_text("called", encoding="utf-8")
            return 0
    """)
    out = run_spec(_spec(tmp_path, "entry.py", ["main"], cases=5))
    assert out["unfuzzable"] == 1 and out["cases_run"] == 0 and out["fuzzed"] == []
    assert not marker.exists(), "a zero-parameter target must not be called at all"


def test_main_reports_a_bad_spec_on_stderr_and_exits_1(tmp_path, capsys):
    assert main([str(tmp_path / "missing.json")]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("fuzzdriver: ") and "missing.json" in err

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main([str(bad)]) == 1
    assert capsys.readouterr().err.startswith("fuzzdriver: Expecting property name")


def test_missing_and_uncallable_functions_each_count_once_as_unfuzzable(tmp_path):
    _module(tmp_path, "sparse", """
        CONSTANT = 3

        def real(a: int) -> int:
            return a
    """)
    out = run_spec(_spec(tmp_path, "sparse.py", ["nope", "CONSTANT", "real"], cases=2))
    assert out["unfuzzable"] == 2
    assert out["fuzzed"] == [["sparse.py", "real"]]
    assert out["cases_run"] == 2


def test_a_crash_record_caps_its_message_at_200_and_its_args_at_100_characters(tmp_path):
    """Both caps sat on lines the unit suite executed but never bounded: a
    short message and a short repr pass under any cap. Thirty int params
    make the kwargs repr long enough to cut; the message is cut mid-run."""
    params = ", ".join(f"p{i}: int" for i in range(30))
    _module(tmp_path, "wide", f"""
        def boom({params}) -> int:
            raise IndexError("m" * 300)
    """)
    out = run_spec(_spec(tmp_path, "wide.py", ["boom"], cases=1))
    (rec,) = out["records"]
    assert rec["msg"] == "m" * 200
    assert len(rec["args_repr"]) == 100 and rec["args_repr"].startswith("{'p0': ")


def test_every_contract_exception_is_counted_once(tmp_path):
    _module(tmp_path, "cli", """
        import sys
        def run(a: int) -> int:
            sys.exit(2)
        def bad(a: int) -> int:
            raise ValueError("no")
    """)
    out = run_spec(_spec(tmp_path, "cli.py", ["run", "bad"], cases=3))
    assert (out["contract_exceptions"], out["crashes"], out["records"]) == (6, 0, [])


def test_run_spec_defaults_to_fifty_cases_and_counts_each_crash_and_unsupported_signature(
        tmp_path):
    _module(tmp_path, "shapes", """
        def fine(a: int) -> int:
            return a
        def odd(a: int, b: "NoSuchType") -> int:
            return a
        def boom(a: int) -> int:
            return [][a]
    """)
    spec = {"root": str(tmp_path), "targets": [{"file": "shapes.py", "functions": ["fine"]}]}
    assert run_spec(spec)["cases_run"] == 50, "no `cases` in the target: fifty"
    out = run_spec(_spec(tmp_path, "shapes.py", ["odd", "boom"], cases=1))
    assert out["unfuzzable"] == 1, "an unsupported signature is one unfuzzable function"
    assert out["fuzzed"] == [["shapes.py", "boom"]]
    assert out["crashes"] == 1 and len(out["records"]) == 1


_BUDGET_MODULE = """
    def bare(a):
        return a
    def one(a: int) -> int:
        return a
    def also_bare(b):
        return b
    def two(a: int) -> int:
        return a
"""


def test_the_budget_is_charged_only_on_functions_the_driver_calls(tmp_path):
    """FN-3: a real row read `functions_seen 10, functions_fuzzed 0,
    skipped_unhinted 10, truncated True` -- the budget went on candidates
    the driver could not call. An unhinted one costs nothing now."""
    _module(tmp_path, "mix", _BUDGET_MODULE)
    spec = {**_spec(tmp_path, "mix.py", ["bare", "one", "also_bare", "two"], cases=1),
            "max_functions": 2}
    out = run_spec(spec)
    assert out["fuzzed"] == [["mix.py", "one"], ["mix.py", "two"]]
    assert (out["unfuzzable"], out["over_budget"]) == (2, 0), "an exact fit leaves nothing over"


def test_a_callable_function_past_the_budget_is_counted_over_budget(tmp_path):
    _module(tmp_path, "mix", _BUDGET_MODULE)
    spec = {**_spec(tmp_path, "mix.py", ["one", "bare", "two"], cases=1), "max_functions": 1}
    out = run_spec(spec)
    assert out["fuzzed"] == [["mix.py", "one"]]
    assert (out["unfuzzable"], out["over_budget"], out["cases_run"]) == (1, 1, 1)


def test_a_spec_without_a_budget_fuzzes_everything_it_can(tmp_path):
    _module(tmp_path, "mix", _BUDGET_MODULE)
    out = run_spec(_spec(tmp_path, "mix.py", ["one", "two"], cases=1))
    assert len(out["fuzzed"]) == 2 and out["over_budget"] == 0


def test_an_import_error_is_recorded_with_200_characters_of_its_message(tmp_path):
    _module(tmp_path, "loud", """
        raise RuntimeError("x" * 300)
    """)
    out = run_spec(_spec(tmp_path, "loud.py", ["f"]))
    assert out["import_failures"] == ["loud.py"]
    assert out["import_errors"] == {"loud.py": ("RuntimeError: " + "x" * 300)[:200]}
