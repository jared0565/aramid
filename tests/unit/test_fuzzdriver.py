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


def test_an_import_error_is_recorded_with_200_characters_of_its_message(tmp_path):
    _module(tmp_path, "loud", """
        raise RuntimeError("x" * 300)
    """)
    out = run_spec(_spec(tmp_path, "loud.py", ["f"]))
    assert out["import_failures"] == ["loud.py"]
    assert out["import_errors"] == {"loud.py": ("RuntimeError: " + "x" * 300)[:200]}
