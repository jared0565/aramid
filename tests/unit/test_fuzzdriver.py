import json
import subprocess
import sys
import textwrap

from aramid.fuzzdriver import ALLOWLIST, run_spec


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
