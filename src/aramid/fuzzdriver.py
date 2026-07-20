"""fuzzdriver -- runs INSIDE the throwaway worktree (invoked as
`python -m aramid.fuzzdriver <spec.json>` with cwd=worktree). Imports each
target module from the worktree, calls the named diff-touched functions with
seeded hint-derived inputs, and records DEEP-CRASH exceptions only. Contract
exceptions (TypeError/ValueError/SystemExit/repo-defined) are counted, never
recorded. Emits one JSON result object to stdout and exits 0; any internal
failure exits nonzero so the consumer counts the batch as errored rather
than trusting partial output.

The consumer never trusts this process with anything but a subprocess
boundary: a hung target is killed by the consumer's run_subprocess timeout."""
import importlib.util
import json
import random
import sys
import traceback
import typing
from pathlib import Path

from aramid import fuzzgen

# Deep-crash oracle (spec section 1): builtin almost-always-a-bug exceptions.
ALLOWLIST = (IndexError, KeyError, ZeroDivisionError, AttributeError,
             UnboundLocalError, RecursionError, UnicodeError, OverflowError)


def _load_module(root: Path, rel: str):
    """Import the target file as a standalone module via its absolute path.
    spec_from_file_location sidesteps package-dottedness entirely -- robust
    for the flat/one-off modules a diff usually touches; a module doing
    package-relative imports may fail here and is counted as import_failure."""
    abs_path = (root / rel).resolve()
    mod_name = "aramid_fuzz_target_" + rel.replace("/", "_").replace("\\", "_").replace(".", "_")
    spec = importlib.util.spec_from_file_location(mod_name, abs_path)
    if spec is None or spec.loader is None:
        raise ImportError(rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module, str(abs_path)


def run_spec(spec: dict) -> dict:
    root = Path(spec["root"])
    records, seen = [], set()
    cases_run = crashes = contract = unfuzzable = 0
    import_failures = []

    for target in spec.get("targets", []):
        rel = target["file"]
        cases = int(target.get("cases", 50))
        try:
            module, abs_path = _load_module(root, rel)
        except Exception:
            import_failures.append(rel)
            continue
        for func_name in target.get("functions", []):
            fn = getattr(module, func_name, None)
            if fn is None or not callable(fn):
                unfuzzable += 1
                continue
            params = fuzzgen.supported_params(fn)
            if params is None:
                unfuzzable += 1
                continue
            hints = typing.get_type_hints(fn)
            for i in range(cases):
                rng = random.Random(fuzzgen.case_seed(rel, func_name, i))
                kwargs = {p: fuzzgen.gen_value(hints.get(p), rng) for p in params}
                cases_run += 1
                try:
                    fn(**kwargs)
                except KeyboardInterrupt:
                    raise
                except ALLOWLIST as exc:
                    crashes += 1
                    key = (rel, func_name, type(exc).__name__)
                    if key in seen:
                        continue
                    seen.add(key)
                    records.append({
                        "func": func_name, "file": rel, "case": i,
                        "exc": type(exc).__name__,
                        "msg": str(exc)[:200],
                        "args_repr": repr(kwargs)[:100],
                        "line": _crash_line(exc, abs_path, fn),
                    })
                except BaseException:  # noqa: BLE001 -- contract, incl. SystemExit
                    contract += 1
    return {"records": records, "cases_run": cases_run, "crashes": crashes,
            "contract_exceptions": contract, "unfuzzable": unfuzzable,
            "import_failures": import_failures}


def _crash_line(exc, abs_path: str, fn) -> int:
    tb = exc.__traceback__
    line = getattr(getattr(fn, "__code__", None), "co_firstlineno", 1)
    for frame, lineno in traceback.walk_tb(tb):
        if frame.f_code.co_filename == abs_path:
            line = lineno
    return line


def main(argv):
    try:
        spec = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
        out = run_spec(spec)
    except Exception as exc:  # noqa: BLE001
        print(f"fuzzdriver: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
