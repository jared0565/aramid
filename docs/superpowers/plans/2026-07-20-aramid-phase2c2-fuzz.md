# Phase 2c-2 Fuzz Consumer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A drain-time `fuzz` consumer that calls diff-touched, type-hinted top-level Python functions with deterministic seeded inputs inside a throwaway worktree and reports deep-crash exceptions as WARN-tier findings.

**Architecture:** An owned stdlib generator (`fuzzgen.py`, hint→value) + a subprocess driver (`fuzzdriver.py`, runs inside the worktree, imports targets, calls with seeded inputs, emits JSON crash records) + a consumer (`consumers/fuzz.py`, scopes the diff, spawns the driver in a worktree, turns records into findings). Same chassis, worktree pattern, and OK/DEGRADED/ERROR state discipline as 2c-1.

**Tech Stack:** Python 3.14 stdlib only (`ast`, `random`, `hashlib`, `typing`, `importlib`, `traceback`, `json`, `tempfile`). Spec: `docs/superpowers/specs/2026-07-20-aramid-phase2c2-fuzz-design.md`.

## Global Constraints

- Branch: `feat/phase2c2-fuzz` off `main` (create in Task 1, Step 1). One commit per task.
- Tests run via `python -m pytest`; the driver is invoked as `[sys.executable, "-m", "aramid.fuzzdriver", <spec.json>]` with `cwd=worktree` (PATH-independent, and `-m` puts cwd on `sys.path[0]` so worktree modules import).
- Invariant 1 (spec section 6): nothing writes to `ctx.root`'s working tree; all execution in the throwaway worktree, removal in a guarded `finally` (copy 2c-1's pattern verbatim).
- Invariant 2: gate untouched — no `pipeline.py`/`policy.py`/`hooks.py`/`check.py` changes.
- Invariant 3: WARN-only — no fuzz entry in `block_rules.toml`; asserted by test.
- Invariant 4: determinism — `case_seed(file, func, index)` is content-only (sha256), never wall-clock/host dependent.
- Invariant 5: contract & repo-defined exceptions never become findings; one finding per (function, exc type).
- State discipline (2c-1 amendment, binding): permanent absence → OK + loud note (never DEGRADED — DEGRADED pins queue items); transient worktree-add failure → ERROR; batch timeout → OK with `timeouts` counted.
- Ruff: no NEW findings vs the Task-1 baseline. Full suite green at end (719 at current main).

---

### Task 1: Generator — `src/aramid/fuzzgen.py`

**Files:**
- Create: `src/aramid/fuzzgen.py`
- Test: `tests/unit/test_fuzzgen.py` (new)

**Interfaces:**
- Produces: `supported_params(fn) -> list[str] | None`; `gen_value(hint, rng, depth=0) -> object`; `case_seed(file: str, func: str, index: int) -> int`; `SUPPORTED_ATOMS` (a set of atom types, for the driver's introspection).

- [ ] **Step 1: Create the branch, record ruff baseline**

```bash
git checkout -b feat/phase2c2-fuzz
python -m ruff check src tests | tail -1   # record the count (expect 43)
```

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/test_fuzzgen.py`:

```python
import random
from typing import Optional

from aramid.fuzzgen import case_seed, gen_value, supported_params


def _rng():
    return random.Random(1234)


def test_supported_params_all_hinted():
    def f(a: int, b: str, c: list[int]) -> bool:
        return True
    assert supported_params(f) == ["a", "b", "c"]


def test_supported_params_none_when_unhinted():
    def f(a, b: int):
        return a
    assert supported_params(f) is None


def test_supported_params_none_on_unsupported_hint():
    class Weird:
        pass

    def f(a: Weird):
        return a
    assert supported_params(f) is None


def test_supported_params_none_on_varargs():
    def f(a: int, *args: int):
        return a
    assert supported_params(f) is None


def test_supported_params_optional_ok():
    def f(a: Optional[int]) -> int:
        return a or 0
    assert supported_params(f) == ["a"]


def test_gen_value_types():
    rng = _rng()
    assert isinstance(gen_value(int, rng), int)
    assert isinstance(gen_value(str, rng), str)
    assert isinstance(gen_value(bytes, rng), bytes)
    assert isinstance(gen_value(bool, rng), bool)
    got = gen_value(list[int], rng)
    assert isinstance(got, list) and all(isinstance(x, int) for x in got)
    d = gen_value(dict[str, int], rng)
    assert isinstance(d, dict)


def test_gen_value_optional_can_be_none_and_value():
    seen_none = seen_val = False
    for i in range(50):
        v = gen_value(Optional[int], random.Random(i))
        seen_none |= v is None
        seen_val |= isinstance(v, int)
    assert seen_none and seen_val


def test_gen_value_special_floats_appear():
    import math
    seen = set()
    for i in range(200):
        v = gen_value(float, random.Random(i))
        if math.isnan(v):
            seen.add("nan")
        elif math.isinf(v):
            seen.add("inf")
        elif v == 0.0:
            seen.add("zero")
    assert {"nan", "inf", "zero"} <= seen


def test_case_seed_deterministic_and_varies():
    assert case_seed("a.py", "f", 0) == case_seed("a.py", "f", 0)
    assert case_seed("a.py", "f", 0) != case_seed("a.py", "f", 1)
    assert case_seed("a.py", "f", 0) != case_seed("b.py", "f", 0)


def test_gen_value_depth_capped():
    # deeply nested container hint must terminate, not recurse forever
    v = gen_value(list[list[list[list[int]]]], _rng())
    assert isinstance(v, list)
```

- [ ] **Step 3: Run to verify failure**

```
python -m pytest tests/unit/test_fuzzgen.py -q
```

Expected: ImportError — `aramid.fuzzgen` does not exist.

- [ ] **Step 4: Implement `src/aramid/fuzzgen.py`**

```python
"""fuzzgen -- owned stdlib input generator for the fuzz consumer (Phase
2c-2 spec section 2). Type-hint-driven, seeded, deterministic: the same
(file, func, case index) always yields the same input, so a crash's seed
IS its repro and fingerprints are stable across drains."""
import hashlib
import random
import typing
from types import NoneType

SUPPORTED_ATOMS = {int, float, str, bytes, bool, NoneType}
_MAX_DEPTH = 3
_MAX_LEN = 5

_BIG = 2 ** 63
_STRS = ["", "a", "0", " ", "\n", "\x00", "é", "🙂", "../../etc", "%s%n",
         "A" * 64]
_BYTES = [b"", b"\x00", b"\xff\xfe", b"ABC", b"\x00" * 16]


def case_seed(file: str, func: str, index: int) -> int:
    digest = hashlib.sha256(f"{file}:{func}:{index}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _origin_args(hint):
    return typing.get_origin(hint), typing.get_args(hint)


def _is_supported(hint) -> bool:
    if hint in SUPPORTED_ATOMS or hint is None:
        return True
    origin, args = _origin_args(hint)
    if origin in (list, set, frozenset):
        return len(args) == 1 and _is_supported(args[0])
    if origin is dict:
        return len(args) == 2 and all(_is_supported(a) for a in args)
    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            return _is_supported(args[0])
        return all(_is_supported(a) for a in args)
    if origin is typing.Union:
        return all(a is NoneType or _is_supported(a) for a in args)
    return False


def supported_params(fn):
    """Param names when EVERY parameter has a supported hint and there is no
    *args/**kwargs; None otherwise (including when hint resolution raises)."""
    import inspect
    try:
        sig = inspect.signature(fn)
        hints = typing.get_type_hints(fn)
    except Exception:
        return None
    names = []
    for name, p in sig.parameters.items():
        if p.kind in (inspect.Parameter.VAR_POSITIONAL,
                      inspect.Parameter.VAR_KEYWORD):
            return None
        hint = hints.get(name)
        if hint is None or not _is_supported(hint):
            return None
        names.append(name)
    return names


def gen_value(hint, rng: random.Random, depth: int = 0):
    if hint is None or hint is NoneType:
        return None
    if hint is bool:
        return rng.random() < 0.5
    if hint is int:
        return rng.choice([0, 1, -1, 2, -2, _BIG, -_BIG, rng.randint(-9999, 9999)])
    if hint is float:
        return rng.choice([0.0, -0.0, 1.5, -1.5, float("inf"), float("-inf"),
                           float("nan"), rng.uniform(-1e6, 1e6)])
    if hint is str:
        return rng.choice(_STRS)
    if hint is bytes:
        return rng.choice(_BYTES)

    origin, args = _origin_args(hint)
    if origin is typing.Union:
        return gen_value(rng.choice(args), rng, depth)
    if depth >= _MAX_DEPTH:
        return None
    if origin in (list, set, frozenset):
        vals = [gen_value(args[0], rng, depth + 1)
                for _ in range(rng.randint(0, _MAX_LEN))]
        return vals if origin is list else origin(
            v for v in vals if _hashable(v))
    if origin is dict:
        out = {}
        for _ in range(rng.randint(0, _MAX_LEN)):
            k = gen_value(args[0], rng, depth + 1)
            if _hashable(k):
                out[k] = gen_value(args[1], rng, depth + 1)
        return out
    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(gen_value(args[0], rng, depth + 1)
                         for _ in range(rng.randint(0, _MAX_LEN)))
        return tuple(gen_value(a, rng, depth + 1) for a in args)
    return None


def _hashable(v) -> bool:
    try:
        hash(v)
        return True
    except TypeError:
        return False
```

- [ ] **Step 5: Run to verify pass**

```
python -m pytest tests/unit/test_fuzzgen.py -q
```

Expected: 10 passed.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(fuzzgen): owned stdlib hint-driven seeded input generator"
```

---

### Task 2: Driver — `src/aramid/fuzzdriver.py`

**Files:**
- Create: `src/aramid/fuzzdriver.py`
- Test: `tests/unit/test_fuzzdriver.py` (new)

**Interfaces:**
- Consumes: `fuzzgen.supported_params`/`gen_value`/`case_seed` (Task 1).
- Produces: a `__main__` entrypoint reading a spec-JSON path from argv, emitting one JSON result object to stdout. Public helper `run_spec(spec: dict) -> dict` (unit-tested directly, not just via subprocess). Result keys: `records`, `cases_run`, `crashes`, `contract_exceptions`, `import_failures`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_fuzzdriver.py`:

```python
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
```

- [ ] **Step 2: Run to verify failure**

```
python -m pytest tests/unit/test_fuzzdriver.py -q
```

Expected: ImportError — `aramid.fuzzdriver` does not exist.

- [ ] **Step 3: Implement `src/aramid/fuzzdriver.py`**

```python
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
```

- [ ] **Step 4: Run to verify pass**

```
python -m pytest tests/unit/test_fuzzdriver.py -q
```

Expected: 9 passed. (The subprocess test imports `aramid` from the installed
package while cwd is a tmp dir — works because aramid is pip-installed editable.)

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(fuzzdriver): worktree subprocess driver, deep-crash oracle, dedupe"
```

---

### Task 3: `[fuzz]` config section

**Files:**
- Modify: `src/aramid/data/defaults.toml` (append section)
- Modify: `src/aramid/config.py` (Config field + load_config wiring)
- Test: `tests/unit/test_config.py`

**Interfaces:**
- Produces: `cfg.fuzz: dict` with `enabled`, `max_functions`, `cases_per_function`, `wall_budget_s`, `batch_timeout_s`, `skip_name_patterns`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_config.py` (reuse the file's `_no_user_config` helper, exactly as the `[mutation]` tests do):

```python
def test_fuzz_defaults_present(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    cfg = config.load_config(tmp_path)
    assert cfg.fuzz["enabled"] is True
    assert cfg.fuzz["max_functions"] == 10
    assert cfg.fuzz["cases_per_function"] == 50
    assert cfg.fuzz["batch_timeout_s"] == 120
    assert "*deploy*" in cfg.fuzz["skip_name_patterns"]


def test_fuzz_repo_override_merges(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    (tmp_path / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 3\n", encoding="utf-8")
    cfg = config.load_config(tmp_path)
    assert cfg.fuzz["max_functions"] == 3
    assert cfg.fuzz["enabled"] is True  # deep-merge keeps defaults
```

- [ ] **Step 2: Run to verify failure**

```
python -m pytest tests/unit/test_config.py -q
```

Expected: the two new tests FAIL (`AttributeError: fuzz`).

- [ ] **Step 3: Implement**

`src/aramid/data/defaults.toml` — append:

```toml
# --- Phase 2c-2 (spec section 5): drain-time fuzz consumer ---
[fuzz]
enabled = true
max_functions = 10        # fuzzed per queue item
cases_per_function = 50
wall_budget_s = 300       # whole-item wall clock
batch_timeout_s = 120     # the single driver subprocess
skip_name_patterns = [
  "*deploy*", "*delete*", "*remove*", "*drop*", "*push*", "*send*",
  "*upload*", "*kill*", "*wipe*", "*publish*", "*destroy*", "*truncate*",
]
```

`src/aramid/config.py` — Config gains a defaulted field alongside `mutation`:

```python
    mutation: dict = field(default_factory=dict)
    fuzz: dict = field(default_factory=dict)
```

`load_config` return — add alongside `mutation=`:

```python
        mutation=merged.get("mutation", {}),
        fuzz=merged.get("fuzz", {}),
```

- [ ] **Step 4: Run to verify pass**

```
python -m pytest tests/unit/test_config.py -q
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(config): [fuzz] section (defaults + Config.fuzz, layered merge)"
```

---

### Task 4: Consumer — `src/aramid/consumers/fuzz.py`

**Files:**
- Create: `src/aramid/consumers/fuzz.py`
- Modify: `src/aramid/commands/drain.py` (one registration import next to `_mutation`)
- Test: `tests/integration/test_fuzz_consumer.py` (new)

**Interfaces:**
- Consumes: `gitutil.diff_new_lines`, `config_mod.filter_paths`, `fuzzgen` (unused directly — candidacy is AST-only), `RawFinding`, `ConsumerResult`/`DrainContext`, `run_subprocess`, `gitutil._run`.
- Produces: `NAME = "fuzz"`, `consume(item, ctx) -> ConsumerResult`; findings `RawFinding(tool="fuzz", rule="crash-<exc>", severity_raw="medium", ...)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/integration/test_fuzz_consumer.py`:

```python
"""Integration: the fuzz consumer against real git worktrees + the real
driver subprocess on tiny fixture repos."""
import subprocess

import pytest

from aramid import config as config_mod
from aramid.consumers import fuzz as fuzz_consumer
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.queue import QueueItem


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root) -> str:
    cp = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                         capture_output=True, text=True)
    return cp.stdout.strip()


BUGGY = ("def head(xs: list[int]) -> int:\n"
         "    return xs[0]\n")            # IndexError on []
CONTRACT = ("def validate(a: int) -> int:\n"
            "    if a < 0:\n"
            "        raise ValueError('neg')\n"
            "    return a\n")
SCARY = ("def delete_everything(target: str) -> None:\n"
         "    return None\n")


def _repo(tmp_path, body, filename="lib.py", extra_toml=""):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 5\ncases_per_function = 40\n"
        "wall_budget_s = 200\nbatch_timeout_s = 90\n" + extra_toml, encoding="utf-8")
    (r / filename).write_text("def placeholder() -> None:\n    return None\n",
                              encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / filename).write_text(body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)


def _consume(r, base, head, monkeypatch, tmp_path):
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id="q1", base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")
    try:
        return fuzz_consumer.consume(item, DrainContext(root=r, cfg=cfg,
                                                        ledger=led, clock=lambda: "t"))
    finally:
        led.close()


def _no_worktrees(r):
    cp = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                         capture_output=True, text=True)
    return len([ln for ln in cp.stdout.splitlines() if ln.strip()]) == 1


def test_deep_crash_reported(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "IndexError crash must be reported"
    f = res.findings[0]
    assert f.tool == "fuzz" and f.file == "lib.py"
    assert f.rule == "crash-indexerror"
    assert "raised IndexError" in f.message
    assert res.extra["crashes"] >= 1
    assert _no_worktrees(r)


def test_contract_exception_not_reported(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, CONTRACT)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["contract_exceptions"] >= 1
    assert _no_worktrees(r)


def test_scary_name_skipped(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, SCARY)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.extra["skipped_name"] >= 1
    assert res.extra["functions_fuzzed"] == 0


def test_unhinted_function_fuzzes_zero_cases_ok(tmp_path, monkeypatch):
    # An unhinted function is a candidate by AST but the driver's
    # supported_params finds it unfuzzable -> zero cases run, zero findings,
    # OK (never DEGRADED). functions_seen counts it; cases_run stays 0.
    r, base, head = _repo(tmp_path, "def f(a):\n    return a\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["cases_run"] == 0
    assert res.extra["functions_seen"] >= 1


def test_no_python_files_ok_noop(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    (r / "notes.md").write_text("hi\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "docs")
    res = _consume(r, head, _sha(r), monkeypatch, tmp_path)
    assert res.state == "ok" and res.findings == []
    assert "no python files" in res.note


def test_truncation_visible(tmp_path, monkeypatch):
    body = BUGGY + "\ndef head2(xs: list[int]) -> int:\n    return xs[0]\n"
    r, base, head = _repo(tmp_path, body, extra_toml="")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 1\ncases_per_function = 20\n",
        encoding="utf-8")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.extra["truncated"] is True
    assert "truncated" in res.note


def test_worktree_removed_on_midloop_exception(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    monkeypatch.setattr(fuzz_consumer.gitutil, "diff_new_lines",
                        lambda *a, **kw: {"lib.py": {1}})
    monkeypatch.setattr(fuzz_consumer, "_candidate_functions",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        _consume(r, base, head, monkeypatch, tmp_path)
    assert _no_worktrees(r)


def test_fuzz_findings_classify_warn_never_block(tmp_path, monkeypatch):
    from aramid.models import Gate
    from aramid import policy
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(tmp_path)
    _sev, verdict = policy.classify("fuzz", "crash-indexerror", "medium",
                                    Gate.ALL, cfg=cfg)
    assert str(verdict) != "block"
    assert not any("fuzz" in key for key in cfg.block_rules)


def test_determinism_same_findings_twice(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    a = _consume(r, base, head, monkeypatch, tmp_path)
    b = _consume(r, base, head, monkeypatch, tmp_path)
    assert [(f.rule, f.file, f.line) for f in a.findings] == \
           [(f.rule, f.file, f.line) for f in b.findings]
```

- [ ] **Step 2: Run to verify failure**

```
python -m pytest tests/integration/test_fuzz_consumer.py -q
```

Expected: ImportError — `aramid.consumers.fuzz` does not exist.

- [ ] **Step 3: Implement `src/aramid/consumers/fuzz.py`**

```python
"""Drain-time fuzz consumer (Phase 2c-2 spec section 4): call the top-level
type-hinted functions the queue item's commits touched with deterministic
seeded inputs, inside a throwaway git worktree at the item's head, and report
DEEP-CRASH exceptions as WARN-tier findings.

Candidacy is AST-only here (top-level def overlapping a changed line, not
async, not scary-named); the driver subprocess re-checks type hints at import
time and skips what it cannot fuzz. All calling happens in the driver, never
in this process -- the worktree + subprocess boundary is the safety line.
Zero tokens; cost stays 0.0 (CPU only, bounded by [fuzz] budgets)."""
import ast
import fnmatch
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

from aramid import config as config_mod
from aramid import gitutil
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.normalizer import RawFinding
from aramid.runners.base import ToolState, run_subprocess

NAME = "fuzz"


def _is_test_file(rel: str) -> bool:
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if p.startswith("tests/") or "/tests/" in p:
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _candidate_functions(source: str, changed: set[int], skip_patterns):
    """Top-level, non-async def names whose line span overlaps `changed` and
    whose name matches no skip pattern. Returns (candidates, skipped_name,
    skipped_async)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], 0, 0
    candidates, skipped_name, skipped_async = [], 0, 0
    for node in tree.body:  # top-level only
        if isinstance(node, ast.AsyncFunctionDef):
            skipped_async += 1
            continue
        if not isinstance(node, ast.FunctionDef):
            continue
        end = node.end_lineno or node.lineno
        if not (set(range(node.lineno, end + 1)) & changed):
            continue
        if any(fnmatch.fnmatch(node.name.lower(), pat.lower()) for pat in skip_patterns):
            skipped_name += 1
            continue
        candidates.append(node.name)
    return candidates, skipped_name, skipped_async


def consume(item, ctx: DrainContext) -> ConsumerResult:
    fcfg = getattr(ctx.cfg, "fuzz", None) or {}
    if not fcfg.get("enabled", True):
        return ConsumerResult(consumer=NAME, state="ok", note="disabled")
    max_functions = int(fcfg.get("max_functions", 10))
    cases = int(fcfg.get("cases_per_function", 50))
    wall_budget = float(fcfg.get("wall_budget_s", 300))
    batch_timeout = float(fcfg.get("batch_timeout_s", 120))
    skip_patterns = list(fcfg.get("skip_name_patterns", []))

    changed = gitutil.diff_new_lines(ctx.root, item.base, item.head)
    files = sorted(f for f in changed
                   if f.endswith(".py") and not _is_test_file(f))
    if ctx.cfg is not None:
        files = config_mod.filter_paths(files, ctx.cfg)
    if not files:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="no python files in range")

    started = time.monotonic()
    stats = {"functions_seen": 0, "functions_fuzzed": 0, "skipped_unhinted": 0,
             "skipped_name": 0, "skipped_async": 0, "cases_run": 0,
             "crashes": 0, "contract_exceptions": 0, "findings": 0,
             "timeouts": 0, "import_failures": 0, "truncated": False}
    findings: list[RawFinding] = []
    tmp = Path(tempfile.mkdtemp(prefix="aramid-fuzz-"))
    wt = tmp / "wt"
    try:
        cp = gitutil._run(ctx.root, "worktree", "add", "--detach", str(wt), item.head)
        if cp.returncode != 0:
            return ConsumerResult(consumer=NAME, state="error",
                                  note=f"worktree add failed: {(cp.stderr or '').strip()[:200]}")

        targets, budget = [], max_functions
        for rel in files:
            if budget <= 0:
                stats["truncated"] = True
                break
            src_path = wt / rel
            if not src_path.exists():
                continue
            try:
                source = src_path.read_text(encoding="utf-8")
            except OSError:
                continue
            cands, skip_name, skip_async = _candidate_functions(
                source, changed[rel], skip_patterns)
            stats["functions_seen"] += len(cands) + skip_name + skip_async
            stats["skipped_name"] += skip_name
            stats["skipped_async"] += skip_async
            if not cands:
                continue
            if len(cands) > budget:
                cands = cands[:budget]
                stats["truncated"] = True
            targets.append({"file": rel, "functions": cands, "cases": cases})
            budget -= len(cands)

        if not targets:
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="no fuzzable functions in range",
                                  duration_s=time.monotonic() - started,
                                  extra=dict(stats))

        spec = {"root": str(wt), "targets": targets}
        spec_path = tmp / "spec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        remaining = max(1.0, min(batch_timeout, wall_budget - (time.monotonic() - started)))
        result = run_subprocess(
            [sys.executable, "-m", "aramid.fuzzdriver", str(spec_path)],
            wt, remaining)
        if result.state is ToolState.TIMEOUT:
            stats["timeouts"] += 1
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="driver timed out (budget did its job)",
                                  duration_s=time.monotonic() - started,
                                  extra=dict(stats))
        if result.state is not ToolState.OK or result.returncode != 0:
            return ConsumerResult(consumer=NAME, state="ok",
                                  note=f"driver error: {result.stderr.strip()[:120]}",
                                  duration_s=time.monotonic() - started,
                                  extra=dict(stats))
        try:
            out = json.loads(result.raw)
        except (ValueError, TypeError):
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="driver produced no parseable output",
                                  duration_s=time.monotonic() - started,
                                  extra=dict(stats))

        stats["cases_run"] = out.get("cases_run", 0)
        stats["crashes"] = out.get("crashes", 0)
        stats["contract_exceptions"] = out.get("contract_exceptions", 0)
        stats["import_failures"] = len(out.get("import_failures", []))
        stats["skipped_unhinted"] = out.get("unfuzzable", 0)
        stats["functions_fuzzed"] = \
            sum(len(t["functions"]) for t in targets) - stats["skipped_unhinted"]
        for rec in out.get("records", []):
            findings.append(RawFinding(
                tool="fuzz", rule=f"crash-{rec['exc'].lower()}",
                severity_raw="medium", file=rec["file"], line=int(rec.get("line", 1)),
                message=(f"fuzz crash: {rec['func']}({rec.get('args_repr', '')}) "
                         f"raised {rec['exc']}: {rec.get('msg', '')}")))
        stats["findings"] = len(findings)
    finally:
        try:
            gitutil._run(ctx.root, "worktree", "remove", "--force", str(wt))
            gitutil._run(ctx.root, "worktree", "prune")
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            print(f"aramid: fuzz: worktree cleanup leaked at {wt}", file=sys.stderr)

    note = (f"{stats['findings']} crash finding(s) from {stats['cases_run']} "
            f"case(s) over {stats['functions_fuzzed']} function(s)")
    if stats["truncated"]:
        note += " (truncated: max_functions cap hit)"
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=time.monotonic() - started, cost=0.0,
                          note=note, extra=dict(stats))


base.CONSUMERS[NAME] = sys.modules[__name__]
```

`src/aramid/commands/drain.py` — next to the mutation registration import:

```python
from aramid.consumers import fuzz as _fuzz  # noqa: F401  (registers itself)
```

- [ ] **Step 4: Run to verify pass**

```
python -m pytest tests/integration/test_fuzz_consumer.py -q
```

Expected: 9 passed (real driver subprocesses — expect ~30-60s).

- [ ] **Step 5: Run consumer/drain neighbors (registration must not break them)**

```
python -m pytest tests/integration/test_drain.py tests/integration/test_mutation_consumer.py tests/integration/test_llm_review.py tests/unit/test_consumers_base.py -q
```

Expected: PASS — a fourth registered consumer must not disturb drain tests
(they rebind `drain_mod.CONSUMERS`) nor the mutation/llm flows. If a drain
e2e now iterates real CONSUMERS and trips on fuzz, fix the TEST fixture to
rebind CONSUMERS as the existing drain tests do — never weaken the consumer.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(consumers): fuzz consumer -- worktree-isolated seeded driver, deep-crash WARN findings"
```

---

### Task 5: Drain e2e, README, full gate

**Files:**
- Test: `tests/integration/test_fuzz_consumer.py` (append e2e)
- Modify: `README.md` (Phase 2c paragraph)

- [ ] **Step 1: Append the drain e2e test**

```python
def test_drain_e2e_records_fuzz_run(tmp_path, monkeypatch):
    from aramid import registry
    from aramid.commands import drain as drain_mod
    from aramid.commands.drain import cmd_drain
    from aramid.models import EventType
    from aramid import queue as queue_mod

    r, base, head = _repo(tmp_path, BUGGY)
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "drain.lock")
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    registry.register(r, "2026-07-20T10:00:00+00:00")
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        queue_mod.enqueue(led, "2026-07-20T10:00:00+00:00", base, head, 55, ["seed"])
    finally:
        led.close()

    rc = cmd_drain([str(r)])
    assert rc in (0, 2)

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        runs = [e for e in led.events()
                if e.type is EventType.CONSUMER_RUN_FINISHED
                and e.payload.get("consumer") == "fuzz"]
        assert runs, "drain must have run the fuzz consumer"
        assert "crashes" in runs[-1].payload   # extra payload merged
        state = led.open_findings()
        assert any(rec.get("tool") == "fuzz" for rec in state.values()), \
            "deep-crash finding must land in the ledger"
    finally:
        led.close()
```

- [ ] **Step 2: Run it**

```
python -m pytest tests/integration/test_fuzz_consumer.py::test_drain_e2e_records_fuzz_run -q
```

Expected: PASS (runs the real drain across all registered consumers, including
mutation — the fixture repo has no tests, so mutation OK-skips; fuzz reports
the IndexError).

- [ ] **Step 3: README**

Update the Phase-2 roadmap paragraph (the 2c-1 sentence added last feature) to
append the fuzz consumer:

```
2c-1 (shipped) adds the mutation consumer; 2c-2 (shipped) adds the fuzz
consumer: diff-touched type-hinted functions are called with deterministic
seeded inputs in a throwaway worktree, and deep-crash exceptions (IndexError,
KeyError, …) are recorded as WARN-tier findings — the seed is the repro
(`[fuzz]` config: budgets, a scary-name skip-list; Python repos with type
hints, no test suite required).
```

(Keep the existing 2c-1 sentence; add this after it, and drop any now-stale
"Phase 2c (mutation/fuzz/DAST) will ride" future-tense wording.)

- [ ] **Step 4: Full gate**

```
python -m ruff check src tests    # count == Task 1 Step-1 baseline (43)
python -m pytest -q               # full suite green
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(fuzz): drain e2e; docs: README 2c-2 shipped"
```

---

### Final gate (controller, not a task)

Whole-branch review (adversarial, invariants 1-7 from spec section 6, with
special attention to: driver side-effect containment, the SystemExit/contract
boundary, determinism across drains, and worktree cleanup on every path), push
+ CI, `superpowers:finishing-a-development-branch`.
