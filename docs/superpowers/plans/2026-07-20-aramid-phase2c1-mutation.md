# Phase 2c-1 Mutation Consumer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A drain-time `mutation` consumer that mutates diff-touched Python functions in a throwaway worktree and reports full-suite-confirmed surviving mutants as WARN-tier test-gap findings.

**Architecture:** An owned stdlib-`ast` mutator (`src/aramid/mutation.py`, four operator families) + a consumer (`src/aramid/consumers/mutation.py`) riding the 2a chassis unchanged. All mutation happens inside `git worktree add --detach <tmp> <item.head>`; two-stage execution (targeted pytest kill-run, capped full-suite confirmation) makes false survivors structurally impossible. Findings flow through the drain's existing normalize/classify/record path (detect-only, WARN by construction).

**Tech Stack:** Python 3.14 stdlib only (`ast`, `copy`, `tempfile`, `threading`-free). Spec: `docs/superpowers/specs/2026-07-20-aramid-phase2c1-mutation-design.md`.

## Global Constraints

- Branch: `feat/phase2c1-mutation` off `main` (create in Task 1, Step 1). One commit per task.
- Tests run via `python -m pytest` (tools live in `%APPDATA%\Python\Python314\Scripts`, not on PATH). The consumer likewise invokes pytest as `[sys.executable, "-m", "pytest", ...]` — a deliberate, documented deviation from `runners/tests.py`'s bare `"pytest"` argv: the drain must be PATH-independent (spec section 3).
- Invariant 1 (spec section 5): NOTHING writes to the live working tree of `ctx.root`; every mutation write targets the throwaway worktree, whose removal runs in a `finally`.
- Invariant 2: gate untouched — no changes to `pipeline.py`, `policy.py`, `hooks.py`, `check.py`.
- Invariant 3: WARN-only — no mutation entry in `block_rules.toml`; asserted by test.
- Invariant 4: a finding requires a full-suite pass on the mutant (stage 2). Cap/budget drops set `extra["truncated"]` and are named in the note.
- Ruff: no NEW findings vs the branch-base count (record in Task 1 Step 1).
- Full suite green at the end (`python -m pytest -q`; 699 at current main).

---

### Task 1: `gitutil.diff_new_lines` — changed-line map

**Files:**
- Modify: `src/aramid/gitutil.py` (append helper; add `import re` to the module imports)
- Test: `tests/unit/test_gitutil.py`

**Interfaces:**
- Consumes: `gitutil._run` (existing).
- Produces: `diff_new_lines(root: Path, base: str | None, head: str) -> dict[str, set[int]]` — repo-relative forward-slash path → 1-based changed line numbers on the NEW side. Task 4's consumer calls this.

- [ ] **Step 1: Create the branch, record ruff baseline**

```bash
git checkout -b feat/phase2c1-mutation
python -m ruff check src tests | tail -1   # record the count
```

- [ ] **Step 2: Write the failing tests**

Append to `tests/unit/test_gitutil.py` (the file already has `_repo`/`_commit`-style helpers — reuse its existing repo fixture helpers; if its helpers are named differently, adapt the calls, not the assertions):

```python
def test_diff_new_lines_maps_changed_lines(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\ny = 2\nz = 3\n", "c1")
    base = rev_sha(r, "HEAD")
    _commit(r, "a.py", "x = 1\ny = 99\nz = 3\nw = 4\n", "c2")
    head = rev_sha(r, "HEAD")
    lines = diff_new_lines(r, base, head)
    assert lines == {"a.py": {2, 4}}


def test_diff_new_lines_root_commit_and_deletion(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "c1")
    head = rev_sha(r, "HEAD")
    # base=None (root/bootstrap): whole file counts as new
    assert diff_new_lines(r, None, head) == {"a.py": {1}}
    # pure deletion contributes nothing on the new side
    base = head
    _commit(r, "b.py", "q = 1\n", "c2")
    (r / "a.py").unlink()
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "c3")
    head2 = rev_sha(r, "HEAD")
    assert "a.py" not in diff_new_lines(r, base, head2)
```

Add `diff_new_lines` (and `rev_sha` if absent) to the file's `from aramid.gitutil import ...` line.

- [ ] **Step 3: Run to verify failure**

```
python -m pytest tests/unit/test_gitutil.py -q
```

Expected: ImportError/AttributeError — `diff_new_lines` does not exist.

- [ ] **Step 4: Implement**

Append to `src/aramid/gitutil.py` (add `import re` at the top with the other imports):

```python
_HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def diff_new_lines(root: Path, base: str | None, head: str) -> dict[str, set[int]]:
    """Changed-line map for base..head: repo-relative forward-slash path ->
    1-based line numbers on the NEW (head) side. Parses --unified=0 hunk
    headers (@@ -a,b +c,d @@); a pure deletion has d==0 and contributes
    nothing; git emits forward-slash paths already."""
    if base is None:
        cp = _run(root, "show", "--format=", "--unified=0", head)
    else:
        cp = _run(root, "diff", "--unified=0", f"{base}..{head}")
    out: dict[str, set[int]] = {}
    current: str | None = None
    for ln in (cp.stdout if cp.returncode == 0 else "").splitlines():
        if ln.startswith("+++ "):
            target = ln[4:].strip()
            current = None if target == "/dev/null" else \
                (target[2:] if target.startswith("b/") else target)
        elif ln.startswith("@@ ") and current is not None:
            m = _HUNK_RE.match(ln)
            if m is None:
                continue
            start, count = int(m.group(1)), int(m.group(2) or "1")
            if count:
                out.setdefault(current, set()).update(range(start, start + count))
    return out
```

- [ ] **Step 5: Run to verify pass**

```
python -m pytest tests/unit/test_gitutil.py -q
```

Expected: PASS (all, including pre-existing).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(gitutil): diff_new_lines changed-line map for mutation scoping"
```

---

### Task 2: Mutator core — `src/aramid/mutation.py`

**Files:**
- Create: `src/aramid/mutation.py`
- Test: `tests/unit/test_mutation.py` (new)

**Interfaces:**
- Consumes: nothing project-internal (stdlib `ast`, `copy`, `dataclasses`).
- Produces: `Mutant(file: str, line: int, op: str, description: str, source: str)` and `generate_mutants(source: str, target_lines: set[int]) -> list[Mutant]` (emits `file=""`; Task 4's consumer stamps the path). Op ids: `"cmp-flip"`, `"bool-swap"`, `"int-bound"`, `"not-drop"`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_mutation.py`:

```python
import ast

from aramid.mutation import generate_mutants

SRC = """\
def clamp(x):
    if x > 10:
        return 10
    return x

def untouched(y):
    return y == 0
"""


def _ops(mutants):
    return sorted(m.op for m in mutants)


def test_cmp_flip_generated_for_targeted_function():
    muts = generate_mutants(SRC, {2})
    assert any(m.op == "cmp-flip" and "clamp" in m.description for m in muts)
    # every mutant parses and differs from the original
    for m in muts:
        assert m.source != SRC
        ast.parse(m.source)
        compile(m.source, "<mutant>", "exec")


def test_function_outside_target_lines_untouched():
    muts = generate_mutants(SRC, {2})
    assert not any("untouched" in m.description for m in muts)


def test_int_bound_skips_bool_constants():
    src = "def f(a):\n    if a is True:\n        return 1\n    return 0\n"
    muts = generate_mutants(src, {1, 2, 3, 4})
    bound = [m for m in muts if m.op == "int-bound"]
    assert bound, "int literals 1 and 0 must be mutated"
    assert all("True" not in m.description for m in bound)


def test_bool_swap_and_not_drop():
    src = ("def g(a, b):\n"
           "    if not a:\n"
           "        return False\n"
           "    return a and b\n")
    muts = generate_mutants(src, {1, 2, 3, 4})
    assert "bool-swap" in _ops(muts)
    assert "not-drop" in _ops(muts)
    nd = next(m for m in muts if m.op == "not-drop")
    assert "if not a" not in nd.source or "if a" in nd.source


def test_deterministic_order():
    a = generate_mutants(SRC, {1, 2, 3, 4})
    b = generate_mutants(SRC, {1, 2, 3, 4})
    assert [(m.line, m.op, m.description) for m in a] == \
           [(m.line, m.op, m.description) for m in b]


def test_syntax_error_source_yields_no_mutants():
    assert generate_mutants("def broken(:\n", {1}) == []
```

- [ ] **Step 2: Run to verify failure**

```
python -m pytest tests/unit/test_mutation.py -q
```

Expected: ImportError — `aramid.mutation` does not exist.

- [ ] **Step 3: Implement `src/aramid/mutation.py`**

```python
"""mutation -- owned stdlib-ast mutator (Phase 2c-1 spec section 2).

Four operator families, applied one site at a time; mutants are rendered
with ast.unparse (comments/formatting lost -- acceptable: mutants exist
only inside the consumer's throwaway worktree). Deterministic ordering so
budget truncation is reproducible and fingerprints stable across drains.
The copy-by-walk-index trick relies on ast.walk's traversal order being a
pure function of tree shape, which deepcopy preserves."""
import ast
import copy
from dataclasses import dataclass

_CMP_FLIP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.LtE,
             ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt}
_CMP_SYM = {ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=",
            ast.Gt: ">", ast.GtE: ">="}


@dataclass
class Mutant:
    file: str          # "" from generate_mutants; the consumer stamps it
    line: int
    op: str
    description: str
    source: str


def _eligible_spans(tree: ast.Module, target_lines: set[int]) -> list[tuple[int, int, str]]:
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = node.end_lineno or node.lineno
            if set(range(node.lineno, end + 1)) & target_lines:
                spans.append((node.lineno, end, node.name))
    return spans


def _enclosing(spans, lineno):
    """Innermost eligible function span containing lineno (a node inside a
    nested non-eligible function still counts via its eligible outer -- the
    inner function is part of the outer's body, deliberate overreach)."""
    best = None
    for start, end, name in spans:
        if start <= lineno <= end and (best is None or start > best[0]):
            best = (start, end, name)
    return best


def _mutations_at(node, func_name):
    """Yield (op, description, mutate_fn); mutate_fn edits the COPY node."""
    if isinstance(node, ast.Compare) and len(node.ops) == 1 \
            and type(node.ops[0]) in _CMP_FLIP:
        old = type(node.ops[0])
        yield ("cmp-flip",
               f"{_CMP_SYM[old]} -> {_CMP_SYM[_CMP_FLIP[old]]} in {func_name}",
               lambda n: n.ops.__setitem__(0, _CMP_FLIP[type(n.ops[0])]()))
    elif isinstance(node, ast.BoolOp):
        old = "and" if isinstance(node.op, ast.And) else "or"
        new = "or" if old == "and" else "and"
        yield ("bool-swap", f"{old} -> {new} in {func_name}",
               lambda n: setattr(n, "op",
                                 ast.Or() if isinstance(n.op, ast.And) else ast.And()))
    elif isinstance(node, ast.Constant) and type(node.value) is int:
        yield ("int-bound", f"{node.value} -> {node.value + 1} in {func_name}",
               lambda n: setattr(n, "value", n.value + 1))
    elif isinstance(node, ast.If) and isinstance(node.test, ast.UnaryOp) \
            and isinstance(node.test.op, ast.Not):
        yield ("not-drop", f"'if not ...' -> 'if ...' in {func_name}",
               lambda n: setattr(n, "test", n.test.operand))


def generate_mutants(source: str, target_lines: set[int]) -> list[Mutant]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    spans = _eligible_spans(tree, target_lines)
    if not spans:
        return []
    mutants: list[Mutant] = []
    nodes = list(ast.walk(tree))
    for idx, node in enumerate(nodes):
        lineno = getattr(node, "lineno", None)
        if lineno is None:
            continue
        enc = _enclosing(spans, lineno)
        if enc is None:
            continue
        for op, desc, mutate in _mutations_at(node, enc[2]):
            tree_copy = copy.deepcopy(tree)
            mutate(list(ast.walk(tree_copy))[idx])
            try:
                mutated = ast.unparse(ast.fix_missing_locations(tree_copy))
            except Exception:
                continue
            mutants.append(Mutant(file="", line=lineno, op=op,
                                  description=desc, source=mutated))
    mutants.sort(key=lambda m: (m.line, m.op, m.description))
    return mutants
```

- [ ] **Step 4: Run to verify pass**

```
python -m pytest tests/unit/test_mutation.py -q
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(mutation): owned stdlib-ast mutator, four operator families, diff-scoped"
```

---

### Task 3: `[mutation]` config section

**Files:**
- Modify: `src/aramid/data/defaults.toml` (append section)
- Modify: `src/aramid/config.py` (Config field + load_config wiring)
- Test: `tests/unit/test_config.py`

**Interfaces:**
- Consumes: existing layered-merge machinery.
- Produces: `cfg.mutation: dict` with keys `enabled`, `max_mutants`, `wall_budget_s`, `mutant_timeout_s`, `confirm_cap`. Task 4 reads them via `.get` with the same defaults.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_config.py` (reuse its existing `_no_user_config`-style seam helper — the file has one; match its exact name):

```python
def test_mutation_defaults_present(tmp_path, monkeypatch):
    _no_user_config(monkeypatch, tmp_path)
    cfg = config.load_config(tmp_path)
    assert cfg.mutation["enabled"] is True
    assert cfg.mutation["max_mutants"] == 20
    assert cfg.mutation["wall_budget_s"] == 600
    assert cfg.mutation["mutant_timeout_s"] == 120
    assert cfg.mutation["confirm_cap"] == 3


def test_mutation_repo_override_merges(tmp_path, monkeypatch):
    _no_user_config(monkeypatch, tmp_path)
    (tmp_path / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 4\n", encoding="utf-8")
    cfg = config.load_config(tmp_path)
    assert cfg.mutation["max_mutants"] == 4
    assert cfg.mutation["enabled"] is True  # deep-merge keeps defaults
```

(If the seam helper has a different signature, adapt the call; the assertions stand.)

- [ ] **Step 2: Run to verify failure**

```
python -m pytest tests/unit/test_config.py -q
```

Expected: the two new tests FAIL (`AttributeError: mutation` / KeyError).

- [ ] **Step 3: Implement**

`src/aramid/data/defaults.toml` — append:

```toml
# --- Phase 2c-1 (spec section 4): drain-time mutation consumer ---
[mutation]
enabled = true
max_mutants = 20        # generated-and-tested per queue item
wall_budget_s = 600     # whole-item wall clock for the mutant loop
mutant_timeout_s = 120  # per pytest invocation (stage 1 and stage 2 alike)
confirm_cap = 3         # full-suite confirmation runs per item
```

`src/aramid/config.py` — Config gains a defaulted field (keeps every direct
`Config(...)` constructor in tests working):

```python
    llm: dict
    mutation: dict = dataclasses.field(default_factory=dict)
```

(if the module imports `dataclass` only, extend the import to
`from dataclasses import dataclass, field` and use `field(default_factory=dict)`).

`load_config` return — add alongside `llm=`:

```python
        llm=merged.get("llm", {}),
        mutation=merged.get("mutation", {}),
```

- [ ] **Step 4: Run to verify pass, plus config neighbors**

```
python -m pytest tests/unit/test_config.py -q
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(config): [mutation] section (defaults + Config.mutation, layered merge)"
```

---

### Task 4: The consumer — `src/aramid/consumers/mutation.py`

**Files:**
- Create: `src/aramid/consumers/mutation.py`
- Modify: `src/aramid/commands/drain.py` (one registration import, next to the llm_review one)
- Test: `tests/integration/test_mutation_consumer.py` (new)

**Interfaces:**
- Consumes: `gitutil.diff_new_lines` (Task 1), `mutation.generate_mutants`/`Mutant` (Task 2), `cfg.mutation` (Task 3), `run_subprocess`, `detectors.detect_tests`, `config_mod.filter_paths`, `RawFinding`, `ConsumerResult`/`DrainContext`, `gitutil._run` (worktree management).
- Produces: `NAME = "mutation"`, `consume(item, ctx) -> ConsumerResult` registered in `base.CONSUMERS`; findings `RawFinding(tool="mutation", rule=<op>, severity_raw="medium", file, line, message="mutant survived: ...")`.

- [ ] **Step 1: Write the failing tests**

Create `tests/integration/test_mutation_consumer.py`:

```python
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
import subprocess

import pytest

from aramid import config as config_mod
from aramid.consumers import mutation as mut_consumer
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.queue import QueueItem


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


def _consume(r, base, head, monkeypatch, tmp_path):
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id="q1", base=base, head=head, score=55, reasons=("t",),
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
    assert res.extra["killed"] >= 1
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
    assert res.extra["killed"] >= 1


def test_no_pytest_stack_degrades(tmp_path, monkeypatch):
    # JS-only / test-less repo: consumer must degrade loudly (the 2c-1b seam),
    # never silently no-op. Strip the tests dir AFTER the commits exist.
    import shutil as _shutil
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _shutil.rmtree(r / "tests")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "drop tests")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    assert "no python test stack" in res.note


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


def test_mutation_findings_classify_warn_never_block(tmp_path, monkeypatch):
    from aramid.models import Gate, Source
    from aramid import policy
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(tmp_path)
    severity, verdict = policy.classify("mutation", "cmp-flip", "medium",
                                        Gate.ALL, cfg=cfg)
    assert str(verdict) != "block"
    assert not any("mutation" in key for key in cfg.block_rules), \
        "block_rules must have no mutation entry (spec invariant 3)"
```

NOTE for the implementer: `policy.classify`'s exact signature is 5-arg with
`cfg` last (see `policy.py`) — if the positional shape differs from this call,
adapt the CALL to the real signature; the two assertions stand as written.
`Source` import is unused if classify doesn't need it — drop it then.

- [ ] **Step 2: Run to verify failure**

```
python -m pytest tests/integration/test_mutation_consumer.py -q
```

Expected: ImportError — `aramid.consumers.mutation` does not exist.

- [ ] **Step 3: Implement `src/aramid/consumers/mutation.py`**

```python
"""Drain-time mutation consumer (Phase 2c-1 spec section 3): mutate the
functions the queue item's commits touched, inside a throwaway git worktree
at the item's head, and report mutants the repo's FULL test suite cannot
kill as WARN-tier test-gap findings.

Two-stage execution (spec decisions table): a targeted pytest kill-run per
mutant (tests/**/test_<module>.py, else -k <module>), then a full-suite
confirmation capped per item -- a survivor is only REPORTED if the full
suite passes on it, so narrow stage-1 selection can never manufacture a
false test-gap finding. pytest runs as [sys.executable, -m, pytest]: the
drain must be PATH-independent (deliberate deviation from runners/tests.py's
bare "pytest" argv). Timeouts are unattributable -- counted, never reported.
Zero tokens; cost stays 0.0 (CPU only, bounded by [mutation] budgets)."""
import shutil
import sys
import tempfile
import time
from pathlib import Path

from aramid import config as config_mod
from aramid import detectors, gitutil, mutation
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.normalizer import RawFinding
from aramid.runners.base import ToolState, run_subprocess

NAME = "mutation"


def _is_test_file(rel: str) -> bool:
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if p.startswith("tests/") or "/tests/" in p:
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _stage1_argv(wt: Path, rel: str) -> list[str]:
    module = Path(rel).stem
    tests_dir = wt / "tests"
    if tests_dir.exists():
        hits = sorted(tests_dir.rglob(f"test_{module}.py"))
        if hits:
            return [sys.executable, "-m", "pytest", "-q",
                    *(str(p.relative_to(wt)) for p in hits)]
    return [sys.executable, "-m", "pytest", "-q", "-k", module]


def _full_argv() -> list[str]:
    return [sys.executable, "-m", "pytest", "-q"]


def consume(item, ctx: DrainContext) -> ConsumerResult:
    mcfg = getattr(ctx.cfg, "mutation", None) or {}
    if not mcfg.get("enabled", True):
        return ConsumerResult(consumer=NAME, state="ok", note="disabled")
    max_mutants = int(mcfg.get("max_mutants", 20))
    wall_budget = float(mcfg.get("wall_budget_s", 600))
    mutant_timeout = float(mcfg.get("mutant_timeout_s", 120))
    confirm_cap = int(mcfg.get("confirm_cap", 3))

    changed = gitutil.diff_new_lines(ctx.root, item.base, item.head)
    files = sorted(f for f in changed
                   if f.endswith(".py") and not _is_test_file(f))
    if ctx.cfg is not None:
        files = config_mod.filter_paths(files, ctx.cfg)
    if not files:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="no python files in range")
    if "pytest" not in detectors.detect_tests(ctx.root):
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="no python test stack")

    started = time.monotonic()
    stats = {"generated": 0, "tested": 0, "killed": 0, "survived": 0,
             "confirmed": 0, "timeouts": 0, "errors": 0, "truncated": False}
    findings: list[RawFinding] = []
    tmp = Path(tempfile.mkdtemp(prefix="aramid-mut-"))
    wt = tmp / "wt"
    try:
        cp = gitutil._run(ctx.root, "worktree", "add", "--detach", str(wt), item.head)
        if cp.returncode != 0:
            return ConsumerResult(consumer=NAME, state="error",
                                  note=f"worktree add failed: {(cp.stderr or '').strip()[:200]}")

        base_res = run_subprocess(_full_argv(), wt, mutant_timeout * 4)
        if base_res.state is not ToolState.OK or base_res.returncode != 0:
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note="baseline failing",
                                  duration_s=time.monotonic() - started)

        confirms_used = 0
        done = False
        for rel in files:
            if done:
                break
            src_path = wt / rel
            if not src_path.exists():
                continue
            try:
                original = src_path.read_text(encoding="utf-8")
            except OSError:
                stats["errors"] += 1
                continue
            muts = mutation.generate_mutants(original, changed[rel])
            stats["generated"] += len(muts)
            for m in muts:
                if stats["tested"] >= max_mutants \
                        or time.monotonic() - started > wall_budget:
                    stats["truncated"] = True
                    done = True
                    break
                stats["tested"] += 1
                try:
                    src_path.write_text(m.source, encoding="utf-8")
                    s1 = run_subprocess(_stage1_argv(wt, rel), wt, mutant_timeout)
                    if s1.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                        continue
                    if s1.state is ToolState.OK and s1.returncode not in (0, 5):
                        stats["killed"] += 1
                        continue
                    # putative survivor (pass, or exit 5 = nothing selected)
                    stats["survived"] += 1
                    if confirms_used >= confirm_cap:
                        stats["truncated"] = True
                        continue
                    confirms_used += 1
                    s2 = run_subprocess(_full_argv(), wt, mutant_timeout)
                    if s2.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                    elif s2.state is ToolState.OK and s2.returncode == 0:
                        stats["confirmed"] += 1
                        findings.append(RawFinding(
                            tool="mutation", rule=m.op, severity_raw="medium",
                            file=rel, line=m.line,
                            message=f"mutant survived: {m.description}"))
                    else:
                        stats["killed"] += 1
                except Exception:
                    stats["errors"] += 1
                finally:
                    # Restore by rewriting the captured original -- equivalent
                    # to the spec's `git checkout -- <file>` with one fewer
                    # subprocess per mutant (sanctioned deviation).
                    try:
                        src_path.write_text(original, encoding="utf-8")
                    except OSError:
                        stats["errors"] += 1
    finally:
        try:
            gitutil._run(ctx.root, "worktree", "remove", "--force", str(wt))
            gitutil._run(ctx.root, "worktree", "prune")
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            print(f"aramid: mutation: worktree cleanup leaked at {wt}",
                  file=sys.stderr)

    note = (f"{stats['confirmed']} confirmed survivor(s) of "
            f"{stats['tested']} mutant(s) tested")
    if stats["truncated"]:
        note += " (truncated: budget/cap hit, remainder dropped)"
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=time.monotonic() - started, cost=0.0,
                          note=note, extra=dict(stats))


base.CONSUMERS[NAME] = sys.modules[__name__]
```

`src/aramid/commands/drain.py` — next to the llm_review registration import:

```python
from aramid.consumers import mutation as _mutation  # noqa: F401  (registers itself)
```

- [ ] **Step 4: Run to verify pass**

```
python -m pytest tests/integration/test_mutation_consumer.py -q
```

Expected: 9 passed (this suite runs real pytest subprocesses — expect ~1-3 min).

- [ ] **Step 5: Run the drain + consumer neighbors**

```
python -m pytest tests/integration/test_drain.py tests/unit/test_consumers_base.py tests/integration/test_llm_review.py -q
```

Expected: PASS — registering a third consumer must not break drain tests that
rebind `drain_mod.CONSUMERS` (they replace the dict wholesale) nor the
llm_review flow. If a drain test iterates real CONSUMERS and now hits
mutation unexpectedly, fix the TEST fixture to rebind CONSUMERS as the
existing drain tests do — do not weaken the consumer.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(consumers): mutation consumer -- worktree-isolated, two-stage kill/confirm, WARN-only"
```

---

### Task 5: Drain e2e, README, full gate

**Files:**
- Test: `tests/integration/test_mutation_consumer.py` (append e2e)
- Modify: `README.md` (Phase 2c paragraph)

**Interfaces:**
- Consumes: `cmd_drain` (existing), registry/queue seams from existing drain tests.

- [ ] **Step 1: Write the e2e test (failing only if wiring is broken — it must RUN, not skip)**

Append to `tests/integration/test_mutation_consumer.py`:

```python
def test_drain_e2e_records_mutation_run(tmp_path, monkeypatch):
    from aramid import registry
    from aramid.commands.drain import cmd_drain
    from aramid.models import EventType
    from aramid import queue as queue_mod

    r, base, head = _repo(tmp_path, WEAK_TEST)
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    registry.register(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        queue_mod.enqueue(led, "2026-07-20T10:00:00+00:00", base, head, 55, ["seed"])
    finally:
        led.close()

    rc = cmd_drain([str(r)])
    assert rc in (0, 2)  # 2 allowed: llm consumer degrades w/o providers

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
```

NOTE for the implementer: check `cmd_drain`'s real signature in
`src/aramid/commands/drain.py` (the CLI passes a target list; mirror
`test_drain.py`'s existing call convention exactly — adapt the `cmd_drain([...])`
call shape, keep the assertions).

- [ ] **Step 2: Run it**

```
python -m pytest tests/integration/test_mutation_consumer.py::test_drain_e2e_records_mutation_run -q
```

Expected: PASS (it runs the real drain; if it fails on drain-lock or registry
isolation, mirror `test_drain.py`'s fixtures — the integration conftest already
isolates the registry autouse).

- [ ] **Step 3: README**

In the Phase-2 roadmap area (the line reading
`drain) that Phase 2b (LLM adversarial review) and Phase 2c (mutation/fuzz/DAST)`
`will ride as new drain-time consumers.` around line 89-91), reword to:

```
Still deterministic, still zero LLM calls — 2a is the chassis (triage → queue →
drain) that Phase 2b (LLM adversarial review, shipped) and Phase 2c ride as
drain-time consumers. 2c-1 (shipped) adds the mutation consumer: diff-touched
functions are mutated in a throwaway worktree and mutants the full test suite
cannot kill are recorded as WARN-tier test-gap findings (`[mutation]` config:
budgets, two-stage targeted/confirm execution; Python repos with pytest).
```

- [ ] **Step 4: Full gate**

```
python -m ruff check src tests    # count == Task 1 Step-1 baseline
python -m pytest -q               # full suite green
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(mutation): drain e2e; docs: README 2c-1 shipped"
```

---

### Final gate (controller, not a task)

Whole-branch review (adversarial, invariants 1-6 from spec section 5), push +
CI, `superpowers:finishing-a-development-branch`.
