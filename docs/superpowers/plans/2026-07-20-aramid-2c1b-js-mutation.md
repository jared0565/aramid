# 2c-1b JS/TS Mutation Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a JavaScript/TypeScript mutation-testing consumer that mutates a queue item's changed lines with an owned pure-Python token mutator and reports mutants the repo's own `npm test` cannot kill as WARN-tier findings.

**Architecture:** Two new modules mirroring the Python `mutation.py`/`consumers/mutation.py` split — `jsmutate.py` (owned region-aware token mutator, pure/no-I/O) and `consumers/js_mutation.py` (drain orchestrator: throwaway worktree at item.head, `node_modules` junctioned from the main repo, single-stage full `<pm> test` per mutant). Stack-gated so it fires only on JS repos; runs alongside the Python consumer.

**Tech Stack:** Python stdlib only. Tests via `python -m pytest` (Windows: never bare `pytest`).

**Spec:** `docs/superpowers/specs/2026-07-20-aramid-2c1b-js-mutation-design.md`

## Global Constraints

- Branch: `feat/2c1b-js-mutation` off main @ 07f6a96. Never implement on main.
- Ruff parity: `python -m ruff check .` must equal the baseline measured at branch creation (expected 43). Every task matches it.
- Full suite green before merge: `python -m pytest -q` (791 base + new).
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` (omitted below for brevity — always add; use `git commit -F -` with a quoted heredoc, NEVER `-m "..."` with backticks in the body).
- Consumer contract: a module exposing `NAME: str` + `consume(item, ctx: DrainContext) -> ConsumerResult`, registered `base.CONSUMERS[NAME] = sys.modules[__name__]`, imported in `commands/drain.py`.
- Mutator public surface identical in shape to Python's: `Mutant(file, line, op, description, source)` + `generate_mutants(source: str, target_lines: set[int]) -> list[Mutant]`.
- Findings are WARN-tier: `RawFinding(tool="js-mutation", rule=<op>, severity_raw="medium", …)`; `cost=0.0`; `PIN_OCCURRENCE = True`.
- OK-not-DEGRADED for structural absence (no JS stack / no node_modules / no pm) — a degraded consumer pins the queue item forever. DEGRADED only for transient (baseline red, worktree/link failure), with give-up after 3.

## File Structure

- **Create** `src/aramid/jsmutate.py` — owned token mutator. Pure functions, no subprocess/I/O. Public: `Mutant`, `generate_mutants`.
- **Create** `src/aramid/consumers/js_mutation.py` — drain consumer. `NAME="js_mutation"`, `consume`, `PIN_OCCURRENCE=True`, worktree/junction/baseline/loop, registration.
- **Modify** `src/aramid/config.py` — add `js_mutation: dict` field + load wiring.
- **Modify** `src/aramid/data/defaults.toml` — add `[js_mutation]` block.
- **Modify** `src/aramid/commands/drain.py` — import the consumer (registration side-effect).
- **Test** `tests/unit/test_jsmutate.py`, `tests/integration/test_js_mutation_consumer.py`.

---

### Task 1: Owned mutator — scanner + region classification + cmp-flip

Establishes the whole mutator architecture (region-aware single-pass scanner, `Mutant`, `generate_mutants`) with the first operator family. The scanner's region safety (never mutate inside strings/comments/regex/templates) is proven here because it is needed the moment any operator exists.

**Files:**
- Create: `src/aramid/jsmutate.py`
- Test: `tests/unit/test_jsmutate.py`

**Interfaces:**
- Produces: `jsmutate.Mutant(file: str, line: int, op: str, description: str, source: str)`; `jsmutate.generate_mutants(source: str, target_lines: set[int]) -> list[Mutant]`. Internally `_candidates(source, target_lines) -> list[tuple[int,int,str,str,str,int]]` = `(offset, length, op, new_text, description, line)`.

- [ ] **Step 0: Branch + ruff baseline**

```bash
git checkout -b feat/2c1b-js-mutation
python -m ruff check . 2>&1 | tail -1   # expect "Found 43 errors." — record it
```

- [ ] **Step 1: Write the failing cmp-flip + region tests**

Create `tests/unit/test_jsmutate.py`:

```python
from aramid.jsmutate import Mutant, generate_mutants


def _sources(muts):
    return sorted(m.source for m in muts)


def test_cmp_flip_strict_equality():
    src = "function f(a, b) {\n  return a === b;\n}\n"
    muts = generate_mutants(src, {2})
    assert any("a !== b" in m.source for m in muts)
    assert any(m.op == "cmp-flip" and m.line == 2 for m in muts)


def test_cmp_flip_relational_single_char():
    src = "const g = (a) => {\n  if (a < 3) return a;\n};\n"
    muts = generate_mutants(src, {2})
    # `<` becomes `<=` (single-char relational), `3` is int-bound (later task)
    assert any("a <= 3" in m.source for m in muts)


def test_no_mutation_inside_string_literals():
    src = "function f() {\n  return 'a === b && c';\n}\n"
    muts = generate_mutants(src, {2})
    assert muts == [], "operators inside a string must never be mutated"


def test_no_mutation_inside_line_comment():
    src = "function f(a, b) {\n  return a; // a === b\n}\n"
    muts = generate_mutants(src, {2})
    assert all("!==" not in m.source for m in muts)


def test_no_mutation_inside_block_comment():
    src = "function f(a, b) {\n  /* a === b */\n  return a;\n}\n"
    muts = generate_mutants(src, {2, 3})
    assert all("!==" not in m.source for m in muts)


def test_no_mutation_inside_regex_literal():
    src = "function f(s) {\n  return /a===b/.test(s);\n}\n"
    muts = generate_mutants(src, {2})
    assert muts == [], "a === inside a regex literal must not be mutated"


def test_no_mutation_inside_regex_after_binary_operator():
    # A `/` after a binary operator (&&, =>, =, ...) opens a regex, NOT division,
    # so operators inside it must never be mutated. A punct-only allow-set for
    # the regex-prev check misses this (prev is the whole op token "&&").
    src = "function f(a, s) {\n  const ok = a && /x===y/.test(s);\n  return ok;\n}\n"
    muts = generate_mutants(src, {2})
    assert all("!==" not in m.source for m in muts), \
        "=== inside a regex after && must not be cmp-flipped"
    assert all(m.op != "cmp-flip" for m in muts)


def test_no_mutation_inside_template_literal():
    src = "function f(a) {\n  return `x === ${a}`;\n}\n"
    muts = generate_mutants(src, {2})
    assert all("!==" not in m.source for m in muts)


def test_division_is_not_a_regex_and_not_mutated():
    src = "function f(a, b) {\n  return a / b === 2;\n}\n"
    muts = generate_mutants(src, {2})
    # the `/` is division (prev token is an identifier), so `=== 2` still parses
    # as code and cmp-flip fires on it
    assert any("a / b !== 2" in m.source for m in muts)
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_jsmutate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'aramid.jsmutate'`.

- [ ] **Step 3: Implement the scanner + cmp-flip**

Create `src/aramid/jsmutate.py`:

```python
"""jsmutate -- owned token-level JS/TS mutator (2c-1b spec section 4).

No AST: Python has no stdlib JS parser, so a single forward-pass region-aware
scanner classifies each character as code / string / template / comment / regex
and applies the operator families ONLY in code regions on the target lines.
Operator swaps are like-for-like (syntactically valid); a `/` in a
regex-possible position opens a regex literal whose interior is never mutated
(the failure mode is a missed mutation, never a mis-mutation). Deterministic
ordering so budget truncation is reproducible and fingerprints stable across
drains. Mirrors mutation.Mutant / mutation.generate_mutants."""
from dataclasses import dataclass

_ID_START = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$")
_ID_CONT = _ID_START | set("0123456789")
_DIGITS = set("0123456789")

# cmp-flip: like-for-like relational/equality swaps.
_CMP_FLIP = {"===": "!==", "!==": "===", "==": "!=", "!=": "==",
             "<": "<=", "<=": "<", ">": ">=", ">=": ">"}

# Multi-char operator tokens recognized for MAXIMAL MUNCH so a longer operator
# is never mis-split into a shorter mutable one (e.g. `=>`/`<<`/`>>`/`===` must
# not be read as `=`/`<`/`>`/`==`). Longest first. Includes non-mutated ops.
_OPERATORS = (">>>=", "===", "!==", ">>>", "<<=", ">>=", "**=", "&&=", "||=",
              "??=", "==", "!=", "<=", ">=", "=>", "<<", ">>", "&&", "||",
              "??", "**", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=",
              "|=", "^=")

# Regex-vs-division: a `/` opens a REGEX literal UNLESS the previous significant
# token is a VALUE (something a `/` could divide) -- see _prev_is_value. These
# keywords are NOT values, so a `/` after them opens a regex (e.g. `return /re/`,
# `typeof /re/`). Enumerating the operators a regex CAN follow is fragile (note
# `++`/`--` ARE values: `x++ / y` divides), so we invert and test for a value.
_REGEX_PREV_KW = {"return", "typeof", "instanceof", "in", "of", "case",
                  "delete", "void", "do", "else", "yield", "await", "new",
                  "throw"}


@dataclass
class Mutant:
    file: str          # "" from generate_mutants; the consumer stamps it
    line: int
    op: str
    description: str
    source: str


def _match_multichar_op(source: str, i: int) -> str | None:
    for op in _OPERATORS:
        if source.startswith(op, i):
            return op
    return None


def _prev_is_value(prev: str) -> bool:
    """True when `prev` is a token a `/` could DIVIDE, so the `/` is division
    (not a regex): a value identifier (variable name, `this`, `true`, ...),
    number, string, template, regex, `)`, `]`, `++`, `--`. False for operators,
    punctuation, a regex-preceding keyword (return/typeof/...), and start-of-
    input -- there a `/` opens a regex."""
    if prev == "":
        return False
    if prev in (")", "]", "'str'", "`t`", "/re/", "++", "--"):
        return True
    first = prev[:1]
    if first in _DIGITS:
        return True
    if first in _ID_START:
        return prev not in _REGEX_PREV_KW   # a keyword like `return` is not a value
    return False   # any operator / punctuation -> not a value -> regex follows


def _consume_string(source: str, i: int) -> int:
    """i at an opening ' or ". Return index just past the closing quote (or at
    the newline / EOF for an unterminated string)."""
    q = source[i]
    i += 1
    n = len(source)
    while i < n:
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == q:
            return i + 1
        if c == "\n":
            return i
        i += 1
    return i


def _consume_template(source: str, i: int) -> int:
    """i at a backtick. Return index just past the matching closing backtick.
    `${...}` interpolations are treated conservatively as string (MVP): brace
    depth is counted so the real closing backtick is found; expression contents
    are NOT mutated."""
    i += 1
    n = len(source)
    depth = 0
    while i < n:
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == "`" and depth == 0:
            return i + 1
        if c == "$" and i + 1 < n and source[i + 1] == "{":
            depth += 1
            i += 2
            continue
        if c == "}" and depth > 0:
            depth -= 1
        i += 1
    return i


def _consume_regex(source: str, i: int) -> int:
    """i at a `/` known to open a regex. Return index just past the closing
    `/` and any flags. Handles [char classes] (where `/` is literal) and
    backslash escapes."""
    i += 1
    n = len(source)
    in_class = False
    while i < n:
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == "\n":
            return i
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            i += 1
            while i < n and source[i] in _ID_CONT:
                i += 1
            return i
        i += 1
    return i


def _candidates(source: str, target_lines: set[int]):
    """Yield (offset, length, op, new_text, description, line) for each mutation
    site in a CODE region on a target line. Single forward pass."""
    out = []
    n = len(source)
    i = 0
    line = 1
    prev = ""   # last significant token seen in code (str); "" at start
    while i < n:
        c = source[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in " \t\r":
            i += 1
            continue
        # comments
        if c == "/" and source.startswith("//", i):
            i += 2
            while i < n and source[i] != "\n":
                i += 1
            continue
        if c == "/" and source.startswith("/*", i):
            j = i + 2
            while j < n and not source.startswith("*/", j):
                j += 1
            j = min(j + 2, n)
            line += source.count("\n", i, j)
            i = j
            continue
        # regex literal: a `/` that is not dividing a value opens a regex whose
        # interior is never mutated (invariant #3). This catches a `/` after a
        # multi-char operator (`&&`/`=>`/`==`/...), which a punct allow-set misses.
        if c == "/" and not _prev_is_value(prev):
            j = _consume_regex(source, i)
            line += source.count("\n", i, j)
            i = j
            prev = "/re/"
            continue
        # strings + template
        if c in "'\"":
            j = _consume_string(source, i)
            line += source.count("\n", i, j)
            i = j
            prev = "'str'"
            continue
        if c == "`":
            j = _consume_template(source, i)
            line += source.count("\n", i, j)
            i = j
            prev = "`t`"
            continue
        # identifier / keyword
        if c in _ID_START:
            j = i + 1
            while j < n and source[j] in _ID_CONT:
                j += 1
            prev = source[i:j]
            i = j
            continue
        # number (int-bound handled in Task 2; consume whole so it is not
        # mis-split and `prev` tracking stays correct)
        if c in _DIGITS or (c == "." and i + 1 < n and source[i + 1] in _DIGITS):
            j = i + 1
            while j < n and (source[j] in _ID_CONT or source[j] == "."):
                j += 1
            prev = source[i:j]
            i = j
            continue
        # multi-char operator (maximal munch)
        op = _match_multichar_op(source, i)
        if op:
            if line in target_lines and op in _CMP_FLIP:
                out.append((i, len(op), "cmp-flip", _CMP_FLIP[op],
                            f"{op} -> {_CMP_FLIP[op]}", line))
            prev = op
            i += len(op)
            continue
        # single-char relational `<` / `>` (bare; multi-char forms handled above)
        if c in "<>":
            if line in target_lines:
                out.append((i, 1, "cmp-flip", _CMP_FLIP[c],
                            f"{c} -> {_CMP_FLIP[c]}", line))
            prev = c
            i += 1
            continue
        # any other single char
        prev = c
        i += 1
    return out


def generate_mutants(source: str, target_lines: set[int]) -> list[Mutant]:
    if not target_lines:
        return []
    mutants: list[Mutant] = []
    for off, length, op, new_text, desc, line in _candidates(source, target_lines):
        mutated = source[:off] + new_text + source[off + length:]
        mutants.append(Mutant(file="", line=line, op=op, description=desc,
                              source=mutated))
    mutants.sort(key=lambda m: (m.line, m.op, m.description))
    return mutants
```

- [ ] **Step 4: Run (green)**

Run: `python -m pytest tests/unit/test_jsmutate.py -v`
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/jsmutate.py tests/unit/test_jsmutate.py
git commit -F - <<'EOF'
feat(jsmutate): region-aware JS/TS token scanner + cmp-flip mutator

Owned pure-Python mutator (no AST -- no stdlib JS parser). Single forward-pass
scanner classifies code/string/template/comment/regex regions and applies
cmp-flip (===/!==, ==/!=, </<=, >/>=) only in code on the target lines. Never
mutates inside strings, comments, regex, or template literals. Maximal-munch
operator table so =>, <<, >>, === are not mis-split.
EOF
```

---

### Task 2: Remaining operators — logical-swap, int-bound, not-drop

**Files:**
- Modify: `src/aramid/jsmutate.py`
- Test: `tests/unit/test_jsmutate.py`

**Interfaces:**
- Consumes: the Task 1 scanner (`_candidates`, `_CMP_FLIP`, region skipping).
- Produces: three more operator families emitted by `_candidates`; helpers `_consume_number(source, i) -> (end, is_int, value)` and `_is_prefix(prev: str) -> bool`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_jsmutate.py`:

```python
def test_logical_swap():
    src = "function f(a, b) {\n  return a && b;\n}\n"
    muts = generate_mutants(src, {2})
    assert any("a || b" in m.source for m in muts)
    assert any(m.op == "logical-swap" for m in muts)


def test_int_bound_increments_integer_literal():
    src = "function f(a) {\n  return a + 3;\n}\n"
    muts = generate_mutants(src, {2})
    assert any("a + 4" in m.source for m in muts)
    assert any(m.op == "int-bound" and m.description == "3 -> 4" for m in muts)


def test_int_bound_skips_float_hex_and_bigint():
    for lit in ("1.5", "0xff", "10n", "1e3"):
        src = f"function f() {{\n  return {lit};\n}}\n"
        muts = generate_mutants(src, {2})
        assert all(m.op != "int-bound" for m in muts), f"{lit} must not int-bound"


def test_not_drop_in_prefix_position():
    src = "function f(a) {\n  if (!a) return 1;\n}\n"
    muts = generate_mutants(src, {2})
    assert any("if (a)" in m.source for m in muts)
    assert any(m.op == "not-drop" for m in muts)


def test_not_drop_leaves_inequality_and_ts_nonnull_alone():
    # `!=` is cmp-flip's job, not not-drop; TS `x!` (non-null assertion, `!`
    # after a value) must NOT be dropped.
    src = "function f(a, b) {\n  const c = a! + b;\n  return a != b;\n}\n"
    muts = generate_mutants(src, {2, 3})
    assert all(m.op != "not-drop" for m in muts)
    assert any(m.op == "cmp-flip" and "a == b" in m.source for m in muts)
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_jsmutate.py -k "logical or int_bound or not_drop" -v`
Expected: FAIL — these operators are not emitted yet.

- [ ] **Step 3: Implement the three operators**

In `src/aramid/jsmutate.py`, add the logical-flip map next to `_CMP_FLIP`:

```python
_LOGIC_FLIP = {"&&": "||", "||": "&&"}
```

Add two helpers above `_candidates`:

```python
def _consume_number(source: str, i: int):
    """Return (end_index, is_plain_int, value). Non-decimal-integer forms
    (hex/bin/oct/float/exponent/bigint) return is_plain_int=False."""
    n = len(source)
    if source[i] == "0" and i + 1 < n and source[i + 1] in "xXbBoO":
        j = i + 2
        while j < n and source[j] in _ID_CONT:
            j += 1
        return j, False, 0
    j = i
    is_float = False
    while j < n and source[j] in _DIGITS:
        j += 1
    if j < n and source[j] == ".":
        is_float = True
        j += 1
        while j < n and source[j] in _DIGITS:
            j += 1
    if j < n and source[j] in "eE":
        is_float = True
        j += 1
        if j < n and source[j] in "+-":
            j += 1
        while j < n and source[j] in _DIGITS:
            j += 1
    if j < n and source[j] in "nN":   # bigint suffix
        return j + 1, False, 0
    if is_float:
        return j, False, 0
    try:
        return j, True, int(source[i:j])
    except ValueError:
        return j, False, 0


def _is_prefix(prev: str) -> bool:
    """True when a `!` at the current position is a UNARY prefix `not` (operand
    start), so dropping it is meaningful. False after a value (identifier /
    number / ) / ] / } / string / template / regex) -- there `!` would be a TS
    non-null assertion. Keywords (prev is identifier-like) are treated as
    non-prefix: we MISS `return !x` (safe) rather than risk mutating `x!`."""
    if prev == "":
        return True
    if prev in (")", "]", "}", "'str'", "`t`", "/re/"):
        return False
    first = prev[:1]
    if first in _ID_START or first in _DIGITS:
        return False
    return True
```

Replace the whole-number consumption block in `_candidates` (currently just advances past the number) with int-bound emission:

```python
        # number
        if c in _DIGITS or (c == "." and i + 1 < n and source[i + 1] in _DIGITS):
            j, is_int, value = _consume_number(source, i)
            if line in target_lines and is_int:
                out.append((i, j - i, "int-bound", str(value + 1),
                            f"{value} -> {value + 1}", line))
            prev = source[i:j]
            i = j
            continue
```

In the multi-char operator branch, add logical-swap alongside cmp-flip:

```python
        op = _match_multichar_op(source, i)
        if op:
            if line in target_lines and op in _CMP_FLIP:
                out.append((i, len(op), "cmp-flip", _CMP_FLIP[op],
                            f"{op} -> {_CMP_FLIP[op]}", line))
            elif line in target_lines and op in _LOGIC_FLIP:
                out.append((i, len(op), "logical-swap", _LOGIC_FLIP[op],
                            f"{op} -> {_LOGIC_FLIP[op]}", line))
            prev = op
            i += len(op)
            continue
```

Add a not-drop branch AFTER the `<>` branch and BEFORE the "any other single char" fallback (a bare `!` reaches here only when `_match_multichar_op` did not match `!=`/`!==`):

```python
        # unary `!` in prefix position -> drop it (not-drop). `!=`/`!==` are
        # multi-char ops handled above, so a `!` here is a standalone `!`.
        if c == "!":
            if line in target_lines and _is_prefix(prev):
                out.append((i, 1, "not-drop", "", "drop unary !", line))
            prev = "!"
            i += 1
            continue
```

- [ ] **Step 4: Run (green)**

Run: `python -m pytest tests/unit/test_jsmutate.py -v`
Expected: all PASS (Task 1 tests still green — the number block now emits int-bound but region/cmp behavior is unchanged).

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/jsmutate.py tests/unit/test_jsmutate.py
git commit -F - <<'EOF'
feat(jsmutate): logical-swap, int-bound, not-drop operators

Completes the four operator families mirroring the Python mutator. int-bound
only touches plain decimal integers (skips hex/bin/oct/float/exponent/bigint);
not-drop only fires on a prefix `!` (operand start), leaving `!=`/`!==` to
cmp-flip and TS `x!` non-null assertions untouched.
EOF
```

---

### Task 3: Mutator hardening — determinism, scoping, invalid input, maximal munch

**Files:**
- Test: `tests/unit/test_jsmutate.py` (behavior already implemented; this task pins the invariants). If a test fails, fix `jsmutate.py` minimally.

- [ ] **Step 1: Write the invariant tests**

Append to `tests/unit/test_jsmutate.py`:

```python
def test_empty_target_lines_yields_nothing():
    src = "function f(a, b) {\n  return a === b;\n}\n"
    assert generate_mutants(src, set()) == []


def test_target_line_scoping():
    src = ("function f(a, b) {\n"
           "  const x = a === b;\n"    # line 2
           "  const y = a && b;\n"     # line 3
           "  return x;\n"
           "}\n")
    muts = generate_mutants(src, {3})
    assert muts, "line 3 has a mutable operator"
    assert all(m.line == 3 for m in muts)
    assert all("!==" not in m.source for m in muts)  # line 2 untouched


def test_ordering_is_deterministic():
    src = "function f(a, b) {\n  return a === b && a < 5;\n}\n"
    a = generate_mutants(src, {2})
    b = generate_mutants(src, {2})
    assert [(m.line, m.op, m.description) for m in a] == \
           [(m.line, m.op, m.description) for m in b]
    keys = [(m.line, m.op, m.description) for m in a]
    assert keys == sorted(keys)


def test_maximal_munch_does_not_mis_split_operators():
    # `=>` arrow, `<<`/`>>` shifts, `===` must not yield a `=`/`<`/`>`/`==`
    # mutation; only the genuine `===` (cmp-flip) and the `<` shift are here.
    src = "const f = (a, b) => {\n  return (a << 2) === (b >> 1);\n};\n"
    muts = generate_mutants(src, {2})
    # the only cmp-flip is on the real `===`
    assert [m.op for m in muts if m.op == "cmp-flip"] == ["cmp-flip"]
    assert any("!==" in m.source for m in muts)
    assert all("<=" not in m.source and ">=" not in m.source for m in muts)


def test_unterminated_string_does_not_hang_or_leak():
    src = "function f() {\n  return 'oops === ;\n}\n"   # unterminated string
    muts = generate_mutants(src, {2, 3})
    assert all("!==" not in m.source for m in muts)   # `===` was inside the string
```

- [ ] **Step 2: Run**

Run: `python -m pytest tests/unit/test_jsmutate.py -v`
Expected: all PASS (the Task 1/2 implementation already satisfies these). If any fail, fix `jsmutate.py` minimally (do not weaken region safety), then re-run.

- [ ] **Step 3: Ruff + commit**

```bash
python -m ruff check .
git add tests/unit/test_jsmutate.py src/aramid/jsmutate.py
git commit -F - <<'EOF'
test(jsmutate): pin determinism, line-scoping, maximal-munch, invalid-input

Locks the invariants the consumer relies on: deterministic (line, op, desc)
ordering for truncation-stable fingerprints; target-line scoping; =>/<<>>/===
maximal munch; unterminated string/regex never leak out of their region.
EOF
```

---

### Task 4: Config — `[js_mutation]` block

**Files:**
- Modify: `src/aramid/data/defaults.toml`, `src/aramid/config.py:44-45` (field) and `:107-108` (load)
- Test: `tests/unit/test_config.py` (append)

**Interfaces:**
- Produces: `Config.js_mutation: dict` with defaults `{enabled: True, max_mutants: 20, wall_budget_s: 600, mutant_timeout_s: 120}`.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_config.py` (mirror an existing `load_config` test's monkeypatch of `_user_config_path`):

```python
def test_js_mutation_defaults_present(tmp_path, monkeypatch):
    from aramid import config as config_mod
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(tmp_path)
    assert cfg.js_mutation.get("enabled") is True
    assert cfg.js_mutation.get("max_mutants") == 20
    assert cfg.js_mutation.get("wall_budget_s") == 600
    assert cfg.js_mutation.get("mutant_timeout_s") == 120
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_config.py -k js_mutation -v`
Expected: FAIL — `Config` has no `js_mutation` attribute.

- [ ] **Step 3: Implement**

`src/aramid/data/defaults.toml`, add after the `[mutation]` block (after its last line `confirm_cap = 3`):

```toml
[js_mutation]
enabled = true
max_mutants = 20        # generated-and-tested per queue item
wall_budget_s = 600     # whole-item wall clock for the mutant loop
mutant_timeout_s = 120  # per `<pm> test` invocation (single-stage)
```

`src/aramid/config.py`, add the field after `fuzz` (line 45):

```python
    fuzz: dict = field(default_factory=dict)
    js_mutation: dict = field(default_factory=dict)
```

And add the load line after `fuzz=merged.get(...)` (line 108):

```python
        fuzz=merged.get("fuzz", {}),
        js_mutation=merged.get("js_mutation", {}),
```

- [ ] **Step 4: Run (green)**

Run: `python -m pytest tests/unit/test_config.py -q`
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/data/defaults.toml src/aramid/config.py tests/unit/test_config.py
git commit -F - <<'EOF'
feat(config): [js_mutation] config block (mirrors [mutation], no confirm_cap)
EOF
```

---

### Task 5: The `js_mutation` consumer

**Files:**
- Create: `src/aramid/consumers/js_mutation.py`
- Modify: `src/aramid/commands/drain.py:29-32` (register)
- Test: `tests/integration/test_js_mutation_consumer.py`

**Interfaces:**
- Consumes: `jsmutate.generate_mutants`; `detectors.detect_tests`/`detect_package_manager`; `gitutil.diff_new_lines`/`_run`; `config_mod.filter_paths`; `base.ConsumerResult`/`DrainContext`/`prior_note_count`; `run_subprocess`/`ToolState`; `RawFinding`.
- Produces: `NAME="js_mutation"`, `consume(item, ctx) -> ConsumerResult`, `PIN_OCCURRENCE=True`; helpers `_link_node_modules(src_root, wt) -> bool`, `_unlink_node_modules(wt) -> None`, `_pm_test_argv(pm) -> list[str] | None`, `_is_test_file(rel) -> bool`.

- [ ] **Step 1: Write the hermetic gate tests + junction-safety test**

Create `tests/integration/test_js_mutation_consumer.py`:

```python
import subprocess

from aramid import config as config_mod
from aramid.consumers import js_mutation as jsc
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
def _js_repo(tmp_path, with_node_modules=True):
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
    (r / "calc.js").write_text("function isAdult(age) {\n  return true;\n}\n"
                               "module.exports = { isAdult };\n", encoding="utf-8")
    (r / "test.js").write_text("process.exit(0);\n", encoding="utf-8")
    if with_node_modules:
        (r / "node_modules").mkdir()
        (r / "node_modules" / ".marker").write_text("real deps", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "calc.js").write_text("function isAdult(age) {\n  return age >= 18;\n}\n"
                               "module.exports = { isAdult };\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)


def _consume(r, base, head, monkeypatch, tmp_path):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id="q1", base=base, head=head, score=55, reasons=("t",),
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
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/integration/test_js_mutation_consumer.py -v`
Expected: FAIL — `No module named 'aramid.consumers.js_mutation'`.

- [ ] **Step 3: Implement the consumer**

Create `src/aramid/consumers/js_mutation.py`:

```python
"""Drain-time JS/TS mutation consumer (2c-1b spec). Mutate the lines the queue
item's commits touched, inside a throwaway git worktree at the item's head with
the main repo's node_modules junctioned in, and report mutants the repo's own
`<pm> test` cannot kill as WARN-tier test-gap findings.

Single-stage (spec section 5): JS test runners have no portable "narrow to
module" flag, so `<pm> test` runs the FULL suite once per mutant -- a full-suite
PASS on a mutant IS a confirmed survivor. Mirrors consumers/mutation.py
otherwise (worktree at head, baseline give-up, WARN survivors, cost 0.0). Zero
tokens. OK-not-degraded for structural absence so a non-JS repo never pins the
queue item."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from aramid import config as config_mod
from aramid import detectors, gitutil, jsmutate
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.normalizer import RawFinding
from aramid.runners.base import ToolState, run_subprocess

NAME = "js_mutation"
_BASELINE_GIVE_UP = 3
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

# See consumers/mutation.py: budget-truncated batches -> pin occurrence_index 0.
PIN_OCCURRENCE = True


def _is_test_file(rel: str) -> bool:
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if "__tests__/" in p or p.startswith("__tests__/"):
        return True
    stem = name.rsplit(".", 1)[0]
    return stem.endswith(".test") or stem.endswith(".spec")


def _pm_test_argv(pm: str) -> list[str] | None:
    """Resolve `<pm> test` to a runnable argv, or None if the pm binary is not
    on PATH. shutil.which finds the `.cmd` shim on Windows (npm.cmd/pnpm.cmd/
    yarn.cmd) -- mirrors eslint/typecheck's Windows-aware binary resolution."""
    binp = shutil.which(pm)
    if binp is None:
        return None
    return [binp, "test"]


def _link_node_modules(src_root: Path, wt: Path) -> bool:
    """Junction (Windows) / symlink (Unix) src_root/node_modules into the
    worktree so `<pm> test` resolves deps. Returns False if the source has no
    node_modules; raises OSError on a link failure."""
    src_nm = src_root / "node_modules"
    if not src_nm.exists():
        return False
    dst_nm = wt / "node_modules"
    if sys.platform == "win32":
        cp = subprocess.run(["cmd", "/c", "mklink", "/J", str(dst_nm), str(src_nm)],
                            capture_output=True, text=True)
        if cp.returncode != 0:
            raise OSError(f"mklink /J failed: {(cp.stderr or '').strip()[:200]}")
    else:
        os.symlink(src_nm, dst_nm, target_is_directory=True)
    return True


def _unlink_node_modules(wt: Path) -> None:
    """Remove ONLY the link, never its target (invariant #7). Must run BEFORE
    the worktree directory is removed, or shutil.rmtree could follow the
    junction into the real node_modules."""
    dst = wt / "node_modules"
    try:
        if not dst.exists() and not dst.is_symlink():
            return
    except OSError:
        pass
    try:
        dst.unlink()          # Unix symlink
    except (OSError, PermissionError):
        try:
            os.rmdir(dst)     # Windows junction: unlinks the reparse point only
        except OSError:
            pass


def consume(item, ctx: DrainContext) -> ConsumerResult:
    mcfg = getattr(ctx.cfg, "js_mutation", None) or {}
    if not mcfg.get("enabled", True):
        return ConsumerResult(consumer=NAME, state="ok", note="disabled")
    max_mutants = int(mcfg.get("max_mutants", 20))
    wall_budget = float(mcfg.get("wall_budget_s", 600))
    mutant_timeout = float(mcfg.get("mutant_timeout_s", 120))

    changed = gitutil.diff_new_lines(ctx.root, item.base, item.head)
    files = sorted(f for f in changed
                   if f.lower().endswith(_JS_SUFFIXES) and not _is_test_file(f))
    if ctx.cfg is not None:
        files = config_mod.filter_paths(files, ctx.cfg)
    if not files:
        return ConsumerResult(consumer=NAME, state="ok", note="no js files in range")

    if "npm" not in detectors.detect_tests(ctx.root):
        # PERMANENT structural absence -> OK, never degraded (the drain refuses
        # to mark an item drained while any consumer is degraded). The 2c-1b
        # seam, mirroring the Python consumer's pytest gate.
        return ConsumerResult(consumer=NAME, state="ok",
                              note="no js test stack (mutation skipped)")

    pm = detectors.detect_package_manager(ctx.root) or "npm"
    test_argv = _pm_test_argv(pm)
    if test_argv is None:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="js package manager not found (mutation skipped)")
    if not (ctx.root / "node_modules").exists():
        return ConsumerResult(consumer=NAME, state="ok",
                              note="node_modules not installed (js mutation skipped)")

    if base.prior_note_count(ctx.ledger, NAME, item.id,
                             f"baseline failing @ {item.head[:12]}") >= _BASELINE_GIVE_UP:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="js mutation giving up: baseline persistently failing")

    started = time.monotonic()
    stats = {"generated": 0, "tested": 0, "killed": 0, "survived": 0,
             "timeouts": 0, "errors": 0, "truncated": False}
    findings: list[RawFinding] = []
    tmp = Path(tempfile.mkdtemp(prefix="aramid-jsmut-"))
    wt = tmp / "wt"
    linked = False
    try:
        cp = gitutil._run(ctx.root, "worktree", "add", "--detach", str(wt), item.head)
        if cp.returncode != 0:
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=f"worktree add failed: {(cp.stderr or '').strip()[:200]}")
        try:
            linked = _link_node_modules(ctx.root, wt)
        except OSError as exc:
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=f"could not link node_modules: {str(exc)[:150]}",
                                  duration_s=time.monotonic() - started)

        base_res = run_subprocess(test_argv, wt, mutant_timeout * 4)
        if base_res.state is not ToolState.OK or base_res.returncode != 0:
            # Load-bearing note prefix: the give-up counter matches it.
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=f"baseline failing @ {item.head[:12]}",
                                  duration_s=time.monotonic() - started)

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
            try:
                muts = jsmutate.generate_mutants(original, changed[rel])
            except Exception:
                stats["errors"] += 1
                continue
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
                    res = run_subprocess(test_argv, wt, mutant_timeout)
                    if res.state is ToolState.TIMEOUT:
                        stats["timeouts"] += 1
                    elif res.state is ToolState.OK and res.returncode == 0:
                        # Full suite PASSED with the mutant applied -> confirmed
                        # survivor (single stage IS the full suite).
                        stats["survived"] += 1
                        findings.append(RawFinding(
                            tool="js-mutation", rule=m.op, severity_raw="medium",
                            file=rel, line=m.line,
                            message=f"mutant survived: {m.description}"))
                    elif res.state is ToolState.OK:
                        # non-zero exit -> the suite (or compile) failed -> killed
                        stats["killed"] += 1
                    else:
                        # MISSING/CRASHED mid-run: unattributable, not a survivor
                        stats["errors"] += 1
                except Exception:
                    stats["errors"] += 1
                finally:
                    try:
                        src_path.write_text(original, encoding="utf-8")
                    except OSError:
                        stats["errors"] += 1
    finally:
        try:
            if linked:
                _unlink_node_modules(wt)   # BEFORE removing the worktree dir
            gitutil._run(ctx.root, "worktree", "remove", "--force", str(wt))
            gitutil._run(ctx.root, "worktree", "prune")
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            print(f"aramid: js_mutation: worktree cleanup leaked at {wt}", file=sys.stderr)

    note = f"{stats['survived']} survivor(s) of {stats['tested']} mutant(s) tested"
    if stats["truncated"]:
        note += " (truncated: budget/cap hit, remainder dropped)"
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=time.monotonic() - started, cost=0.0,
                          note=note, extra=dict(stats))


base.CONSUMERS[NAME] = sys.modules[__name__]
```

Register it in `src/aramid/commands/drain.py` after the `fuzz` import (line 32):

```python
from aramid.consumers import fuzz as _fuzz  # noqa: F401  (registers itself)
from aramid.consumers import js_mutation as _js_mutation  # noqa: F401  (registers itself)
```

- [ ] **Step 4: Run the gate/junction tests (green)**

Run: `python -m pytest tests/integration/test_js_mutation_consumer.py -v`
Expected: all PASS (these paths return before any real `<pm> test`; the junction test uses only the filesystem).

- [ ] **Step 5: Write the scripted-execution tests (red → green)**

Append the mutant-loop tests, which drive `consume` through the worktree/baseline/loop by monkeypatching `run_subprocess`, `_link_node_modules`, and `_unlink_node_modules` (no real Node, no real junction):

```python
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
    assert res.note.startswith(f"baseline failing @ {head[:12]}")


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
                                      "note": f"baseline failing @ {head[:12]}"}))
    finally:
        led.close()
    _scripted(monkeypatch, [(ToolState.OK, 0)])   # would pass, but give-up first
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "giving up" in res.note
```

Run: `python -m pytest tests/integration/test_js_mutation_consumer.py -v`
Expected: all PASS.

- [ ] **Step 6: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/consumers/js_mutation.py src/aramid/commands/drain.py tests/integration/test_js_mutation_consumer.py
git commit -F - <<'EOF'
feat(consumers): js_mutation drain consumer (owned mutator + single-stage npm test)

Mutates a queue item's changed JS/TS lines in a throwaway worktree at item.head
with node_modules junctioned from the main repo; runs the repo's own `<pm> test`
once per mutant (full-suite pass = confirmed survivor). WARN-tier survivors
(tool="js-mutation", medium sev, cost 0.0, PIN_OCCURRENCE). OK-skip for
structural absence (no js stack / no pm / no node_modules); DEGRADED + head-
scoped give-up for a red baseline; junction unlinked BEFORE worktree teardown so
the real node_modules is never deleted (invariant #7). Registered in drain.py.
EOF
```

---

### Task 6: Real-`npm test` smoke test (skip-gated) + final gate

**Files:**
- Test: `tests/integration/test_js_mutation_consumer.py` (append one skip-gated test)

- [ ] **Step 1: Add the skip-gated real-Node smoke test**

First edit the TOP import block of `tests/integration/test_js_mutation_consumer.py` to add `shutil` and `pytest` (keeping all imports at module top so ruff E402 never fires):

```python
import shutil
import subprocess

import pytest

from aramid import config as config_mod
```

(i.e. add `import shutil` above `import subprocess`, and `import pytest` as its own group before the `from aramid …` imports.)

Then append the skip-gated test + its helper:

```python
_HAS_NODE = shutil.which("node") is not None and shutil.which("npm") is not None


def _no_worktrees(r):
    cp = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                        capture_output=True, text=True)
    return len([ln for ln in cp.stdout.splitlines() if ln.strip()]) == 1


@pytest.mark.skipif(not _HAS_NODE, reason="node+npm not on PATH (Python-only CI)")
def test_real_npm_weak_suite_reports_survivor(tmp_path, monkeypatch):
    # End-to-end with a REAL `npm test`: a weak test (exit 0 regardless) cannot
    # kill the `>= -> >` mutant on the changed line, so it must be reported.
    r, base, head = _js_repo(tmp_path)   # test.js is `process.exit(0)` = weak
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "the weak suite cannot kill the mutant -> survivor"
    assert res.findings[0].tool == "js-mutation"
    assert _no_worktrees(r)
```

(`_js_repo` seeds a real `node_modules/` dir, so `_link_node_modules` junctions it and `node test.js` runs. On CI without Node the test is skipped, keeping CI green. `os`/`sys` are already imported for the junction-safety test.)

- [ ] **Step 2: Run**

Run: `python -m pytest tests/integration/test_js_mutation_consumer.py -q`
Expected: PASS locally (Node present) or SKIP (no Node) for the real test; all others PASS.

- [ ] **Step 3: Full suite + ruff**

Run: `python -m pytest -q` — expect 791 base + new, all green.
Run: `python -m ruff check .` — must equal the recorded baseline (43).

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_js_mutation_consumer.py
git commit -F - <<'EOF'
test(js_mutation): skip-gated real-npm survivor smoke test

Exercises the full worktree + junction + `node test.js` path when node/npm are
on PATH; skipped on the Python-only CI so CI stays green.
EOF
```

- [ ] **Step 5: Whole-branch review + finish**

Dispatch the sonnet whole-branch adversarial review (project convention), apply any fix wave, then use superpowers:finishing-a-development-branch.

---

## Self-Review notes (author)

- **Spec coverage:** §2 modules → Tasks 1-3 (jsmutate) + Task 5 (consumer). §3 stack gate → Task 5. §4 lexer + 4 operators → Tasks 1-3. §5 single-stage → Task 5 mutant loop. §6 worktree + node_modules junction + safe teardown → Task 5 (`_link/_unlink_node_modules`, teardown order) + its junction-safety test. §7 baseline + give-up → Task 5. §8 config → Task 4. §9 findings → Task 5. §10 file selection → Task 5 (`_is_test_file`, `_JS_SUFFIXES`). §11 error handling → Task 5. §12 testing/CI → Tasks 1-6 (pure-Python unit + scripted consumer + skip-gated real-npm). §13/§15 decisions/invariants → covered; invariant #7 has a dedicated test (`test_link_and_unlink_node_modules_preserves_target`).
- **Placeholder scan:** every code step shows complete code; test bodies are concrete; no TBD/TODO.
- **Type consistency:** `Mutant(file, line, op, description, source)` and `generate_mutants(source, target_lines)` identical across tasks and to the Python mutator. `_candidates` tuple shape `(offset, length, op, new_text, description, line)` consistent in Tasks 1-2. Consumer helper names (`_link_node_modules`, `_unlink_node_modules`, `_pm_test_argv`, `_is_test_file`) identical between the implementation and the tests. `stats` keys (`generated/tested/killed/survived/timeouts/errors/truncated`) consistent between the consumer and its assertions.
- **Ordering:** Task 4 (config) precedes Task 5 (consumer reads `cfg.js_mutation`). Tasks 1-3 (mutator) precede Task 5 (consumer imports `jsmutate`). Correct.
