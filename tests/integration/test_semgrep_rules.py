"""integration: the vendored, offline OWASP semgrep ruleset actually loads
and fires. This is the regression test for the bug described in Task 8a:
real semgrep runs used to crash because
`aramid.runners.semgrep.VENDORED_RULES_PATH` (`src/aramid/rules/owasp.yml`)
did not exist on disk.

Semgrep ships as a `semgrep`/`semgrep.exe` console-script entry point that is
not necessarily on PATH -- on this dev machine it installs into the
interpreter's *user-site* Scripts dir (`site-packages/../Scripts`), not
`sys.executable`'s own Scripts dir, and `python -m semgrep` is deprecated as
of 1.38 and exits 2 without running anything. `_find_semgrep()` below
searches `shutil.which`, the dir next to `sys.executable`, and every
`site-packages` sibling on `sys.path` for the real console script -- the
same places `aramid.runners.base.run_subprocess`'s own `shutil.which("semgrep")`
check would find it once that directory is on PATH.

If no working semgrep binary is found, the live-scan tests below skip with a
clear reason (portability for CI environments without semgrep installed).
`test_owasp_yaml_parses` never skips -- it is the brief's documented minimum
bar (valid YAML) and runs regardless of whether semgrep itself is runnable.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from aramid.runners import semgrep as semgrep_runner
from aramid.runners.base import RunContext, ToolState


def _find_semgrep() -> Path | None:
    candidates: list[Path] = []
    which = shutil.which("semgrep")
    if which:
        candidates.append(Path(which))
    exe_dir = Path(sys.executable).parent
    candidates.append(exe_dir / "Scripts" / "semgrep.exe")
    candidates.append(exe_dir / "semgrep")
    for entry in sys.path:
        p = Path(entry)
        if p.name == "site-packages":
            candidates.append(p.parent / "Scripts" / "semgrep.exe")
            candidates.append(p.parent / "bin" / "semgrep")
    for c in candidates:
        if c.exists():
            return c
    return None


_SEMGREP_BIN = _find_semgrep()
_SKIP_REASON = (
    "semgrep console-script not found via shutil.which, next to sys.executable, "
    "or next to any sys.path site-packages dir -- cannot exercise a live scan "
    "in this environment."
)


@pytest.fixture
def semgrep_path_env(monkeypatch):
    """Prepend the discovered semgrep's directory to PATH.

    Needed for two independent reasons: (1) `aramid.runners.base.run_subprocess`
    gates on `shutil.which(argv[0])` before it will even attempt to run
    "semgrep", and (2) the semgrep.exe console script itself shells out to a
    sibling `pysemgrep` process by bare name -- if that directory isn't on
    PATH, semgrep.exe fails with "executing pysemgrep failed" even when
    invoked by its own full path.
    """
    assert _SEMGREP_BIN is not None
    monkeypatch.setenv("PATH", str(_SEMGREP_BIN.parent) + os.pathsep + os.environ.get("PATH", ""))


# --- minimum bar: valid YAML, runs even with no semgrep installed at all ----

def test_owasp_yaml_parses():
    data = yaml.safe_load(semgrep_runner.VENDORED_RULES_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert len(data["rules"]) >= 10


# --- (a): the vendored ruleset loads OFFLINE (no registry fetch), for real --

@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_semgrep_validate_loads_ruleset_offline(semgrep_path_env):
    result = subprocess.run(
        [str(_SEMGREP_BIN), "--validate", "--config", str(semgrep_runner.VENDORED_RULES_PATH),
         "--metrics=off"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # semgrep's stream for this message moved between releases (stderr on the
    # 1.100.x line, stdout on current) -- match the combined output.
    combined = (result.stdout + result.stderr).lower()
    assert "configuration is valid" in combined, result.stdout + result.stderr


# --- (b)/(c): the real aramid.runners.semgrep.run()/parse() path, live ------

_SQLI_SRC = (
    'def get_user(cursor, user):\n'
    '    return cursor.execute("SELECT * FROM t WHERE x=" + user)\n'
)
_PICKLE_SRC = (
    'import pickle\n\n\n'
    'def load(data):\n'
    '    return pickle.loads(data)\n'
)
_CLEAN_SRC = (
    'import hashlib\n\n\n'
    'def get_user(cursor, user):\n'
    '    return cursor.execute("SELECT * FROM t WHERE x=%s", (user,))\n\n\n'
    'def strong_hash(x):\n'
    '    return hashlib.sha256(x).hexdigest()\n'
)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_reports_sqli_and_pickle_as_error(tmp_path, semgrep_path_env):
    """Drives the exact path aramid.pipeline uses at scan time: run() builds
    the argv and shells out to real semgrep against the vendored ruleset,
    parse() turns the JSON report into RawFindings. Proves the crash
    described in the brief is fixed, not just that some semgrep somewhere
    can read this YAML."""
    (tmp_path / "vuln.py").write_text(_SQLI_SRC + "\n" + _PICKLE_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["vuln.py"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    findings = semgrep_runner.parse(result, ctx)
    sqli = [f for f in findings if "sqli" in f.rule]
    pickled = [f for f in findings if "pickle" in f.rule]

    assert sqli, findings
    assert pickled, findings
    assert all(f.severity_raw == "ERROR" for f in sqli)
    assert all(f.severity_raw == "ERROR" for f in pickled)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_clean_code_yields_zero_findings(tmp_path, semgrep_path_env):
    (tmp_path / "clean.py").write_text(_CLEAN_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["clean.py"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    findings = semgrep_runner.parse(result, ctx)
    assert findings == []


# --- Task 8a precision fix: JS BLOCK-tier eval/Function rules must not fire
# on literal-only arguments (I1/I2). Each pair below drives the exact
# aramid.runners.semgrep.run()/parse() path against real semgrep so the
# vendored `pattern-not` exclusions are proven live, not just YAML-valid.
# NOTE: the eval()/new Function() calls below are inert JS *source text*
# stored as Python string literals -- they are written to temp .js files for
# semgrep to statically scan and are never executed by this test process. ---

_NEW_FUNCTION_LITERAL_SRC = (
    'function safe() {\n'
    '  return new Function("return 1+1");\n'
    '}\n'
)
_NEW_FUNCTION_TAINTED_SRC = (
    'function unsafe(userInput) {\n'
    '  return new Function(userInput);\n'
    '}\n'
)
_EVAL_LITERAL_SRC = (
    'function safe() {\n'
    '  return eval("1+1");\n'
    '}\n'
)
_EVAL_TAINTED_SRC = (
    'function unsafe(userInput) {\n'
    '  return eval(userInput);\n'
    '}\n'
)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_function_constructor_literal_arg_no_finding(tmp_path, semgrep_path_env):
    """I1: new Function() with only a string-literal argument is safe,
    fixed source -- must NOT trip javascript-dangerous-function-constructor."""
    (tmp_path / "newfunc_literal.js").write_text(_NEW_FUNCTION_LITERAL_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["newfunc_literal.js"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    findings = semgrep_runner.parse(result, ctx)
    function_ctor = [f for f in findings if "dangerous-function-constructor" in f.rule]
    assert function_ctor == [], findings


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_function_constructor_tainted_arg_still_fires(tmp_path, semgrep_path_env):
    """I1 regression guard: new Function(variable) still trips ERROR."""
    (tmp_path / "newfunc_tainted.js").write_text(_NEW_FUNCTION_TAINTED_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["newfunc_tainted.js"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    findings = semgrep_runner.parse(result, ctx)
    function_ctor = [f for f in findings if "dangerous-function-constructor" in f.rule]
    assert function_ctor, findings
    assert all(f.severity_raw == "ERROR" for f in function_ctor)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_eval_literal_arg_no_finding(tmp_path, semgrep_path_env):
    """I2: eval() with only a string-literal argument is safe, fixed source
    -- must NOT trip javascript-eval-untrusted-data."""
    (tmp_path / "eval_literal.js").write_text(_EVAL_LITERAL_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["eval_literal.js"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    findings = semgrep_runner.parse(result, ctx)
    eval_untrusted = [f for f in findings if "eval-untrusted-data" in f.rule]
    assert eval_untrusted == [], findings


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_eval_tainted_arg_still_fires(tmp_path, semgrep_path_env):
    """I2 regression guard: eval(variable) still trips ERROR."""
    (tmp_path / "eval_tainted.js").write_text(_EVAL_TAINTED_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["eval_tainted.js"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    findings = semgrep_runner.parse(result, ctx)
    eval_untrusted = [f for f in findings if "eval-untrusted-data" in f.rule]
    assert eval_untrusted, findings
    assert all(f.severity_raw == "ERROR" for f in eval_untrusted)


# --- Rust security rules ----------------------------------------------------
#
# Closes the gap round 16 left explicitly open: clippy gave Rust *lint*
# coverage, but the vendored ruleset carried 13 rules across javascript,
# typescript and python and ZERO for Rust, so semgrep scanned Rust code and
# could never match anything -- independent of `semgrep_block_armed`.
#
# Rust's memory safety does not extend to what it hands an interpreter: a
# shell or a SQL engine parses attacker-controlled text exactly as unsafely
# as it does from Python. Those two rules are therefore BLOCK-tier under
# `owasp-top-ten.`, matching the Python/JS rules one-for-one. The
# memory-safety lints live under `rust-memory-safety.` precisely so they do
# NOT block by default -- see semgrep.VENDORED_RULE_PREFIXES.

_RUST_CMD_INJECTION_SRC = '''
use std::process::Command;
pub fn run(user: &str) {
    let _ = Command::new("sh").arg("-c").arg(user).output();
}
'''

_RUST_CMD_SAFE_SRC = '''
use std::process::Command;
pub fn run(user: &str) {
    let _ = Command::new("sh").arg("-c").arg("ls -la").output();
    let _ = Command::new("ls").arg(user).output();
}
'''

_RUST_UNSAFE_SRC = '''
pub unsafe fn f(bytes: &[u8], v: &mut Vec<u8>, x: &u64) {
    let _: &i64 = std::mem::transmute(x);
    let _ = std::str::from_utf8_unchecked(bytes);
    let _ = bytes.get_unchecked(99);
    v.set_len(1024);
}
'''


def test_ruleset_covers_rust_at_all():
    """Never skips: the point of the gap was that Rust had no rules, so the
    minimum bar is checkable without a semgrep binary."""
    doc = yaml.safe_load(semgrep_runner.VENDORED_RULES_PATH.read_text(encoding="utf-8"))
    rust_rules = [r for r in doc["rules"] if "rust" in r.get("languages", [])]
    assert rust_rules, "the vendored ruleset must carry Rust rules"

    from aramid.runners.semgrep import VENDORED_RULE_PREFIXES
    for rule in rust_rules:
        assert rule["id"].startswith(VENDORED_RULE_PREFIXES), (
            f"{rule['id']} is in no vendored namespace, so `_canonical_rule_id` "
            f"would leave a machine-dependent config path attached to it")


def test_rust_memory_safety_rules_are_outside_the_block_namespace():
    """The semgrep tier is rule-id driven. These lints have legitimate uses
    in FFI and perf-critical code, so shipping them inside `owasp-top-ten.`
    would make every `transmute` in a codebase block a push by default."""
    doc = yaml.safe_load(semgrep_runner.VENDORED_RULES_PATH.read_text(encoding="utf-8"))
    memory = [r["id"] for r in doc["rules"] if r["id"].startswith("rust-memory-safety.")]
    assert memory, "expected the Rust memory-safety lints"
    assert not any(r.startswith("owasp-top-ten.") for r in memory)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_rust_command_injection_fires(tmp_path, semgrep_path_env):
    (tmp_path / "vuln.rs").write_text(_RUST_CMD_INJECTION_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["vuln.rs"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    findings = semgrep_runner.parse(result, ctx)
    hits = [f for f in findings if "rust-command-injection" in f.rule]
    assert hits, findings
    assert all(f.severity_raw == "ERROR" for f in hits)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_rust_literal_shell_and_direct_argv_do_not_fire(tmp_path, semgrep_path_env):
    """An all-literal shell string is not injectable, and passing user data
    as its own argv entry never reaches a shell parser. Both must stay
    silent or the rule is unusable noise on real codebases."""
    (tmp_path / "safe.rs").write_text(_RUST_CMD_SAFE_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["safe.rs"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)
    assert [f for f in semgrep_runner.parse(result, ctx)
            if "rust-command-injection" in f.rule] == []


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_live_scan_rust_memory_safety_lints_fire_at_warn_tier(tmp_path, semgrep_path_env):
    (tmp_path / "unsafe.rs").write_text(_RUST_UNSAFE_SRC, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=["unsafe.rs"])

    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    findings = semgrep_runner.parse(result, ctx)
    rules = {f.rule for f in findings}
    for expected in ("rust-memory-safety.transmute",
                     "rust-memory-safety.from-utf8-unchecked",
                     "rust-memory-safety.get-unchecked",
                     "rust-memory-safety.set-len"):
        assert expected in rules, (expected, rules)
    # Canonicalised, not carrying the config path -- otherwise the rule id,
    # and every fingerprint built from it, differs per machine.
    assert all(not f.rule.startswith("/") and "aramid" not in f.rule.split(".")[0]
               for f in findings if f.rule.startswith("rust-memory-safety."))


# --- the SQL blind-spot fixture (interop round 86) -------------------------
#
# graphite delivered a 14-form fixture in which every hazardous shape is PAIRED
# with a safe twin that looks almost identical, and ran both their taint oracle
# and this rule against it.
#
# The fixture's own warning drives the structure below: "a score against this
# fixture is a probe result, not a benchmark". Every shape in it came from a
# PUBLISHED blind-spot list, so it holds the gaps both sides already knew about
# and structurally cannot hold the ones they do not -- the round-69 fixture
# scored 6/6 while it and the oracle were both blind to
# build-then-execute-inside-a-loop, because neither had a loop.
#
# So the four shapes this rule MISSES are xfail, never asserted absent.
# Asserting them absent would encode four defects as expected behaviour and
# hand a red "regression" to whoever eventually fixes one.
_BLIND_SPOT_SRC = '''\
import sqlite3

cur = sqlite3.connect(":memory:").cursor()

UNTRUSTED = "'; DROP TABLE t; --"
UNTRUSTED_VALUES = [UNTRUSTED, "b"]
UNTRUSTED_TABLES = [UNTRUSTED, "beta"]
MIGRATIONS = {"alpha": ("ALTER TABLE alpha ADD COLUMN c TEXT", ["c"])}


def _assemble(value):
    return "SELECT * FROM t WHERE x = '" + value + "'"


def bs_cross_function():
    cur.execute(_assemble(UNTRUSTED))


def _assemble_parameterized():
    return "SELECT * FROM t WHERE x = ?"


def bs_cross_function_safe():
    cur.execute(_assemble_parameterized(), (UNTRUSTED,))


class Repo:
    def build(self):
        self.q = f"SELECT * FROM t WHERE x = '{UNTRUSTED}'"

    def run(self):
        cur.execute(self.q)


class SafeRepo:
    def build(self):
        self.q = "SELECT * FROM t WHERE x = ?"

    def run(self):
        cur.execute(self.q, (UNTRUSTED,))


def bs_subscript_target():
    d = {}
    d["q"] = f"SELECT * FROM t WHERE x = '{UNTRUSTED}'"
    cur.execute(d["q"])


def bs_container_iterated():
    statements = []
    for table in UNTRUSTED_TABLES:
        statements.append(f"DROP TABLE {table}")
    for statement in statements:
        cur.execute(statement)


def bs_container_iterated_safe():
    statements = ["SELECT 1", "SELECT 2"]
    for statement in statements:
        cur.execute(statement)


def bs_augmented_in_loop():
    query = "SELECT * FROM t WHERE 1=0"
    for value in UNTRUSTED_VALUES:
        query += f" OR x = '{value}'"
    cur.execute(query)


def bs_augmented_in_loop_safe():
    query = "SELECT * FROM t WHERE 1=0"
    params = []
    for value in UNTRUSTED_VALUES:
        query += " OR x = ?"
        params.append(value)
    cur.execute(query, params)


def bs_one_branch_only(flag):
    query = "SELECT * FROM t WHERE x = ?"
    if flag:
        query = f"SELECT * FROM t WHERE x = '{UNTRUSTED}'"
    cur.execute(query)


def bs_dead_interpolation():
    query = f"SELECT * FROM t WHERE x = '{UNTRUSTED}'"
    query = "SELECT * FROM t WHERE x = ?"
    cur.execute(query, (UNTRUSTED,))


def bs_tuple_unpacking_safe():
    for _table, (ddl, _cols) in MIGRATIONS.items():
        cur.execute(ddl)


def bs_tuple_unpacking_tainted():
    for table, (suffix, _cols) in {"alpha": (UNTRUSTED, [])}.items():
        ddl = f"ALTER TABLE {table} ADD COLUMN {suffix} TEXT"
        cur.execute(ddl)


def bs_probe_unrelated_execute():
    _unused = f"SELECT * FROM t WHERE x = '{UNTRUSTED}'"
    cur.execute("SELECT 1")
'''

# Written HERE, not by graphite: the adversarial cases for the dead-interpolation
# FIX, as opposed to for the rule's original behaviour.
_REBIND_SRC = '''\
import sqlite3

cur = sqlite3.connect(":memory:").cursor()
UNTRUSTED = "'; DROP TABLE t; --"


def adv_conditional_rebind():
    query = f"SELECT * FROM t WHERE x = '{UNTRUSTED}'"
    if UNTRUSTED:
        query = "SELECT * FROM t WHERE x = ?"
    cur.execute(query)


def adv_rebind_after_execute():
    query = f"SELECT * FROM t WHERE x = '{UNTRUSTED}'"
    cur.execute(query)
    query = "SELECT * FROM t WHERE x = ?"


def adv_concat_dead_interpolation():
    query = "SELECT * FROM t WHERE x = '" + UNTRUSTED + "'"
    query = "SELECT * FROM t WHERE x = ?"
    cur.execute(query, (UNTRUSTED,))
'''


_SCAN_CACHE: dict = {}


def _flagged_functions(tmp_path, source: str, name: str = "sqlfix.py") -> set:
    """Names of the functions semgrep flagged, through the real runner path.

    Reports the ENCLOSING function rather than a line number, so the assertions
    read as claims about forms and survive the fixture being reformatted.

    Cached on the source text, which is the ONLY input that can change the
    answer -- `tmp_path` varies per test but nothing in the scan depends on it.
    Nine call sites over two distinct sources was nine real semgrep spawns and
    ~105 s of a suite that is already long.
    """
    import ast

    if source in _SCAN_CACHE:
        return _SCAN_CACHE[source]

    (tmp_path / name).write_text(source, encoding="utf-8")
    ctx = RunContext(root=tmp_path, files=[name])
    result = semgrep_runner.run(ctx)
    assert result.state is ToolState.OK, (result.state, result.stderr)

    spans = sorted((n.lineno, n.end_lineno, n.name)
                   for n in ast.walk(ast.parse(source))
                   if isinstance(n, ast.FunctionDef))

    def owner(line: int) -> str:
        best = None
        for start, end, fn in spans:
            if start <= line <= end and (best is None or start > best[0]):
                best = (start, fn)
        return best[1] if best else "<module>"

    _SCAN_CACHE[source] = {owner(f.line) for f in semgrep_runner.parse(result, ctx)}
    return _SCAN_CACHE[source]


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_blind_spot_safe_twins_are_never_flagged(tmp_path, semgrep_path_env):
    """PRECISION contract -- the half the fixture exists for.

    Every hazardous form is paired with a twin that LOOKS the same and is not
    vulnerable, so a matcher keying on syntax rather than flow is caught
    over-firing instead of rewarded for it. Most sharply
    `bs_augmented_in_loop_safe`: the CORRECT idiom for a variable-length
    clause, where `+=` still appears in a loop directly above an execute, but
    what accumulates is placeholders and the values travel bound.
    """
    flagged = _flagged_functions(tmp_path, _BLIND_SPOT_SRC)

    for safe in ("bs_cross_function_safe", "bs_container_iterated_safe",
                  "bs_augmented_in_loop_safe", "bs_tuple_unpacking_safe",
                  "run"):
        assert safe not in flagged, (safe, sorted(flagged))


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_the_scope_pairing_probe_is_not_flagged(tmp_path, semgrep_path_env):
    """graphite hypothesised the false positive came from scope-level pairing
    -- any build plus any execute in one function -- then added this probe,
    which KILLED that hypothesis. It matters because under scope-level pairing
    the catch on `bs_subscript_target` would have been earned by the very
    looseness that produced the false positive: right answer, wrong reason.

    Pinned so a future widening cannot quietly make that true.
    """
    assert "bs_probe_unrelated_execute" not in _flagged_functions(tmp_path, _BLIND_SPOT_SRC)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_blind_spot_recall_floor_is_held(tmp_path, semgrep_path_env):
    """RECALL floor: the two fixture forms this rule genuinely catches. No
    precision work may cost them."""
    flagged = _flagged_functions(tmp_path, _BLIND_SPOT_SRC)

    assert "bs_subscript_target" in flagged, sorted(flagged)
    assert "bs_tuple_unpacking_tainted" in flagged, sorted(flagged)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_dead_interpolation_is_not_flagged(tmp_path, semgrep_path_env):
    """The reported false positive. The interpolated binding is unconditionally
    replaced by a constant before a parameterized execute, so nothing tainted
    reaches the database -- and it was flagged anyway, because the sequential
    patterns pair on the NAME and semgrep's `...` spans the rebinding."""
    assert "bs_dead_interpolation" not in _flagged_functions(tmp_path, _BLIND_SPOT_SRC)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_a_conditional_rebind_is_still_reported(tmp_path, semgrep_path_env):
    """THE GUARD ON THE FIX, and why the pattern-not requires adjacency.

    The first version put `...` between the two assignments. It cleared the
    false positive and was MEASURED to drop this: with `...` there an
    intervening `if` matches too, so a rebind on only ONE branch reads as
    unconditional and the still-vulnerable else path stops being reported.
    A precision fix that costs a true positive is not a precision fix.
    """
    assert "adv_conditional_rebind" in _flagged_functions(
        tmp_path, _REBIND_SRC, name="rebind.py")


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_a_rebind_after_the_execute_does_not_excuse_it(tmp_path, semgrep_path_env):
    """Ordering is load-bearing: a safe reassignment BELOW the execute cannot
    save it. Without this arm, a pattern-not keyed on "the name is reassigned
    to a literal somewhere" would look correct."""
    assert "adv_rebind_after_execute" in _flagged_functions(
        tmp_path, _REBIND_SRC, name="rebind.py")


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_dead_interpolation_is_cleared_for_every_build_form(tmp_path, semgrep_path_env):
    """The reported repro used an f-string; the defect never was specific to
    one. Found here rather than reported: the same shape built by concatenation
    fired identically, so the fix covers all five build forms."""
    assert "adv_concat_dead_interpolation" not in _flagged_functions(
        tmp_path, _REBIND_SRC, name="rebind.py")


# --- documented gaps: missed by this rule AND by graphite's oracle ----------
#
# Four of the seven real hazards in the fixture are invisible to BOTH
# instruments -- the failure mode two independent implementations are supposed
# to rule out. They fail together because they fail for the same structural
# reason: both reason within one scope about one name. Any recall figure
# derived by comparing them is uninformative on this class.
#
# xfail rather than an absence assert: a fix should XPASS these.
_DOUBLE_BLIND = [
    ("bs_cross_function",
     "query assembled in a helper and executed one frame away"),
    ("Repo.run",
     "built into self.q in one method, executed in another (attribute target)"),
    ("bs_container_iterated",
     "list of queries built in a loop then iterated -- nothing tainted is ever "
     "the direct argument to execute"),
    ("bs_augmented_in_loop",
     "`q +=` accumulating in a loop -- no single statement builds the query"),
]


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
@pytest.mark.parametrize("func,gap", _DOUBLE_BLIND, ids=[f for f, _ in _DOUBLE_BLIND])
def test_known_double_blind_shapes(tmp_path, semgrep_path_env, func, gap):
    """These SHOULD be reported and are not."""
    if func not in _flagged_functions(tmp_path, _BLIND_SPOT_SRC):
        pytest.xfail(f"known gap, missed by this rule and by graphite's oracle: {gap}")
