"""toolset -- the live predicate: which tool names would THIS repo produce
findings under, right now (not which tools ran in some past gate run --
that's `scope_tools`, computed per-run in aramid.pipeline.run_gate from
actual RunnerResult.state). Spec: docs/superpowers/specs/2026-07-28-aramid-
unreachable-findings-design.md, section 3.

RUNNER_TOOL_NAMES is the retireable universe -- every tool name a real
runner (aramid.pipeline.RUNNERS) can stamp onto a Finding.tool.
PRODUCER_TOOL_NAMES is never retireable BY CONSTRUCTION: excluding those
families from the universe, rather than checking for them at the point of
use, is what makes them un-selectable even by a caller who never considers
the question (spec section 7).
"""
from pathlib import Path

from aramid.detectors import detect_package_manager, detect_stacks, detect_tests
from aramid.pipeline import GATE_RUNNER_KEYS, _is_applicable
from aramid.runners import clippy, deps, eslint, ruff, typecheck
from aramid.runners import tests as tests_runner
from aramid.runners.base import RunContext

# Every tool name a real runner (aramid.pipeline.RUNNERS) can stamp onto a
# Finding.tool. Measured by reading every RawFinding(...) construction site
# in src/aramid/runners/ (spec section 3) and pinned by
# test_toolset.py's membership/disjointness test.
#
# "tests" (the literal registry key, not a real binary) is included
# deliberately -- see this project's T-8 plan, Global Constraint 5. It is
# the ONE name in this set that selected_tool_names() below does not
# derive from a sub-tool's own applicability check alone; it tracks the
# "tests" runner key's OWN applicability instead.
RUNNER_TOOL_NAMES = frozenset({
    "gitleaks", "semgrep", "ruff", "eslint", clippy.NAME,
    typecheck.NAME_TSC, typecheck.NAME_MYPY,
    deps.NAME_PIP_AUDIT, deps.NAME_CARGO_AUDIT,
    deps.NAME_CARGO_AUDIT_WARNINGS, "npm", "pnpm", "yarn",
    "pytest", "tests",
})

# The producer/consumer families from spec section 1.2/7: async consumers
# (llm-review, mutation, js-mutation, fuzz, dast) and synchronous producers
# appended outside the runner dict (tdd, red-proof, mutation-score). Each
# has its own resolution mechanism (an auto_resolve_* function, or -- for
# mutation-score -- no persistence to resolve at all, see
# mutation_score_gate.py's own docstring); none is ever retired by hand.
#
# "regression_pack" is deliberately NOT here: it reuses the tool name
# "semgrep" for its findings (consumers/regression_pack.py:41,46 --
# json_or_crashed("semgrep", ...) then semgrep_runner.parse(...)), never
# its own name, so it needs no entry in either set (verified by reading;
# see the T-8 plan's Global Constraint 6).
PRODUCER_TOOL_NAMES = frozenset({
    "tdd", "red-proof", "mutation", "mutation-score",
    "llm-review", "js-mutation", "fuzz", "dast",
})


def _build_ctx(root: Path, cfg) -> RunContext:
    """A RunContext built directly from config/filesystem state, with no
    gate run -- mirrors the subset of aramid.pipeline.run_gate's own
    RunContext construction (pipeline.py:465-474) that pipeline._is_applicable
    actually reads: stacks, pkg_manager, and the [tests] trio. Fields
    _is_applicable never reads (files, rng, gate_deadline, ...) are left at
    their RunContext defaults."""
    tests_cfg = cfg.tests if isinstance(cfg.tests, dict) else {}
    return RunContext(
        root=root,
        pkg_manager=detect_package_manager(root),
        stacks=detect_stacks(root, root),
        test_command=tests_cfg.get("command", cfg.test_command),
        tests_enabled=tests_cfg.get("enabled", True),
        detected_tests=detect_tests(root),
        cargo_audit_warnings=(cfg.deps or {}).get("cargo_audit_warnings", False)
        if isinstance(getattr(cfg, "deps", None), dict) else False,
    )


def selected_tool_names(root: Path, cfg) -> set[str]:
    """Which tool names this repo would produce findings under, right now.
    Reuses pipeline._is_applicable's own rules, unioned across EVERY gate's
    key list -- Gate.PRE_COMMIT's ["gitleaks","ruff"] is not a subset of
    Gate.PRE_PUSH's list (ruff only ever runs at pre-commit; ruff findings
    must still count as "selected" when checking a pre-commit-produced
    finding). Then expands each applicable key to the tool name(s) a
    Finding.tool actually carries for it -- the expansion is NOT identity
    for three of the keys (spec section 3's table).

    Known conservative limitation, inherited from the spec (section 3.1),
    not fixed here: "npm" is emitted by two different runners (deps.py's
    JS dependency audit and tests.py's npm test suite) -- one string, two
    producers. A repo that loses its npm TEST suite while keeping its npm
    DEPS audit has a stranded finding whose tool still reads as selected,
    so mark-unreachable will refuse to retire it. Fails toward refusing to
    retire, which is the safe direction.
    """
    ctx = _build_ctx(root, cfg)
    all_keys = {key for keys in GATE_RUNNER_KEYS.values() for key in keys}
    return _expand_keys(all_keys, root, ctx)


def expected_tool_names(root: Path, cfg, gate) -> set[str]:
    """Which tool names THIS GATE should produce findings under, right now.

    `selected_tool_names` above answers the same question unioned across every
    gate, which is right for "can this finding's producer still run anywhere"
    and wrong for "did this gate run what it was supposed to". Those differ by
    exactly the tools that are tier-specific: ruff only ever runs at
    pre-commit, semgrep and tests only at pre-push.

    Exists because `status`'s skip streak had no way to ask this. It derived
    each gate's universe from tools that had PREVIOUSLY APPEARED in that gate's
    runs, so a scanner misconfigured, renamed, or failing from the very first
    run never entered the universe and was never reported skipped -- an absent
    security control reading as a healthy one. Found by aramid's own reviewer
    in the change that fixed the opposite bug (a tier-absent tool wrongly
    reported AS skipped), and reported to the consumer repo that depends on
    this report.

    Returns recorded LABELS, not registry keys, because that is what
    `RUN_STARTED.tools` and `Finding.tool` carry -- the tests slot records
    `pytest`/`npm`/`cargo`, never the literal key. Comparing keys against
    recorded labels would report a perfectly healthy suite run as skipped
    forever, which is a worse failure than the blind spot it replaces.
    """
    ctx = _build_ctx(root, cfg)
    keys = set(GATE_RUNNER_KEYS.get(gate, ()))
    # `_expand_keys` adds the literal key "tests" beside the suite's label
    # (T-8 GC5: `selected_tool_names` must keep a still-configured test
    # setup selected so mark-unreachable refuses). That key is never a
    # recorded label -- `RUN_STARTED.tools` carries `python.exe`/`pytest`/
    # `npm`/`cargo` -- so here, where the answer is compared against
    # recorded labels, it read a suite that ran on every push as skipped
    # on every push (interop round 155 s1: 210 of 210 on the consumer,
    # 191 on aramid's own ledger). Removed at this decision point, not in
    # the shared expansion, so `selected` keeps it.
    return _expand_keys(keys, root, ctx) - {"tests"}


def _expand_keys(keys, root: Path, ctx) -> set[str]:
    """Applicable keys -> the tool name(s) a `Finding.tool` carries for them.

    Split out so `selected_tool_names` and `expected_tool_names` cannot drift:
    they differ only in WHICH keys they consider, never in how a key expands.
    The expansion is NOT identity for typecheck, deps or tests (spec section
    3's table), which is precisely the part that must not be duplicated.
    """
    applicable = {key for key in keys if _is_applicable(key, ctx)}

    names: set[str] = set()
    for key in applicable:
        if key in ("gitleaks", "semgrep", "ruff", "eslint", clippy.NAME):
            names.add(key)
        elif key == "typecheck":
            # Both can be added independently of each other -- see the T-8
            # plan's Global Constraint 6 (mypy-starvation caveat) for the
            # one known conservative inaccuracy this causes.
            if typecheck.has_mypy_config(root):
                names.add(typecheck.NAME_MYPY)
            if typecheck.has_tsconfig(root):
                names.add(typecheck.NAME_TSC)
        elif key == "deps":
            if ctx.pkg_manager == "cargo":
                # Unlike npm/pnpm/yarn, "cargo" (the package manager) and
                # "cargo-audit" (the security tool that stamps Finding.tool)
                # are different names -- see runners/deps.py's _LOCKFILES
                # comment for the same distinction.
                names.add(deps.NAME_CARGO_AUDIT)
                # Only selected while the opt-in is ON. That is deliberate:
                # turning `[deps].cargo_audit_warnings` back off must let the
                # findings it produced become ghost candidates and retire,
                # rather than stranding them open forever with no producer.
                if ctx.cargo_audit_warnings:
                    names.add(deps.NAME_CARGO_AUDIT_WARNINGS)
            elif ctx.pkg_manager:
                names.add(ctx.pkg_manager)
            if deps.python_sources(root):
                names.add(deps.NAME_PIP_AUDIT)
        elif key == "tests":
            # See the T-8 plan's Global Constraint 5: "tests" (the literal
            # registry key) tracks its OWN applicability, not just its
            # sub-tools' -- this is what lets a broken-but-still-configured
            # test setup be correctly REFUSED by mark-unreachable rather
            # than silently retired.
            names.add("tests")
            if ctx.test_command:
                argv = tests_runner._argv(ctx.test_command)
                if argv:
                    names.add(Path(argv[0]).name)
            else:
                names.update(ctx.detected_tests)
    return names


def ghost_candidates(state: dict, selected: set[str]) -> dict[str, dict]:
    """Every OPEN finding whose tool is in the retireable universe but not
    currently selected -- the set `aramid status` lists as retirement
    candidates and the set `aramid ledger mark-unreachable` accepts. The
    predicate, spec section 3:
    candidate(finding) <=> finding.tool in RUNNER_TOOL_NAMES
                         and finding.tool not in selected
                         and finding.status == "open"
    """
    return {
        fid: rec for fid, rec in state.items()
        if rec.get("status") == "open"
        and rec.get("tool") in RUNNER_TOOL_NAMES
        and rec.get("tool") not in selected
    }


# Which paths a runner EXAMINES, read from each runner's own suffix rule so
# the runner and the retire path below cannot drift apart -- round 139 was a
# runner whose scope narrowed. A tool absent from this table has no suffix
# scope (gitleaks and semgrep read every file; tests and deps scope by suite
# and manifest), and for it the answer is "cannot say", never "no".
_SUFFIX_SCOPE: dict[str, tuple[str, ...]] = {
    "ruff": ruff._PY_SUFFIXES,
    typecheck.NAME_MYPY: typecheck._PY_SUFFIXES,
    "eslint": eslint._JS_SUFFIXES,
    clippy.NAME: (".rs",),
}


def examines_path(tool: str, path: str, root: Path | None = None) -> bool | None:
    """True/False when `tool`'s runner scopes files by suffix and the answer
    follows from the path alone; None when the tool has no such scope.

    With `root`, mypy's answer also honours the repo's own `[tool.mypy]
    files`/`exclude` (round 149 b) -- the same helper `run_mypy` filters by,
    so what the retire path calls out of scope is exactly what the runner
    will never hand over."""
    suffixes = _SUFFIX_SCOPE.get(tool)
    if suffixes is None:
        return None
    if not str(path).lower().endswith(tuple(s.lower() for s in suffixes)):
        return False
    if root is not None and tool == typecheck.NAME_MYPY:
        try:
            return typecheck.in_mypy_scope(str(path), typecheck.mypy_scope(root))
        except Exception:
            return True                 # cannot read the scope: assume examinable, never "no"
    return True


def out_of_scope_candidates(state: dict, selected: set[str],
                            root: Path | None = None) -> dict[str, dict]:
    """Every OPEN finding whose tool is still selected here but whose path
    that tool's runner will never examine again -- the set `aramid status`
    lists and `aramid ledger resolve --out-of-scope` accepts. Disjoint from
    `ghost_candidates` by construction: a ghost's tool is NOT selected.
    candidate(finding) <=> finding.status == "open"
                         and finding.tool in selected
                         and examines_path(finding.tool, finding.file) is False
    """
    return {
        fid: rec for fid, rec in state.items()
        if rec.get("status") == "open"
        and rec.get("tool") in selected
        and examines_path(str(rec.get("tool")), str(rec.get("file") or ""), root=root) is False
    }
