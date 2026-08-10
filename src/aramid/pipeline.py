"""pipeline -- wires detectors, runners, normalizer, policy, config, ledger,
redact, and gitutil into a single gate run (`run_gate`).

Two ignore-path filter passes (spec section 8b -- graphite artifacts must
never be scanned/fingerprinted):
  1. the discovered file set is filtered via `config.filter_paths` BEFORE
     it is handed to any runner as `RunContext.files` -- file-scoped tools
     (ruff/eslint/tsc/mypy/semgrep) never see an ignored path;
  2. the parsed RawFindings are filtered AGAIN, by path, before
     `normalizer.normalize()` runs -- because gitleaks scans by git log
     range (`--log-opts <rng>` / `--staged`), not by `ctx.files`, it can
     surface a finding for a path that was never in the file set at all.
     Filtering only step 1 would leave such a finding to be fingerprinted;
     this second pass is what actually guarantees "never fingerprinted".

Runner selection is a monkeypatchable module-level registry (`RUNNERS`,
`GATE_RUNNER_KEYS`) precisely so tests can swap in fake runner doubles
without touching real tool binaries -- see tests/unit/test_pipeline.py.
"""
import functools
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from aramid import config as config_mod
from aramid import (gitutil, mutation_gate, mutation_score_gate, policy, red_proof, redact,
                    tdd, tests_gate, toolpath)
from aramid import review as review_mod
from aramid.detectors import (detect_package_manager, detect_stacks, detect_tests,
                              unrooted_stack_notices)
from aramid.fingerprint import normalize_path
from aramid import ledger as ledger_mod
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Verdict
from aramid.normalizer import RawFinding, normalize
from aramid.pack import RULES_REL_PATH
from aramid.policy import OverrideRecord
from aramid.runners import clippy, deps, eslint, gitleaks, ruff, semgrep, tests, typecheck
from aramid.runners.base import RunContext, RunnerResult, ToolState

# --------------------------------------------------------------- registry ----
# Monkeypatchable: tests replace entries/keys here to inject fake runner
# doubles instead of invoking real tool binaries.

RUNNERS: dict[str, object] = {
    "gitleaks": gitleaks,
    "ruff": ruff,
    "semgrep": semgrep,
    "eslint": eslint,
    "clippy": clippy,
    "typecheck": typecheck,
    "deps": deps,
    "tests": tests,
}

GATE_RUNNER_KEYS: dict[Gate, list[str]] = {
    Gate.PRE_COMMIT: ["gitleaks", "ruff"],
    Gate.PRE_PUSH: ["gitleaks", "semgrep", "eslint", "clippy", "typecheck", "deps", "tests"],
    # Gate.ALL isn't specified by the brief's runner-selection table; the
    # comprehensive (pre-push) set is the reasonable default for a full scan.
    Gate.ALL: ["gitleaks", "semgrep", "eslint", "clippy", "typecheck", "deps", "tests"],
}

# Tool keys whose degradation (MISSING/CRASHED/TIMEOUT) drives the pre-push
# degraded-BLOCK-tier escalation (brief's "CRITICAL correctness" note).
BLOCK_TIER_KEYS = frozenset({"gitleaks", "semgrep", "tests"})

_BUDGET_KEY = {Gate.PRE_COMMIT: "pre_commit", Gate.PRE_PUSH: "pre_push", Gate.ALL: "pre_push"}
_BAD_STATES = (ToolState.MISSING, ToolState.CRASHED, ToolState.TIMEOUT)


@dataclass
class GateResult:
    exit_code: int
    findings: list[Finding]
    degraded: list[str]
    new_ids: list[str]
    stale_overrides: list[OverrideRecord]
    run_id: str
    # Whether a BLOCK_TIER_KEYS tool (gitleaks/semgrep/tests) degraded
    # (MISSING/CRASHED/TIMEOUT) -- i.e. this run's own `degraded_block_tier`
    # local, exposed so callers (check.py's fresh-clone rule) can reuse the
    # EXACT value this function computed, rather than re-deriving it from
    # `degraded` (tool NAMES, from RunnerResult.tool) against BLOCK_TIER_KEYS
    # (registry KEYS) -- those two can diverge: e.g. the "tests" registry key
    # can produce a RunnerResult with `.tool == "pytest"` when the pytest
    # binary itself is missing (see runners/tests.py's `run_pytest` ->
    # `run_subprocess`), which would never name-match "tests" in
    # BLOCK_TIER_KEYS even though it IS the BLOCK-tier "tests" slot degrading.
    degraded_block_tier: bool = False
    # WHICH BINARY produced these findings, per runner key that actually ran:
    # {"ruff": {"path": "...", "dependency_copy": "..."}}. `dependency_copy`
    # appears ONLY when it differs from `path` -- i.e. when the tool aramid
    # declares as a dependency lost to a copy earlier on PATH, which is
    # intended resolution behaviour but changes what gets reported
    # (`toolpath.divergence` has the measured 1-vs-3-findings example).
    #
    # In the RUN's output rather than only in `doctor` because this is what
    # someone reads when CI and local disagree: two finding sets are only
    # comparable when the analyzers behind them are.
    tool_provenance: dict = field(default_factory=dict)


def _tool_provenance(selected) -> dict:
    """Which binary backed each runner key this run selected.

    Keyed on the REGISTRY KEY rather than `RunnerResult.tool`, deliberately:
    those two diverge (the "tests" slot reports `.tool == "pytest"`), and the
    key is what a reader matches against config and against another run.

    Cheap by construction -- `toolpath.resolve` is a `shutil.which` plus at
    most a few `exists()` calls, and NO `--version` subprocess. Versions are
    doctor's job; paying a process launch per tool on every commit to enrich
    an informational field would be a bad trade.

    Tolerant of filesystem weirdness, NOT of programming errors. `OSError`
    only, deliberately: the first version of this caught bare `Exception`,
    and when `toolpath` turned out not to be imported here the resulting
    NameError was swallowed into an empty dict on every run -- a feature that
    silently did nothing, with green tests either side of it. `resolve` and
    `divergence` already absorb their own OSErrors, so this layer is for a
    path vanishing between the two calls and nothing else."""
    out: dict = {}
    for key in selected:
        if key not in toolpath.PROVENANCE_TOOLS:
            continue
        try:
            resolved = toolpath.resolve(key)
            if resolved is None:
                continue
            entry = {"path": str(resolved)}
            div = toolpath.divergence(key, resolved=resolved)
            if div is not None:
                entry["dependency_copy"] = str(div.dependency_copy)
            out[key] = entry
        except OSError:
            continue
    return out


def _default_clock() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------- file set ------

# Sentinel `RunContext.rng` value meaning "range mode, but there is no
# @{u}/origin/HEAD to diff against yet -- scan EVERYTHING reachable from
# HEAD" (spec §3: "no remote refs at all -- first push of a new repo --
# scan every commit reachable from HEAD. Never exit 3 merely because a
# branch is new."). Deliberately distinct from `None` (which every range-
# mode consumer -- `newest_commit_touching`, `gitleaks._build_argv` --
# already treats as "not range-based" / "staged"): using the same `None`
# for both "genuinely staged mode" and "range mode with nothing to diff
# against" is exactly the bug this sentinel fixes (`gitleaks._build_argv`
# fell back to `protect --staged`, silently scanning nothing, instead of a
# full-history scan). Empty string is itself a valid `--log-opts` value for
# gitleaks' `git log` passthrough -- `git log` with no revision argument
# defaults to walking every commit reachable from HEAD, which IS "every
# commit reachable from HEAD."
FULL_HISTORY_RNG = ""


def _discover_files(root: Path, mode: str) -> tuple[list[str], str | None]:
    if mode == "staged":
        return gitutil.staged_files(root), None
    if mode == "range":
        rng = gitutil.resolve_range(root)
        if rng is None:
            # No upstream and no origin/HEAD yet -- brand-new repo, first
            # push. `changed_files(root, None)` would diff the working tree
            # against bare "HEAD", which is empty on a clean tree (nothing
            # staged) -- effectively scanning nothing. Use the full tracked
            # file set instead, and signal gitleaks to scan full history via
            # FULL_HISTORY_RNG (see above).
            return gitutil.all_tracked_files(root), FULL_HISTORY_RNG
        return gitutil.changed_files(root, rng), rng
    if mode == "all":
        return gitutil.all_tracked_files(root), None
    raise ValueError(f"unknown mode: {mode!r}")


def _ref_for_builder(mode: str, root: Path, rng: str | None) -> Callable[[str], str]:
    if mode == "staged":
        return lambda f: ":"
    if mode == "range":
        return lambda f: gitutil.newest_commit_touching(root, rng, f)
    return lambda f: "HEAD"  # mode == "all"


# ------------------------------------------------------------- execution -----

# Per-runner gate+stack applicability (Important #1 fix). A runner that
# isn't applicable to this repo is simply never selected -- it must NOT
# surface as a MISSING/degraded tool (that was the bug: `tests` used to be
# selected at every pre-push regardless of whether the repo had any test
# setup, so a repo with none forced exit_code=1 on every push). gitleaks
# and semgrep have no stack condition (cross-language secrets/SAST) and
# ruff/eslint/typecheck/deps/tests keep their existing GATE_RUNNER_KEYS gate
# assignment -- this only narrows *within* that gate, it never adds a gate.
def _is_applicable(key: str, ctx: RunContext) -> bool:
    if key == "ruff":
        return "python" in ctx.stacks
    if key == "eslint":
        return "js" in ctx.stacks
    if key == "clippy":
        return "rust" in ctx.stacks
    if key == "typecheck":
        return typecheck.has_tsconfig(ctx.root) or typecheck.has_mypy_config(ctx.root)
    if key == "deps":
        return ctx.pkg_manager is not None or any(ctx.root.glob("requirements*.txt"))
    if key == "tests":
        # `[tests].enabled = false` removes the gate rather than degrading
        # it: a runner that is never selected cannot surface as
        # MISSING/degraded, which for a BLOCK_TIER_KEYS member would block
        # every push -- exactly what disabling it is meant to avoid.
        # run_gate prints a notice whenever this suppresses a real suite.
        if not ctx.tests_enabled:
            return False
        # A configured command IS the repo's test setup, so it makes the
        # gate applicable on its own. Without this, pointing `[tests].command`
        # at a `make test` wrapper (or a suite the pytest/npm heuristics
        # don't recognize) would silently do nothing at all.
        return bool(ctx.test_command) or bool(_detected_tests(ctx))
    # gitleaks, semgrep, and any unrecognized key (e.g. test doubles): always applicable.
    return True


def _detected_tests(ctx: RunContext) -> set[str]:
    """`detect_tests(ctx.root)`, cached on `ctx.detected_tests` when
    aramid.pipeline.run_gate precomputed it (Task 4, review M6+B7) -- see
    RunContext.detected_tests's own docstring for why that field defaults
    to `None`, never `set()`. Every reader in this module goes through
    here (rather than calling `detect_tests` directly) so a gate run walks
    the tree once, not once per reader."""
    return ctx.detected_tests if ctx.detected_tests is not None else detect_tests(ctx.root)


def _plausible_test_setup(root: Path) -> bool:
    """[review I3 + B1] A repo-level signal that SOME kind of test setup
    exists, independent of whether detect_tests() recognizes it. Task 1
    tightened detect_tests() to require a real pytest-shaped file name
    (test_*.py / *_test.py / conftest.py) or a package.json test script --
    correctly closing a false-positive bug (a bare tests/*.test.ts
    directory used to count on its own) -- but that same tightening
    creates real false negatives this notice exists to surface: a custom
    `python_files` pytest.ini pattern, unittest-style `testfoo.py` naming,
    or a doctest-only suite all leave detect_tests() empty even though a
    real suite is right there. Literal signals, deliberately -- this only
    decides whether to print an informational notice, never gate/policy
    behavior, so a loose match costs one stderr line, never a false BLOCK."""
    if (root / "tests").is_dir() or (root / "test").is_dir():
        return True
    if (root / "pytest.ini").exists() or (root / "tox.ini").exists():
        return True
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            return "[tool.pytest.ini_options]" in pyproject.read_text(encoding="utf-8")
        except OSError:
            return False
    return False


def _no_suite_notice(ctx: RunContext) -> str:
    """The BLOCK-tier test gate has nothing to run -- and the gate will still
    exit 0.

    MEASURED on synthetic Rust and Go repos, both with a real, working suite:
    `check --gate pre-push --all --strict` returned **0**, completing only the
    language-agnostic runners, because `detect_tests` recognizes exactly two
    kinds -- a pytest-shaped file, or an npm `test` script. `cargo test` and
    `go test` are neither.

    This used to be reported only when `_plausible_test_setup` was true, which
    keys on Python-flavoured markers (tests/, pytest.ini, tox.ini). Rust trips
    it by convention and got a message written entirely in pytest vocabulary;
    Go, whose `main_test.go` sits beside the source with no tests/ directory,
    got **total silence**. Both variants now say the same three things: the
    gate ran nothing, what IS recognized, and how to fix or opt out.

    Deliberately not gated on the stack being known: an unrecognized stack is
    when a reader most needs to be told coverage is thin.
    """
    if _plausible_test_setup(ctx.root):
        found = ("a tests/, test/, pytest.ini, tox.ini or "
                 "[tool.pytest.ini_options] setup was found, but aramid "
                 "recognized no suite in it")
    else:
        found = "no test suite was detected"
    stacks = ", ".join(sorted(ctx.stacks or ())) or "none recognized"
    return (
        f"aramid: tests: {found} -- the BLOCK-tier test gate ran NOTHING on "
        f"this run, so a pass here says nothing about your tests. Detected "
        f"stack(s): {stacks}. aramid detects pytest (test_*.py, "
        f"*_test.py, conftest.py), an npm `test` script, cargo (a "
        f"tests/*.rs file) and go (a *_test.go file) -- a Rust crate whose "
        f"tests are all inline #[cfg(test)] is the known gap. Set "
        f"[tests].command to point aramid at your suite, or "
        f"[tests].enabled = false to declare this repo has none.")


def _tests_config_notices(gate: Gate, ctx: RunContext, budget_s: float) -> list[str]:
    """Loud, per-run notices for `[tests]` config that would otherwise
    silently weaken or neuter the BLOCK-tier test gate. Every case below is
    the same failure class this engine exists to prevent: a check that
    reports nothing for a reason indistinguishable from "clean".

    [review I5] These ACCUMULATE: multiple independent conditions can be
    true in the same run (e.g. a false-negative test setup AND an
    over-budget timeout_s), and each gets its own notice. The first version
    of this function `return`ed at the first matching branch, which would
    have silently hidden every notice after it -- collect into a list and
    return once, at the end, instead."""
    if "tests" not in GATE_RUNNER_KEYS.get(gate, []):
        return []          # this gate never runs tests -- nothing to suppress
    notices: list[str] = []
    if not ctx.tests_enabled:
        # Only worth saying when a suite actually exists to be skipped.
        # Nothing else below is reachable once the gate is off outright --
        # every other notice here is about a suite that WOULD run.
        if _detected_tests(ctx) or ctx.test_command:
            notices.append(
                "aramid: [tests].enabled = false -- the BLOCK-tier test "
                "gate is DISABLED for this repo; nothing here runs your "
                "suite.")
        return notices

    # [review I3 + B1] "suite present but not running": only meaningful
    # when nothing already tells the gate exactly what to run -- an
    # explicit `[tests].command` IS the repo's answer and short-circuits
    # detection entirely (runners.tests.run()'s own first check), so
    # neither case below can be silently dropping anything while one is set.
    if not ctx.test_command:
        kinds = _detected_tests(ctx)
        if not kinds:
            notices.append(_no_suite_notice(ctx))
        elif len(kinds) >= 2:
            # [review I3 + B1, MANDATORY case] Both kinds detected, but the
            # C1 lockfile gate (runners/tests.py) means npm only actually
            # runs when a JS package-manager lockfile backs it up. Resolved
            # the same way _dual_stack_run does (ctx.pkg_manager first, a
            # fresh detect_package_manager(root) only as fallback) so this
            # check and the real runner never disagree about which repos
            # get promoted to a dual run.
            effective = set(kinds)
            if "pytest" in kinds and "npm" in kinds:
                pkg_manager = ctx.pkg_manager or detect_package_manager(ctx.root)
            else:
                pkg_manager = "n/a"     # gate does not apply to this pairing
            if pkg_manager is None:
                effective.discard("npm")
                notices.append(
                    "aramid: tests: both a Python test suite and a "
                    "package.json test script were detected, but no JS "
                    "lockfile (package-lock.json / pnpm-lock.yaml / "
                    "yarn.lock) was found -- the npm suite is being "
                    "skipped this run (pytest still runs). Run `npm "
                    "install` (or pnpm/yarn), or set [tests].command to "
                    "run it explicitly.")
            if len(effective) >= 2:
                # [review B5] Informational only -- Task 3's shared
                # ctx.gate_deadline is what actually keeps a dual-suite run
                # inside budget_s; this only explains a run that had to
                # share it. Deliberately NOT `2 * effective > budget_s`
                # (rev 1's rule): stock timeout_s/pre_push are both 300, so
                # that form fires on every push for every dual-stack repo.
                # A SINGLE effective timeout already exceeding the WHOLE
                # shared budget is a narrower, still-exact signal: it
                # guarantees runners.tests._run_one_within_deadline's
                # `min(_timeout(ctx), remaining)` caps whichever suite runs
                # second below its nominal timeout on EVERY invocation,
                # regardless of how fast either suite actually runs (even a
                # zero-duration first suite leaves only budget_s <
                # effective_timeout for the second) -- a guarantee, not a
                # hypothetical "might". Uses `ctx.test_timeout_s or
                # tests.TIMEOUT_S`, NOT the `if ctx.test_timeout_s and ...`
                # shape of the single-suite notice below -- that guard
                # would skip this comparison entirely whenever timeout_s is
                # unset, exactly the case this notice must still cover
                # (e.g. a repo that only lowers [timeouts].pre_push).
                #
                # [MUST FIX 3, whole-branch review] KNOWN, ACCEPTED GAP --
                # strict `>`, not `>=`, means this notice is PROVABLY INERT
                # at stock defaults: timeout_s and timeouts.pre_push both
                # default to 300 (defaults.toml), so `effective_timeout >
                # budget_s` is `300 > 300` = False and nothing prints. Yet
                # runners.tests._run_one_within_deadline's `min(_timeout(ctx),
                # remaining)` still truncates the SECOND suite below 300s the
                # moment the first suite consumes any wall-clock time at all
                # -- which is every real run. So a stock dual-stack repo
                # whose two suites' true durations sum past 300s can still
                # block with a bare "npm timeout: test suite failed" and NO
                # notice at all explaining that the shared budget, not the
                # suite, ran out. Switching to `>=` was considered and
                # rejected: at stock defaults EVERY dual-stack repo has
                # effective_timeout == budget_s, so `>=` fires on every
                # single push for every such repo regardless of how fast its
                # suites actually run -- reintroducing the exact always-
                # fires false-positive rev 1's `2 * effective > budget_s`
                # rule caused and review B5 forbade (see above). Closing this
                # honestly requires a POST-RUN notice (something that can
                # see whether `_run_one_within_deadline` actually had to
                # truncate a suite, which this call site -- two lines before
                # `_run_selected` even runs, see run_gate below -- cannot);
                # that is a separate, out-of-scope sub-project, not a
                # same-round fix. Tracked as a follow-up, not fixed here.
                effective_timeout = ctx.test_timeout_s or tests.TIMEOUT_S
                if effective_timeout > budget_s:
                    key = _BUDGET_KEY.get(gate, "pre_push")
                    notices.append(
                        f"aramid: tests: this repo runs "
                        f"{len(effective)} suites "
                        f"({', '.join(sorted(effective))}) sequentially, "
                        f"sharing ONE "
                        f"[timeouts].{key} budget of {budget_s:g}s -- the "
                        f"effective per-suite timeout "
                        f"({effective_timeout:g}s) already exceeds that "
                        f"shared budget on its own, so the second suite is "
                        f"guaranteed a reduced (or zero) allotment. Raise "
                        f"[timeouts].{key}, or lower [tests].timeout_s.")

    if ctx.test_timeout_s and ctx.test_timeout_s > budget_s:
        key = _BUDGET_KEY.get(gate, "pre_push")
        notices.append(f"aramid: [tests].timeout_s = {ctx.test_timeout_s:g}s exceeds the "
                        f"[timeouts].{key} budget of {budget_s:g}s -- the gate abandons "
                        f"the runner at {budget_s:g}s, so the larger timeout can never "
                        f"be reached. Raise both, or lower timeout_s.")
    return notices


def _select_runners(gate: Gate, ctx: RunContext) -> dict[str, object]:
    keys = GATE_RUNNER_KEYS.get(gate, [])
    return {key: RUNNERS[key] for key in keys if _is_applicable(key, ctx)}


def _run_selected(selected: dict[str, object], ctx: RunContext,
                   budget_s: float) -> dict[str, RunnerResult]:
    """Run every applicable runner concurrently; abandon stragglers at
    `budget_s`.

    RAW DAEMON THREADS, NOT A ThreadPoolExecutor -- that is the point of this
    function, not a style choice. Important #2 fixed only half of it by
    dropping the executor's context manager, whose implicit
    `shutdown(wait=True)` joined every submitted thread and let one hung
    runner block run_gate past the budget. `shutdown(wait=False)` does make
    run_gate RETURN on time -- but a pool worker is not a daemon, so both
    `concurrent.futures._python_exit` and `threading._shutdown` join it during
    INTERPRETER SHUTDOWN. aramid printed its verdict and the process then sat
    there for as long as the straggler ran. Measured: a 12s hung runner
    returned in 0.22s and the process exited at 12.36s; 3s -> 3.42s.

    The gate runs inside a git hook, so that is `git push` HANGING after
    aramid has already decided -- and it is not bounded by `[timeouts]`,
    because `runners.base.run_subprocess` passes `timeout_s` to
    `communicate()`, which does not cover `subprocess.Popen`. A runner stuck
    in process creation hangs the hook with no ceiling at all (a test capped
    at 60s was measured running past 600s on this repo).

    Detaching the pool's threads from `concurrent.futures._threads_queues`
    looks like the one-line fix and is NOT one: measured at 10.21s against
    10.23s unfixed, because `threading._shutdown` joins non-daemon threads
    whatever the futures module thinks. `t.daemon = True` cannot be set after
    a thread has started, so getting daemons at all means owning them here.
    Daemon threads exit in 0.63s. Guarded by
    test_the_process_can_exit_while_an_abandoned_runner_is_still_running,
    which measures a CHILD process because interpreter shutdown is not
    observable from inside the interpreter doing it.

    THE TRADE, stated plainly: a daemon thread is killed at interpreter exit,
    so an abandoned runner's child process can outlive the gate. Its result
    was already discarded as TIMEOUT, and run_subprocess deliberately launches
    children detached (CREATE_NEW_PROCESS_GROUP / start_new_session) so they
    are not ours to reap either way. A short-lived orphan analyzer is strictly
    better than a hung push.
    """
    results: dict[str, RunnerResult] = {}
    if not selected:
        return results

    outcomes: dict[str, tuple[bool, object]] = {}
    lock = threading.Lock()
    all_done = threading.Event()
    pending = len(selected)

    def _work(key: str, module) -> None:
        nonlocal pending
        try:
            outcome = (True, module.run(ctx))
        except Exception as exc:  # a runner raising is a crash, not a pipeline failure
            outcome = (False, exc)
        with lock:
            outcomes[key] = outcome
            pending -= 1
            if pending == 0:
                all_done.set()

    for key, module in selected.items():
        threading.Thread(target=_work, args=(key, module), daemon=True,
                         name=f"aramid-runner-{key}").start()

    # Same duration measured from the same point as the wait() this replaces,
    # so run_gate's gate_deadline argument below is unaffected.
    all_done.wait(timeout=budget_s)

    with lock:
        finished = dict(outcomes)
    for key in selected:
        if key not in finished:
            results[key] = RunnerResult(key, ToolState.TIMEOUT)
            continue
        ok, value = finished[key]
        results[key] = value if ok else RunnerResult(key, ToolState.CRASHED,
                                                     stderr=str(value))
    return results


def _flatten(results: dict[str, RunnerResult]) -> list[RunnerResult]:
    """Expand deps.py's `.sub_results` (mixed py+js audits collapse into one
    top-level RunnerResult -- see aramid.runners.deps module docstring) so
    each real sub-tool gets its own degraded flag and log file."""
    flat: list[RunnerResult] = []
    for r in results.values():
        subs = getattr(r, "sub_results", None)
        flat.extend(subs) if subs else flat.append(r)
    return flat


# Tail of stdout kept per runner per run. Bounded because there is no log
# rotation: an unbounded copy of every semgrep JSON report would grow
# `.aramid/logs` without limit. The TAIL is the half worth keeping -- pytest
# prints its short summary last.
_LOG_STDOUT_CAP = 64 * 1024


# Runners whose stdout is NEVER persisted, whatever their exit code.
#
# gitleaks is the one runner whose output can quote secret material, and the
# scrubber cannot help exactly when it matters: `_write_logs` scrubs with the
# secrets recovered from THIS run's successfully PARSED gitleaks findings, so a
# gitleaks that crashed or timed out mid-scan parses nothing, hands the
# redactor an EMPTY list, and its stdout is written verbatim --
# `.github/scripts/dump_aramid_logs.py` then prints every log to a PUBLIC CI
# job log under `if: failure()`. GitHub masks registered `secrets.*` values,
# not secrets found in repository content.
#
# Nothing diagnostic is lost. runners/gitleaks.py passes `--report-format json
# --report-path <file>`, so findings go to a file `_log_body` never reads and
# stdout carries only a banner and a count; failures explain themselves on
# stderr, which is still persisted.
_NO_STDOUT_TOOLS = frozenset({"gitleaks"})


def _log_body(r: RunnerResult) -> str:
    """What to persist for one runner: stderr, plus stdout when the run had a
    problem -- except for `_NO_STDOUT_TOOLS` above, whose stdout is never kept.

    stderr alone was not enough, and the gap was worst exactly where it hurt
    most. Measured 2026-08-07: a failing `[tests]` command returns
    `state=OK, returncode=1` with **zero** bytes of stderr and its whole
    pytest report -- the only thing naming the failing test -- on stdout. So
    the BLOCK-tier gate that stops a push wrote an EMPTY log and reported
    `python exited 1: test suite failed`, with no surface anywhere that could
    say which test. A `windows-latest / py3.14` leg hit precisely that, passed
    on re-run, and the flake could not be identified.

    stdout is written only when `state` is not OK or the exit code is
    non-zero. A clean ruff or semgrep puts its entire JSON report on stdout
    and it is ALREADY surfaced as findings; copying it on every green run
    would grow the log directory for nothing.

    When there is no stdout to add, the body is byte-identical to the
    pre-2026-08-07 format -- no headers, no blank lines -- so nothing that
    reads these files sees a gratuitous change.
    """
    err = r.stderr or ""
    out = r.raw or ""
    if (not out or r.tool in _NO_STDOUT_TOOLS
            or (r.state is ToolState.OK and r.returncode == 0)):
        return err
    if len(out) > _LOG_STDOUT_CAP:
        out = (f"[{len(out) - _LOG_STDOUT_CAP} earlier bytes truncated]\n"
               f"{out[-_LOG_STDOUT_CAP:]}")
    body = f"--- stdout ---\n{out}"
    return f"{body}\n--- stderr ---\n{err}" if err else body


def _examined_by_tool(flat_results: list[RunnerResult]) -> dict[str, set[str]]:
    """What each runner can VOUCH for having analyzed, keyed by tool name.

    `state is OK` alone conflates "ran and found nothing" with "ran over
    nothing" -- ruff exits 0 with zero findings both for a clean file and for
    one the repo's own `exclude` config skips -- so resolution keyed on
    scope_files credited runners for files they never opened, recording false
    repairs. A runner reporting None is absent from this map and falls back
    (ledger.record_run); a runner reporting the empty set is present and
    blocks resolution outright.

    The KEY here is `RunnerResult.tool`, and `ledger.record_run` looks it up
    by the tool stamped on each Finding. Those two must agree or the lookup
    misses, `tool_scope` comes back None, and resolution SILENTLY falls back
    to the pre-fix behaviour -- the hole reopens with nothing to show for it.
    They only agree because every adapter restamps: `run_subprocess` names a
    result after `Path(argv[0]).name`, which is "tsc.cmd" on win32, "cargo"
    for clippy and "python" for the tests runner. `tests/unit/
    test_examined_tool_keys_match_findings.py` pins that agreement.
    """
    return {r.tool: set(r.examined) for r in flat_results
            if r.state is ToolState.OK and r.examined is not None}


def _write_logs(root: Path, run_id: str, flat_results: list[RunnerResult],
                 raw_secrets: list[str]) -> None:
    logs_dir = root / ".aramid" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    for r in flat_results:
        scrubbed = redact.scrub(_log_body(r), raw_secrets)
        (logs_dir / f"{r.tool}-{run_id}.log").write_text(scrubbed, encoding="utf-8")


# --------------------------------------------------------------- overrides ---

def _overrides_from_ledger(ledger: Ledger) -> list[OverrideRecord]:
    records = []
    for finding_id, rec in ledger.open_findings().items():
        if rec.get("status") == "overridden":
            records.append(OverrideRecord(
                id=finding_id, tool=rec.get("tool", ""), rule=rec.get("rule", ""),
                path=normalize_path(rec.get("file", "")), reason=rec.get("reason", "")))
    return records


# -------------------------------------------------------------------- run ----

def run_gate(root: Path, gate: Gate, mode: str, cfg: config_mod.Config, ledger: Ledger,
             accept_degraded: str | None = None, *,
             clock: Callable[[], str] = _default_clock,
             run_id: str | None = None) -> GateResult:
    run_id = run_id if run_id is not None else uuid.uuid4().hex
    at = clock()

    # 1. file set for mode, then the always-on ignore-path filter (spec §8b).
    raw_files, rng = _discover_files(root, mode)
    files = config_mod.filter_paths(raw_files, cfg)

    # 2. build the shared RunContext (stack detection feeds runner
    #    applicability), then select applicable runners for this gate.
    # Regression pack replay (Task 15, spec §5): the committed pack, if
    # present and not disabled via aramid.toml's [pack].enabled, rides along
    # as an extra semgrep --config so a reintroduction is caught by the
    # NORMAL gates (pre-commit/pre-push), not merely at the next drain.
    pack_file = root / RULES_REL_PATH
    extra_configs = ((str(pack_file),)
                     if cfg.pack.get("enabled", True) and pack_file.exists() else ())
    # `[tests]` (schema v1's top-level `test_command` shipped documented but
    # with no read site anywhere; it is consumed as a fallback rather than
    # orphaned beside a new key doing the same job -- `[tests].command` wins).
    tests_cfg = cfg.tests if isinstance(cfg.tests, dict) else {}
    # Computed here (not after ctx construction, as before) so it can ride
    # onto RunContext.gate_deadline as an ABSOLUTE instant, captured BEFORE
    # _select_runners/detect_tests() or any other pre-flight filesystem
    # work below runs: runners.tests's dual pytest+npm path needs to
    # measure "time left" against the SAME origin _run_selected's own
    # budget wait (`all_done.wait(timeout=budget_s)`) effectively uses, not a
    # fresh clock restarted after its own detect_tests() walk -- two
    # differently-anchored clocks is what let a completed suite's real
    # result be silently replaced by a bare pipeline-level TIMEOUT (review
    # B2 follow-up). See RunContext.gate_deadline's docstring for the
    # single-origin argument in full, including why leaving
    # _run_selected's own wait() as a duration (rather than also
    # recomputing it from this deadline) is still safe: every step between
    # this line and _run_selected's wait() call below (_select_runners
    # included) can only ADD time before wait() starts counting, never
    # subtract it, so wait()'s effective cutoff is provably >= this
    # deadline -- never earlier.
    budget_s = cfg.timeouts.get(_BUDGET_KEY.get(gate, "pre_push"), 60.0)
    gate_deadline = time.monotonic() + budget_s
    # detect_tests() is a filesystem walk -- cached on RunContext (Task 4,
    # review M6+B7) so _is_applicable, _tests_config_notices, and
    # runners.tests.run() each read the SAME result instead of each
    # repeating the walk. Computed here, AFTER gate_deadline's own origin
    # is captured, for the identical single-origin reason gate_deadline's
    # docstring gives for detect_package_manager/detect_stacks below: this
    # walk must count against the budget, never be free relative to it.
    detected_tests = detect_tests(root)
    ctx = RunContext(root=root, files=files, rng=rng,
                      pkg_manager=detect_package_manager(root),
                      stacks=detect_stacks(root, root),
                      extra_semgrep_configs=extra_configs,
                      force_refresh=(mode == "all"),
                      test_command=tests_cfg.get("command", cfg.test_command),
                      test_timeout_s=tests_cfg.get("timeout_s"),
                      tests_enabled=tests_cfg.get("enabled", True),
                      gate_deadline=gate_deadline,
                      detected_tests=detected_tests,
                      cargo_audit_warnings=(cfg.deps or {}).get(
                          "cargo_audit_warnings", False))
    selected = _select_runners(gate, ctx)

    # 3. run concurrently under the gate's wall-clock budget.
    # Both notice sources answer the same question -- "is this gate reporting
    # nothing because there is nothing, or because it never ran?" -- so they
    # print together, before any runner does. unrooted_stack_notices walks,
    # and does so AFTER gate_deadline is captured for the same single-origin
    # reason detect_tests does: the walk must count against the budget.
    for notice in (_tests_config_notices(gate, ctx, budget_s)
                   + unrooted_stack_notices(root)):
        print(notice, file=sys.stderr)
    results = _run_selected(selected, ctx, budget_s)
    flat_results = _flatten(results)

    # 4/5. parse every result -> RawFindings (deps.parse recurses into its
    # own sub_results already, so top-level results are enough here).
    all_raws: list[RawFinding] = []
    for key, result in results.items():
        all_raws.extend(selected[key].parse(result, ctx))

    # TDD gate (1a): synchronous git-fact code-without-test producer. PRE_PUSH
    # only; joins the raw stream so classify/fingerprint/ratchet/overrides all
    # apply. Fail-open inside tdd.scan -- never raises here.
    rp_proven_red: set[str] = set()
    if gate is Gate.PRE_PUSH:
        all_raws.extend(tdd.scan(ctx, cfg))
        # Red-first proof (sub-project 3): the range's changed test files run
        # against the range base -- rc 0 there means the test was never red.
        # Same pre-normalize seam as tdd.scan; fail-open inside red_proof.scan.
        # ctx.rng falsy (first push / staged / all) makes it a silent no-op.
        rp_raws, rp_proven_red = red_proof.scan_scoped(ctx, cfg)
        all_raws.extend(rp_raws)

    # secrets never land in logs, raw -- collected before writing them out.
    raw_secrets = [r.secret for r in all_raws if r.secret]
    _write_logs(root, run_id, flat_results, raw_secrets)

    # second ignore-path pass: drop any raw finding for an ignored path
    # BEFORE fingerprinting, regardless of whether it ever went through
    # ctx.files (gitleaks scans by git-log range, not by file list).
    raws_in_scope = [r for r in all_raws if not config_mod.is_ignored(r.file, cfg.ignore_paths)]

    salt = redact.load_or_create_salt(root / ".aramid")
    ref_for = _ref_for_builder(mode, root, rng)
    classify = functools.partial(policy.classify, cfg=cfg)
    findings = normalize(raws_in_scope, root, ref_for, salt, gate, classify)

    # 6. overrides (ledger-recorded WARN overrides) + suppressions (BLOCK
    # suppressions + reasonless-suppression synthetic WARN findings).
    overrides = _overrides_from_ledger(ledger)
    suppress_records, suppress_warnings = config_mod.load_suppressions(root)
    findings = findings + suppress_warnings
    findings, stale = policy.apply_overrides(findings, overrides, suppress_records)

    # 7. record this run; enforce the pre-push no-new-warnings ratchet.
    scope_tools = {r.tool for r in flat_results if r.state is ToolState.OK}
    scope_files = set(files)
    # What each runner can VOUCH for having analyzed. `state is OK` alone
    # conflates "ran and found nothing" with "ran over nothing" -- ruff exits
    # 0 with zero findings both for a clean file and for one the repo's own
    # `exclude` config skips -- so resolution keyed on scope_files credited a
    # runner for files it never opened, recording false repairs. A runner that
    # reports None is absent here and falls back (ledger.record_run).
    examined_by_tool = _examined_by_tool(flat_results)
    # Local import: toolset.py imports pipeline.GATE_RUNNER_KEYS/_is_applicable
    # at module scope, so importing it here at module scope would be
    # circular (mirrors ledger.compact()'s identical fix for the
    # queue.py/ledger.py cycle, ledger.py:155).
    from aramid import toolset
    selected_tools = toolset.selected_tool_names(root, cfg)
    # `root=` opts this run into resolving findings whose file has LEFT the
    # repo. Deliberately passed here and nowhere else: init._scan_history
    # records historical gitleaks findings whose paths belong to old commits
    # and usually do not exist at HEAD, so the same flag there would clear
    # every historical secret on sight (see ledger._departed).
    new_ids = ledger.record_run(run_id, at, str(gate), scope_tools, scope_files, findings,
                                selected_tools=selected_tools, root=root,
                                examined_by_tool=examined_by_tool)

    # record_run above can NEVER resolve a whole-suite finding: those carry the
    # synthetic `<test-suite>` marker, which is not a path and so is never in
    # scope_files. Without this call they are immortal -- one failed or
    # timed-out suite leaves a BLOCK-tier finding open through every later
    # green run (seen in aramid's own ledger: detected 2026-07-12, still open
    # weeks and thousands of passing tests later).
    #
    # Gated on the REGISTRY KEY, not on a result's `.tool` label: those two
    # diverge for exactly this slot, as the BLOCK_TIER_KEYS comment above
    # already documents (`.tool` is Path(argv[0]).name -- "pytest", "npm", or
    # "python" under a configured [tests].command). Deliberately outside the
    # PRE_PUSH block so `check --all` clears stale suite findings too;
    # pre-commit never runs tests, so the slot is absent and this no-ops.
    _tests_result = results.get("tests")
    tests_gate.auto_resolve_tests(
        ledger, run_id, at, {f.id for f in findings},
        suite_completed=(_tests_result is not None
                         and _tests_result.state is ToolState.OK))

    if gate is Gate.PRE_PUSH:
        # ---- THE RATCHET, AND THE ONE RULE THAT GOVERNS ITS EXEMPTION LIST --
        # A new WARN escalates to BLOCK so warning debt cannot accumulate. The
        # governing principle for the exemptions, settled by the maintainer's
        # delegation in interop round 38 (round 21 declined to take it, round
        # 38 granted it):
        #
        #   A new WARN finding is ratchet-exempt if and only if the push's
        #   author cannot make it go away by changing what they are pushing.
        #
        # One falsifiable question per candidate, deliberately phrased as a
        # single test rather than the two-clause "not caused by this push AND
        # no remedy but suppression". The two-clause form is ambiguous on
        # exactly the entry that discriminates: a push that upgrades pnpm DOES
        # cause DEPS_SHAPE_DRIFT_RULE (the audit tool's output shape changed),
        # so "not caused by this push" fails -- yet the author still cannot fix
        # it, because the fix belongs to aramid's parser. The one-question form
        # admits it cleanly and for the right reason.
        #
        # Admitted under the principle:
        #   DEPS_SHAPE_DRIFT_RULE      -- aramid cannot parse the audit output;
        #                                 the remedy is a change to aramid.
        #   NAME_CARGO_AUDIT_WARNINGS  -- an upstream RUSTSEC informational
        #                                 advisory is a publication event,
        #                                 usually with no fix available. This is
        #                                 guarantee 3 of three from round 20 (a
        #                                 MAINTAINER decision; do not reverse it
        #                                 here). Round 21 asked that it arrive
        #                                 under a principle rather than as a
        #                                 fourth ad-hoc entry -- it now does.
        #
        # DOCUMENTED EXCEPTION -- admitted by a different, named mechanism:
        #   tdd, red-proof   -- these FAIL the principle (the author caused them
        #                       and can fix them: write the test, make it red
        #                       first). They are exempt only because an operator
        #                       DELIBERATELY DISARMED the producer; `aramid arm`
        #                       ends that. Kept in this list by tool name rather
        #                       than moved, because the post-ratchet region below
        #                       is regression-pinned by shape.
        #   the LLM + mutation gates -- the SAME disarm mechanism, implemented
        #                       structurally by being appended after this block.
        #                       Stated here so the third mechanism is explicit
        #                       rather than an accident of ordering.
        #
        # NOT exempt, decided under the principle (round 38):
        #   semgrep's WARN-only bake -- the bake exists to absorb the EXISTING
        #                       backlog, and it still does: baselined findings
        #                       are not in `new_ids`, so the ratchet never
        #                       touches them. Holding NEW code to the standard
        #                       is the ratchet working, not the bake failing.
        #   clippy           -- a lint the author wrote and can fix.
        findings = [
            replace(f, verdict=Verdict.BLOCK)
            if (f.id in new_ids and f.verdict is Verdict.WARN
                and f.rule != deps.DEPS_SHAPE_DRIFT_RULE
                and f.tool not in ("tdd", "red-proof",
                                   deps.NAME_CARGO_AUDIT_WARNINGS))
            else f
            for f in findings
        ]

    # Phase 2b (spec section 5) + 1b: the pre-push LLM and mutation ledger
    # gates -- zero tokens, DB reads. Auto-resolve runs FIRST so fixed findings
    # never block. The gate producers are appended AFTER the ratchet above, so
    # a disarmed (WARN) finding is ratchet-exempt and never auto-escalates.
    if gate is Gate.PRE_PUSH:
        review_mod.auto_resolve_llm(root, ledger, run_id, at)
        # Departed-file resolution. Sits HERE and not in the `mode == "range"`
        # nest below for the same reason auto_resolve_llm does: the guards
        # there protect resolvers that read scope_files, and this one derives
        # nothing from the range -- it asks only whether a path still exists,
        # which is true or false identically under "all", "staged", and a
        # rangeless "range".
        #
        # No listed producer's own rule can clear a finding whose FILE is gone:
        # red-proof needs a base-tree pytest run on it; tdd and mutation need
        # the push to have touched it, and a deleted path is never in
        # scope_files (discovery filters --diff-filter=ACMR). record_run cannot
        # either -- it gates on `tool in scope_tools`, which holds runner
        # labels, and none of these emit a RunnerResult. mutation is further
        # out of reach because the DRAIN records it, passing no root at all.
        #
        # OPT-IN, ONE NAME AT A TIME, and the list is a whitelist on purpose.
        # Relaxing record_run's tool gate instead would cover every producer in
        # one line and silently resolve those whose stored `file` is not a path
        # -- dast writes "GET /login", which does not exist, joins to
        # root/GET/login, passes containment, and reads as departed. A name
        # belongs here only if its findings are anchored to a real
        # repo-relative path. See ledger.resolve_departed for who is still out
        # and why.
        _departed_present = {f.id for f in findings}
        for _producer in ("red-proof", "tdd", "mutation"):
            ledger_mod.resolve_departed(ledger, run_id, at, root=root,
                                        tool=_producer,
                                        present_ids=_departed_present)
        # EVERY scope_files-driven resolver below needs BOTH guards, for two
        # independent reasons -- each has its own regression test naming this
        # nest by shape, so keep it nested rather than collapsing to one
        # condition. Both reduce to "scope_files is not the push's delta":
        #   mode: under "all"/"staged" it is the whole tracked tree / the
        #         staged set.
        #   rng:  under "range" with no upstream it is ALSO the whole tree.
        # Resolving on either durably clears every open finding on tracked
        # source -- FINDING_RESOLVED is persisted and cannot be un-appended.
        # Surfacing below still runs in all modes so a full audit shows open
        # findings. auto_resolve_llm above needs neither guard: it resolves on
        # whether the evidence quote still exists at HEAD, deriving no range.
        if mode == "range":
            if rng:
                # mode == "range" is NOT enough: with no upstream and no
                # origin/HEAD, _discover_files returns the whole tracked tree
                # with rng == FULL_HISTORY_RNG (""), so scope_files is the
                # repo, not the push's delta. Truthy rng == genuine range.
                mutation_gate.auto_resolve_mutation(ledger, run_id, at, scope_files)
                # 1a-F2: the two synchronous producers resolve too. present_ids
                # skips anything re-fired THIS run (these producers, unlike the
                # drain's, fire in the run being resolved).
                present_ids = {f.id for f in findings}
                if getattr(cfg, "tdd", {}).get("enabled", True):
                    tdd.auto_resolve_tdd(ledger, run_id, at, scope_files, present_ids)
                red_proof.auto_resolve_red_proof(ledger, run_id, at,
                                                 rp_proven_red, present_ids)
        synthesized = [
            *review_mod.llm_gate_findings(cfg, ledger, gate),
            *mutation_gate.mutation_gate_findings(cfg, ledger, gate),
            # 2b: derived mutation-score regressions. changed_files
            # only for a GENUINE push delta, which needs both halves
            # of the resolver guard above: under "all"/"staged" --
            # and equally under "range" with no upstream --
            # scope_files is the whole tree / staged set, so every
            # module-mapped test looks "just changed" and the
            # test-mapped suppression silences every regression.
            # Ephemeral only (no ledger write), so unlike its two
            # siblings this costs one quiet run, not a durable
            # false resolve -- still wrong, just recoverable.
            *mutation_score_gate.mutation_score_gate_findings(
                cfg, ledger, gate,
                scope_files if (mode == "range" and rng) else None)]
        # SECOND override pass, for these three only. They are materialized
        # from ledger state rather than parsed from a RunnerResult, so they do
        # not exist yet at step 6 where `apply_overrides` ran -- and they must
        # stay out of `record_run` above, being a derived VIEW of the ledger
        # rather than a fresh detection. The consequence was that a tracked,
        # reviewed, reason-bearing `.aramid-suppressions.toml` entry naming
        # tool `llm-review`, `mutation` or `mutation-score` bound NOTHING, and
        # was not reported stale either -- stale detection only ever saw the
        # list apply_overrides was handed. Silent in both directions.
        #
        # Scope of what this newly permits: the tracked file can now downgrade
        # an armed confirmed-critical LLM BLOCK. Deliberate -- section 6 gives
        # the committed file ANY tier, as it already had over gitleaks and
        # semgrep BLOCKs. The machine-local ledger-override channel is NOT
        # widened: apply_overrides keeps its `elif f.verdict is Verdict.WARN`
        # branch, so an unreviewable `.aramid/` entry still cannot hide a
        # BLOCK. (It could not reach these three anyway -- both synthesizers
        # skip a record whose status is not "open".)
        synthesized, _ = policy.apply_overrides(synthesized, overrides,
                                                suppress_records)
        # Recomputed with the synthesized list passed SEPARATELY, not merged:
        # `stale_records` judges the suppression channel against both pools and
        # the override channel against the runner findings alone, because an
        # override binds by flipping ledger status and so is absent from
        # `synthesized` exactly when it is working. Merging the lists here
        # reports every working override on these three producers as stale,
        # forever, whenever any sibling finding shares its tool/rule/path --
        # measured against aramid's own ledger. See policy.stale_records.
        #
        # This second pass is also what finally makes a genuinely dead
        # SUPPRESSION for these three reportable: before it, no mutation or
        # llm-review finding was ever in the list stale detection saw, so an
        # entry whose id had rotted stayed silent forever.
        stale = policy.stale_records(findings, overrides, suppress_records,
                                     synthesized)
        findings = [*findings, *synthesized]

    # 8. exit code.
    degraded_tools = sorted({r.tool for r in flat_results if r.state in _BAD_STATES})
    degraded_block_tier = any(
        key in results and results[key].state in _BAD_STATES for key in BLOCK_TIER_KEYS
    )
    # [MUST FIX 2, whole-branch review] `gating_block_findings` -- the BLOCK
    # findings that must hard-gate BEFORE accept_degraded is ever consulted
    # -- deliberately excludes `tool == "tests"` findings carrying the
    # `tests-tool-missing` rule (runners/tests.py's dual-suite aggregate: a
    # detected sub-suite whose own tool binary could not be resolved at
    # all). That rule exists to EXPLAIN a degradation already carried by
    # `degraded_block_tier` above; it is not an independent test failure, so
    # it must not defeat the documented `--accept-degraded` escape hatch the
    # SAME way a top-level single-suite MISSING result already doesn't
    # (that path never reaches this variable at all: parse() returns [] for
    # it, so there is no BLOCK finding to trip over -- see
    # runners/tests.py's TOOL_MISSING_RULE docstring).
    #
    # [Closer 1, re-review round 2] MUST match BOTH tool AND rule, not rule
    # alone -- a repo's own `.gitleaks.toml` can name a custom rule anything,
    # including literally "tests-tool-missing". `policy.classify` dispatches
    # on TOOL FIRST (its `if tool == "gitleaks": return ... Verdict.BLOCK`
    # is the very first branch, unconditional on rule; classify never even
    # reaches the rule-based `tests-tool-missing` branch for a gitleaks
    # finding) -- so classify is already effectively tool-scoped for
    # gitleaks/tdd/mutation/mutation-score/red-proof/semgrep via that early
    # per-tool dispatch, while this `any()` was rule-only. That asymmetry is
    # exactly what the `f.tool == "tests"` conjunct below closes: without
    # it, a `RawFinding(tool="gitleaks", rule="tests-tool-missing")` -- a
    # real secret, reported by a repo's own custom-named gitleaks rule --
    # would classify BLOCK (via the gitleaks branch, correctly) and then be
    # silently excluded from gating and bypassed by `--accept-degraded`
    # anyway, exit 2 instead of 1. Scoped to this ONE tool+rule pair,
    # deliberately -- every OTHER BLOCK-tier finding (gitleaks secret, armed
    # semgrep, a genuine tests-failed, a critical CVE, ...) must still gate
    # HERE, before accept_degraded is ever reached; broadening this
    # exclusion to Verdict.BLOCK in general would make every block
    # bypassable, which is not the fix.
    gating_block_findings = any(
        f.verdict is Verdict.BLOCK
        and not (f.tool == "tests" and f.rule == tests.TOOL_MISSING_RULE)
        for f in findings
    )

    if gating_block_findings:
        exit_code = 1
    elif accept_degraded and gate is Gate.PRE_PUSH and degraded_block_tier:
        ledger.append(Event(
            EventType.INFRASTRUCTURE_BYPASS, run_id, at,
            payload={"reason": accept_degraded, "gate": str(gate), "degraded": degraded_tools}))
        exit_code = 2 if degraded_tools else 0
    else:
        exit_code = policy.escalate_degraded(0, degraded_block_tier, gate)
        if exit_code == 0 and degraded_tools:
            exit_code = 2

    return GateResult(exit_code=exit_code, findings=findings, degraded=degraded_tools,
                       new_ids=new_ids, stale_overrides=stale, run_id=run_id,
                       degraded_block_tier=degraded_block_tier,
                       tool_provenance=_tool_provenance(selected))
