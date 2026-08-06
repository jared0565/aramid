import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from aramid import toolpath

class ToolState(StrEnum):
    OK = "ok"
    MISSING = "missing"
    CRASHED = "crashed"
    TIMEOUT = "timeout"

@dataclass
class RunnerResult:
    tool: str
    state: ToolState
    raw: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    returncode: int = 0
    # Repo-relative paths this runner can VOUCH for having analyzed.
    #
    # `None` means "cannot report" and is NOT the empty set: it falls back to
    # the gate-wide file set, preserving the pre-2026-08-06 behaviour for
    # runners that have not opted in. The empty set is a positive claim that
    # nothing was examined, and it BLOCKS resolution.
    #
    # This exists because `state is ToolState.OK` conflates "ran and found
    # nothing" with "ran over nothing". Measured: ruff exits 0 with zero
    # findings both when a file is clean and when the repo's own `exclude`
    # config skips it (`--force-exclude`), so resolution credited ruff for a
    # file it never opened. See tests/unit/test_resolution_requires_examination.py.
    examined: frozenset[str] | None = None

@dataclass
class RunContext:
    """Shared invocation context passed to every adapter's run()/parse().

    root: repo root (cwd for subprocesses, and the base gitutil paths are
      relative to).
    files: the file set in scope (staged files for pre-commit, changed files
      for pre-push/--all, etc.) -- adapters that scan by range/config ignore
      this.
    rng: git revision range (e.g. "@{u}..HEAD") when scanning history/commits;
      None means "staged" / "not range-based". An empty string ("",
      `pipeline.FULL_HISTORY_RNG`) is a distinct sentinel meaning "range
      mode, but no @{u}/origin/HEAD exists yet -- scan every commit
      reachable from HEAD" (first push of a brand-new repo, spec §3);
      gitleaks' `_build_argv` branches on `is not None`, not truthiness, so
      this sentinel still routes to the `git log`/`--log-opts` history scan
      rather than falling back to `protect --staged`.
    pkg_manager: detected JS package manager ("npm"/"pnpm"/"yarn") or None.
    stacks: detected language stacks (subset of {"python","js"}, from
      aramid.detectors.detect_stacks) -- consulted by aramid.pipeline for
      gate+stack runner applicability (a repo with no "js" stack never gets
      eslint selected, etc.).
    extra_semgrep_configs: additional `--config <path>` values the semgrep
      adapter appends after the vendored OWASP ruleset (Task 15, spec §5) --
      populated by aramid.pipeline.run_gate with the repo's committed
      regression pack (`<root>/.aramid-rules/regression.yml`) when it exists
      and pack replay is enabled, so a reintroduction is caught by the
      NORMAL gates, not just the next drain. Additive field: default `()`
      keeps every existing RunContext(...) construction site (and every
      adapter that never reads it) valid unchanged.
    force_refresh: bypass the deps audit cache (deps.run_js/run_python read
      it via getattr). run_gate sets it True for mode=="all" so `check --all`
      (and CI's `check --all --strict`) re-audits fresh instead of serving a
      <=24h cache -- a CVE that appeared inside the window is not masked. The
      interactive gates (pre-commit/pre-push) leave it False and keep the
      cache. Additive field: default False keeps every construction site valid.
    test_command / test_timeout_s / tests_enabled: the `[tests]` config
      section (plus the legacy top-level `test_command`), resolved by
      aramid.pipeline.run_gate. The Runner protocol is `run(ctx)` -- ctx is
      the ONLY channel a real runner has to config, which is why these are
      narrow purpose-built fields rather than a whole Config (matching
      `extra_semgrep_configs` above). `test_command` None/empty means
      auto-detect; `test_timeout_s` None means the runner's own default
      (runners.tests.TIMEOUT_S); `tests_enabled` False makes the tests
      runner inapplicable, so it is never selected at all. All three are
      additive with defaults, so every existing construction site (and
      every runner that ignores them) stays valid unchanged.
    gate_deadline: an ABSOLUTE `time.monotonic()`-based instant -- NOT a
      duration -- marking when the CURRENT gate run's wall-clock budget
      expires. Set ONCE, in aramid.pipeline.run_gate, as `time.monotonic()
      + budget_s`, at (or as close as practical to) the same reference
      point that budget_s itself is computed from -- BEFORE _select_runners
      / detect_tests() / any other pre-flight filesystem work runs. Carried
      onto ctx so a runner that internally executes more than one
      sequential sub-invocation (today: only runners.tests's dual
      pytest+npm path) can check "how much time is actually left until
      THIS instant" from wherever it happens to be in its own call chain,
      rather than restarting its own clock partway through (e.g. inside a
      worker thread, after its own detect_tests() filesystem walk has
      already spent part of the budget) -- a fresh `time.monotonic()`
      capture taken anywhere after the true origin systematically
      UNDER-counts elapsed time and can let a runner's internal accounting
      drift later than aramid.pipeline._run_selected's own
      ThreadPoolExecutor `wait(timeout=budget_s)`, which measures from
      close to that same original instant. Once `wait()` gives up, any
      future still running is abandoned and REPLACED wholesale by a bare
      TIMEOUT result with none of its real sub-results -- two clocks with
      different origins is what let that happen (review B2 follow-up).
      None means "no shared deadline known" (e.g. a RunContext built
      outside run_gate, as unit tests do) -- callers must treat that as
      "unbounded", not "already expired", so a runner that never opts in
      keeps its current unbounded-by-this-field behavior. Additive field:
      default None keeps every existing construction site valid unchanged.
    detected_tests: `detectors.detect_tests(root)` cached by
      aramid.pipeline.run_gate (Task 4, review M6+B7) -- a filesystem walk
      that would otherwise be repeated once per reader per gate run
      (pipeline.py's `_is_applicable` and `_tests_config_notices`, plus
      runners.tests.run() -- three call sites, three walks). Computed ONCE,
      after `gate_deadline`'s own origin is captured (same single-origin
      reasoning as gate_deadline itself: the walk must count against the
      budget, not be free relative to it), and threaded onto ctx so every
      reader sees the SAME result instead of re-walking.
      Deliberately defaults to `None`, NOT `stacks`' `field(
      default_factory=set)` pattern above -- `stacks` makes "empty" and "not
      computed" indistinguishable, which is harmless for `stacks` (nothing
      treats an empty set as significant on its own) but would be actively
      wrong here: a `detected_tests` field defaulting to `set()` and read
      directly would make every bare `RunContext(root=...)` -- how the vast
      majority of this repo's own unit tests construct one, well over a
      hundred call sites across tests/ -- silently read as "no suite
      detected", which flips `_is_applicable`'s tests-gate check to False
      and makes runners.tests.run() return MISSING unconditionally. `None`
      is instead an explicit "not computed here" sentinel: every reader
      must fall back to a fresh `detect_tests(ctx.root)` walk when this is
      `None` (`ctx.detected_tests if ctx.detected_tests is not None else
      detect_tests(ctx.root)`), which is exactly today's uncached behavior
      for any RunContext built outside run_gate. Additive field: default
      None keeps every existing construction site valid unchanged.
    cargo_audit_warnings: `[deps].cargo_audit_warnings`, default False --
      opt in to RUSTSEC's informational `warnings` (unmaintained/unsound/
      yanked crates) as findings alongside the real `vulnerabilities`.
      Threaded onto ctx rather than read from cfg inside the runner because
      `parse()` takes (result, ctx) and never sees a Config. Additive field:
      default False keeps every existing construction site valid AND keeps
      the feature off for every repo that has not asked for it.
    """
    root: Path
    files: list[str] = field(default_factory=list)
    rng: str | None = None
    pkg_manager: str | None = None
    stacks: set[str] = field(default_factory=set)
    extra_semgrep_configs: tuple[str, ...] = ()
    force_refresh: bool = False
    test_command: str | list[str] | None = None
    test_timeout_s: float | None = None
    tests_enabled: bool = True
    gate_deadline: float | None = None
    detected_tests: set[str] | None = None
    cargo_audit_warnings: bool = False

_WIN = sys.platform == "win32"
_POST_KILL_DRAIN_S = 5.0   # cap on the post-_kill_tree reap wait (test seam)

def _kill_tree(proc: subprocess.Popen):
    try:
        if _WIN:
            # S603/S607 justification: fixed argv killing a process
            # tree aramid itself spawned via subprocess.Popen above -- proc.pid
            # is our own child's PID, not attacker-controlled, and "taskkill"
            # resolving via PATH is standard on every Windows host.
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],  # noqa: S603,S607
                           capture_output=True)
        else:
            os.killpg(os.getpgid(proc.pid), 9)
    except Exception:
        proc.kill()

def run_subprocess(argv, cwd: Path, timeout_s: float, env=None) -> RunnerResult:
    tool = Path(argv[0]).name
    # Resolve through toolpath, NOT bare `shutil.which`: aramid downloads some
    # binaries itself (gitleaks -> ~/.aramid/tools) and pip can place console
    # scripts outside PATH. Using `which` alone here is what let `doctor --fix`
    # report "OK gitleaks" while the gate skipped it as MISSING -- doctor and
    # the runner must resolve identically or doctor is a false green light.
    resolved = toolpath.resolve(argv[0])
    if resolved is None:
        return RunnerResult(tool, ToolState.MISSING)
    # Launch by absolute path so the child does not re-resolve against a PATH
    # that may not contain the tool at all.
    argv = [str(resolved), *argv[1:]]
    kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if _WIN \
             else {"start_new_session": True}
    start = time.monotonic()
    # S603 justification: this is aramid's single generic subprocess
    # launcher -- invoking external static-analysis tools (ruff, semgrep,
    # gitleaks, pip-audit, npm/pnpm/yarn, eslint, tsc, pytest...) is the
    # entire purpose of this function, not attacker-controlled input. Every
    # `argv` is built by a runner's own `_build_argv()` from fixed tool names
    # and repo-relative file paths, never from untrusted external strings.
    proc = subprocess.Popen(argv, cwd=str(cwd), stdout=subprocess.PIPE,  # noqa: S603
                            stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace",
                            env={**os.environ, **(env or {})}, **kwargs)
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.communicate(timeout=_POST_KILL_DRAIN_S)
        except subprocess.TimeoutExpired:
            proc.kill()
        return RunnerResult(tool, ToolState.TIMEOUT, duration_s=time.monotonic()-start)
    return RunnerResult(tool, ToolState.OK, out, err, time.monotonic()-start, proc.returncode)

class Runner(Protocol):
    name: str
    def applies(self, ctx) -> bool: ...
    def run(self, ctx) -> RunnerResult: ...
