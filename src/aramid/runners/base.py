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


# Fingerprinted in place of a line the scanner flagged but that could not be
# read back. Deliberately not "" and not None: "" is a real (blank) line, and
# None routes to the ref lookup -- the very path that let an unreviewed
# statement inherit a SUPPRESSED finding's id. A value that cannot occur in
# source guarantees the failure case can never collide with an adjudicated
# finding. The id is still deterministic, so a persistent failure is stable
# rather than churning.
CONTENT_UNREADABLE = "\x00aramid:line-unreadable"


def scanned_line_reader(root):
    """A cached `(path, row) -> line` reader over the bytes a runner scanned.

    The runner ran moments ago against exactly these files, so reading them
    back here reads what the scanner saw. That is the point:
    `normalizer.normalize` otherwise re-reads the line BY NUMBER out of a git
    blob that may be a different revision, and the fingerprint then describes a
    line that was never flagged.

    `root` is REQUIRED and is the runner's `ctx.root`. Tool-reported paths are
    not uniformly absolute -- semgrep runs with `cwd=ctx.root` and reports
    invocation-relative paths, while ruff reports absolute ones -- and
    resolving a relative path against the aramid PROCESS's cwd is wrong
    whenever the two differ (a `check` run from a subdirectory, a hook invoked
    from elsewhere). That either fails, silently reverting to the ref lookup
    this exists to avoid, or -- worse -- finds a same-named file somewhere else
    and succeeds, fingerprinting a line from an unrelated file.

    Caches per file, not per finding: a rule that fires forty times in one file
    must not re-read it forty times.

    Never returns None. An unreadable file or an out-of-range row yields
    `CONTENT_UNREADABLE`, so a converted runner always makes a positive
    statement about what it saw and the ambiguous "runner said nothing" case
    stays reserved for runners that do not participate at all.
    """
    base = Path(root)
    cache: dict[str, list[str] | None] = {}

    def read(path: str, row: int) -> str:
        lines = cache.get(path, ...)
        if lines is ...:
            p = Path(path)
            if not p.is_absolute():
                p = base / p
            try:
                lines = (p.read_text(errors="replace")
                          .replace("\r\n", "\n").splitlines())
            except OSError:
                lines = None
            cache[path] = lines
        if lines is None:
            return CONTENT_UNREADABLE
        idx = row - 1
        return lines[idx] if 0 <= idx < len(lines) else CONTENT_UNREADABLE

    return read

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
    full_tree: mode=="all" -- scan the whole working tree rather than a git
      revision or the index. Exists because `rng=None` was overloaded to mean
      BOTH "staged" and "not range-based", and `--all` is the second while
      needing the opposite behaviour of the first. gitleaks read that None,
      fell back to `git --staged`, found an empty index, scanned NOTHING and
      reported OK -- which put it in `scope_tools` and let `record_run`
      resolve open secret findings across the whole tracked tree. Measured on
      the published 0.2.0 wheel: two committed secrets invisible to
      `check --all`, and both prior BLOCK findings written `finding_resolved`
      while the secrets were still in the files. Additive field: default
      False keeps every construction site valid, and only gitleaks reads it.
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
    full_tree: bool = False
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

def worktree_import_env(wt: Path) -> dict[str, str]:
    """Put a WORKTREE's own source ahead of everything else on a child's import
    path. Pass as `run_subprocess(..., env=worktree_import_env(wt))` for any
    subprocess whose whole purpose is to exercise the code in `wt`.

    WITHOUT THIS, THE RUN EXERCISES THE INSTALLED PACKAGE. Under a pip editable
    install (a `.pth` naming the live source dir) that is the code the push is
    changing -- so a worktree run silently tests the wrong tree. pytest's own
    cwd insertion does not save a src-layout package either: it adds `<root>`,
    while the package sits at `<root>/src/<pkg>`, so the installed copy wins
    outright.

    It has inverted a producer once already. `red_proof` reported every
    genuinely red-first test as "never red" until `f462d27` added this, because
    the base-tree run imported head source and therefore passed. The identical
    bug then sat unfixed in `consumers/mutation.py`, which ran three worktree
    subprocesses with no env at all: a mutant written into the worktree was
    never the code under test, so every mutant would have been reported
    SURVIVED. It lives here, next to `run_subprocess`, precisely so the next
    caller does not have to rediscover it -- it was a private helper in
    `red_proof` with one caller and no tests, which is how mutation missed it.

    PREPENDED, NEVER ASSIGNED. `run_subprocess` merges this over `os.environ`,
    so replacing PYTHONPATH would drop whatever the developer's environment
    already puts there and break imports the run legitimately needs.

    Both layouts are offered -- `<wt>/src` and `<wt>` -- because a path that
    does not exist is simply inert on `sys.path`.

    Does NOT defeat a PEP 660 *strict* editable install, which installs a
    MetaPathFinder rather than a sys.path entry: no PYTHONPATH entry outranks a
    meta-path hook. That case remains a live limitation.
    """
    parts = [str(wt / "src"), str(wt)]
    existing = os.environ.get("PYTHONPATH", "")
    if existing:
        parts.append(existing)
    return {"PYTHONPATH": os.pathsep.join(parts)}


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
        # The result says what happened, because nothing else can: a killed
        # child leaves no report and no exit code, so a bare TIMEOUT wrote a
        # 0-byte log and the gate named the tool with no reason (2026-09-04,
        # gitleaks on a pre-push gate, two pushes refused with blocking 0).
        return RunnerResult(tool, ToolState.TIMEOUT,
                            stderr=(f"aramid: {tool} timed out after {timeout_s:g} s and was "
                                    f"killed; whatever it had written is discarded"),
                            duration_s=time.monotonic()-start)
    return RunnerResult(tool, ToolState.OK, out, err, time.monotonic()-start, proc.returncode)

class Runner(Protocol):
    name: str
    def applies(self, ctx) -> bool: ...
    def run(self, ctx) -> RunnerResult: ...
