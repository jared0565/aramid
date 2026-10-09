import codecs
import contextlib
import io
import itertools
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Callable, Protocol

from aramid import proctree, toolpath

# Set, to the worktree, in every subprocess a consumer runs
# (`worktree_import_env` below; `consumers/js_mutation.py` builds its own
# env and carries it too). `registry.register` refuses under it. Defined
# HERE, not in `registry`, because this module must import nothing outside
# the standard library: the release's sdist smoke test installs with
# `--no-deps` and imports the runners, and `registry` imports `tomli_w`
# (0.17.10's first tag run failed on exactly that, 2026-09-19).
CONSUMER_WORKTREE_ENV = "ARAMID_CONSUMER_WORKTREE"

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

# cmd.exe's maximum command-line length. A `.cmd` / `.bat` program runs
# through cmd.exe, which refuses a longer line with "The command line is too
# long." and exits 1 -- an exit code several tools accept as a verdict (FN-34).
CMD_EXE_LINE_LIMIT = 8191


def cmd_line_length(argv) -> int:
    """`argv`'s command line as cmd.exe counts it: the line CreateProcess
    receives (`subprocess.list2cmdline`), in UTF-16 units, so a character
    outside the BMP is two."""
    return len(subprocess.list2cmdline(argv).encode("utf-16-le")) // 2


def cmd_exe_line_budget() -> int:
    """The longest line a `.cmd` / `.bat` launch may have, in
    `cmd_line_length`'s units.

    CreateProcess runs a batch file as `%COMSPEC% /c <line>`, and cmd.exe
    holds that WHOLE line to the limit, so the interpreter's own path --
    quoted when it holds a space -- and ` /c ` come off the top. COMSPEC is
    this process's, not the child's: CreateProcess reads the caller's.
    Measured 2026-10-08, Windows 11, with a .cmd writing a marker: with
    COMSPEC=C:\\WINDOWS\\system32\\cmd.exe a line of 8,160 runs and 8,161 is
    refused (27 + 4 under 8,191); a COMSPEC 24 characters longer moved the
    boundary down by exactly 24; one set only in the child's environment
    moved it not at all; with COMSPEC unset it was 8,160 again, the system
    directory's cmd.exe; a 130-character COMSPEC with a space put it at
    8,055, two under the unquoted 8,057; and a line of 8,160 code points with
    one character outside the BMP was refused."""
    comspec = os.environ.get("COMSPEC") or os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "system32", "cmd.exe")
    return CMD_EXE_LINE_LIMIT - cmd_line_length([comspec]) - len(" /c ")


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
    # Seconds of NO CPU in the child's whole process tree and NO output on
    # either pipe when the stall watchdog killed it; None when it was not
    # stalled. A stall is still ToolState.TIMEOUT -- a dozen sites branch on
    # TIMEOUT (a killed mutation run must never read as a killed mutant), so
    # only the REPORT differs, never the control flow.
    stalled_s: float | None = None
    # Trailing seconds of no CPU and no output when the WALL CLOCK, not the
    # watchdog, killed the child: set only with the watch on, a measurable
    # tree, and at least one sample interval (`_SAMPLE_S`) of quiet. At the
    # default 300 s window the watchdog cannot decide before any gate
    # runner's budget, so this is what tells a hung tool from a slow one
    # there. REPORTING ONLY, and never set together with `stalled_s`: it is
    # read by the timeout text and `pipeline._degraded_reasons` and by
    # nothing that branches on a stall, so a run that hit its budget stays
    # a budget timeout everywhere (the mutation budget give-up among them).
    idle_s: float | None = None

@dataclass
class RunContext:
    """Shared invocation context passed to every adapter's run()/parse().

    root: repo root (cwd for subprocesses, and the base gitutil paths are
      relative to).
    files: the file set in scope, set by the scan mode rather than the gate
      (staged files under `staged`, the pushed range's changed files under
      `range`, every tracked file under `--all`) -- adapters that scan by
      range/config ignore this.
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
    progress: a sink `(text: str) -> None` a long runner may hand short
      status lines to while its child is still running (today: the tests
      runner, reading pytest's `[ N/M]` marker off a tapped stdout). run_gate
      provides `aramid.progress.StderrReporter`; a sink with a callable
      `flush()` gets it called when the runner is done. Additive field:
      default None means no tap, no extra argv, no extra output -- the
      launcher is called exactly as before, which is what every RunContext
      built outside run_gate (consumers, tests) gets.
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
    progress: Callable[[str], None] | None = None

_WIN = sys.platform == "win32"
_POST_KILL_DRAIN_S = 5.0   # cap on the post-_kill_tree reap wait (test seam)

def own_group() -> dict:
    """Popen kwargs that start a child in a process group of its own. On POSIX
    `_kill_tree` kills the child's GROUP: a child left in aramid's group would
    take aramid with it -- and, inside a hook, the `git push` that ran it."""
    return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if _WIN \
           else {"start_new_session": True}


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


# FN-14: every child aramid's launchers have alive, as a kill callable --
# `run_subprocess` here, `providers.base.run_provider_subprocess`, and (FN-17)
# `gitutil._run`. The drain's hard deadline ends the process with `os._exit`,
# which runs no `finally`, so a consumer's own cleanup never kills what it
# started; the deadline calls `kill_live(close=True)` first. NOT registered:
# `consumers.js_mutation._link_node_modules`' one-shot `mklink`, which is
# bounded instead. Module state rather than a parameter because the launchers
# are reached from deep inside consumers that have no handle on the drain.
#
# CLOSED is what makes the kill stick. Killing only what is registered at
# that instant leaves a looping consumer (mutation runs one pytest per
# mutant) free to start its next child before the process exits, and that
# child, in a group of its own, outlives the drain. Closing and the
# snapshot happen under one lock, so a child registered after is killed on
# the spot, and neither launcher starts a new one once closed. Only the
# deadline closes; the process ends right after, so it never reopens.
_LIVE: dict[int, Callable[[], None]] = {}
_LIVE_LOCK = threading.Lock()
_LIVE_IDS = itertools.count()
_CLOSED = False


def _call(kill: Callable[[], None]) -> bool:
    try:
        kill()
        return True
    except Exception:  # noqa: BLE001 -- best effort at a deadline
        return False


def closed() -> bool:
    """True once the drain's hard deadline has closed the registry: no
    launcher may start a child, and a child that ends now was killed."""
    return _CLOSED


@contextlib.contextmanager
def live_process(kill: Callable[[], None]):
    """Hold `kill` in the registry for the duration of the block. Once the
    registry is closed, `kill` runs at once instead: the child was started
    after the deadline took its snapshot."""
    token = next(_LIVE_IDS)
    with _LIVE_LOCK:
        late = _CLOSED
        if not late:
            _LIVE[token] = kill
    if late:
        _call(kill)
    try:
        yield
    finally:
        with _LIVE_LOCK:
            _LIVE.pop(token, None)


def kill_live(*, close: bool = False) -> int:
    """Kill every registered child; how many kills did not raise. One that
    raises (already gone, access denied) does not spare the rest. `close`
    (the deadline's call) also closes the registry, in the same step as
    the snapshot, so nothing registered after it escapes."""
    global _CLOSED
    with _LIVE_LOCK:
        if close:
            _CLOSED = True
        kills = list(_LIVE.values())
    return sum(_call(kill) for kill in kills)

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

    AND NO BYTECODE. Python validates a cached .pyc by the source's mtime in
    whole seconds and its SIZE. Two mutants of one file differ by one
    operator -- the same size -- and a fast runner writes them within one
    second, so the second mutant imported the FIRST one's bytecode and was
    "killed" by a test that never saw it (CI 34158187545, 2026-09-07: the
    five fast legs failed the two-occurrence claim test, the two slow legs
    passed). Every subprocess under this env is exercising a tree that is
    about to be rewritten under it -- a mutant, a base checkout, a fuzz
    target -- and a worktree starts with no __pycache__; forbidding the
    write keeps it that way, so nothing stale can exist. Import cost is one
    compile per module per run, which is noise next to a pytest start.

    AND THE CONSUMER MARKER. The subprocess runs the consumed repo's OWN
    commands -- its test suite, a fuzz target's imports -- and on 2026-09-18
    one of those ran `aramid init` on the checkout, which registered
    `<temp>/aramid-fuzz-*/wt` as a fleet member the drain then waited on
    forever. `registry.register` refuses under the marker, so whatever the
    repo's tooling does, a descendant `aramid init` cannot touch the real
    registry. (`consumers/js_mutation.py` builds its own env for `npm test`
    and carries the marker itself.)
    """
    parts = [str(wt / "src"), str(wt)]
    existing = os.environ.get("PYTHONPATH", "")
    if existing:
        parts.append(existing)
    return {"PYTHONPATH": os.pathsep.join(parts), "PYTHONDONTWRITEBYTECODE": "1",
            CONSUMER_WORKTREE_ENV: str(wt)}


# Stall watchdog (0.20.4). A wall-clock timeout alone cannot tell a slow
# child from one that stopped working: a pip-audit whose inner pip blocked on
# a full stderr pipe (Windows pipes hold 4096 bytes; pip-audit reads stdout
# to EOF before touching stderr) sat at zero CPU for 97 minutes on
# 2026-10-06. Every SAMPLE_S the launcher compares the child TREE's
# {pid: (created, cpu)} and the bytes read so far; no change in any of
# them for the stall window = stalled. Module state, like the drain's
# `closed()`: the launchers are reached from inside consumers that hold no
# config. `apply_stall_window` sets it from `[timeouts].stall_s`, called by
# `pipeline.run_gate` (check, init, rebaseline) and by the drain per repo.
_SAMPLE_S = 15.0
DEFAULT_STALL_S = 300.0
_STALL_S = DEFAULT_STALL_S


def set_stall_window(seconds: float) -> None:
    """0 disables the watchdog (wall clock only); negatives clamp to 0."""
    global _STALL_S
    _STALL_S = max(0.0, float(seconds))


def stall_window() -> float:
    return _STALL_S


def apply_stall_window(cfg) -> None:
    """Set the window from the repo's `[timeouts].stall_s`. It must run before
    any runner or consumer launches; `pipeline.run_gate` and the drain call it.
    Here, below the commands, so neither has to import a command module.
    `aramid.config` is imported inside: this module imports nothing outside
    the standard library at import time (config needs `tomli_w`, and the
    release's sdist smoke imports the runners with `--no-deps`)."""
    from aramid import config as config_mod
    set_stall_window(config_mod.stall_window_s(cfg))


class _Stalled(Exception):
    def __init__(self, idle_s: float, procs: int):
        super().__init__(f"stalled for {idle_s:.0f} s")
        self.idle_s = idle_s
        self.procs = procs


class _TimedOut(subprocess.TimeoutExpired):
    """The wall clock ran out. `idle_s` is the trailing no-CPU/no-output
    time measured AT the deadline, or None: watch off, tree unmeasurable,
    or quiet for less than one sample interval."""
    def __init__(self, cmd, timeout: float, idle_s: float | None):
        super().__init__(cmd, timeout)
        self.idle_s = idle_s


_READ_CHUNK = 65536


def _text_decoder() -> io.IncrementalNewlineDecoder:
    """What `text=True, encoding="utf-8", errors="replace"` pipes decode with:
    UTF-8 with U+FFFD for a bad byte, and universal newlines (`\\r\\n` and a
    lone `\\r` both become `\\n`). Incremental, so a multibyte character or a
    `\\r\\n` split across two reads decodes as if it had arrived whole."""
    return io.IncrementalNewlineDecoder(
        codecs.getincrementaldecoder("utf-8")(errors="replace"), translate=True)


def _watched_communicate(proc: subprocess.Popen, timeout_s: float, on_stdout_line):
    """Drain both pipes on daemon threads (a single-threaded read of one pipe
    lets the other fill its OS buffer and wedge the child -- exactly the bug
    that hung pip-audit), tap stdout lines to `on_stdout_line` when given, and
    wait in SAMPLE_S slices. Raises `_TimedOut` (a `subprocess.TimeoutExpired`)
    at the wall clock and `_Stalled` when neither the tree's CPU/membership
    nor the output moved for the stall window. An unmeasurable tree
    (sample() -> None) counts as activity, so a watchdog that cannot see is
    today's timeout, never a false stall; so is a wake more than two sample
    intervals late, or a sample that itself took that long, either of which
    restarts the quiet clock. At the wall clock the watch takes
    one last sample, so `_TimedOut.idle_s` runs to the deadline rather than
    to the previous wake; the deadline still wins over a stall there.

    The pipes are BINARY and read in chunks as the bytes arrive, never by
    line: a line reader counted nothing until a newline, so a child printing
    progress dots read as silent and was killed as stalled, and an
    unterminated last line sat inside a `readline` that a still-running
    grandchild kept blocked. Each stream is decoded on its reader thread,
    exactly as the old text-mode pipes decoded it (`_text_decoder`).

    Returns (stdout, stderr, held). `held` is True when a reader was still
    blocked after the child exited and the `_POST_KILL_DRAIN_S` join ran out:
    a process the child started holds the pipe, and the strings are what
    had arrived by then."""
    chunks: dict[str, list[str]] = {"out": [], "err": []}
    # Bytes read per stream. Each counter is written by its own reader thread
    # only, so no update is lost; the watch compares their sum.
    seen = {"out": 0, "err": 0}

    def pump(name, stream, tap):
        decoder = _text_decoder()
        pending = ""   # tapped text after its last newline: a line not yet complete

        def deliver(text: str, final: bool = False) -> None:
            nonlocal tap, pending
            chunks[name].append(text)
            if tap is None:
                return
            pending += text
            if "\n" not in text and not final:
                return   # no line completed; never rescan a long unterminated one
            lines = pending.split("\n")
            pending = lines.pop()
            if final and pending:
                # `readline` handed over an unterminated last line at EOF too.
                lines.append(pending)
            for line in lines:
                try:
                    tap(line)
                except Exception as exc:  # noqa: BLE001 -- decoration never fails the run
                    print(f"aramid: progress reporting stopped: {exc!r}", file=sys.stderr)
                    tap = None
                    return

        while chunk := stream.read1(_READ_CHUNK):
            seen[name] += len(chunk)
            deliver(decoder.decode(chunk))
        deliver(decoder.decode(b"", final=True), final=True)
        stream.close()

    readers = [threading.Thread(target=pump, args=("out", proc.stdout, on_stdout_line), daemon=True),
               threading.Thread(target=pump, args=("err", proc.stderr, None), daemon=True)]
    for t in readers:
        t.start()
    deadline = time.monotonic() + timeout_s
    window = _STALL_S
    last_tree, last_seen = None, -1
    quiet_since = sampled_at = time.monotonic()
    while True:
        try:
            proc.wait(timeout=max(0.0, min(_SAMPLE_S, deadline - time.monotonic())))
            break
        except subprocess.TimeoutExpired:
            pass
        expired = time.monotonic() >= deadline
        if not window:
            if expired:
                raise _TimedOut(proc.args, timeout_s, None) from None
            continue
        now = time.monotonic()
        # A wake much later than asked for (a suspended machine, a starved
        # aramid) observed nothing in between, so the gap is not evidence
        # of a stall: this sample starts the quiet clock afresh (it leans
        # toward active). Measured from the END of the previous sample, so
        # a slow sampler (`ps` on macOS) is not mistaken for a gap.
        unobserved = now - sampled_at > 2 * _SAMPLE_S
        try:
            tree = proctree.sample(proc.pid)
        except Exception:  # noqa: BLE001 -- a sampler that raises is unmeasurable, i.e. active
            tree = None
        sampled_at = time.monotonic()
        if sampled_at - now > 2 * _SAMPLE_S:
            # The same suspend or starvation, landing INSIDE the sample call:
            # unobserved as well. The quiet clock restarts where the sample
            # ENDED -- restarting it at `now` would hand the whole stretch to
            # the next wake as idle time.
            unobserved, now = True, sampled_at
        read = seen["out"] + seen["err"]
        if (unobserved or tree is None or last_tree is None or tree != last_tree
                or read != last_seen):
            quiet_since = now
        last_tree, last_seen = tree, read
        idle = now - quiet_since
        if expired:
            # The budget killed it, whatever the sample says: the idle time
            # is only REPORTED (`RunnerResult.idle_s`), never a stall.
            measured = tree is not None and idle >= _SAMPLE_S
            raise _TimedOut(proc.args, timeout_s, idle if measured else None) from None
        if idle >= window:
            raise _Stalled(idle, len(tree))
    # One shared bound for both readers: joined one after the other with a
    # full bound each, a holder of BOTH pipes cost twice the bound.
    drained_by = time.monotonic() + _POST_KILL_DRAIN_S
    for t in readers:
        t.join(timeout=max(0.0, drained_by - time.monotonic()))
    held = any(t.is_alive() for t in readers)
    # A reader still blocked owns its decoder, so only what it has already
    # handed over is used: a `\r` or half a character it holds back is lost.
    return "".join(chunks["out"]), "".join(chunks["err"]), held


def run_subprocess(argv, cwd: Path, timeout_s: float, env=None, *,
                   on_stdout_line=None) -> RunnerResult:
    """Launch `argv` and capture it. `on_stdout_line`, when given, is called
    with every stdout line AS IT ARRIVES (the gate's test suite ran ~19 min
    with nothing on screen because output was only read at exit). Both pipes
    are ALWAYS drained on threads, tap or not, and the wait is watched: past
    the wall clock `timeout_s`, or once the child tree shows no CPU and no
    output for the stall window (`stall_window()`), it is killed and the
    result is ToolState.TIMEOUT -- with `stalled_s` set in the second case,
    and `idle_s` in the first when the tree sat idle up to the deadline."""
    tool = Path(argv[0]).name
    if closed():
        return RunnerResult(tool, ToolState.TIMEOUT,
                            stderr=f"aramid: {tool} not started: the drain's hard deadline has passed")
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
    # Not started rather than refused: cmd.exe's refusal is an exit 1 with an
    # empty stdout, which a tool that accepts 1 as a verdict reads as a clean
    # report (FN-34). This measures the line handed to cmd.exe, and only that:
    # a program that re-expands its arguments into a longer line -- an npm
    # shim puts node's path and its script's in front of `%*` -- can still be
    # refused inside it. Such a runner batches under its own headroom and
    # judges an exit 1 that reported nothing, as the eslint adapter does.
    if Path(argv[0]).suffix.lower() in (".cmd", ".bat"):
        line = cmd_line_length(argv)
        budget = cmd_exe_line_budget()
        if line > budget:
            return RunnerResult(tool, ToolState.CRASHED,
                                stderr=(f"aramid: {tool} not started: its command line is "
                                        f"{line:,} characters, over the {budget:,} cmd.exe "
                                        f"allows a .cmd/.bat program ({CMD_EXE_LINE_LIMIT:,} "
                                        f"less its own `%COMSPEC% /c `)"))
    kwargs = own_group()
    start = time.monotonic()
    # S603 justification: this is aramid's single generic subprocess
    # launcher -- invoking external static-analysis tools (ruff, semgrep,
    # gitleaks, pip-audit, npm/pnpm/yarn, eslint, tsc, pytest...) is the
    # entire purpose of this function, not attacker-controlled input. Every
    # `argv` is built by a runner's own `_build_argv()` from fixed tool names
    # and repo-relative file paths, never from untrusted external strings.
    # BINARY pipes: `_watched_communicate` reads bytes as they arrive and
    # decodes them itself, to exactly what text=True/utf-8/replace gave.
    proc = subprocess.Popen(argv, cwd=str(cwd), stdout=subprocess.PIPE,  # noqa: S603
                            stderr=subprocess.PIPE,
                            env={**os.environ, **(env or {})}, **kwargs)
    try:
        with live_process(lambda: _kill_tree(proc)):
            out, err, held = _watched_communicate(proc, timeout_s, on_stdout_line)
    except (subprocess.TimeoutExpired, _Stalled) as stop:
        _kill_tree(proc)
        try:
            # The reader threads own the pipes; `communicate` here would race
            # them for a stream one of them may already have closed.
            proc.wait(timeout=_POST_KILL_DRAIN_S)
        except subprocess.TimeoutExpired:
            proc.kill()
        elapsed = time.monotonic() - start
        if isinstance(stop, _Stalled):
            return RunnerResult(tool, ToolState.TIMEOUT,
                                stderr=(f"aramid: {tool} stalled: no CPU in any of its "
                                        f"{stop.procs} processes and no output for "
                                        f"{stop.idle_s:.0f} s; killed after {elapsed:.0f} s. "
                                        f"A child blocked on a full pipe or on a read with "
                                        f"no timeout looks like this; a slow one does not."),
                                duration_s=elapsed, stalled_s=stop.idle_s)
        # The result says what happened, because nothing else can: a killed
        # child leaves no report and no exit code, so a bare TIMEOUT wrote a
        # 0-byte log and the gate named the tool with no reason (2026-09-04,
        # gitleaks on a pre-push gate, two pushes refused with blocking 0).
        # A tree that had sat idle up to the deadline is said to: at the
        # default window that is the only way a hang reads as one.
        idle = stop.idle_s if isinstance(stop, _TimedOut) else None
        why = (f"aramid: {tool} timed out after {timeout_s:g} s and was "
               f"killed; whatever it had written is discarded")
        if idle is not None:
            why += f" -- no CPU or output for the last {idle:.0f} s, which looks hung, not slow"
        return RunnerResult(tool, ToolState.TIMEOUT, stderr=why,
                            duration_s=elapsed, idle_s=idle)
    if closed():
        # Killed by the drain's hard deadline, not finished: its exit code
        # is the kill's, and a killed test run must not read as a failing
        # one (to the mutation consumer, "the mutant was killed").
        return RunnerResult(tool, ToolState.TIMEOUT,
                            stderr=f"aramid: {tool} was killed at the drain's hard deadline",
                            duration_s=time.monotonic()-start)
    if held:
        # Said on aramid's own stderr and nowhere else: the child finished,
        # so the result stands as it is. Refusing it would refuse every push
        # whose `npm test` leaves a server holding stdout. The holder is not
        # killed (parked: it outlived the run in 0.20.3 as well).
        print(f"aramid: {tool}: a process it started still holds its output pipe after it "
              f"exited; using the output read so far", file=sys.stderr)
    return RunnerResult(tool, ToolState.OK, out, err, time.monotonic()-start, proc.returncode)

class Runner(Protocol):
    name: str
    def applies(self, ctx) -> bool: ...
    def run(self, ctx) -> RunnerResult: ...
