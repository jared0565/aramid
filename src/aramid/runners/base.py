import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

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
    """
    root: Path
    files: list[str] = field(default_factory=list)
    rng: str | None = None
    pkg_manager: str | None = None
    stacks: set[str] = field(default_factory=set)
    extra_semgrep_configs: tuple[str, ...] = ()

_WIN = sys.platform == "win32"

def _kill_tree(proc: subprocess.Popen):
    try:
        if _WIN:
            # noqa justification (S603/S607): fixed argv killing a process
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
    if shutil.which(argv[0]) is None and not Path(argv[0]).exists():
        return RunnerResult(tool, ToolState.MISSING)
    kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if _WIN \
             else {"start_new_session": True}
    start = time.monotonic()
    # noqa justification (S603): this is aramid's single generic subprocess
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
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return RunnerResult(tool, ToolState.TIMEOUT, duration_s=time.monotonic()-start)
    return RunnerResult(tool, ToolState.OK, out, err, time.monotonic()-start, proc.returncode)

class Runner(Protocol):
    name: str
    def applies(self, ctx) -> bool: ...
    def run(self, ctx) -> RunnerResult: ...
