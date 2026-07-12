import os, shutil, subprocess, sys, time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

class ToolState(StrEnum):
    OK="ok"; MISSING="missing"; CRASHED="crashed"; TIMEOUT="timeout"

@dataclass
class RunnerResult:
    tool: str; state: ToolState; raw: str = ""; stderr: str = ""; duration_s: float = 0.0

_WIN = sys.platform == "win32"

def _kill_tree(proc: subprocess.Popen):
    try:
        if _WIN:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
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
    proc = subprocess.Popen(argv, cwd=str(cwd), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True,
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
    return RunnerResult(tool, ToolState.OK, out, err, time.monotonic()-start)

class Runner(Protocol):
    name: str
    def applies(self, ctx) -> bool: ...
    def run(self, ctx) -> RunnerResult: ...
