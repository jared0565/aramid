"""Provider protocol (spec section 4): a provider is a module exposing
NAME: str, available(cfg) -> bool, and
review(prompt: str, model: str, timeout_s: float) -> ProviderResponse.
Mirrors consumers/: modules self-register into PROVIDERS at import time;
`chain(cfg)` orders them by [llm].provider_order and drops unavailable ones.

`run_provider_subprocess` is the shared CLI transport: fixed argv (callers
resolve the absolute exe path via shutil.which), prompt on STDIN (packets
exceed Windows argv limits), utf-8 with errors="replace" (the Phase 2a
cp1252 lesson), and a Windows process-TREE kill on timeout -- node-based
CLIs spawn children that subprocess.run's own kill would orphan.
"""
import subprocess
import sys
from dataclasses import dataclass

ERR_UNAVAILABLE = "unavailable"
ERR_QUOTA = "quota"
ERR_TIMEOUT = "timeout"
ERR_MALFORMED = "malformed"
ERR_ERROR = "error"


@dataclass
class ProviderResponse:
    text: str          # raw model output ("" on transport failure)
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    error: str = ""    # "" | unavailable | quota | timeout | malformed | error


PROVIDERS: dict[str, object] = {}  # populated by provider modules at import


def chain(cfg) -> list[object]:
    """Available providers in configured order. A probe that raises counts
    as unavailable (fail-open: the drain never crashes on a provider)."""
    out = []
    for name in cfg.llm.get("provider_order", []):
        module = PROVIDERS.get(name)
        if module is None:
            continue
        try:
            if module.available(cfg):
                out.append(module)
        except Exception:
            continue
    return out


def _tree_kill(pid: int) -> None:
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=30)


def run_provider_subprocess(argv: list[str], prompt: str,
                            timeout_s: float) -> tuple[int, str, str] | None:
    """Returns (returncode, stdout, stderr), or None on timeout (after
    killing the whole child tree)."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace")
    try:
        out, err = proc.communicate(input=prompt, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _tree_kill(proc.pid)
        proc.kill()
        proc.communicate()
        return None
    return proc.returncode, out, err
