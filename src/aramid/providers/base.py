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

from aramid import diagnostics

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
        except Exception as exc:
            # Named: a provider whose probe RAISES is indistinguishable from
            # one that is merely not configured, and the difference is the
            # entire LLM half of the product quietly doing nothing forever.
            # A well-behaved available() returns False (see claude_cli), so
            # reaching here at all is the anomaly -- this is not chatter.
            diagnostics.note_failed("providers", f"{name} probe failed", exc)
            continue
    return out


def _tree_kill(pid: int) -> None:
    if sys.platform == "win32":
        # S603/S607 justification: fixed argv killing a process tree aramid
        # itself spawned -- `pid` is our own child's, not external input, and
        # `taskkill` resolves via PATH on every Windows host. Mirrors
        # runners.base._kill_tree, which makes the identical call.
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],  # noqa: S603,S607
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=30)


def run_provider_subprocess(argv: list[str], prompt: str,
                            timeout_s: float) -> tuple[int, str, str] | None:
    """Returns (returncode, stdout, stderr), or None on timeout (after
    killing the whole child tree)."""
    # S603 justification: the LLM-provider counterpart of
    # runners.base.run_subprocess -- launching a provider's own CLI is this
    # function's entire purpose. Every `argv` is built by a provider module
    # from its fixed binary name plus flags; the PROMPT never enters argv, it
    # is written to the child's stdin below, so no prompt content can be read
    # as an argument. No shell is involved.
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,  # noqa: S603
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
