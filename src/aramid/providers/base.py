"""Provider protocol (spec section 4): a provider is a module exposing
NAME: str, available(cfg) -> bool, and
review(prompt: str, model: str, timeout_s: float) -> ProviderResponse.
Mirrors consumers/: modules self-register into PROVIDERS at import time;
`chain(cfg)` orders them by [llm].provider_order and drops unavailable ones.

`run_provider_subprocess` is the shared CLI transport: fixed argv (callers
resolve the exe's path via `toolpath.which`), prompt on STDIN (packets
exceed Windows argv limits), utf-8 with errors="replace" (the Phase 2a
cp1252 lesson), and a Windows process-TREE kill on timeout -- node-based
CLIs spawn children that subprocess.run's own kill would orphan.

A failed call says why in `detail` (`failure_detail`, operator decision
2026-10-30): an HTTP status or exit code and one masked line of what the
provider said. Until then the reason was dropped, and two retired models
(an HTTP 410 from ollama, an exit 1 from codex) read as a four-day outage.
"""
import json
import os
import subprocess
import sys
from dataclasses import dataclass

from aramid import config_keys, diagnostics, toolpath
from aramid.runners import base as runners_base

ERR_UNAVAILABLE = "unavailable"
ERR_QUOTA = "quota"
ERR_TIMEOUT = "timeout"
ERR_MALFORMED = "malformed"
ERR_ERROR = "error"
# The model ran to its output cap and the text is cut mid-answer. Distinct
# from MALFORMED, which is the reviewer's own verdict being unparseable: a
# capped response is the PROVIDER failing to answer, so the arm loop falls
# through to the next arm on it (interop rounds 179/180: 65,536 tokens from
# deepseek-v4-flash in 166 s, read as a malformed verdict, item degraded).
ERR_TRUNCATED = "truncated"


@dataclass
class ProviderResponse:
    text: str          # raw model output ("" on transport failure)
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    error: str = ""    # "" | unavailable | quota | timeout | malformed | error | truncated
    detail: str = ""   # why it failed, one masked line (failure_detail); "" otherwise


PROVIDERS: dict[str, object] = {}  # populated by provider modules at import

# The longest `detail` an attempt keeps.
DETAIL_MAX = 200
# The keys aramid itself sends. A value shorter than _KEY_MIN is not a key,
# and masking it would mangle every place its letters occur in the line.
_KEY_ENV = ("OLLAMA_API_KEY", "OPENROUTER_API_KEY")
_KEY_MIN = 8


def last_line(text: str) -> str:
    """The last line of `text` with anything but whitespace on it."""
    lines = [line for line in (text or "").splitlines() if line.strip()]
    return lines[-1] if lines else ""


def failure_detail(head: str, text: str = "") -> str:
    """`head` (an HTTP status, an exit code, an exception's class), then
    `text` on one line, cut to DETAIL_MAX. The provider keys in the
    environment and the secret shapes the review packet masks
    (`review.redact_packet`) are masked first, so no part of one survives
    the cut. A CLI's error line can quote the prompt, which is the repo's
    code; the attempt it lands in stays in the local ledger."""
    from aramid import redact, review   # here, not at the top: review imports the ledger
    keys = [k for k in (os.environ.get(name, "") for name in _KEY_ENV) if len(k) >= _KEY_MIN]
    text = " ".join(review.redact_packet(redact.scrub(text or "", keys)).split())
    return (f"{head}: {text}" if text else head)[:DETAIL_MAX]


def http_detail(exc) -> str:
    """`failure_detail` for an urllib HTTPError: the status, and what the
    body says -- its JSON `error` (a string, or an object's `message`), else
    the body itself, else the reason phrase. Ollama's "retired on September
    25, 2026" came as `{"error": "..."}` with HTTP 410."""
    try:
        body = exc.read(4096).decode("utf-8", "replace")
    except Exception:   # a body that cannot be read is a body not kept
        body = ""
    said = body
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, dict):
            error = error.get("message")
        if isinstance(error, str) and error.strip():
            said = error
    if not said.strip():
        said = str(exc.reason or "")
    return failure_detail(f"HTTP {exc.code}", said)


def timeout_refused(timeout_s) -> ProviderResponse | None:
    """The response for a timeout no call can run under -- not a number,
    not finite, at or below 0, or above config_keys.CALL_TIMEOUT_MAX_S --
    else None. Every provider asks before it starts anything: an infinite
    one started the CLI and then raised OverflowError, leaving it running
    (config_keys.CALL_TIMEOUT_MAX_S says what was measured)."""
    if config_keys.in_bounds(("llm", "call_timeout_s"), timeout_s):
        return None
    return ProviderResponse(text="", error=ERR_ERROR, detail=failure_detail(
        "bad timeout", f"timeout_s must be a number above 0 and at most "
                       f"{config_keys.CALL_TIMEOUT_MAX_S:g}, got {timeout_s!r}"))


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
        # S603 justification: fixed argv killing a process tree aramid
        # itself spawned -- `pid` is our own child's, not external input, and
        # `taskkill` is started by its absolute path (`toolpath.program`):
        # the bare name is looked for in the current directory before
        # System32 (FN-47). Mirrors runners.base._kill_tree, which makes the
        # same call.
        subprocess.run(  # noqa: S603
            toolpath.launchable(["taskkill", "/PID", str(pid), "/T", "/F"]),
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)


def run_provider_subprocess(argv: list[str], prompt: str, timeout_s: float,
                            *, cwd=None) -> tuple[int, str, str] | None:
    """Returns (returncode, stdout, stderr), or None on timeout (after
    killing the whole child tree) -- and None, unstarted, once the drain's
    hard deadline has closed the registry (FN-14), or for a child it
    killed. `cwd` is the directory the child starts in; without it the
    child starts where this process is."""
    if runners_base.closed():
        return None
    # S603 justification: the LLM-provider counterpart of
    # runners.base.run_subprocess -- launching a provider's own CLI is this
    # function's entire purpose. Every `argv` is built by a provider module
    # from its fixed binary name plus flags; the PROMPT never enters argv, it
    # is written to the child's stdin below, so no prompt content can be read
    # as an argument. No shell is involved.
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,  # noqa: S603
                            stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", cwd=cwd)
    def kill() -> None:
        _tree_kill(proc.pid)
        proc.kill()
    try:
        # Registered so the drain's hard deadline can stop it (FN-14,
        # runners.base.kill_live): the provider CLI is not in a group of its
        # own, so this kill is the tree kill on Windows and the direct child
        # elsewhere, the same reach as the timeout below.
        with runners_base.live_process(kill):
            out, err = proc.communicate(input=prompt, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _tree_kill(proc.pid)
        proc.kill()
        proc.communicate()
        return None
    if runners_base.closed():
        return None
    return proc.returncode, out, err
