"""claude-cli provider (spec section 4): one-shot `claude -p` review on the
user's Claude subscription. cost_usd is ALWAYS 0.0 -- the envelope's
total_cost_usd is an estimate of what the call would have cost via API and
must not count against the OpenRouter dollar cap; quota burn is the real
currency and is visible via the logged token counts.

Quota detection is pattern-based on stderr/stdout (the CLI's usage-limit
message wording); unknown nonzero exits map to ERR_ERROR so the consumer
falls to the next provider (fail-open, spec section 6).

THE REVIEWER HOLDS NOTHING (FN-41). The prompt is a review packet built from
a repo's diff, so in a consumer repo part of it is written by whoever wrote
the commit, and a reviewer that holds tools can be told by that text to use
them. It is started with none, and with nothing of the operator's Claude
Code setup around it (`_RESTRICT`), in an empty directory of its own. A
`claude` too old to take those options is not used at all: the launch is
never repeated without them."""
import json
import sys
import tempfile

from aramid import toolpath
from aramid.providers import base, spend
from aramid.providers.base import ProviderResponse

NAME = "claude-cli"
_QUOTA_MARKERS = ("usage limit", "rate limit", "quota")

# Every option that takes something away from the reviewer, as `claude --help`
# (2.1.296) describes them:
#   --tools ""                  none of the built-in tools
#   --strict-mcp-config         no MCP server but those of --mcp-config (none)
#   --safe-mode                 no CLAUDE.md, hook, skill, plugin, MCP server,
#                               custom command or agent
#   --restricted                no user, project or local settings file. User
#                               settings can switch a tool on by themselves:
#                               with them loaded, `advisorModel` gave the
#                               reviewer an `advisor` tool (measured, FN-41)
#   --no-session-persistence    the review is not saved as a session
#   --permission-prompts none   whatever would ask for permission is denied
_RESTRICT = ("--tools", "", "--strict-mcp-config", "--safe-mode", "--restricted",
             "--no-session-persistence", "--permission-prompts", "none")

# How a stderr line starts when the CLI does not take its command line
# (each measured on 2.1.296 with an empty prompt, so no review was made):
# an option it does not know, and a value it does not accept or that is
# missing.
_REFUSED = ("error: unknown option", "error: option ")


def installed() -> bool:
    return toolpath.which("claude") is not None


def available(cfg) -> bool:
    return installed()


def review(prompt: str, model: str, timeout_s: float, *, effort: str = "") -> ProviderResponse:
    exe = toolpath.which("claude")
    if exe is None:
        return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
    argv = [exe, "-p", "--model", model, "--output-format", "json", *_RESTRICT]
    if effort:
        argv += ["--effort", effort]
    # An empty directory, new for this call: where the drain was started is a
    # repository, and its CLAUDE.md, settings and .mcp.json are what a later
    # CLI would find if it stopped honouring one of the options above. A
    # directory that will not go (a child killed on timeout can hold it for a
    # moment on Windows) is left behind rather than failing the review.
    with tempfile.TemporaryDirectory(prefix="aramid-review-",
                                     ignore_cleanup_errors=True) as cwd:
        got = base.run_provider_subprocess(argv, prompt, timeout_s, cwd=cwd)
    if got is None:
        return ProviderResponse(text="", error=base.ERR_TIMEOUT)
    rc, out, err = got
    combined = f"{out}\n{err}".lower()
    if rc != 0:
        if any(m in combined for m in _QUOTA_MARKERS):
            return ProviderResponse(text="", error=base.ERR_QUOTA)
        refused = [line for line in err.splitlines() if line.startswith(_REFUSED)]
        if refused:
            # Said, because without this line the arm just fails on every
            # review and nothing tells an old CLI from a broken one.
            print(f"aramid: providers: claude-cli: this `claude` did not accept its "
                  f"command line, so the reviewer was not run. It is never started "
                  f"without the options that keep it from using tools: upgrade Claude "
                  f"Code. It said: {refused[0][:200]}", file=sys.stderr)
            return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
        return ProviderResponse(text="", error=base.ERR_ERROR)
    try:
        envelope = json.loads(out)
        text = envelope["result"]
        usage = envelope.get("usage", {})
        usage = usage if isinstance(usage, dict) else {}
        tokens_in = int(usage.get("input_tokens", 0))
        tokens_out = int(usage.get("output_tokens", 0))
    except (ValueError, KeyError, TypeError, AttributeError):
        return ProviderResponse(text="", error=base.ERR_MALFORMED)
    resp = ProviderResponse(text=text, tokens_in=tokens_in, tokens_out=tokens_out,
                            cost_usd=0.0)
    _log(resp, model)
    return resp


def _log(resp: ProviderResponse, model: str) -> None:
    from datetime import datetime, timezone
    try:
        spend.append_spend({"at": datetime.now(timezone.utc).isoformat(),
                            "provider": NAME, "model": model,
                            "tokens_in": resp.tokens_in, "tokens_out": resp.tokens_out,
                            "cost_usd": resp.cost_usd})
    except OSError:
        pass  # observability only -- never fail a successful call over logging


base.PROVIDERS[NAME] = sys.modules[__name__]
