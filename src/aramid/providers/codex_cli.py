"""codex-cli provider (spec section 4): one-shot `codex exec` on the user's
Codex subscription (cost_usd always 0.0). Invoked sandboxed read-only with
`-` so the prompt arrives on stdin; --json gives a JSONL event stream from
which the LAST agent_message item is the reply. The parser is deliberately
lenient (skip unparseable lines) because the event vocabulary evolves
between CLI versions -- only "no agent_message at all" is malformed.

THE REVIEWER HOLDS NOTHING (FN-49, the codex half of FN-41). The prompt is
a review packet built from a repo's diff, so in a consumer repo part of it
is written by whoever wrote the commit. Measured on codex 0.162.0: under
`--sandbox read-only` the reviewer read a file outside its directory
through its shell (the sandbox stops writes, not reads), and it had a web
tool and the operator's own codex setup around it. It is started without
those (`_RESTRICT`), in an empty directory of its own. A `codex` that does
not take that command line is not used at all: the launch is never repeated
without it. And because a switch can be accepted and not applied (measured:
`--disable unified_exec` exits 0 and leaves it on), the stream is read too:
a reply that came after any item but a reply, reasoning, a plan or an error
is thrown away (`_HARMLESS_ITEMS`)."""
import json
import sys
import tempfile

from aramid import toolpath
from aramid.providers import base, spend
from aramid.providers.base import ProviderResponse

NAME = "codex-cli"
_QUOTA_MARKERS = ("usage limit", "rate limit", "quota")

# Every option that takes something away from the reviewer, as codex 0.162.0
# describes them (`codex exec --help`, `codex features list`):
#   --ignore-user-config   $CODEX_HOME/config.toml is not loaded: no MCP
#                          server, no setting of the operator's
#   --ignore-rules         no user or project execpolicy .rules file
#   --ephemeral            the review is not saved as a session
#   --disable <feature>    one per feature that hands the model a tool: the
#                          shell, image viewing (a path to a file), apps and
#                          plugins (connectors), image generation, the
#                          browsers and computer use, sub-agents, hooks, and
#                          the tools that offer to install more. Each was
#                          read back `false` from `features list` under the
#                          switch. A name codex does not know is refused.
#   -c web_search=disabled the web tool (default "cached"). Unquoted: codex
#                          takes a value that is not TOML as a string, and
#                          `codex` is a .cmd on Windows, where quotes are
#                          cmd.exe's to read.
# `unified_exec` is not here: codex accepts `--disable unified_exec` and
# leaves it on (measured), so naming it would claim what it does not do.
_DISABLED_FEATURES = ("shell_tool", "view_image", "apps", "plugins", "remote_plugin",
                      "image_generation", "browser_use", "browser_use_external",
                      "browser_use_full_cdp_access", "computer_use", "in_app_browser",
                      "multi_agent", "hooks", "tool_suggest", "skill_mcp_dependency_install")
_RESTRICT = ("--ignore-user-config", "--ignore-rules", "--ephemeral",
             *(arg for feature in _DISABLED_FEATURES for arg in ("--disable", feature)),
             "-c", "web_search=disabled")

# How a stderr line starts when the CLI does not take its command line (each
# measured on codex 0.162.0 without a model call): an argument it does not
# know, a switch with no value, and a feature name it does not know.
_REFUSED = ("error: unexpected argument ", "error: a value is required ",
            "Error: Unknown feature flag: ")

# The items a reply may come with: the reply itself, the model's reasoning,
# its plan, and an error codex reports about itself (the 16:02Z call's one
# error item was the skills budget). Anything else is a tool that ran.
_HARMLESS_ITEMS = ("agent_message", "reasoning", "todo_list", "error")


def installed() -> bool:
    return toolpath.which("codex") is not None


def available(cfg) -> bool:
    return installed()


def review(prompt: str, model: str, timeout_s: float, *, effort: str = "") -> ProviderResponse:
    exe = toolpath.which("codex")
    if exe is None:
        return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
    argv = [exe, "exec", "--json", "--sandbox", "read-only", "--skip-git-repo-check"]
    if model:
        argv += ["-m", model]
    if effort:
        argv += ["-c", f"model_reasoning_effort={effort}"]
    argv += [*_RESTRICT, "-"]
    # An empty directory, new for this call: where the drain was started is a
    # repository, and its AGENTS.md and .codex/ are what a later CLI would
    # find if it stopped honouring one of the options above. A directory that
    # will not go (a child killed on timeout can hold it for a moment on
    # Windows) is left behind rather than failing the review.
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
            # review and nothing tells a CLI that changed from a broken one.
            print(f"aramid: providers: codex-cli: this `codex` did not accept its "
                  f"command line, so the reviewer was not run. It is never started "
                  f"without the options that keep it from using tools. It said: "
                  f"{refused[0][:200]}", file=sys.stderr)
            return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
        return ProviderResponse(text="", error=base.ERR_ERROR)

    text, tokens_in, tokens_out = None, 0, 0
    tool = None
    for line in out.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            # Unparseable line - skip (lenient parsing)
            continue

        # Hardening: skip if event is not a dict (e.g., bare scalar like 5)
        if not isinstance(event, dict):
            continue

        # Any item, started, updated or completed: a tool killed before it
        # completed has still run.
        item = event.get("item")
        if isinstance(item, dict) and item.get("type") not in _HARMLESS_ITEMS and tool is None:
            tool = str(item["type"]) if item.get("type") is not None else "an item with no type"

        # Check for agent_message item
        if event.get("type") == "item.completed":
            # Hardening: skip if item is not a dict
            if isinstance(item, dict) and item.get("type") == "agent_message":
                text = item.get("text", "")

        # Check for turn.completed with usage info
        if event.get("type") == "turn.completed":
            usage = event.get("usage")
            # Hardening: skip if usage is not a dict
            if isinstance(usage, dict):
                # Safe int conversion - wrong types zero out
                try:
                    tokens_in = int(usage.get("input_tokens", 0))
                except (ValueError, TypeError):
                    tokens_in = 0
                try:
                    tokens_out = int(usage.get("output_tokens", 0))
                except (ValueError, TypeError):
                    tokens_out = 0

    if tool is not None:
        # The reply may carry what the tool read, and it would reach the
        # ledger as a finding's text. The tokens were spent all the same.
        _log(ProviderResponse(text="", tokens_in=tokens_in, tokens_out=tokens_out),
             model or "default")
        print(f"aramid: providers: codex-cli: the reviewer used a tool ({tool[:80]}), so its "
              f"reply was thrown away. It is started without tools; this `codex` gave it "
              f"one anyway.", file=sys.stderr)
        return ProviderResponse(text="", error=base.ERR_ERROR)

    if text is None:
        return ProviderResponse(text="", error=base.ERR_MALFORMED)

    resp = ProviderResponse(text=text, tokens_in=tokens_in, tokens_out=tokens_out,
                            cost_usd=0.0)
    _log(resp, model or "default")
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
