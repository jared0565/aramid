"""mcp_tools -- the seven MCP tools over the CLI internals (spec §7).

Tools call the SAME functions the CLI commands use -- no subprocess
self-reinvocation, one code path to test, and suppression over MCP
carries identical authority and audit trail to the CLI (the transport
changes, the ledger event does not).

Handlers run the internals under redirect_stdout/redirect_stderr into
buffers: the cmd_* functions speak through print(), and stdout belongs
to the protocol. The captured text IS the tool result. isError marks a
failed OPERATION -- not a gate honestly reporting findings: aramid_check
exiting 1 (blocking findings) or 2 (degraded tools) did its job and
returns isError False with the report; an engine or config error
(exit 3) is a failed operation. Likewise an override the ledger
REFUSED returns isError True.

aramid_check always runs record=False (a ledger SNAPSHOT): MCP is the
consumer-measurement surface, exactly the shape that motivated
`check --no-record` after a consumer's whole-tree look wrote 683 rows.
Recording gate runs stay with the git hooks and the CLI.
"""
import contextlib
import io
from pathlib import Path

from aramid.mcp import _InvalidParams


def _repo() -> Path | None:
    from aramid import gitutil
    try:
        repo = gitutil.repo_root(Path.cwd())
    except Exception:
        return None
    if not (repo / "aramid.toml").is_file():
        return None
    return repo


_NOT_ONBOARDED = (
    "aramid: this directory is not an onboarded repo (no aramid.toml"
    " at the git root) -- run `aramid init` there first.")


def _text_result(text: str, *, is_error: bool) -> dict:
    return {"content": [{"type": "text", "text": text}],
            "isError": is_error}


def _run(fn, *args, ok_codes=(0,), report_codes=(), **kwargs) -> dict:
    """Run a cmd_* internal with stdout+stderr captured; the combined
    text is the tool result. Exit codes in ok_codes and report_codes
    are isError False (report_codes are 'the command worked and is
    telling you something is wrong with the REPO'); everything else is
    isError True."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn(*args, **kwargs)
    text = out.getvalue()
    if err.getvalue():
        text += ("\n[stderr]\n" if text else "[stderr]\n") + err.getvalue()
    text += f"\n(exit code {rc})"
    return _text_result(text, is_error=rc not in (*ok_codes, *report_codes))


def _require_id_and_reason(args: dict) -> tuple[str, str]:
    fid = args.get("id")
    reason = args.get("reason")
    if not isinstance(fid, str) or not fid:
        raise _InvalidParams("`id` is required (a finding id string)")
    if not isinstance(reason, str) or not reason.strip():
        raise _InvalidParams(
            "`reason` is required and must be non-empty -- suppression"
            " without a reason is not recordable")
    return fid, reason


def _onboarded(handler):
    def wrapped(root, args):
        repo = _repo()
        if repo is None:
            return _text_result(_NOT_ONBOARDED, is_error=True)
        return handler(repo, args)
    return wrapped


@_onboarded
def _check(repo, args):
    from aramid.commands.check import cmd_check
    from aramid.models import Gate
    gate_raw = args.get("gate", "pre-commit")
    try:
        gate = Gate(gate_raw)
    except ValueError:
        raise _InvalidParams(
            f"`gate` must be one of pre-commit, pre-push, all"
            f" (got {gate_raw!r})") from None
    if args.get("staged", False):
        mode = "staged"
    elif gate is Gate.ALL:
        mode = "all"
    else:
        mode = "staged" if gate is Gate.PRE_COMMIT else "range"
    return _run(cmd_check, repo, gate, mode,
                strict=bool(args.get("strict", False)),
                record=False, report_codes=(1, 2))


@_onboarded
def _status(repo, args):
    from aramid.commands.status import cmd_status
    return _run(cmd_status, repo)


@_onboarded
def _ledger_filter(repo, args):
    from aramid.commands.ledger_cmd import cmd_ledger_filter
    return _run(cmd_ledger_filter, repo,
                tool=args.get("tool"), rule=args.get("rule"),
                status=args.get("status"), severity=args.get("severity"))


@_onboarded
def _resolvers(repo, args):
    from aramid.commands.resolvers import cmd_resolvers
    return _run(cmd_resolvers, repo)


@_onboarded
def _override(repo, args):
    from aramid.commands.override import cmd_override
    fid, reason = _require_id_and_reason(args)
    return _run(cmd_override, repo, fid, reason)


@_onboarded
def _mark_not_a_secret(repo, args):
    from aramid.commands.ledger_cmd import cmd_ledger_mark_not_a_secret
    fid, reason = _require_id_and_reason(args)
    return _run(cmd_ledger_mark_not_a_secret, repo, fid, reason)


@_onboarded
def _mark_rotated(repo, args):
    from aramid.commands.ledger_cmd import cmd_ledger_mark_rotated
    fid, reason = _require_id_and_reason(args)
    return _run(cmd_ledger_mark_rotated, repo, fid, reason)


_ID_REASON_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "minLength": 1,
               "description": "the finding id (from aramid_ledger_filter)"},
        "reason": {"type": "string", "minLength": 1,
                   "description": "why -- recorded in the ledger"},
    },
    "required": ["id", "reason"],
}

TOOLS: dict[str, dict] = {
    "aramid_check": {
        "description": (
            "Run aramid's security/quality gate against a read-only"
            " SNAPSHOT of the ledger (nothing is written). gate:"
            " pre-commit (default, staged scope), pre-push, or all."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "gate": {"type": "string",
                         "enum": ["pre-commit", "pre-push", "all"]},
                "staged": {"type": "boolean"},
                "strict": {"type": "boolean"},
            },
        },
        "handler": _check,
    },
    "aramid_status": {
        "description": "Live gate posture: open findings, bakes, streaks,"
                       " agent surfaces -- the same output as `aramid"
                       " status`.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": _status,
    },
    "aramid_ledger_filter": {
        "description": "Filter ledger findings (status/tool/rule/severity);"
                       " suppression notes included.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string"}, "tool": {"type": "string"},
                "rule": {"type": "string"}, "severity": {"type": "string"},
            },
        },
        "handler": _ledger_filter,
    },
    "aramid_resolvers": {
        "description": "Per-resolver yield report -- what each analyzer"
                       " actually produced here.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": _resolvers,
    },
    "aramid_override": {
        "description": "Suppress a WARN finding, reason required --"
                       " identical authority and ledger audit trail to"
                       " `aramid override`.",
        "inputSchema": _ID_REASON_SCHEMA,
        "handler": _override,
    },
    "aramid_mark_not_a_secret": {
        "description": "Mark a secret finding as not-a-secret, reason"
                       " required; ledger-logged.",
        "inputSchema": _ID_REASON_SCHEMA,
        "handler": _mark_not_a_secret,
    },
    "aramid_mark_rotated": {
        "description": "Mark a leaked secret as rotated, reason required;"
                       " ledger-logged.",
        "inputSchema": _ID_REASON_SCHEMA,
        "handler": _mark_rotated,
    },
}
