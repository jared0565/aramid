"""cli -- top-level argparse dispatch tree. Each subcommand maps 1:1 to a
`aramid.commands.<name>.cmd_<name>` function; this module's only job is
argv parsing and translating parsed args into that function's positional/
keyword arguments, then returning its int exit code unchanged.

Any argparse parse failure -- unknown subcommand, missing required
argument, bad flag -- normally raises `SystemExit(2)`; that is intercepted
here and remapped to exit code 3 (design doc section 3's "engine or config
error" tier), so `python -m aramid bogus-command` and a genuinely crashed
engine report the same code, never a bare argparse 2. `-h`/`--help`
(`SystemExit(0)`) and `--version` are the only paths that exit 0 without
dispatching to a subcommand.
"""
import argparse
import sys
from pathlib import Path

from aramid import __version__
from aramid.commands.autolearn_cmd import cmd_autolearn
from aramid.commands.arm import cmd_arm
from aramid.commands.check import cmd_check
from aramid.commands.doctor import cmd_doctor
from aramid.commands.drain import cmd_drain
from aramid.commands.init import cmd_init
from aramid.commands.ledger_cmd import (
    cmd_ledger_filter,
    cmd_ledger_list,
    cmd_ledger_mark_not_a_secret,
    cmd_ledger_mark_rotated,
    cmd_ledger_mark_unreachable,
    cmd_ledger_resolve,
    cmd_ledger_show,
)
from aramid.commands.mutation_score import cmd_mutation_score
from aramid.commands.override import cmd_override
from aramid.commands.pack_cmd import cmd_pack_add, cmd_pack_compile, cmd_pack_list
from aramid.commands.rebaseline import cmd_rebaseline
from aramid.commands.resolvers import cmd_resolvers
from aramid.commands.schedule import cmd_schedule
from aramid.commands.status import cmd_status
from aramid.commands.triage_cmd import cmd_triage
from aramid.commands.uninstall import cmd_uninstall
from aramid.commands.update_rules import cmd_update_rules
from aramid.models import Gate


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aramid")
    p.add_argument("--version", action="store_true")
    sub = p.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="onboard a repo (write config, install hooks, baseline)")
    p_init.add_argument("path", nargs="?", default=".")
    p_init.add_argument("--discover", action="store_true")

    p_check = sub.add_parser("check", help="run the gate pipeline")
    p_check.add_argument("--gate", choices=["pre-commit", "pre-push"], default="pre-commit")
    mode = p_check.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--range", action="store_true")
    mode.add_argument("--all", action="store_true")
    p_check.add_argument("--strict", action="store_true", help="CI mode: treat 2/3 as failure")
    p_check.add_argument("--json", action="store_true")
    p_check.add_argument("--accept-degraded", action="store_true")
    p_check.add_argument("--reason", default=None)

    p_doctor = sub.add_parser("doctor", help="probe/repair the toolchain")
    p_doctor.add_argument("--fix", action="store_true")

    sub.add_parser("status", help="report ledger/config state")

    p_res = sub.add_parser("resolvers",
                           help="grade each auto-resolver on what it SAW, not "
                                "only on what it cleared (finds resolvers that "
                                "silently stopped firing)")
    p_res.add_argument("--json", action="store_true")

    p_ms = sub.add_parser("mutation-score",
                          help="advisory per-function mutation-score + regression report")
    p_ms.add_argument("--json", action="store_true")

    p_triage = sub.add_parser("triage", help="score a commit (or range) and enqueue if risky")
    p_triage.add_argument("rev", nargs="?", default="HEAD")
    p_triage.add_argument("--budget", type=float, default=None,
                          help="wall-clock watchdog in seconds; on expiry triage "
                               "self-kills with exit 3 (used by the post-commit shim)")

    p_drain = sub.add_parser("drain", help="sweep registered repos, pop queued items, consume")
    drain_scope = p_drain.add_mutually_exclusive_group()
    drain_scope.add_argument("--all", action="store_true", help="drain every registered repo")
    drain_scope.add_argument("--repo", default=None, help="drain a single repo (default: .)")
    p_drain.add_argument("--dry-run", action="store_true")
    p_drain.add_argument("--max-items", type=int, default=None)

    p_ledger = sub.add_parser("ledger", help="query the findings ledger")
    ledger_sub = p_ledger.add_subparsers(dest="ledger_command")
    ledger_sub.add_parser("list")
    p_show = ledger_sub.add_parser("show")
    p_show.add_argument("id")
    p_filter = ledger_sub.add_parser("filter")
    p_filter.add_argument("--tool")
    p_filter.add_argument("--rule")
    p_filter.add_argument("--status")
    p_filter.add_argument("--severity")
    p_filter.add_argument("--json", action="store_true")
    p_rotated = ledger_sub.add_parser("mark-rotated")
    p_rotated.add_argument("id")
    p_rotated.add_argument("--reason", required=True)
    p_nas = ledger_sub.add_parser("mark-not-a-secret")
    p_nas.add_argument("id")
    p_nas.add_argument("--reason", required=True)
    p_unreachable = ledger_sub.add_parser("mark-unreachable")
    p_unreachable.add_argument("id")
    p_unreachable.add_argument("--reason", required=True)
    p_resolve = ledger_sub.add_parser("resolve")
    p_resolve.add_argument("id")
    p_resolve.add_argument("--out-of-scope", action="store_true", dest="out_of_scope",
                           help="the finding's runner still runs here but no longer "
                                "examines this path (its file scope narrowed)")
    p_resolve.add_argument("--reason", required=True)

    p_override = sub.add_parser("override", help="suppress a WARN finding (ledger-logged)")
    p_override.add_argument("id")
    p_override.add_argument("--reason", required=True)

    p_pack = sub.add_parser("pack", help="manage the regression attack pack")
    pack_sub = p_pack.add_subparsers(dest="pack_command")
    pack_sub.add_parser("list")
    p_pack_add = pack_sub.add_parser("add")
    p_pack_add.add_argument("id")
    pack_sub.add_parser("compile")

    p_autolearn = sub.add_parser("autolearn",
                                 help="learned model-selection report (--rebuild: replay registry ledgers)")
    p_autolearn.add_argument("--rebuild", action="store_true")

    p_arm = sub.add_parser("arm", help="end a WARN-only bake (semgrep default, --llm for the LLM reviewer, --autolearn for learned uplift, --tdd for code-without-test findings, --mutation for surviving-mutant findings, --mutation-score for score-regression transitions, --red-proof for never-red test findings, --shadow for a repo-root file that hijacks `python -m aramid`)")
    arm_which = p_arm.add_mutually_exclusive_group()
    arm_which.add_argument("--llm", action="store_true")
    arm_which.add_argument("--autolearn", action="store_true")
    arm_which.add_argument("--tdd", action="store_true")
    arm_which.add_argument("--mutation", action="store_true")
    arm_which.add_argument("--mutation-score", action="store_true")
    arm_which.add_argument("--red-proof", action="store_true")
    arm_which.add_argument("--shadow", action="store_true")
    sub.add_parser("update-rules", help="refresh the vendored semgrep ruleset")

    p_uninstall = sub.add_parser("uninstall", help="reverse init")
    p_uninstall.add_argument("path", nargs="?", default=".")

    p_schedule = sub.add_parser("schedule", help="register/remove/query the Windows Task Scheduler drain job")
    p_schedule.add_argument("action", choices=["install", "remove", "status"])

    p_hooks = sub.add_parser("hooks",
                             help="manage the machine-wide git hook template (seeds NEW clones/inits; "
                                  "the shims no-op in repos without an aramid.toml)")
    p_hooks.add_argument("action", choices=["install", "remove", "status"])

    p_rebaseline = sub.add_parser("rebaseline",
                                  help="re-snapshot current findings as the ratchet baseline (after a fingerprint-affecting upgrade)")
    p_rebaseline.add_argument("path", nargs="?", default=".")
    p_rebaseline.add_argument("--yes", action="store_true",
                              help="required: confirms discarding current ratchet grandfathering")

    return p


def _check_mode(args: argparse.Namespace) -> str:
    if args.all:
        return "all"
    if args.range:
        return "range"
    if args.staged:
        return "staged"
    return "staged" if args.gate == "pre-commit" else "range"


def _force_utf8_on_redirect() -> None:
    """Make REDIRECTED output valid UTF-8 regardless of the locale encoding.

    Windows picks the ANSI code page (cp1252 here, measured) for a stdout that
    is a pipe or a file rather than a console. Any non-ASCII character then
    goes out as a legacy single byte -- U+2014 as 0x97 -- which is not valid
    UTF-8 in any position, so a consumer doing the obvious `decode("utf-8")`
    gets an exception or replacement characters. That is how round 64 item 5b
    reached us: a downstream repo's audit script mis-parsed a redirected
    `ledger filter`.

    Findings carry tool-authored text -- semgrep messages, code snippets, file
    paths -- so non-ASCII arrives from outside this codebase and cannot be
    fixed by keeping our own strings ASCII. The encoding of the STREAM is the
    only place to fix it once.

    Deliberately only when the stream is NOT a tty: a console already renders
    correctly through its own code page, and reconfiguring it can break that.
    An explicit PYTHONIOENCODING is overridden on purpose -- redirected output
    is machine-facing, and a stable UTF-8 contract is worth more than honouring
    a setting whose only reachable effect here is to emit undecodable bytes.

    Never raises: a stream that has been replaced (pytest capture, a
    non-TextIOWrapper) simply keeps whatever encoding it has.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_on_redirect()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        return 0 if code == 0 else 3

    if args.version:
        print(f"aramid {__version__}")
        return 0

    if args.command is None:
        print("aramid: no command", file=sys.stderr)
        return 3

    root = Path.cwd()

    if args.command == "init":
        return cmd_init(Path(args.path), discover=args.discover)

    if args.command == "check":
        gate = Gate(args.gate)
        accept_degraded = (args.reason or "no reason given") if args.accept_degraded else None
        return cmd_check(root, gate, _check_mode(args), strict=args.strict,
                          as_json=args.json, accept_degraded=accept_degraded)

    if args.command == "doctor":
        return cmd_doctor(root, fix=args.fix)

    if args.command == "status":
        return cmd_status(root)

    if args.command == "resolvers":
        return cmd_resolvers(root, as_json=args.json)

    if args.command == "mutation-score":
        return cmd_mutation_score(root, as_json=args.json)

    if args.command == "triage":
        return cmd_triage(root, args.rev, budget=args.budget)

    if args.command == "drain":
        targets = [] if args.all else ([args.repo] if args.repo else [str(root)])
        return cmd_drain(targets, dry_run=args.dry_run, max_items=args.max_items)

    if args.command == "ledger":
        if args.ledger_command == "list":
            return cmd_ledger_list(root)
        if args.ledger_command == "show":
            return cmd_ledger_show(root, args.id)
        if args.ledger_command == "filter":
            return cmd_ledger_filter(root, tool=args.tool, rule=args.rule,
                                      status=args.status, severity=args.severity,
                                      as_json=args.json)
        if args.ledger_command == "mark-rotated":
            return cmd_ledger_mark_rotated(root, args.id, args.reason)
        if args.ledger_command == "mark-not-a-secret":
            return cmd_ledger_mark_not_a_secret(root, args.id, args.reason)
        if args.ledger_command == "mark-unreachable":
            return cmd_ledger_mark_unreachable(root, args.id, args.reason)
        if args.ledger_command == "resolve":
            return cmd_ledger_resolve(root, args.id, args.out_of_scope, args.reason)
        print("aramid: ledger: a subcommand is required "
              "(list|show|filter|mark-rotated|mark-not-a-secret|mark-unreachable|resolve)",
              file=sys.stderr)
        return 3

    if args.command == "override":
        return cmd_override(root, args.id, args.reason)

    if args.command == "pack":
        if args.pack_command == "list":
            return cmd_pack_list(root)
        if args.pack_command == "add":
            return cmd_pack_add(root, args.id)
        if args.pack_command == "compile":
            return cmd_pack_compile(root)
        print("aramid: pack: a subcommand is required (list|add|compile)",
              file=sys.stderr)
        return 3

    if args.command == "autolearn":
        return cmd_autolearn(root, rebuild=args.rebuild)

    if args.command == "arm":
        return cmd_arm(root, llm=args.llm, autolearn=args.autolearn,
                       tdd=args.tdd, mutation=args.mutation,
                       mutation_score=args.mutation_score,
                       red_proof=args.red_proof, shadow=args.shadow)

    if args.command == "update-rules":
        return cmd_update_rules(root)

    if args.command == "uninstall":
        return cmd_uninstall(Path(args.path))

    if args.command == "schedule":
        return cmd_schedule(root, args.action)

    if args.command == "hooks":
        from aramid.commands.hooks_template import cmd_hooks
        return cmd_hooks(args.action)

    if args.command == "rebaseline":
        return cmd_rebaseline(Path(args.path), yes=args.yes)

    print(f"aramid: unknown command: {args.command}", file=sys.stderr)
    return 3
