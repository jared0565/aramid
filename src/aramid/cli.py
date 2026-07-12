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
from aramid.commands.arm import cmd_arm
from aramid.commands.check import cmd_check
from aramid.commands.doctor import cmd_doctor
from aramid.commands.init import cmd_init
from aramid.commands.ledger_cmd import (
    cmd_ledger_filter,
    cmd_ledger_list,
    cmd_ledger_mark_rotated,
    cmd_ledger_show,
)
from aramid.commands.override import cmd_override
from aramid.commands.status import cmd_status
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
    p_rotated = ledger_sub.add_parser("mark-rotated")
    p_rotated.add_argument("id")
    p_rotated.add_argument("--reason", required=True)

    p_override = sub.add_parser("override", help="suppress a WARN finding (ledger-logged)")
    p_override.add_argument("id")
    p_override.add_argument("--reason", required=True)

    sub.add_parser("arm", help="end the WARN-only semgrep bake")
    sub.add_parser("update-rules", help="refresh the vendored semgrep ruleset")

    p_uninstall = sub.add_parser("uninstall", help="reverse init")
    p_uninstall.add_argument("path", nargs="?", default=".")

    return p


def _check_mode(args: argparse.Namespace) -> str:
    if args.all:
        return "all"
    if args.range:
        return "range"
    if args.staged:
        return "staged"
    return "staged" if args.gate == "pre-commit" else "range"


def main(argv: list[str] | None = None) -> int:
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

    if args.command == "ledger":
        if args.ledger_command == "list":
            return cmd_ledger_list(root)
        if args.ledger_command == "show":
            return cmd_ledger_show(root, args.id)
        if args.ledger_command == "filter":
            return cmd_ledger_filter(root, tool=args.tool, rule=args.rule,
                                      status=args.status, severity=args.severity)
        if args.ledger_command == "mark-rotated":
            return cmd_ledger_mark_rotated(root, args.id, args.reason)
        print("aramid: ledger: a subcommand is required (list|show|filter|mark-rotated)",
              file=sys.stderr)
        return 3

    if args.command == "override":
        return cmd_override(root, args.id, args.reason)

    if args.command == "arm":
        return cmd_arm(root)

    if args.command == "update-rules":
        return cmd_update_rules(root)

    if args.command == "uninstall":
        return cmd_uninstall(Path(args.path))

    print(f"aramid: unknown command: {args.command}", file=sys.stderr)
    return 3
