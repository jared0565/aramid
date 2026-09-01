import sys

# Fast path for the pre-tool-use hook (spec §5/§9): this launch rides
# `python -P -m aramid` on EVERY Bash/PowerShell tool call in an onboarded
# repo, and `aramid.cli` eagerly imports the whole command tree (~315ms
# measured) before argparse ever sees "agent-hook". Importing only
# `aramid.commands.agent_hook` keeps the hot path inside the <2s budget.
# Trailing argv beyond the event token is ignored -- matches the REMAINDER
# tolerance the subcommand's own argparse wiring gives it, and an
# unknown/empty event is a silent exit 0 by cmd_agent_hook's own contract,
# so there is nothing to validate here that dropping the tail would lose.
# Everything else falls through to cli.main unchanged.
if sys.argv[1:2] == ["agent-hook"]:
    from aramid.commands.agent_hook import cmd_agent_hook
    sys.exit(cmd_agent_hook(sys.argv[2] if len(sys.argv) > 2 else "", None))

from aramid.cli import main
sys.exit(main())
