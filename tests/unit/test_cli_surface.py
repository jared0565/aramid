"""The CLI's parser is public surface (API-2), and the knowledge base
documents all of it (DOC-12).

ONE walk of the real `build_parser()` feeds all three checks, so the pin
and the doc guards cannot disagree about what the surface is. The walk
sees every subcommand, every option string, every choice and every
positional -- choices included, because `schedule install|remove|status`
is as much the surface as a flag is.

- Frozen: the whole tree as it stands, so adding, renaming or removing a
  command, flag or choice is a CHANGELOG entry, not a side effect.
- Section 4: every subcommand and option is mentioned, token-bounded, in
  its command's own subsection -- a whole-document match would let one
  `--json` anywhere cover every command. Every choice appears in that
  subsection's heading (the synopsis), because a bare word such as `all`
  is satisfied by any prose. Positional names are internal (`id`, `rev`)
  and are held by the freeze, not the docs.
- Section 5: every top-level command has a row in the per-command table.
"""
import argparse
import re
from pathlib import Path

from aramid import cli

KB = Path(__file__).resolve().parents[2] / "docs" / "knowledge-base.md"

SURFACE = {
    "": ["--version", "agent-hook", "arm", "autolearn", "check", "doctor", "drain", "fleet",
         "hooks", "init", "ledger", "mutation-score", "notices", "override", "pack",
         "rebaseline", "resolvers", "schedule", "status", "triage", "uninstall",
         "update-rules"],
    "agent-hook": ["<event>", "<rest>"],
    "arm": ["--agent", "--autolearn", "--llm", "--mutation", "--mutation-score",
            "--red-proof", "--shadow", "--tdd"],
    "autolearn": ["--rebuild"],
    "check": ["--accept-degraded", "--all", "--gate", "--gate=all", "--gate=pre-commit",
              "--gate=pre-push", "--json", "--no-record", "--range", "--reason", "--staged",
              "--strict"],
    "doctor": ["--fix"],
    "drain": ["--all", "--dry-run", "--max-items", "--repo"],
    "fleet": ["--json", "deregister"],
    "fleet deregister": ["<target>"],
    "hooks": ["<action>", "<action>=install", "<action>=remove", "<action>=status"],
    "init": ["--discover", "<path>"],
    "ledger": ["consumers", "filter", "list", "mark-not-a-secret", "mark-rotated",
               "mark-unreachable", "resolve", "show"],
    "ledger consumers": ["--consumer", "--json", "--last"],
    "ledger filter": ["--json", "--rule", "--severity", "--status", "--tool"],
    "ledger list": [],
    "ledger mark-not-a-secret": ["--reason", "<id>"],
    "ledger mark-rotated": ["--reason", "<id>"],
    "ledger mark-unreachable": ["--reason", "<id>"],
    "ledger resolve": ["--out-of-scope", "--reason", "<id>"],
    "ledger show": ["<id>"],
    "mutation-score": ["--json"],
    "notices": ["ack", "list", "show"],
    "notices ack": ["<id>"],
    "notices list": [],
    "notices show": ["<id>"],
    "override": ["--reason", "<id>"],
    "pack": ["add", "compile", "list"],
    "pack add": ["<id>"],
    "pack compile": [],
    "pack list": [],
    "rebaseline": ["--yes", "<path>"],
    "resolvers": ["--json"],
    "schedule": ["<action>", "<action>=install", "<action>=remove", "<action>=status"],
    "status": [],
    "triage": ["--budget", "<rev>"],
    "uninstall": ["<path>"],
    "update-rules": [],
}


def _walk(p: argparse.ArgumentParser, path: tuple = ()) -> dict[str, list[str]]:
    """{"ledger filter": [tokens]} for every parser in the tree. A token is
    a subcommand name (aliases included), an option string, `<dest>` for a
    positional, or `<flag or <dest>>=<choice>` for each choice."""
    out: dict[str, list[str]] = {}
    toks: list[str] = []
    for a in p._actions:
        if isinstance(a, argparse._HelpAction):
            continue
        if isinstance(a, argparse._SubParsersAction):
            by_parser: dict[int, tuple] = {}
            for name, sp in a.choices.items():       # every name AND alias
                by_parser.setdefault(id(sp), (name, sp, []))[2].append(name)
            for name, sp, names in by_parser.values():
                toks.extend(names)
                out.update(_walk(sp, path + (name,)))
        elif a.option_strings:
            toks.extend(a.option_strings)
            toks.extend(f"{a.option_strings[0]}={c}" for c in (a.choices or ()))
        else:
            toks.append(f"<{a.dest}>")
            toks.extend(f"<{a.dest}>={c}" for c in (a.choices or ()))
    out[" ".join(path)] = sorted(toks)
    return out


def _surface() -> dict[str, list[str]]:
    return _walk(cli.build_parser())


def test_the_parser_surface_is_exactly_this():
    assert _surface() == SURFACE


def _section(title: str, end: str) -> str:
    text = KB.read_text(encoding="utf-8")
    return text[text.index(title):text.index(end)]


def _subsections() -> dict[str, list[str]]:
    """Section-4 subsections by the top-level commands their heading names
    (`aramid fleet [--json]` / `aramid fleet deregister` is one, for fleet)."""
    s4 = _section("## 4. CLI Command Reference", "## 5. Exit-Code Reference")
    out: dict[str, list[str]] = {}
    for sub in re.split(r"(?m)^### ", s4)[1:]:
        for top in set(re.findall(r"aramid ([a-z][a-z-]*)", sub.splitlines()[0])):
            out.setdefault(top, []).append(sub)
    return out


def _mentioned(token: str, text: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(token)}(?![\w-])", text) is not None


def test_section_4_mentions_every_subcommand_option_and_choice():
    subs = _subsections()
    assert len(subs) >= 15, f"the section-4 split has gone blind: {sorted(subs)}"
    missing = []
    for path, tokens in _surface().items():
        for tok in tokens:
            if path == "":
                if tok.startswith("-"):
                    continue          # --version: the section's own intro
                top, what = tok, None
            else:
                top, what = path.split()[0], tok
            if top not in subs:
                missing.append(f"`aramid {top}` has no section-4 subsection")
                continue
            if what is None or (what.startswith("<") and "=" not in what):
                continue              # a positional's name is internal
            body = "\n".join(subs[top])
            heading = "\n".join(s.splitlines()[0] for s in subs[top])
            if "=" in what:
                choice = what.split("=", 1)[1]
                if not _mentioned(choice, heading):
                    missing.append(f"{path}: choice {what} not in the heading")
            elif not _mentioned(what, body):
                missing.append(f"{path}: {what} not mentioned")
    assert sorted(set(missing)) == []


def test_the_global_version_flag_is_documented():
    intro = _section("## 4. CLI Command Reference", "### `aramid init")
    assert _mentioned("--version", intro)


def test_section_5_has_a_row_for_every_top_level_command():
    s5 = _section("### Per-command exit codes", "## 6. FAQ")
    rows = re.findall(r"(?m)^\| (.+?) \|", s5)
    # `aramid init` / `uninstall` is one row for two commands
    named = {c for first in rows
             for c in re.findall(r"(?:aramid |/ `)([a-z][a-z-]*)", first)}
    assert len(named) >= 15, f"the section-5 parse has gone blind: {sorted(named)}"
    assert set(_surface()[""]) - {"--version"} - named == set()
