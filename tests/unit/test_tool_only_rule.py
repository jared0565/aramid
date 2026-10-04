"""Operator mandate (2026-10-04): aramid is used only as a TOOL. Consumers
never talk to aramid's agent, and the shared agent channel carries only bug
reports and improvement suggestions for aramid. An installation ships the
tool, never its agent, so the rule has to reach consumers through what the
tool itself writes into their repo: the fenced CLAUDE.md/AGENTS.md block
(pinned in test_agent_files.py) and ARAMID.md (pinned here).

Full-text pins, not substring needles: a needle passes while the sentence
around it says something else."""
from aramid.commands.init import _render_aramid_md

_SECTION = """\
## aramid is a tool, not an agent

Use aramid only through its commands (above), its MCP tools and this file.
An installation ships the tool, never its agent, so do not talk to aramid's
agent: no questions, no requests, no replies, and no expectation of
announcements from it.

The shared agent channel carries exactly two kinds of message for aramid,
addressed to `aramid-agent`:

- a **bug report**: what you ran, what happened, and what you expected;
- a **suggestion for improvement**.

Nothing else goes there. Fixes and changes reach you in a release. After
upgrading, re-run `aramid init` to refresh this file and the aramid block in
`CLAUDE.md` / `AGENTS.md`.

"""


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    nxt = text.find("\n## ", start + len(heading))
    return text[start:nxt + 1] if nxt != -1 else text[start:]


def test_aramid_md_states_the_tool_only_rule_in_full():
    rendered = _render_aramid_md({"python"}, None)
    assert _section(rendered, "## aramid is a tool, not an agent") == _SECTION


def test_tool_only_section_sits_inside_the_managed_region():
    rendered = _render_aramid_md({"python"}, None)
    assert rendered.index("## aramid is a tool, not an agent") \
        < rendered.index("<!-- /aramid:managed -->")
