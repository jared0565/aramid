"""unit: agent_files -- the managed block aramid owns inside CLAUDE.md and
AGENTS.md. Fence-scoped writes: content outside the markers is untouchable,
and a damaged fence (begin without end) refuses the write entirely."""
from aramid import agent_files


def test_created_when_absent(tmp_path):
    actions = agent_files.write_agent_blocks(tmp_path)

    assert actions == [("CLAUDE.md", "created"), ("AGENTS.md", "created")]
    for name in ("CLAUDE.md", "AGENTS.md"):
        assert (tmp_path / name).read_text(encoding="utf-8") == agent_files.render_block()


def test_appended_preserves_existing_content_byte_for_byte(tmp_path):
    user_text = "# My project\n\nDo the thing.\n"
    (tmp_path / "CLAUDE.md").write_text(user_text, encoding="utf-8")

    actions = agent_files.write_agent_blocks(tmp_path)

    assert ("CLAUDE.md", "appended") in actions
    text = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert text == user_text + "\n" + agent_files.render_block()


def test_replaced_touches_only_the_fence(tmp_path):
    before = "# Mine\n"
    stale = ("<!-- aramid:begin -- old header -->\nOLD CONTENT\n"
             "<!-- aramid:end -->\n")
    after = "\n# Also mine\n"
    (tmp_path / "CLAUDE.md").write_text(before + stale + after, encoding="utf-8")

    actions = agent_files.write_agent_blocks(tmp_path)

    assert ("CLAUDE.md", "replaced") in actions
    text = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert text == before + agent_files.render_block() + after


def test_second_run_is_unchanged_and_byte_identical(tmp_path):
    agent_files.write_agent_blocks(tmp_path)
    first = (tmp_path / "CLAUDE.md").read_bytes()

    actions = agent_files.write_agent_blocks(tmp_path)

    assert actions == [("CLAUDE.md", "unchanged"), ("AGENTS.md", "unchanged")]
    assert (tmp_path / "CLAUDE.md").read_bytes() == first


def test_damaged_fence_is_never_written(tmp_path):
    damaged = "# Mine\n<!-- aramid:begin -- managed -->\nno end marker here\n"
    (tmp_path / "AGENTS.md").write_text(damaged, encoding="utf-8")

    actions = agent_files.write_agent_blocks(tmp_path)

    assert ("AGENTS.md", "damaged") in actions
    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == damaged


def test_block_content_names_the_commands():
    block = agent_files.render_block()
    assert block.startswith("<!-- aramid:begin")
    assert block.endswith("<!-- aramid:end -->\n")
    for needle in ("ARAMID.md", "aramid check --staged",
                   "aramid ledger filter --status open", "--no-verify",
                   "aramid override"):
        assert needle in block
