"""unit: agent_files -- the managed block aramid owns inside CLAUDE.md and
AGENTS.md. Fence-scoped writes: content outside the markers is untouchable,
and a damaged fence (begin without end) refuses the write entirely."""
import subprocess

from aramid import agent_files
from aramid.commands.init import render_agent_blocks_notice


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


def test_remove_strips_fence_and_keeps_user_content(tmp_path):
    user_text = "# My project\n\nDo the thing.\n"
    (tmp_path / "CLAUDE.md").write_text(user_text, encoding="utf-8")
    agent_files.write_agent_blocks(tmp_path)

    actions = agent_files.remove_agent_blocks(tmp_path)

    assert ("CLAUDE.md", "removed") in actions
    # append inserted one "\n" separator; removal strips only fence lines.
    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == user_text + "\n"


def test_remove_deletes_file_that_was_only_the_block(tmp_path):
    agent_files.write_agent_blocks(tmp_path)

    actions = agent_files.remove_agent_blocks(tmp_path)

    assert actions == [("CLAUDE.md", "deleted"), ("AGENTS.md", "deleted")]
    assert not (tmp_path / "CLAUDE.md").exists()
    assert not (tmp_path / "AGENTS.md").exists()


def test_remove_reports_absent_and_damaged(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("no fence here\n", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text(
        "<!-- aramid:begin -- x -->\nno end\n", encoding="utf-8")

    actions = agent_files.remove_agent_blocks(tmp_path)

    assert actions == [("CLAUDE.md", "absent"), ("AGENTS.md", "damaged")]
    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == (
        "<!-- aramid:begin -- x -->\nno end\n")


def test_states_ok_stale_absent_damaged(tmp_path):
    agent_files.write_agent_blocks(tmp_path)                       # CLAUDE ok
    stale = agent_files.render_block().replace(
        "security & quality gate", "old title")
    (tmp_path / "AGENTS.md").write_text(stale, encoding="utf-8")   # stale

    states = dict(agent_files.agent_block_states(tmp_path))
    assert states == {"CLAUDE.md": "ok", "AGENTS.md": "stale"}

    (tmp_path / "CLAUDE.md").unlink()
    (tmp_path / "AGENTS.md").write_text(
        "<!-- aramid:begin -- x -->\nno end\n", encoding="utf-8")
    states = dict(agent_files.agent_block_states(tmp_path))
    assert states == {"CLAUDE.md": "absent", "AGENTS.md": "damaged"}


# --- notice renderer (for init) -----------------------------------------------

def _git_repo(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True,
                   capture_output=True)
    return tmp_path


def test_notice_names_changed_files_and_gives_the_command(tmp_path):
    root = _git_repo(tmp_path)
    notice = render_agent_blocks_notice(
        root, [("CLAUDE.md", "created"), ("AGENTS.md", "appended")])
    assert notice == (
        "aramid: init: wrote the managed agent block into CLAUDE.md, AGENTS.md"
        " -- agent coders read these files from the repo:\n"
        'aramid: init:       git add CLAUDE.md AGENTS.md && '
        'git commit -m "chore: aramid agent block"')


def test_notice_silent_when_unchanged(tmp_path):
    root = _git_repo(tmp_path)
    assert render_agent_blocks_notice(
        root, [("CLAUDE.md", "unchanged"), ("AGENTS.md", "unchanged")]) == ""


def test_notice_reports_damaged_even_outside_git(tmp_path):
    notice = render_agent_blocks_notice(tmp_path, [("AGENTS.md", "damaged")])
    assert notice == (
        "aramid: init: AGENTS.md has an aramid fence with no closing marker"
        " -- left untouched; restore the `<!-- aramid:end -->` line (or"
        " delete the fence) and re-run `aramid init`")
