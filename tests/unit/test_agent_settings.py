"""unit: agent_settings -- aramid's entries in .claude/settings.json.
Own-entry-by-marker merge: foreign hook entries are preserved structurally
intact, aramid's own entry is rewritten to the current template, and a file
that cannot be parsed is never written."""
import json

from aramid import agent_settings


def _read(tmp_path):
    return json.loads(
        (tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))


def _write(tmp_path, data):
    p = tmp_path / ".claude" / "settings.json"
    p.parent.mkdir(exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return p


GRAPHITE_PRE = {"matcher": "Grep|Glob|Bash|PowerShell", "hooks": [
    {"type": "command",
     "command": "python -P -m graphite agent-hook pre-tool-use --mode strict"}]}
GRAPHITE_SESSION = {"hooks": [
    {"type": "command",
     "command": "python -P -m graphite agent-hook session-start"}]}


def test_created_when_absent(tmp_path):
    assert agent_settings.merge_claude_settings(tmp_path) == "created"
    data = _read(tmp_path)
    assert data == {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command",
                    "command": agent_settings.SESSION_START_COMMAND}]}]}}


def test_merge_preserves_foreign_entries(tmp_path):
    _write(tmp_path, {"hooks": {"PreToolUse": [GRAPHITE_PRE],
                                "SessionStart": [GRAPHITE_SESSION]}})

    assert agent_settings.merge_claude_settings(tmp_path) == "updated"

    data = _read(tmp_path)
    assert data["hooks"]["PreToolUse"] == [GRAPHITE_PRE]
    assert data["hooks"]["SessionStart"][0] == GRAPHITE_SESSION
    assert data["hooks"]["SessionStart"][1]["hooks"][0]["command"] == (
        agent_settings.SESSION_START_COMMAND)


def test_second_merge_is_unchanged_and_byte_identical(tmp_path):
    agent_settings.merge_claude_settings(tmp_path)
    first = (tmp_path / ".claude" / "settings.json").read_bytes()

    assert agent_settings.merge_claude_settings(tmp_path) == "unchanged"
    assert (tmp_path / ".claude" / "settings.json").read_bytes() == first


def test_tampered_own_entry_is_rewritten(tmp_path):
    # The -P-stripping attack: an aramid-named entry whose command lost the
    # flag is rewritten to the template on the next init.
    _write(tmp_path, {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command",
                    "command": "python -m aramid agent-hook session-start"}]}]}})

    assert agent_settings.merge_claude_settings(tmp_path) == "updated"
    cmds = [h["command"]
            for e in _read(tmp_path)["hooks"]["SessionStart"]
            for h in e["hooks"]]
    assert cmds == [agent_settings.SESSION_START_COMMAND]


def test_unparseable_is_never_written(tmp_path):
    p = tmp_path / ".claude" / "settings.json"
    p.parent.mkdir()
    p.write_text("{not json", encoding="utf-8")

    assert agent_settings.merge_claude_settings(tmp_path) == "unparseable"
    assert p.read_text(encoding="utf-8") == "{not json"


def test_wrong_shape_is_never_written(tmp_path):
    p = _write(tmp_path, {"hooks": {"SessionStart": "a string, not a list"}})
    before = p.read_bytes()

    assert agent_settings.merge_claude_settings(tmp_path) == "unparseable"
    assert p.read_bytes() == before
