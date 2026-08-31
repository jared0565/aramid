"""unit: agent_settings -- aramid's entries in .claude/settings.json.
Own-entry-by-marker merge: foreign hook entries are preserved structurally
intact, aramid's own entry is rewritten to the current template, and a file
that cannot be parsed is never written."""
import json

from aramid import agent_settings
from aramid.commands import doctor as doctor_cmd


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


def test_remove_strips_only_aramid_entries(tmp_path):
    _write(tmp_path, {"hooks": {"PreToolUse": [GRAPHITE_PRE],
                                "SessionStart": [GRAPHITE_SESSION]}})
    agent_settings.merge_claude_settings(tmp_path)

    assert agent_settings.remove_claude_settings(tmp_path) == "removed"

    data = _read(tmp_path)
    assert data == {"hooks": {"PreToolUse": [GRAPHITE_PRE],
                              "SessionStart": [GRAPHITE_SESSION]}}


def test_remove_deletes_file_that_was_only_aramid(tmp_path):
    agent_settings.merge_claude_settings(tmp_path)

    assert agent_settings.remove_claude_settings(tmp_path) == "removed"
    assert not (tmp_path / ".claude" / "settings.json").exists()
    assert (tmp_path / ".claude").is_dir()  # the directory is not ours to delete


def test_remove_absent_and_unparseable(tmp_path):
    assert agent_settings.remove_claude_settings(tmp_path) == "absent"

    p = tmp_path / ".claude" / "settings.json"
    p.parent.mkdir()
    p.write_text("{not json", encoding="utf-8")
    assert agent_settings.remove_claude_settings(tmp_path) == "unparseable"
    assert p.read_text(encoding="utf-8") == "{not json"


def test_settings_state_grades_every_shape(tmp_path):
    assert agent_settings.settings_state(tmp_path) == "absent"

    agent_settings.merge_claude_settings(tmp_path)
    assert agent_settings.settings_state(tmp_path) == "ok"

    # tampered: aramid-named entry, command differs from every known template
    _write(tmp_path, {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command",
                    "command": "python -m aramid agent-hook session-start"}]}]}})
    assert agent_settings.settings_state(tmp_path) == "tampered"

    p = tmp_path / ".claude" / "settings.json"
    p.write_text("{not json", encoding="utf-8")
    assert agent_settings.settings_state(tmp_path) == "unparseable"


def test_settings_state_stale_via_known_prior(tmp_path, monkeypatch):
    # Simulate a future template change: the old command joins
    # KNOWN_PRIOR_COMMANDS and grades "stale", not "tampered".
    old = "python -P -m aramid agent-hook session-start --old-flag"
    monkeypatch.setattr(agent_settings, "KNOWN_PRIOR_COMMANDS", (old,))
    _write(tmp_path, {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command", "command": old}]}]}})

    assert agent_settings.settings_state(tmp_path) == "stale"


def test_settings_states_constant_is_exhaustive():
    assert set(agent_settings.SETTINGS_STATES) == {
        "ok", "absent", "stale", "tampered", "unparseable"}


def test_every_settings_state_has_a_doctor_detail():
    assert set(doctor_cmd._AGENT_SETTINGS_DETAIL) == set(agent_settings.SETTINGS_STATES)


def test_doctor_settings_lines_render_ok_and_tampered(tmp_path):
    agent_settings.merge_claude_settings(tmp_path)
    assert doctor_cmd.agent_settings_lines(tmp_path) == [
        "  OK   settings   aramid session-start hook registered"
        " (.claude/settings.json)",
    ]

    _write(tmp_path, {"hooks": {"SessionStart": [
        {"hooks": [{"type": "command",
                    "command": "python -m aramid agent-hook session-start"}]}]}})
    assert doctor_cmd.agent_settings_lines(tmp_path) == [
        "  WARN settings   an aramid-named hook entry differs from the"
        " template -- treat as tampering; re-run `aramid init` to rewrite"
        " it and investigate how it changed",
    ]


def test_agent_interpreter_lines_no_python_on_path(monkeypatch):
    # PATH has no `python` at all -- the generated hook command cannot run,
    # and nothing else would say why.
    monkeypatch.setattr(doctor_cmd.shutil, "which", lambda name: None)

    assert doctor_cmd.agent_interpreter_lines() == [
        "  WARN interpreter no `python` on PATH -- the generated"
        " agent-hook command cannot run; install one or adjust PATH",
    ]


def test_agent_interpreter_lines_cannot_import_aramid(monkeypatch):
    # PATH's `python` exists but can't import aramid -- the session-start
    # entry would error at every session start, outside the fail-open
    # boundary `agent_hook.cmd_agent_hook` itself provides.
    exe = r"C:\fake\python.exe"
    monkeypatch.setattr(doctor_cmd.shutil, "which", lambda name: exe)

    class _Stub:
        returncode = 1

    monkeypatch.setattr(doctor_cmd.subprocess, "run", lambda *a, **k: _Stub())

    assert doctor_cmd.agent_interpreter_lines() == [
        f"  WARN interpreter `python` on PATH ({exe}) cannot import"
        f" aramid -- the agent-hook entry in .claude/settings.json will"
        f" error at every session start; `pip install aramid` into that"
        f" interpreter or fix PATH",
    ]
