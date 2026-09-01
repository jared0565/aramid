"""aramid's entry in a consumer's .mcp.json (spec §4/§7). The graphite
postmortem names .mcp.json the most serious agent surface -- a hijacked
launch means every non-Claude agent talks to whatever the repo planted --
so grading is full-shape from day one."""
import json
from pathlib import Path

from aramid import agent_mcp


def _write(root: Path, data) -> Path:
    p = root / ".mcp.json"
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return p


def _template_entry() -> dict:
    return {"command": "python", "args": ["-P", "-m", "aramid.mcp"]}


def test_command_constant_and_derivation():
    assert agent_mcp.MCP_COMMAND == "python -P -m aramid.mcp"
    assert agent_mcp.MCP_SERVER_KEY == "aramid"
    assert agent_mcp.KNOWN_PRIOR_MCP_COMMANDS == ()


def test_merge_creates_file(tmp_path):
    assert agent_mcp.merge_mcp_json(tmp_path) == "created"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data == {"mcpServers": {"aramid": _template_entry()}}


def test_merge_is_byte_idempotent(tmp_path):
    agent_mcp.merge_mcp_json(tmp_path)
    before = (tmp_path / ".mcp.json").read_bytes()
    assert agent_mcp.merge_mcp_json(tmp_path) == "unchanged"
    assert (tmp_path / ".mcp.json").read_bytes() == before


def test_merge_preserves_foreign_servers_byte_level(tmp_path):
    _write(tmp_path, {"mcpServers": {"graphite": {
        "command": "python", "args": ["-P", "-m", "graphite.mcp"]}}})
    assert agent_mcp.merge_mcp_json(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["graphite"] == {
        "command": "python", "args": ["-P", "-m", "graphite.mcp"]}
    assert data["mcpServers"]["aramid"] == _template_entry()


def test_merge_rewrites_tampered_own_entry(tmp_path):
    # The -P-stripping class, planted under our key.
    _write(tmp_path, {"mcpServers": {"aramid": {
        "command": "python", "args": ["-m", "aramid.mcp"]}}})
    assert agent_mcp.merge_mcp_json(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["aramid"] == _template_entry()


def test_merge_refuses_unparseable(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_text("{not json", encoding="utf-8")
    assert agent_mcp.merge_mcp_json(tmp_path) == "unparseable"
    assert p.read_text(encoding="utf-8") == "{not json"


def test_merge_refuses_wrong_shape(tmp_path):
    _write(tmp_path, {"mcpServers": ["not", "a", "dict"]})
    before = (tmp_path / ".mcp.json").read_bytes()
    assert agent_mcp.merge_mcp_json(tmp_path) == "unparseable"
    assert (tmp_path / ".mcp.json").read_bytes() == before


def test_state_ok_after_merge(tmp_path):
    agent_mcp.merge_mcp_json(tmp_path)
    assert agent_mcp.mcp_state(tmp_path) == "ok"


def test_state_absent_without_file_or_entry(tmp_path):
    assert agent_mcp.mcp_state(tmp_path) == "absent"
    _write(tmp_path, {"mcpServers": {"graphite": {
        "command": "python", "args": ["-P", "-m", "graphite.mcp"]}}})
    assert agent_mcp.mcp_state(tmp_path) == "absent"


def test_full_shape_grading_extra_key_is_tampered(tmp_path):
    entry = _template_entry()
    entry["env"] = {"X": "1"}
    _write(tmp_path, {"mcpServers": {"aramid": entry}})
    assert agent_mcp.mcp_state(tmp_path) == "tampered"


def test_dropped_dash_p_is_tampered(tmp_path):
    _write(tmp_path, {"mcpServers": {"aramid": {
        "command": "python", "args": ["-m", "aramid.mcp"]}}})
    assert agent_mcp.mcp_state(tmp_path) == "tampered"


def test_foreign_key_launching_aramid_mcp_is_tampered(tmp_path):
    # Ownership is the key OR the launch target: a second entry that
    # reaches aramid.mcp under another name is not a foreign server.
    _write(tmp_path, {"mcpServers": {
        "aramid": _template_entry(),
        "helpful-tools": {"command": "python", "args": ["-m", "aramid.mcp"]},
    }})
    assert agent_mcp.mcp_state(tmp_path) == "tampered"


def test_tokens_absorbed_into_command_grade_tampered(tmp_path):
    # The -P-and-args-absorbing class: all tokens in command, args empty.
    # This is the regression pin for the review finding.
    _write(tmp_path, {"mcpServers": {"aramid": {
        "command": "python -P -m aramid.mcp", "args": []}}})
    assert agent_mcp.mcp_state(tmp_path) == "tampered"


def test_per_token_whitespace_is_normalized(tmp_path):
    # Per-token whitespace is stripped; token-identical entry grades ok.
    _write(tmp_path, {"mcpServers": {"aramid": {
        "command": "  python ", "args": [" -P ", "-m", " aramid.mcp "]}}})
    assert agent_mcp.mcp_state(tmp_path) == "ok"


def test_state_unparseable(tmp_path):
    (tmp_path / ".mcp.json").write_text("{not json", encoding="utf-8")
    assert agent_mcp.mcp_state(tmp_path) == "unparseable"


def test_remove_deletes_entry_and_empty_file(tmp_path):
    agent_mcp.merge_mcp_json(tmp_path)
    assert agent_mcp.remove_mcp_json(tmp_path) == "removed"
    assert not (tmp_path / ".mcp.json").exists()


def test_remove_preserves_foreign_and_file(tmp_path):
    _write(tmp_path, {"mcpServers": {
        "aramid": _template_entry(),
        "graphite": {"command": "python", "args": ["-P", "-m", "graphite.mcp"]},
    }})
    assert agent_mcp.remove_mcp_json(tmp_path) == "removed"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data == {"mcpServers": {"graphite": {
        "command": "python", "args": ["-P", "-m", "graphite.mcp"]}}}


def test_remove_absent_and_unparseable(tmp_path):
    assert agent_mcp.remove_mcp_json(tmp_path) == "absent"
    (tmp_path / ".mcp.json").write_text("{not json", encoding="utf-8")
    assert agent_mcp.remove_mcp_json(tmp_path) == "unparseable"
    assert (tmp_path / ".mcp.json").read_text(encoding="utf-8") == "{not json"


def test_states_constant_is_exhaustive():
    assert set(agent_mcp.MCP_STATES) == {
        "ok", "absent", "stale", "tampered", "unparseable"}
