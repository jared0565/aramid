"""Tool handlers over the CLI internals -- same code path, captured
output, isError only when the OPERATION failed (not when a gate honestly
reports findings)."""
import subprocess
from pathlib import Path

import pytest

from aramid import mcp_tools


def _repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True,
                   capture_output=True)
    (r / "aramid.toml").write_text(
        "schema_version = 1\nsemgrep_block_armed = false\n"
        "agent_block_armed = false\n", encoding="utf-8")
    return r


def test_tool_names_are_exactly_the_spec_seven():
    assert set(mcp_tools.TOOLS) == {
        "aramid_check", "aramid_status", "aramid_ledger_filter",
        "aramid_resolvers", "aramid_override", "aramid_mark_not_a_secret",
        "aramid_mark_rotated"}
    for spec in mcp_tools.TOOLS.values():
        assert set(spec) == {"description", "inputSchema", "handler"}
        assert spec["inputSchema"]["type"] == "object"


def test_status_returns_captured_text(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    out = mcp_tools.TOOLS["aramid_status"]["handler"](None, {})
    assert out["isError"] is False
    assert out["content"][0]["type"] == "text"
    assert "aramid status" in out["content"][0]["text"]


def test_not_onboarded_is_isError_with_remedy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)          # no git repo, no aramid.toml
    out = mcp_tools.TOOLS["aramid_status"]["handler"](None, {})
    assert out["isError"] is True
    assert out["content"] == [{"type": "text", "text":
        "aramid: this directory is not an onboarded repo (no aramid.toml"
        " at the git root) -- run `aramid init` there first."}]


def test_check_snapshot_never_writes_ledger(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    out = mcp_tools.TOOLS["aramid_check"]["handler"](
        None, {"gate": "pre-commit", "staged": True})
    assert out["isError"] is False
    assert not (r / ".aramid" / "ledger.db").exists()


def test_check_rejects_unknown_gate(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    from aramid.mcp import _InvalidParams
    for bad_gate in ("sneaky", ["pre-commit"]):
        # A string that isn't a known gate raises ValueError out of
        # Gate(); a non-string JSON value (a list, here) must not slip
        # past that except clause and surface as a generic -32603.
        with pytest.raises(_InvalidParams):
            mcp_tools.TOOLS["aramid_check"]["handler"](
                None, {"gate": bad_gate})


def test_check_gate_mode_mapping_matches_the_cli(tmp_path, monkeypatch):
    """Pins the gate->mode branches `_check` derives, against a recorder
    standing in for cmd_check -- the same mapping `cli.py`'s own
    `_check_mode()` uses. `record=False` must be present every time."""
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    import aramid.commands.check as check_mod
    from aramid.models import Gate

    calls = []

    def _recorder(repo, gate, mode, **kwargs):
        calls.append((gate, mode, kwargs))
        return 0

    monkeypatch.setattr(check_mod, "cmd_check", _recorder)

    cases = [
        ({}, Gate.PRE_COMMIT, "staged"),
        ({"gate": "pre-push"}, Gate.PRE_PUSH, "range"),
        ({"gate": "all"}, Gate.ALL, "all"),
        ({"gate": "pre-push", "staged": True}, Gate.PRE_PUSH, "staged"),
    ]
    for args, expected_gate, expected_mode in cases:
        calls.clear()
        out = mcp_tools.TOOLS["aramid_check"]["handler"](None, args)
        assert out["isError"] is False
        assert len(calls) == 1, args
        gate, mode, kwargs = calls[0]
        assert gate is expected_gate, args
        assert mode == expected_mode, args
        assert kwargs.get("record") is False, args


def test_check_iserror_follows_check_exit_vocabulary(tmp_path, monkeypatch):
    """check's real exit vocabulary (pipeline.py): 0 clean, 1 blocking
    findings, 2 degraded tools, 3 engine/config error. A gate that found
    blocking findings or ran degraded still DID its job -- isError False;
    only an engine/config error is a failed operation -- isError True."""
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    import aramid.commands.check as check_mod
    for rc, expected in ((0, False), (1, False), (2, False), (3, True)):
        monkeypatch.setattr(check_mod, "cmd_check", lambda *a, rc=rc, **k: rc)
        out = mcp_tools.TOOLS["aramid_check"]["handler"](None, {})
        assert out["isError"] is expected, f"rc={rc}"


def test_override_requires_nonempty_id_and_reason(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    from aramid.mcp import _InvalidParams
    for bad in ({}, {"id": "abc"}, {"id": "abc", "reason": ""},
                {"id": "abc", "reason": "   "},
                # A whitespace-only id must not fall through to the
                # ledger's unknown-id path (wrong mechanism, wrong error
                # shape) -- it is invalid params, same as an empty one.
                {"id": "   ", "reason": "test reason"}):
        with pytest.raises(_InvalidParams):
            mcp_tools.TOOLS["aramid_override"]["handler"](None, bad)


def test_override_unknown_finding_is_isError(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    out = mcp_tools.TOOLS["aramid_override"]["handler"](
        None, {"id": "0" * 64, "reason": "test reason"})
    assert out["isError"] is True


def test_ledger_filter_passes_filters(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    out = mcp_tools.TOOLS["aramid_ledger_filter"]["handler"](
        None, {"status": "open"})
    assert out["isError"] is False


_ID_REASON_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "minLength": 1,
               "description": "the finding id (from aramid_ledger_filter)"},
        "reason": {"type": "string", "minLength": 1,
                   "description": "why -- recorded in the ledger"},
    },
    "required": ["id", "reason"],
}


def test_tool_input_schemas_are_pinned():
    assert mcp_tools.TOOLS["aramid_check"]["inputSchema"] == {
        "type": "object",
        "properties": {
            "gate": {"type": "string",
                     "enum": ["pre-commit", "pre-push", "all"]},
            "staged": {"type": "boolean"},
            "strict": {"type": "boolean"},
        },
    }
    assert mcp_tools.TOOLS["aramid_status"]["inputSchema"] == {
        "type": "object", "properties": {}}
    assert mcp_tools.TOOLS["aramid_ledger_filter"]["inputSchema"] == {
        "type": "object",
        "properties": {
            "status": {"type": "string"}, "tool": {"type": "string"},
            "rule": {"type": "string"}, "severity": {"type": "string"},
        },
    }
    assert mcp_tools.TOOLS["aramid_resolvers"]["inputSchema"] == {
        "type": "object", "properties": {}}
    assert mcp_tools.TOOLS["aramid_override"]["inputSchema"] == _ID_REASON_SCHEMA
    assert (mcp_tools.TOOLS["aramid_mark_not_a_secret"]["inputSchema"]
            == _ID_REASON_SCHEMA)
    assert (mcp_tools.TOOLS["aramid_mark_rotated"]["inputSchema"]
            == _ID_REASON_SCHEMA)
