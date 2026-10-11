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


def test_tool_names_are_exactly_the_spec_eleven():
    assert set(mcp_tools.TOOLS) == {
        "aramid_check", "aramid_status", "aramid_ledger_filter",
        "aramid_resolvers", "aramid_override", "aramid_mark_not_a_secret",
        "aramid_mark_rotated", "aramid_ledger_resolve",
        "aramid_handover_show", "aramid_handover_write", "aramid_handover_done"}
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


# ------------------------------------------- aramid_ledger_resolve (FN-36) --

_CLOSE = {"id": "abc", "commit": "c0ffee1", "tests": ["tests/test_x.py::test_y"],
          "reason": "guarded in the caller"}


def _recorded_close(monkeypatch, rc=0):
    """Stand in for the close itself; returns the calls it was given."""
    import aramid.commands.ledger_cmd as ledger_cmd
    calls = []

    def recorder(*args, **kwargs):
        calls.append((args, kwargs))
        return rc
    monkeypatch.setattr(ledger_cmd, "cmd_ledger_resolve_selected", recorder)
    return calls


def test_ledger_resolve_hands_over_selectors_and_nothing_that_could_be_a_command(
        tmp_path, monkeypatch):
    """The handler passes the id, the commit, the selectors and the reason.
    No argument of the tool reaches the close as a program to run: a `test`
    or `command` a caller adds is not read at all."""
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    calls = _recorded_close(monkeypatch)

    out = mcp_tools.TOOLS["aramid_ledger_resolve"]["handler"](
        None, {**_CLOSE, "test": "python evil.py", "command": "python evil.py",
               "red_proof": False})

    assert out["isError"] is False
    (args, kwargs), = calls
    assert (Path(args[0]).resolve(), args[1:], kwargs) == (
        r.resolve(), ("abc", "c0ffee1", ["tests/test_x.py::test_y"], "guarded in the caller"),
        {})


def test_ledger_resolve_reports_a_refused_close_as_an_error(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    _recorded_close(monkeypatch, rc=3)

    out = mcp_tools.TOOLS["aramid_ledger_resolve"]["handler"](None, dict(_CLOSE))

    assert out["isError"] is True
    assert out["content"][0]["text"].endswith("(exit code 3)")


@pytest.mark.parametrize("bad, said", [
    ({"id": ""}, "`id` is required (a finding id string)"),
    ({"reason": "  "}, "`reason` is required and must be non-empty -- a close without a"
                       " reason is not recordable"),
    ({"commit": None}, "`commit` is required (the commit that fixed the finding)"),
    ({"commit": "  "}, "`commit` is required (the commit that fixed the finding)"),
    ({"commit": ["c0ffee1"]}, "`commit` is required (the commit that fixed the finding)"),
    ({"tests": None}, None),
    ({"tests": []}, None),
    ({"tests": "tests/test_x.py"}, None),
    ({"tests": ["tests/test_x.py", ""]}, None),
    ({"tests": ["tests/test_x.py", 3]}, None),
])
def test_ledger_resolve_rejects_malformed_arguments_before_anything_runs(
        tmp_path, monkeypatch, bad, said):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    calls = _recorded_close(monkeypatch)
    from aramid.mcp import _InvalidParams

    with pytest.raises(_InvalidParams) as exc:
        mcp_tools.TOOLS["aramid_ledger_resolve"]["handler"](None, {**_CLOSE, **bad})

    assert str(exc.value) == (said or (
        "`tests` is required: a non-empty list of test selectors, each a committed test"
        " file (for pytest, optionally `file::test`)"))
    assert calls == []


def test_the_suppression_tools_still_say_suppression(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)
    from aramid.mcp import _InvalidParams

    with pytest.raises(_InvalidParams) as exc:
        mcp_tools.TOOLS["aramid_override"]["handler"](None, {"id": "abc", "reason": ""})

    assert str(exc.value) == ("`reason` is required and must be non-empty -- suppression"
                              " without a reason is not recordable")


def test_ledger_resolve_input_schema_is_pinned():
    assert mcp_tools.TOOLS["aramid_ledger_resolve"]["inputSchema"] == {
        "type": "object",
        "properties": {
            "id": {"type": "string", "minLength": 1,
                   "description": "the finding id (from aramid_ledger_filter)"},
            "commit": {"type": "string", "minLength": 1,
                       "description": "the commit that fixed it"},
            "tests": {"type": "array", "minItems": 1,
                      "items": {"type": "string", "minLength": 1},
                      "description": "test selectors: committed test files, or file::test"
                                     " when the declared command is pytest"},
            "reason": {"type": "string", "minLength": 1,
                       "description": "why -- recorded in the ledger"},
        },
        "required": ["id", "commit", "tests", "reason"],
    }


def test_ledger_resolve_in_a_repo_that_declares_no_command_names_the_key(tmp_path,
                                                                        monkeypatch):
    """End to end through the handler, on a repo whose committed aramid.toml
    has no `[tests].select_command`: refused, with what to add."""
    r = _repo(tmp_path)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "-c", "commit.gpgsign=false", "add", "-A"], cwd=r, check=True,
                   capture_output=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "-c", "commit.gpgsign=false", "commit", "-q", "-m", "seed"], cwd=r,
                   check=True, capture_output=True)
    monkeypatch.chdir(r)

    out = mcp_tools.TOOLS["aramid_ledger_resolve"]["handler"](None, dict(_CLOSE))

    assert out["isError"] is True
    assert out["content"][0]["text"] == (
        "[stderr]\naramid: ledger resolve: the aramid.toml at HEAD declares no"
        " [tests].select_command -- through MCP the close runs only a command the repo"
        " has committed, with the test selectors appended. Declare one, for example"
        " select_command = \"python -m pytest -q\", commit it and call again; or close"
        " at the command line with --test\n\n(exit code 3)")
