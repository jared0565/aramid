"""Spec §10 conformance smoke: spawn the real server, complete a real
initialize handshake, list tools, call aramid_status and one suppression
tool end-to-end against a scratch ledger, and prove stdout purity.

The child is spawned with the suite-wide `checkout_env` FIXTURE (see
tests/conftest.py) -- without it the child imports the installed wheel,
which has no aramid.mcp, and every assertion here would be measuring a
different program.

`checkout_env` is decorated with `@pytest.fixture` in tests/conftest.py,
so it cannot be imported and called directly (pytest fails fixture
functions invoked outside injection). tests/integration/test_agent_hook_cli.py
-- the working subprocess-test precedent from sub-3 -- takes it as an
ordinary fixture PARAMETER on each test function and threads the dict
through; this file follows that exact precedent instead of the brief's
`sys.path.insert` + `from conftest import checkout_env` fallback.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest


def _repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True,
                   capture_output=True)
    (r / "aramid.toml").write_text(
        "schema_version = 1\nsemgrep_block_armed = false\n"
        "agent_block_armed = false\n", encoding="utf-8")
    return r


class _Client:
    def __init__(self, cwd: Path, env: dict):
        self.proc = subprocess.Popen(
            [sys.executable, "-P", "-m", "aramid.mcp"],
            cwd=cwd, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._id = 0

    def request(self, method: str, params=None) -> dict:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        out = json.loads(line.decode("utf-8"))
        assert out["id"] == self._id
        return out

    def notify(self, method: str) -> None:
        self.proc.stdin.write(
            (json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
            .encode("utf-8"))
        self.proc.stdin.flush()

    def close(self) -> tuple[bytes, bytes]:
        self.proc.stdin.close()
        out = self.proc.stdout.read()
        err = self.proc.stderr.read()
        self.proc.wait(timeout=30)
        return out, err


@pytest.fixture
def client(tmp_path, checkout_env):
    c = _Client(_repo(tmp_path), checkout_env)
    yield c
    if c.proc.poll() is None:
        c.proc.kill()
        c.proc.wait(timeout=10)


def _handshake(c: _Client) -> dict:
    out = c.request("initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "conformance-test", "version": "0"}})
    c.notify("notifications/initialized")
    return out


def test_initialize_result_shape(client):
    out = _handshake(client)
    assert out["result"]["protocolVersion"] == "2025-06-18"
    assert out["result"]["capabilities"] == {"tools": {}}
    assert out["result"]["serverInfo"]["name"] == "aramid"


def test_tools_list_names(client):
    _handshake(client)
    out = client.request("tools/list")
    assert [t["name"] for t in out["result"]["tools"]] == [
        "aramid_check", "aramid_status", "aramid_ledger_filter",
        "aramid_resolvers", "aramid_override", "aramid_mark_not_a_secret",
        "aramid_mark_rotated"]


def test_status_call_end_to_end(client):
    _handshake(client)
    out = client.request("tools/call",
                         {"name": "aramid_status", "arguments": {}})
    result = out["result"]
    assert result["isError"] is False
    assert "aramid status" in result["content"][0]["text"]


def test_suppression_tool_end_to_end(client):
    # Unknown id against the scratch ledger: the OPERATION fails ->
    # isError True; the server survives and keeps answering.
    _handshake(client)
    out = client.request("tools/call", {
        "name": "aramid_override",
        "arguments": {"id": "0" * 64, "reason": "conformance probe"}})
    assert out["result"]["isError"] is True
    assert client.request("ping")["result"] == {}


def test_missing_reason_is_invalid_params(client):
    _handshake(client)
    out = client.request("tools/call", {
        "name": "aramid_override", "arguments": {"id": "0" * 64}})
    assert out["error"]["code"] == -32602


def test_unknown_method_and_tool(client):
    _handshake(client)
    assert client.request("prompts/list")["error"]["code"] == -32601
    out = client.request("tools/call", {"name": "nope", "arguments": {}})
    assert out["error"]["code"] == -32602


def test_stdout_is_pure_json_lines_and_eof_exits(tmp_path, checkout_env):
    # A fresh process whose ENTIRE stdout is captured in one read -- the
    # readline-per-request client would have consumed the very lines this
    # test exists to inspect, leaving the purity loop vacuous.
    r = _repo(tmp_path)
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "aramid_status", "arguments": {}}},
    ]
    payload = "".join(json.dumps(m) + "\n" for m in msgs).encode("utf-8")
    proc = subprocess.run(
        [sys.executable, "-P", "-m", "aramid.mcp"], cwd=r,
        env=checkout_env, input=payload, capture_output=True, timeout=300)
    assert proc.returncode == 0               # EOF -> clean exit
    lines = proc.stdout.splitlines()
    parsed = [json.loads(ln.decode("utf-8")) for ln in lines]  # pure JSON
    assert [p["id"] for p in parsed] == [1, 2, 3]  # every response, in order
    assert parsed[2]["result"]["isError"] is False  # status ran inside


def test_not_onboarded_refuses_calls_but_completes_handshake(tmp_path, checkout_env):
    bare = tmp_path / "bare"
    bare.mkdir()
    c = _Client(bare, checkout_env)
    try:
        _handshake(c)
        assert c.request("tools/list")["result"]["tools"]  # discovery works
        out = c.request("tools/call",
                        {"name": "aramid_status", "arguments": {}})
        assert out["result"]["isError"] is True
        assert "not an onboarded repo" in out["result"]["content"][0]["text"]
    finally:
        c.proc.kill()
        c.proc.wait(timeout=10)
