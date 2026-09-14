"""`commands.agent_hook` at unit scope: the event dispatcher, the repo
guard, the session-start emitter and the PreToolUse screen -- every
return value and every byte of output, one exact assertion each.

The drain confirms a mutant against the unit suite alone, and until this
file nothing in it executed `cmd_agent_hook`, `_repo_with_aramid`,
`_session_start`, `_pre_tool_use` or `_describe`: the 14 mutants the
generator emits for them were held by tests/integration/test_agent_hook*.py
(which onboard a repo through `cmd_init`), which the drain never runs.
`_pre_tool_use` is the enforcement hook -- the code that turns a
`--no-verify` into a deny while the agent surface is armed -- so a mutant
there is a bypass, not a test gap.

Seams: a real tmp git repo with a two-line aramid.toml (`_repo_with_aramid`
resolves it through git, `load_config` reads `agent_block_armed` from it),
`sys.stdin` replaced with the payload, stdout captured. Fail-open is the
contract: every non-happy path returns 0 with NOTHING printed."""
import io
import json
import subprocess

from aramid.commands import agent_hook as ah

FLAG = {"session_id": "t", "cwd": ".", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "git commit --no-verify -m x"}}
HOOKS_PATH = {**FLAG, "tool_input": {"command": "git -c core.hooksPath=/tmp/x commit -m y"}}
CLEAN = {**FLAG, "tool_input": {"command": "pytest -q tests/unit"}}

DENY_FLAG = {"hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": (
        "aramid: `git commit` carrying `--no-verify` bypasses the gate and is REJECTED"
        " in this repo (agent surface armed). Re-run without the bypass; to suppress a"
        " specific blocking finding use `aramid override <id> --reason \"...\"` after"
        " `aramid ledger filter --status open`.")}}
ADVISE_FLAG = {"hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "additionalContext": (
        "aramid: `git commit` carrying `--no-verify` bypasses this repo's gate. The"
        " bypass is ledger-visible, and the armed version of this hook rejects the call"
        " outright -- re-run without it; suppress a specific finding with `aramid"
        " override <id> --reason \"...\"` instead.")}}


def _git(root, *a):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a],
                   cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, *, onboarded=True, armed=False):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "app.py").write_text("x = 1\n", encoding="utf-8")
    if onboarded:
        (r / "aramid.toml").write_text(
            f"schema_version = 1\nagent_block_armed = {'true' if armed else 'false'}\n",
            encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "seed")
    return r


def _stdin(monkeypatch, payload):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


class _Raising(io.StringIO):
    def read(self, *a, **k):
        raise RuntimeError("stdin exploded")


# ------------------------------------------------------------ dispatch --

def test_session_start_in_an_onboarded_repo_prints_the_posture_block(tmp_path, capsys):
    r = _repo(tmp_path)

    rc = ah.cmd_agent_hook("session-start", r)

    out, err = capsys.readouterr()
    assert rc == 0 and err == ""
    assert out == ah._session_context(r), "exactly the block, nothing else"
    assert out.startswith("aramid: this repo is GATED (pre-commit + pre-push hooks)."
                          " Read ARAMID.md; NEVER pass --no-verify.\n")
    assert out.endswith('aramid: commands: aramid check --staged | aramid ledger filter'
                        ' --status open | aramid override <id> --reason "..."\n')


def test_pre_tool_use_routes_to_the_screen_not_the_posture_block(tmp_path, monkeypatch, capsys):
    r = _repo(tmp_path, armed=True)
    _stdin(monkeypatch, FLAG)

    rc = ah.cmd_agent_hook("pre-tool-use", r)

    out, err = capsys.readouterr()
    assert rc == 0 and err == ""
    assert json.loads(out) == DENY_FLAG
    assert out == json.dumps(DENY_FLAG) + "\n", "one JSON line, no posture block"


def test_an_unknown_event_is_silent_even_with_a_bypass_on_stdin(tmp_path, monkeypatch, capsys):
    r = _repo(tmp_path, armed=True)
    _stdin(monkeypatch, FLAG)

    rc = ah.cmd_agent_hook("post-tool-use", r)

    assert rc == 0 and capsys.readouterr() == ("", "")


def test_an_internal_error_fails_open_with_nothing_printed(tmp_path, monkeypatch, capsys):
    r = _repo(tmp_path, armed=True)
    monkeypatch.setattr("sys.stdin", _Raising())

    rc = ah.cmd_agent_hook("pre-tool-use", r)

    assert rc == 0 and capsys.readouterr() == ("", "")


# ---------------------------------------------------------- repo guard --

def test_the_guard_wants_a_git_repo_with_aramid_toml_at_its_root(tmp_path):
    r = _repo(tmp_path)
    (r / "sub").mkdir()

    assert ah._repo_with_aramid(r / "sub") == r
    (tmp_path / "bare").mkdir()
    assert ah._repo_with_aramid(_repo(tmp_path / "bare", onboarded=False)) is None
    assert ah._repo_with_aramid(tmp_path / "nowhere") is None


def test_session_start_outside_a_repo_and_in_an_un_onboarded_repo_is_silent(
        tmp_path, capsys):
    plain = _repo(tmp_path, onboarded=False)

    assert ah.cmd_agent_hook("session-start", plain) == 0
    assert ah.cmd_agent_hook("session-start", tmp_path / "nowhere") == 0
    assert ah._session_start(plain) == 0
    assert capsys.readouterr() == ("", "")


# ---------------------------------------------------------- the screen --

def test_a_flag_bypass_is_denied_when_armed(tmp_path, monkeypatch, capsys):
    r = _repo(tmp_path, armed=True)
    _stdin(monkeypatch, FLAG)

    assert ah._pre_tool_use(r) == 0
    assert json.loads(capsys.readouterr().out) == DENY_FLAG


def test_a_flag_bypass_is_an_advisory_while_baking(tmp_path, monkeypatch, capsys):
    r = _repo(tmp_path, armed=False)
    _stdin(monkeypatch, FLAG)

    assert ah._pre_tool_use(r) == 0
    assert json.loads(capsys.readouterr().out) == ADVISE_FLAG


def test_a_hooks_path_wrapper_is_described_as_such(tmp_path, monkeypatch, capsys):
    r = _repo(tmp_path, armed=True)
    _stdin(monkeypatch, HOOKS_PATH)

    assert ah._pre_tool_use(r) == 0
    body = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert body["permissionDecision"] == "deny"
    assert body["permissionDecisionReason"].startswith(
        "aramid: `git commit` under `-c core.hooksPath=/tmp/x` bypasses the gate")


def test_describe_names_the_flag_or_the_hooks_path_value(tmp_path):
    from aramid.agent_bypass import find_bypass

    assert ah._describe(find_bypass("git push --no-verify")) == \
        "`git push` carrying `--no-verify`"
    assert ah._describe(find_bypass("git -c core.hooksPath=/tmp/x commit -m y")) == \
        "`git commit` under `-c core.hooksPath=/tmp/x`"


def test_a_clean_command_is_silent_before_the_repo_is_looked_at(tmp_path, monkeypatch, capsys):
    _stdin(monkeypatch, CLEAN)

    def never(root):
        raise AssertionError("the repo must not be resolved for a clean command")
    monkeypatch.setattr(ah, "_repo_with_aramid", never)

    assert ah._pre_tool_use(tmp_path) == 0
    assert capsys.readouterr() == ("", "")


def test_a_bypass_outside_an_onboarded_repo_is_silent(tmp_path, monkeypatch, capsys):
    plain = _repo(tmp_path, onboarded=False)
    _stdin(monkeypatch, FLAG)

    assert ah._pre_tool_use(plain) == 0
    assert capsys.readouterr() == ("", "")


def test_unreadable_stdin_and_non_command_payloads_are_silent(tmp_path, monkeypatch, capsys):
    r = _repo(tmp_path, armed=True)
    for payload in ("not json", "[1, 2]", json.dumps({"tool_input": "git commit --no-verify"}),
                    json.dumps({"tool_input": {"command": ["git", "commit", "--no-verify"]}}),
                    json.dumps({"tool_input": {}}), ""):
        _stdin(monkeypatch, payload)
        assert ah._pre_tool_use(r) == 0, payload
    assert capsys.readouterr() == ("", "")
