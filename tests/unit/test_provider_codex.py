import json
import os
import shutil
from pathlib import Path

import pytest

from aramid.providers import base, codex_cli, spend

JSONL = "\n".join([
    json.dumps({"type": "session.created", "session_id": "s1"}),
    "this line is not json and must be skipped",
    json.dumps({"type": "item.completed",
                "item": {"type": "reasoning", "text": "thinking..."}}),
    json.dumps({"type": "item.completed",
                "item": {"type": "agent_message", "text": '{"findings": []}'}}),
    json.dumps({"type": "turn.completed",
                "usage": {"input_tokens": 1500, "output_tokens": 40}}),
])

# The whole restriction, in the order it is passed (FN-49). Written out here
# and not imported: a flag dropped from the source must fail a test.
RESTRICTION = ["--ignore-user-config", "--ignore-rules", "--ephemeral",
               "--disable", "shell_tool", "--disable", "view_image",
               "--disable", "apps", "--disable", "plugins", "--disable", "remote_plugin",
               "--disable", "image_generation", "--disable", "browser_use",
               "--disable", "browser_use_external",
               "--disable", "browser_use_full_cdp_access", "--disable", "computer_use",
               "--disable", "in_app_browser", "--disable", "multi_agent",
               "--disable", "hooks", "--disable", "tool_suggest",
               "--disable", "skill_mcp_dependency_install",
               "-c", "web_search=disabled"]


@pytest.fixture(autouse=True)
def _isolated_spend(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")


def test_registers_in_providers():
    assert base.PROVIDERS["codex-cli"] is codex_cli


def test_installed_iff_on_path(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    assert codex_cli.installed() is True
    monkeypatch.setattr(shutil, "which", lambda n: None)
    assert codex_cli.installed() is False


def test_review_parses_jsonl(monkeypatch):
    seen = {}

    def fake_run(argv, prompt, timeout_s, *, cwd=None):
        seen["argv"] = argv
        return 0, JSONL, ""
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess", fake_run)
    resp = codex_cli.review("PACKET", "", 240.0)
    assert resp.text == '{"findings": []}'
    assert (resp.tokens_in, resp.tokens_out) == (1500, 40)
    assert resp.cost_usd == 0.0
    # model "" (CLI default) -> no -m flag; sandboxed read-only one-shot
    assert seen["argv"] == [r"C:\bin\codex.cmd", "exec", "--json",
                            "--sandbox", "read-only", "--skip-git-repo-check",
                            *RESTRICTION, "-"]


def test_review_model_flag_when_set(monkeypatch):
    seen = {}

    def fake_run(argv, prompt, timeout_s, *, cwd=None):
        seen["argv"] = argv
        return 0, JSONL, ""
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess", fake_run)
    codex_cli.review("PACKET", "o4-mini", 240.0)
    assert "-m" in seen["argv"] and "o4-mini" in seen["argv"]


def test_review_no_agent_message_is_malformed(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, json.dumps({"type": "noise"}), ""))
    assert codex_cli.review("P", "", 240.0).error == base.ERR_MALFORMED


def test_review_quota_and_timeout(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (1, "", "You've hit your usage limit"))
    assert codex_cli.review("P", "", 240.0).error == base.ERR_QUOTA
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess", lambda *a, **k: None)
    assert codex_cli.review("P", "", 240.0).error == base.ERR_TIMEOUT


def test_review_nonzero_exit_is_error(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (1, "", "boom"))
    assert codex_cli.review("P", "", 240.0).error == base.ERR_ERROR


def test_review_unavailable_when_not_on_path(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: None)
    assert codex_cli.review("P", "", 240.0).error == base.ERR_UNAVAILABLE


# Extra hardening tests
def test_review_bare_scalar_in_jsonl_is_skipped(monkeypatch):
    """A bare scalar (5) in JSONL should be skipped, not crash."""
    jsonl = "\n".join([
        "5",  # bare scalar
        json.dumps({"type": "item.completed",
                    "item": {"type": "agent_message", "text": "valid reply"}}),
        json.dumps({"type": "turn.completed",
                    "usage": {"input_tokens": 100, "output_tokens": 20}}),
    ])
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, jsonl, ""))
    resp = codex_cli.review("P", "", 240.0)
    assert resp.text == "valid reply"
    assert (resp.tokens_in, resp.tokens_out) == (100, 20)
    assert resp.error == ""


def test_review_item_not_dict_is_skipped(monkeypatch):
    """A line where item is not a dict (e.g. string) should be skipped."""
    jsonl = "\n".join([
        json.dumps({"type": "item.completed", "item": "oops"}),  # item is string, not dict
        json.dumps({"type": "item.completed",
                    "item": {"type": "agent_message", "text": "valid reply"}}),
        json.dumps({"type": "turn.completed",
                    "usage": {"input_tokens": 100, "output_tokens": 20}}),
    ])
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, jsonl, ""))
    resp = codex_cli.review("P", "", 240.0)
    assert resp.text == "valid reply"
    assert (resp.tokens_in, resp.tokens_out) == (100, 20)
    assert resp.error == ""


def test_review_wrong_token_types_zero_out(monkeypatch):
    """Token fields of wrong type should zero out, text kept."""
    jsonl = "\n".join([
        json.dumps({"type": "item.completed",
                    "item": {"type": "agent_message", "text": "valid reply"}}),
        json.dumps({"type": "turn.completed",
                    "usage": {"input_tokens": "bad", "output_tokens": None}}),
    ])
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, jsonl, ""))
    resp = codex_cli.review("P", "", 240.0)
    assert resp.text == "valid reply"
    assert (resp.tokens_in, resp.tokens_out) == (0, 0)
    assert resp.error == ""


# ------------------------------------------- the reviewer holds nothing (FN-49) --

def _recorded_run(monkeypatch, result=(0, JSONL, "")):
    """Stand in for the launch; returns the calls, each with what the
    directory it was given looked like while the reviewer ran."""
    calls = []

    def fake_run(argv, prompt, timeout_s, *, cwd=None):
        there = Path(cwd) if cwd is not None else None
        calls.append({"argv": list(argv), "cwd": cwd,
                      "is_dir": there is not None and there.is_dir(),
                      "holds": sorted(os.listdir(cwd)) if cwd is not None else None})
        return result
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess", fake_run)
    return calls


def test_the_reviewer_is_started_with_no_tools_no_user_config_and_no_web(monkeypatch):
    """The prompt is a review packet built from a repo's diff, so part of it
    is written by whoever wrote the commit. Measured on codex 0.162.0 (FN-49):
    under `--sandbox read-only` the reviewer READ a file outside its
    directory through its shell, and it had a web tool. The command line is
    pinned whole, the model and effort before the restriction, so nothing
    after it can give a tool back."""
    calls = _recorded_run(monkeypatch)

    codex_cli.review("PACKET", "gpt-5.5", 240.0, effort="medium")

    assert [c["argv"] for c in calls] == [[
        r"C:\bin\codex.cmd", "exec", "--json", "--sandbox", "read-only",
        "--skip-git-repo-check", "-m", "gpt-5.5", "-c", "model_reasoning_effort=medium",
        *RESTRICTION, "-"]]


def test_the_reviewer_runs_in_an_empty_directory_of_its_own(monkeypatch, tmp_path):
    """Not where the drain was started: that is a repository, with an
    AGENTS.md and a .codex/ a later CLI might read whatever the flags say.
    The directory is new and empty for each call and gone after it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "AGENTS.md").write_text("not for the reviewer", encoding="utf-8")
    calls = _recorded_run(monkeypatch)

    codex_cli.review("PACKET", "gpt-5.5", 240.0)
    codex_cli.review("PACKET", "gpt-5.5", 240.0)

    first, second = calls
    assert (first["is_dir"], first["holds"]) == (True, [])
    assert (second["is_dir"], second["holds"]) == (True, [])
    assert first["cwd"] != second["cwd"]
    assert Path(first["cwd"]).resolve() != tmp_path.resolve()
    assert tmp_path.resolve() not in Path(first["cwd"]).resolve().parents
    assert Path(first["cwd"]).name.startswith("aramid-review-")
    assert not Path(first["cwd"]).exists() and not Path(second["cwd"]).exists()


@pytest.mark.parametrize("said", [
    # Each as codex 0.162.0 says it (measured on `codex features list`, which
    # takes the same global switches; an exec-only flag there is refused the
    # way an older `codex exec` refuses it).
    "error: unexpected argument '--ignore-user-config' found",
    "error: a value is required for '--disable <FEATURE>' but none was supplied",
    "Error: Unknown feature flag: shell_tool",
])
def test_a_codex_that_does_not_take_the_command_line_is_named_and_never_run_without_it(
        monkeypatch, capsys, said):
    """An older or newer CLI may not know a flag or a feature name. The
    reviewer is then not used at all: one launch, no second one with the
    restriction taken off, and a line that says why."""
    calls = _recorded_run(monkeypatch, result=(2, "", said + "\n"))

    resp = codex_cli.review("PACKET", "gpt-5.5", 240.0)

    assert resp.error == base.ERR_UNAVAILABLE
    assert len(calls) == 1
    assert capsys.readouterr().err == (
        "aramid: providers: codex-cli: this `codex` did not accept its command line, so"
        " the reviewer was not run. It is never started without the options that keep it"
        " from using tools. It said: " + said + "\n")


@pytest.mark.parametrize("err", [
    "boom",
    "the reviewer said: error: unexpected argument",      # not at the start of a line
    "",
])
def test_any_other_failure_is_still_a_plain_error_and_says_nothing(monkeypatch, capsys, err):
    _recorded_run(monkeypatch, result=(1, "", err))

    assert codex_cli.review("PACKET", "gpt-5.5", 240.0).error == base.ERR_ERROR
    assert capsys.readouterr().err == ""


def test_a_refused_command_line_on_stdout_alone_is_not_read_as_one(monkeypatch, capsys):
    # The CLI writes option errors to stderr. stdout is the model's event
    # stream, and text in it is never a reason to call the CLI too old.
    _recorded_run(monkeypatch, result=(2, "error: unexpected argument '--ephemeral' found\n",
                                       ""))

    assert codex_cli.review("PACKET", "gpt-5.5", 240.0).error == base.ERR_ERROR
    assert capsys.readouterr().err == ""


def test_the_first_refusal_is_quoted_and_cut_so_one_line_stays_one_line(monkeypatch, capsys):
    said = "error: unexpected argument '" + "x" * 400 + "' found"
    _recorded_run(monkeypatch, result=(2, "", said + "\nError: Unknown feature flag: y\n"))

    codex_cli.review("PACKET", "gpt-5.5", 240.0)

    assert capsys.readouterr().err.endswith("It said: " + said[:200] + "\n")


def test_a_directory_that_will_not_go_does_not_fail_the_review(monkeypatch):
    """A child killed on timeout can hold the directory for a moment. The
    review's answer stands and the directory is left behind."""
    held = []

    def fake_run(argv, prompt, timeout_s, *, cwd=None):
        held.append(open(Path(cwd) / "held", "w", encoding="utf-8"))  # noqa: SIM115
        return 0, JSONL, ""
    monkeypatch.setattr(shutil, "which", lambda n: r"C:\bin\codex.cmd")
    monkeypatch.setattr(codex_cli.base, "run_provider_subprocess", fake_run)

    try:
        resp = codex_cli.review("PACKET", "gpt-5.5", 240.0)
    finally:
        held[0].close()
        shutil.rmtree(Path(held[0].name).parent, ignore_errors=True)

    assert (resp.error, resp.text) == ("", '{"findings": []}')


# -------------------------------- a review that used a tool is not a review (FN-49) --

def _events(*pairs, reply="the canary says: CANARY-1"):
    """A codex --json stream: (event type, item type) pairs. The measured
    one (2026-10-12 16:02Z, types only) is MEASURED below."""
    lines = []
    for event, item in pairs:
        if item is None:
            lines.append({"type": event})
        elif item == "agent_message":
            lines.append({"type": event, "item": {"id": "i", "type": item, "text": reply}})
        else:
            lines.append({"type": event, "item": {"id": "i", "type": item}})
    lines.append({"type": "turn.completed", "usage": {"input_tokens": 51126,
                                                      "output_tokens": 502}})
    return "\n".join(json.dumps(x) for x in lines)


MEASURED = _events(("thread.started", None), ("turn.started", None),
                   ("item.completed", "error"), ("item.completed", "agent_message"),
                   ("item.started", "command_execution"),
                   ("item.completed", "command_execution"),
                   ("item.completed", "agent_message"))


def test_the_measured_stream_that_read_a_file_gives_no_review(monkeypatch, capsys, tmp_path):
    """The stream of the 16:02Z call, whose shell read a file outside its
    directory and whose reply carried that file's line. Whatever the flags
    did or did not switch off, a reply that came after a tool ran is not
    passed on: it would reach the ledger as the finding's text. The tokens
    were spent, so they are logged."""
    _recorded_run(monkeypatch, result=(0, MEASURED, ""))

    resp = codex_cli.review("PACKET", "gpt-5.5", 240.0)

    assert (resp.error, resp.text) == (base.ERR_ERROR, "")
    assert capsys.readouterr().err == (
        "aramid: providers: codex-cli: the reviewer used a tool (command_execution), so its"
        " reply was thrown away. It is started without tools; this `codex` gave it one"
        " anyway.\n")
    logged = json.loads((tmp_path / "llm_spend.jsonl").read_text(encoding="utf-8"))
    assert (logged["provider"], logged["model"], logged["tokens_in"], logged["tokens_out"]) == (
        "codex-cli", "gpt-5.5", 51126, 502)


@pytest.mark.parametrize("item", [
    "command_execution", "file_change", "mcp_tool_call", "web_search",
    "collab_tool_call", "a_tool_no_codex_has_yet",
])
def test_any_item_but_a_reply_reasoning_a_plan_or_an_error_gives_no_review(
        monkeypatch, capsys, item):
    """An allowlist, not a list of known tools: a tool a later codex adds is
    caught the day it ships. Started is enough, a tool killed before it
    completed has still run."""
    _recorded_run(monkeypatch, result=(0, _events(("item.started", item),
                                                  ("item.completed", "agent_message")), ""))

    resp = codex_cli.review("PACKET", "gpt-5.5", 240.0)

    assert (resp.error, resp.text) == (base.ERR_ERROR, "")
    assert f"used a tool ({item})" in capsys.readouterr().err


def test_an_item_with_no_type_gives_no_review(monkeypatch, capsys):
    stream = "\n".join([json.dumps({"type": "item.completed", "item": {"id": "x"}}),
                        _events(("item.completed", "agent_message"))])
    _recorded_run(monkeypatch, result=(0, stream, ""))

    assert codex_cli.review("PACKET", "gpt-5.5", 240.0).error == base.ERR_ERROR
    assert "used a tool (an item with no type)" in capsys.readouterr().err


def test_reasoning_a_plan_and_an_error_item_leave_the_review_alone(monkeypatch, capsys):
    """The 16:02Z stream's `error` item was the skills budget, said by codex
    itself; reasoning and a plan update reach nothing outside the model."""
    stream = _events(("item.completed", "error"), ("item.completed", "reasoning"),
                     ("item.updated", "todo_list"), ("item.completed", "todo_list"),
                     ("item.completed", "agent_message"), reply='{"findings": []}')
    _recorded_run(monkeypatch, result=(0, stream, ""))

    resp = codex_cli.review("PACKET", "gpt-5.5", 240.0)

    assert (resp.error, resp.text) == ("", '{"findings": []}')
    assert capsys.readouterr().err == ""


def test_a_tool_name_is_cut_so_one_line_stays_one_line(monkeypatch, capsys):
    item = "t" * 100
    _recorded_run(monkeypatch, result=(0, _events(("item.started", item),
                                                  ("item.completed", "agent_message")), ""))

    codex_cli.review("PACKET", "gpt-5.5", 240.0)

    assert f"used a tool ({'t' * 80}), so its reply" in capsys.readouterr().err


# ------------------------------------------------------------ what is logged --

def _logged(tmp_path):
    return [json.loads(line) for line in
            (tmp_path / "llm_spend.jsonl").read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize(("model", "logged_as"), [("gpt-5.5", "gpt-5.5"), ("", "default")])
def test_the_model_is_logged_by_name_and_the_cli_default_as_default(
        monkeypatch, tmp_path, model, logged_as):
    _recorded_run(monkeypatch)

    codex_cli.review("PACKET", model, 240.0)

    assert [x["model"] for x in _logged(tmp_path)] == [logged_as]


@pytest.mark.parametrize("tail", [
    [],                                                          # no turn.completed at all
    [{"type": "turn.completed", "usage": {}}],                   # usage without its counts
])
def test_a_stream_that_gives_no_counts_counts_no_tokens(monkeypatch, tmp_path, tail):
    stream = "\n".join(json.dumps(x) for x in [
        {"type": "item.completed", "item": {"type": "agent_message", "text": "ok"}}, *tail])
    _recorded_run(monkeypatch, result=(0, stream, ""))

    resp = codex_cli.review("PACKET", "gpt-5.5", 240.0)

    assert (resp.text, resp.tokens_in, resp.tokens_out) == ("ok", 0, 0)
    assert [(x["tokens_in"], x["tokens_out"]) for x in _logged(tmp_path)] == [(0, 0)]
