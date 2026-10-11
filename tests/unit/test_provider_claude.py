import json
import os
import shutil
from pathlib import Path

import pytest

from aramid.providers import base, claude_cli, spend

ENVELOPE = json.dumps({
    "type": "result", "subtype": "success", "is_error": False,
    "duration_ms": 4200, "num_turns": 1, "session_id": "abc",
    "result": "{\"findings\": []}",
    "total_cost_usd": 0.0123,
    "usage": {"input_tokens": 2100, "output_tokens": 60},
})


# The whole restriction, in the order it is passed (FN-41). Written out here
# and not imported: a flag dropped from the source must fail a test.
RESTRICTION = ["--tools", "", "--strict-mcp-config", "--safe-mode", "--restricted",
               "--no-session-persistence", "--permission-prompts", "none"]


@pytest.fixture(autouse=True)
def _isolated_spend(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")


def test_registers_in_providers():
    assert base.PROVIDERS["claude-cli"] is claude_cli


def test_available_and_installed_iff_on_path(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    assert claude_cli.available(None) is True
    assert claude_cli.installed() is True
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: None)
    assert claude_cli.available(None) is False
    assert claude_cli.installed() is False


def test_review_parses_envelope_and_logs_zero_cost(monkeypatch, tmp_path):
    seen = {}

    def fake_run(argv, prompt, timeout_s, *, cwd=None):
        seen["argv"], seen["prompt"] = argv, prompt
        return 0, ENVELOPE, ""
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess", fake_run)
    resp = claude_cli.review("PACKET", "sonnet", 240.0)
    assert resp.text == '{"findings": []}'
    assert (resp.tokens_in, resp.tokens_out) == (2100, 60)
    assert resp.cost_usd == 0.0     # subscription: cost 0.0 regardless of envelope estimate
    assert resp.error == ""
    assert seen["argv"] == [r"C:\bin\claude.exe", "-p", "--model", "sonnet",
                            "--output-format", "json", *RESTRICTION]
    assert seen["prompt"] == "PACKET"
    logged = (tmp_path / "llm_spend.jsonl").read_text(encoding="utf-8")
    assert json.loads(logged)["provider"] == "claude-cli"


def test_review_timeout(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: None)
    assert claude_cli.review("P", "sonnet", 1.0).error == base.ERR_TIMEOUT


def test_review_quota_error(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (1, "", "Claude usage limit reached|resets 3pm"))
    assert claude_cli.review("P", "sonnet", 240.0).error == base.ERR_QUOTA


def test_review_nonzero_exit_is_error(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (1, "", "boom"))
    assert claude_cli.review("P", "sonnet", 240.0).error == base.ERR_ERROR


def test_review_unparseable_envelope_is_malformed(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, "garbage not json", ""))
    assert claude_cli.review("P", "sonnet", 240.0).error == base.ERR_MALFORMED


def test_review_null_usage_keeps_text_zeroes_tokens(monkeypatch):
    envelope = json.dumps({"result": "ok text", "usage": None})
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, envelope, ""))
    resp = claude_cli.review("P", "sonnet", 240.0)
    assert resp.text == "ok text"
    assert (resp.tokens_in, resp.tokens_out) == (0, 0)
    assert resp.error == ""


def test_review_non_dict_envelope_is_malformed(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess",
                        lambda *a, **k: (0, "[1, 2]", ""))
    assert claude_cli.review("P", "sonnet", 240.0).error == base.ERR_MALFORMED


def test_review_unavailable_when_not_on_path(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: None)
    assert claude_cli.review("P", "sonnet", 240.0).error == base.ERR_UNAVAILABLE


# ------------------------------------------- the reviewer holds nothing (FN-41) --

def _recorded_run(monkeypatch, result=(0, ENVELOPE, "")):
    """Stand in for the launch; returns the calls, each with what the
    directory it was given looked like while the reviewer ran."""
    calls = []

    def fake_run(argv, prompt, timeout_s, *, cwd=None):
        there = Path(cwd) if cwd is not None else None
        calls.append({"argv": list(argv), "cwd": cwd,
                      "is_dir": there is not None and there.is_dir(),
                      "holds": sorted(os.listdir(cwd)) if cwd is not None else None})
        return result
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess", fake_run)
    return calls


def test_the_reviewer_is_started_with_no_tools_no_mcp_servers_and_no_customizations(
        monkeypatch):
    """The prompt is a review packet built from a repo's diff, so part of it
    is written by whoever wrote the commit. The command line is pinned whole:
    every token of the restriction, and nothing that gives a tool back."""
    calls = _recorded_run(monkeypatch)

    claude_cli.review("PACKET", "opus", 240.0)

    assert [c["argv"] for c in calls] == [[
        r"C:\bin\claude.exe", "-p", "--model", "opus", "--output-format", "json",
        "--tools", "", "--strict-mcp-config", "--safe-mode", "--restricted",
        "--no-session-persistence", "--permission-prompts", "none"]]


def test_effort_follows_the_restriction_and_replaces_none_of_it(monkeypatch):
    calls = _recorded_run(monkeypatch)

    claude_cli.review("PACKET", "opus", 240.0, effort="high")

    assert calls[0]["argv"] == [r"C:\bin\claude.exe", "-p", "--model", "opus",
                                "--output-format", "json", *RESTRICTION, "--effort", "high"]


def test_the_reviewer_runs_in_an_empty_directory_of_its_own(monkeypatch, tmp_path):
    """Not where the drain was started: that is a repository, with a CLAUDE.md,
    settings and a .mcp.json a later CLI might read whatever the flags say.
    The directory is new and empty for each call and gone after it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "CLAUDE.md").write_text("not for the reviewer", encoding="utf-8")
    calls = _recorded_run(monkeypatch)

    claude_cli.review("PACKET", "opus", 240.0)
    claude_cli.review("PACKET", "opus", 240.0)

    first, second = calls
    assert (first["is_dir"], first["holds"]) == (True, [])
    assert (second["is_dir"], second["holds"]) == (True, [])
    assert first["cwd"] != second["cwd"]
    assert Path(first["cwd"]).resolve() != tmp_path.resolve()
    assert tmp_path.resolve() not in Path(first["cwd"]).resolve().parents
    assert Path(first["cwd"]).name.startswith("aramid-review-")
    assert not Path(first["cwd"]).exists() and not Path(second["cwd"]).exists()


@pytest.mark.parametrize("said", [
    "error: unknown option '--safe-mode'",
    "error: option '--permission-prompts <target>' argument 'none' is invalid. Allowed"
    " choices are host.",
    "error: option '--tools <tools...>' argument missing",
])
def test_a_claude_that_does_not_take_the_command_line_is_named_and_never_run_without_it(
        monkeypatch, capsys, said):
    """An older CLI does not know these options. The reviewer is then not
    used at all: one launch, no second one with the restriction taken off,
    and a line that says why."""
    calls = _recorded_run(monkeypatch, result=(1, "", said + "\n"))

    resp = claude_cli.review("PACKET", "opus", 240.0)

    assert resp.error == base.ERR_UNAVAILABLE
    assert len(calls) == 1
    assert capsys.readouterr().err == (
        "aramid: providers: claude-cli: this `claude` did not accept its command line, so"
        " the reviewer was not run. It is never started without the options that keep it"
        " from using tools: upgrade Claude Code. It said: " + said + "\n")


@pytest.mark.parametrize("err", [
    "boom",
    "the reviewer said: error: unknown option",      # not at the start of a line
    "",
])
def test_any_other_failure_is_still_a_plain_error_and_says_nothing(monkeypatch, capsys, err):
    _recorded_run(monkeypatch, result=(1, "", err))

    assert claude_cli.review("PACKET", "opus", 240.0).error == base.ERR_ERROR
    assert capsys.readouterr().err == ""


def test_a_refused_command_line_on_stdout_alone_is_not_read_as_one(monkeypatch, capsys):
    # The CLI writes option errors to stderr. stdout is the model's reply
    # envelope, and text in it is never a reason to call the CLI too old.
    _recorded_run(monkeypatch, result=(1, "error: unknown option '--safe-mode'\n", ""))

    assert claude_cli.review("PACKET", "opus", 240.0).error == base.ERR_ERROR
    assert capsys.readouterr().err == ""


def test_the_first_refusal_is_quoted_and_cut_so_one_line_stays_one_line(monkeypatch, capsys):
    said = "error: unknown option '" + "x" * 400 + "'"
    _recorded_run(monkeypatch,
                  result=(1, "", said + "\nerror: unknown option '--second'\n"))

    claude_cli.review("PACKET", "opus", 240.0)

    assert capsys.readouterr().err.endswith("It said: " + said[:200] + "\n")


def test_a_directory_that_will_not_go_does_not_fail_the_review(monkeypatch):
    """A child killed on timeout can hold the directory for a moment. The
    review's answer stands and the directory is left behind. This bites on
    Windows, where a file that is open cannot be deleted; elsewhere the
    directory simply goes."""
    held = []

    def fake_run(argv, prompt, timeout_s, *, cwd=None):
        held.append(open(Path(cwd) / "held", "w", encoding="utf-8"))  # noqa: SIM115
        return 0, ENVELOPE, ""
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: r"C:\bin\claude.exe")
    monkeypatch.setattr(claude_cli.base, "run_provider_subprocess", fake_run)

    try:
        resp = claude_cli.review("PACKET", "opus", 240.0)
    finally:
        held[0].close()
        shutil.rmtree(Path(held[0].name).parent, ignore_errors=True)

    assert (resp.error, resp.text) == ("", '{"findings": []}')
