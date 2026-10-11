"""integration: FN-44 -- what `aramid_check` runs when it is called through MCP.

At the pre-push tier the gate runs the repository's test suite, and it runs it
in the WORKING TREE: a file that no commit holds takes part. For whoever asked
for the gate that is the gate doing its job. It also means that a caller who
can write a file in the repository, and cannot start a program, has one
started by this tool.

The operator decided on 2026-10-11 that aramid's MCP tools do not have to hold
such a caller: they are for an agent one would let run the repository's tests.
ARAMID.md, the user guide and the tool's own description say so, and until
this file that sentence rested on a reading of `mcp_tools`. These tests are
the measurement, and they keep the sentence from going stale: change what the
tool runs and one of them fails.

The real MCP handler and the real `tests` runner run here. Every other
pre-push runner is a clean double, so nothing depends on which analyzers a
machine has, and the runner list itself is left alone.
"""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import config as config_mod
from aramid import mcp_tools, pipeline
from aramid.models import Gate
from aramid.runners import inline
from aramid.runners.base import RunnerResult, ToolState


def _clean(key: str) -> RunnerResult:
    own = RunnerResult(key, ToolState.OK)
    if key not in inline.LABELS:
        return own
    return inline.bundle(own, RunnerResult(inline.LABELS[key], ToolState.OK,
                                           examined=frozenset()))


@pytest.fixture
def only_the_suite_is_real(monkeypatch, tmp_path):
    """Every runner of the gates below except `tests` is a clean no-op."""
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    keys = {key for gate in (Gate.PRE_COMMIT, Gate.PRE_PUSH, Gate.ALL)
            for key in pipeline.GATE_RUNNER_KEYS[gate]}
    assert "tests" in pipeline.GATE_RUNNER_KEYS[Gate.PRE_PUSH]
    assert "tests" in pipeline.GATE_RUNNER_KEYS[Gate.ALL]
    for key in keys - {"tests"}:
        monkeypatch.setitem(pipeline.RUNNERS, key, SimpleNamespace(
            run=lambda ctx, _k=key: _clean(_k),
            parse=lambda result, ctx: []))


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True, text=True)


def _repo_with_an_uncommitted_conftest(tmp_path: Path) -> tuple[Path, Path]:
    """An onboarded repo with an upstream, one committed test that passes, and
    an UNTRACKED `conftest.py` that writes `marker` when anything imports it.
    The marker lies outside the repo, so only running the file can make it."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)],
                   check=True, capture_output=True, text=True)
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    command = json.dumps([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"])
    (root / "aramid.toml").write_text(
        "schema_version = 1\nsemgrep_block_armed = false\n"
        f"agent_block_armed = false\n[tests]\ncommand = {command}\n", encoding="utf-8")
    _git(root, "add", "aramid.toml")
    _git(root, "commit", "-q", "-m", "seed")
    _git(root, "remote", "add", "origin", str(origin))
    _git(root, "push", "-q", "-u", "origin", "main")
    (root / "tests").mkdir()
    (root / "tests" / "test_ok.py").write_text("def test_ok():\n    assert True\n",
                                               encoding="utf-8")
    _git(root, "add", "tests/test_ok.py")
    _git(root, "commit", "-q", "-m", "a test that passes")

    marker = tmp_path / "the-uncommitted-file-ran"
    (root / "conftest.py").write_text(
        "import pathlib\n"
        f"pathlib.Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n",
        encoding="utf-8")
    status = subprocess.run(["git", "status", "--porcelain"], cwd=str(root), check=True,
                            capture_output=True, text=True).stdout
    assert status.strip() == "?? conftest.py", status
    return root, marker


def _check(args: dict) -> dict:
    return mcp_tools.TOOLS["aramid_check"]["handler"](None, args)


def test_check_through_mcp_at_pre_push_runs_an_uncommitted_file_of_the_working_tree(
        tmp_path, monkeypatch, only_the_suite_is_real):
    """The fact the docs state. The suite passes, the gate reports no finding,
    and the file no commit holds has been run."""
    root, marker = _repo_with_an_uncommitted_conftest(tmp_path)
    monkeypatch.chdir(root)

    out = _check({"gate": "pre-push"})

    text = out["content"][0]["text"]
    assert out["isError"] is False, text
    assert text.rstrip().endswith("(exit code 0)"), text
    assert marker.read_text(encoding="utf-8") == "ran", text


def test_check_through_mcp_at_the_all_tier_runs_it_too(
        tmp_path, monkeypatch, only_the_suite_is_real):
    """`all` holds every runner `pre-push` does, the suite among them."""
    root, marker = _repo_with_an_uncommitted_conftest(tmp_path)
    monkeypatch.chdir(root)

    out = _check({"gate": "all"})

    assert out["isError"] is False, out["content"][0]["text"]
    assert marker.exists(), out["content"][0]["text"]


def test_check_through_mcp_at_the_pre_commit_tier_runs_no_suite(
        tmp_path, monkeypatch, only_the_suite_is_real):
    """The control, and the other half of the sentence: the default tier has
    no `tests` runner, so the same file in the same repo is not run. Without
    this arm the marker above could come from anything the handler does."""
    root, marker = _repo_with_an_uncommitted_conftest(tmp_path)
    monkeypatch.chdir(root)

    assert "tests" not in pipeline.GATE_RUNNER_KEYS[Gate.PRE_COMMIT]
    for args in ({}, {"gate": "pre-commit"}, {"gate": "pre-commit", "staged": True}):
        out = _check(args)
        assert out["isError"] is False, out["content"][0]["text"]

    assert not marker.exists()
