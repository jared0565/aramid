"""FN-33: no test may reach a real LLM provider or the real spend log.

A provider counts as installed when `codex` / `claude` is on PATH
(`shutil.which`) or when `OPENROUTER_API_KEY` / `OLLAMA_API_KEY` is set. CI
has none of the four, so a test that drains through the llm-review consumer
degrades quietly there -- and on a developer machine that has them, the same
test makes real provider calls and appends to `~/.aramid/llm_spend.jsonl`.
The autouse `_no_reachable_providers` fixture in tests/conftest.py makes
every test machine look like CI; these tests pin that it does.

The PATH half is red on any machine without the fixture: the test plants its
own `codex` / `claude` on PATH. The key half can only be red on a machine
whose environment sets a key (CI sets none, so there it passes either way).
"""
import os
import shutil
import sys
from pathlib import Path

from aramid import config
from aramid.providers import base, spend
from aramid.providers import claude_cli, codex_cli, ollama_cloud, openrouter  # noqa: F401  (register)

_ALL = ["claude-cli", "codex-cli", "ollama-cloud", "openrouter"]


def _plant(bin_dir: Path, name: str) -> None:
    if sys.platform == "win32":
        (bin_dir / f"{name}.cmd").write_text("@echo off\r\nexit /b 1\r\n", encoding="utf-8")
    else:
        p = bin_dir / name
        p.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        p.chmod(0o755)


def _path_with(monkeypatch, tmp_path: Path, *names: str) -> None:
    bin_dir = tmp_path / "planted-bin"
    bin_dir.mkdir()
    for name in names:
        _plant(bin_dir, name)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))


def test_a_provider_cli_on_path_is_not_found(tmp_path, monkeypatch):
    _path_with(monkeypatch, tmp_path, "codex", "claude", "notcodex")
    # Control: the planted directory and shim shape ARE findable here, so the
    # two Nones below are the fixture hiding them, not a PATH that never took.
    assert shutil.which("notcodex") is not None
    assert shutil.which("codex") is None
    assert shutil.which("claude") is None
    # Every spelling a caller might use: an extension, a Path, a full path.
    assert shutil.which("codex.cmd") is None
    assert shutil.which(Path("claude")) is None
    assert shutil.which(str(tmp_path / "planted-bin" / "codex")) is None
    assert not codex_cli.installed()
    assert not claude_cli.installed()


def test_every_other_name_still_resolves(tmp_path, monkeypatch):
    # The fixture hides two names, never `which` itself: the runners, toolpath
    # and doctor find git, gitleaks, ruff and semgrep through it.
    _path_with(monkeypatch, tmp_path, "notcodex")
    assert shutil.which("notcodex") is not None
    assert shutil.which("git") is not None


def test_no_provider_key_reaches_a_test():
    assert "OPENROUTER_API_KEY" not in os.environ
    assert "OLLAMA_API_KEY" not in os.environ
    assert not openrouter.installed()
    assert not ollama_cloud.installed()


def test_the_provider_chain_is_empty_even_with_every_provider_ordered(tmp_path, monkeypatch):
    _path_with(monkeypatch, tmp_path, "codex", "claude")
    cfg = config.load_config(tmp_path)
    cfg.llm["provider_order"] = list(_ALL)
    assert base.chain(cfg) == []


def test_the_spend_log_is_per_test(tmp_path):
    real = Path.home() / ".aramid" / "llm_spend.jsonl"
    got = spend.spend_path()
    assert got != real
    assert tmp_path in got.parents
