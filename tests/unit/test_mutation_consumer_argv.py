"""Unit-scope pins for the mutation consumer's argv helpers.

The drain confirms a survivor with this repo's own `[mutation].test_command`
(`pytest -q tests/unit`), so a rule that only the integration suite
exercises reads as a survivor there even when it is covered. These pin the
two such rules the 2026-09-04 drain surfaced (item 7dea7f37) at unit scope.
"""
import sys
from types import SimpleNamespace

from aramid.consumers import mutation as mut_consumer


def test_stage1_falls_back_to_the_full_suite_for_a_k_keyword_stem(tmp_path):
    # "and" satisfies _SAFE_STEM but is a pytest -k keyword: `-k and` is a
    # usage error (exit 4), so the full suite is the only correct selection.
    argv = mut_consumer._stage1_argv(tmp_path, "and.py")
    assert argv == mut_consumer._full_argv(None)
    assert "-k" not in argv


def test_stage1_selects_by_keyword_for_a_safe_stem(tmp_path):
    argv = mut_consumer._stage1_argv(tmp_path, "calc.py")
    assert argv == [sys.executable, "-m", "pytest", "-q", "-k", "calc"]


def test_full_argv_honours_mutation_test_command_over_tests_command():
    cfg = SimpleNamespace(mutation={"test_command": "pytest -q tests/unit"},
                          tests={"command": "pytest -q"})
    assert mut_consumer._full_argv(cfg) == ["pytest", "-q", "tests/unit"]


def test_full_argv_falls_through_a_missing_section_to_the_next():
    # No `mutation` attribute at all: the lookup must read it as empty and
    # move on to [tests].command, not fail on it.
    cfg = SimpleNamespace(tests={"command": ["pytest", "-q"]})
    assert mut_consumer._full_argv(cfg) == ["pytest", "-q"]
