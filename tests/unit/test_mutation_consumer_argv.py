"""Unit-scope pins for the mutation consumer's argv helpers.

The drain confirms a survivor with this repo's own `[mutation].test_command`
(`pytest -q tests/unit`), so a rule that only the integration suite
exercises reads as a survivor there even when it is covered. These pin the
two such rules the 2026-09-04 drain surfaced (item 7dea7f37) at unit scope.
"""
import sys
from pathlib import Path
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


# The 2026-09-06 02:00Z drain reported every one of the 10 mutants it made
# in src/aramid/runners/tests.py as a TIMEOUT -- silently not a finding. The
# stem is `tests`; no `test_tests.py` exists, so stage 1 fell back to
# `pytest -q -k tests`, and under pytest 8+ a directory is a collector whose
# name is a keyword of every item under it: `-k tests` selects all 2544
# tests of the tree (measured with --collect-only), a 19-minute run inside a
# 120 s mutant budget. Two rules close it: the suffix form `test_<stem>_*.py`
# is a direct hit like `test_<stem>.py`, and a stem that names a directory
# under tests/ can never be a -k token.

def _touch(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def test_stage1_selects_suffix_named_test_files_as_direct_hits(tmp_path):
    _touch(tmp_path / "tests" / "unit" / "test_calc_progress.py")
    _touch(tmp_path / "tests" / "integration" / "test_calc.py")
    _touch(tmp_path / "tests" / "unit" / "test_calculator.py")     # not calc_*
    argv = mut_consumer._stage1_argv(tmp_path, "calc.py")
    assert argv == [sys.executable, "-m", "pytest", "-q",
                    str(Path("tests", "integration", "test_calc.py")),
                    str(Path("tests", "unit", "test_calc_progress.py"))]


def test_stage1_direct_hits_stay_inside_the_configured_suite_scope(tmp_path):
    # `consumers/mutation.py` has ten `test_mutation*.py` files, four of them
    # integration files that run for minutes: unfiltered, the suffix rule
    # would send every mutant of it into a stage-1 timeout. The scope is the
    # path arguments of the configured full suite, the same scope stage 2
    # confirms against and `_suite_label` names.
    _touch(tmp_path / "tests" / "unit" / "test_calc.py")
    _touch(tmp_path / "tests" / "unit" / "test_calc_argv.py")
    _touch(tmp_path / "tests" / "integration" / "test_calc_e2e.py")
    cfg = SimpleNamespace(mutation={"test_command": ["pytest", "-q", "tests/unit"]})
    argv = mut_consumer._stage1_argv(tmp_path, "calc.py", cfg, tmp_path)
    assert argv == [sys.executable, "-m", "pytest", "-q",
                    str(Path("tests", "unit", "test_calc.py")),
                    str(Path("tests", "unit", "test_calc_argv.py"))]
    # A module whose only named tests live outside the scope gets the
    # keyword fallback, not an out-of-scope file.
    _touch(tmp_path / "tests" / "integration" / "test_other.py")
    assert mut_consumer._stage1_argv(tmp_path, "other.py", cfg, tmp_path)[-2:] == ["-k", "other"]


def test_stage1_falls_back_to_the_full_suite_when_the_stem_names_a_test_directory(tmp_path):
    _touch(tmp_path / "tests" / "unit" / "test_other.py")
    for stem in ("tests.py", "unit.py", "Tests.py"):    # -k matches case-insensitively
        argv = mut_consumer._stage1_argv(tmp_path, stem)
        assert argv == mut_consumer._full_argv(None), stem
        assert "-k" not in argv, stem
