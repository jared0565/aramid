import json
from pathlib import Path

from aramid import detectors

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_stack_and_pm(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "package.json").write_text('{"scripts":{"test":"vitest"}}')
    (tmp_path / "pnpm-lock.yaml").write_text("")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"python", "js"}
    assert detectors.detect_package_manager(tmp_path) == "pnpm"
    assert "npm" in detectors.detect_tests(tmp_path)


# --- task-1 brief fixture matrix (15 rows) ----------------------------------
#
# Each test below is named after its row in the brief's table. The brief's
# values are load-bearing and reproduced verbatim; see
# .superpowers/sdd/2026-07-26-aramid-detector-fix/task-1-brief.md.


def test_ts_repo_with_bare_tests_dir_and_lockfile(tmp_path):
    """Row 1: TS-only, tests/ of .test.ts, package.json test script +
    lockfile. This is the reported bug scenario itself: a bare tests/
    directory of non-python files must not produce a pytest false positive."""
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "vitest"}}))
    (tmp_path / "package-lock.json").write_text("{}")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "thing.test.ts").write_text("test('x', () => {});\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"js"}
    assert detectors.detect_tests(tmp_path) == {"npm"}


def test_ts_repo_py_only_under_dot_dir(tmp_path):
    """Row 2: TS repo whose only .py is .claude/graph-reminder.py -- a
    dot-directory must be pruned from the walk so it doesn't count."""
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "vitest"}}))
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "graph-reminder.py").write_text("# not a stack signal\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"js"}
    assert detectors.detect_tests(tmp_path) == {"npm"}


def test_python_repo_test_foo(tmp_path):
    """Row 3: Python repo, tests/test_foo.py."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_foo.py").write_text("def test_x(): assert True\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"python"}
    assert detectors.detect_tests(tmp_path) == {"pytest"}


def test_python_repo_foo_test_only(tmp_path):
    """Row 4: Python repo, tests/foo_test.py only."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "foo_test.py").write_text("def test_x(): assert True\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"python"}
    assert detectors.detect_tests(tmp_path) == {"pytest"}


def test_python_repo_conftest_only(tmp_path):
    """Row 5: Python repo, conftest.py only -- conftest.py alone is a
    deliberate positive pytest signal (not weakened for any other test's
    sake; see the brief)."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    (tmp_path / "conftest.py").write_text("import pytest\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"python"}
    assert detectors.detect_tests(tmp_path) == {"pytest"}


def test_python_repo_pyproject_no_py_at_all(tmp_path):
    """Row 6: Python repo, pyproject.toml, no .py at all."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"python"}
    assert detectors.detect_tests(tmp_path) == set()


def test_python_repo_py_files_no_pyproject(tmp_path):
    """Row 7 (review M1): .py files but NO pyproject.toml. This is the row
    that actually forces detect_stacks to evaluate the walk -- with
    pyproject.toml present, `or` short-circuits and the walk is never run, so
    without this row the aramid-root row (below) would prove nothing about
    the new os.walk logic."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_foo.py").write_text("def test_x(): assert True\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"python"}
    assert detectors.detect_tests(tmp_path) == {"pytest"}


def test_genuine_dual_stack_with_lockfile(tmp_path):
    """Row 8: genuine dual-stack (pyproject.toml + test_*.py + script +
    lockfile)."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "vitest"}}))
    (tmp_path / "package-lock.json").write_text("{}")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_foo.py").write_text("def test_x(): assert True\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"js", "python"}
    assert detectors.detect_tests(tmp_path) == {"npm", "pytest"}


def test_package_json_test_script_no_lockfile(tmp_path):
    """Row 9: package.json with a test script but NO lockfile. The lockfile
    requirement belongs only to runners/tests.py:run() (Task 3's business,
    per the C1/B1/B3 decision) and must not appear in detect_tests."""
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "vitest"}}))
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"js"}
    assert detectors.detect_tests(tmp_path) == {"npm"}


def test_dual_stack_no_lockfile(tmp_path):
    """Row 10: dual-stack but NO lockfile (pyproject.toml + test_*.py +
    script)."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "vitest"}}))
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_foo.py").write_text("def test_x(): assert True\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"js", "python"}
    assert detectors.detect_tests(tmp_path) == {"npm", "pytest"}


def test_py_only_under_node_modules(tmp_path):
    """Row 11: .py present only under node_modules/. Also plants a
    would-be pytest-signal filename there, so this row proves node_modules
    is pruned from BOTH walks, not just the stack-detection one."""
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "vitest"}}))
    nm = tmp_path / "node_modules" / "somepkg"
    nm.mkdir(parents=True)
    (nm / "test_fake.py").write_text("# vendored, must not count\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"js"}
    assert detectors.detect_tests(tmp_path) == {"npm"}


def test_py_only_under_venv_and_build(tmp_path):
    """Row 12: .py/test_*.py present only under venv/ and build/."""
    venv_dir = tmp_path / "venv" / "lib"
    venv_dir.mkdir(parents=True)
    (venv_dir / "site.py").write_text("# vendored\n")
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    (build_dir / "test_generated.py").write_text("# generated, must not count\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == set()
    assert detectors.detect_tests(tmp_path) == set()


# --- MUST FIX 1 (whole-branch review): the three _EXCLUDED_DIRS names ------
# review B6 mandated but this branch originally shipped without --
# ("graph-out", "env", "site-packages"). One test per newly-added name,
# plus the reviewer's own literal live repro.

def test_py_only_under_env(tmp_path):
    """`env/` (not just `venv/`) must be pruned -- `python -m venv env` is
    at least as common a convention, and the dot-directory rule does not
    cover it."""
    env_dir = tmp_path / "env" / "lib"
    env_dir.mkdir(parents=True)
    (env_dir / "test_vendored.py").write_text("# vendored, must not count\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == set()
    assert detectors.detect_tests(tmp_path) == set()


def test_py_only_under_graph_out(tmp_path):
    """`graph-out/` is aramid's own graphite artifact directory (also in
    defaults.toml's own `ignore_paths`) -- a stray test_*.py under it must
    not contribute a stack or test signal."""
    go_dir = tmp_path / "graph-out"
    go_dir.mkdir()
    (go_dir / "test_generated.py").write_text("# graph artifact, must not count\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == set()
    assert detectors.detect_tests(tmp_path) == set()


def test_py_only_under_site_packages_without_env_or_venv_wrapper(tmp_path):
    """`site-packages/` is excluded independently of `env`/`venv` -- some
    virtualenv tools and vendoring conventions place it directly, with no
    `env`/`venv`-named wrapper directory at all."""
    sp_dir = tmp_path / "site-packages" / "somepkg"
    sp_dir.mkdir(parents=True)
    (sp_dir / "test_thing.py").write_text("# vendored, must not count\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == set()
    assert detectors.detect_tests(tmp_path) == set()


def test_ts_repo_with_env_virtualenv_site_packages_not_detected_as_python(tmp_path):
    """MUST FIX 1's own live repro (whole-branch-findings.md): a TypeScript
    repo with a `python -m venv env` virtualenv whose site-packages
    contains a vendored conftest.py/test_*.py must NOT be detected as
    python/pytest -- this exact shape was reopening the bug this whole
    branch exists to fix, reached by a different vector (`env` was missing
    from _EXCLUDED_DIRS)."""
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "vitest"}}))
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.ts").write_text("export const a = 1;\n")
    pkg_dir = tmp_path / "env" / "Lib" / "site-packages" / "somepkg"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "conftest.py").write_text("import pytest\n")
    (pkg_dir / "test_thing.py").write_text("def test_x(): assert True\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"js"}
    assert detectors.detect_tests(tmp_path) == {"npm"}


def test_repo_nested_under_dot_ancestor(tmp_path):
    """Row 13: whole repo nested under a dot-ancestor (<tmp>/.local/src/repo).
    The walk starts AT the repo root and never re-examines its own
    ancestors' names, so a dot directory ABOVE the repo must not blank out
    the result."""
    repo = tmp_path / ".local" / "src" / "repo"
    repo.mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_foo.py").write_text("def test_x(): assert True\n")
    assert detectors.detect_stacks(repo, repo) == {"python"}
    assert detectors.detect_tests(repo) == {"pytest"}


def test_scope_subdirectory_excludes_py_outside_it(tmp_path):
    """Row 14 (review I9): scope = a subdirectory, .py only outside it.
    detect_stacks's walk is based at `scope`, not `root` -- a .py file
    outside scope must not leak in. No pyproject.toml/package.json at root,
    so the walk is the only possible source of 'python' here."""
    (tmp_path / "outside.py").write_text("# outside scope, must not count\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    assert "python" not in detectors.detect_stacks(tmp_path, sub)


def test_aramid_own_repo_root():
    """Row 15 / global constraint 1: aramid's own repo must still
    self-detect as python/pytest, verified against the real repo root."""
    assert "python" in detectors.detect_stacks(REPO_ROOT, REPO_ROOT)
    assert "pytest" in detectors.detect_tests(REPO_ROOT)


# --- MUST FIX 5 (whole-branch review / deferred #2): case-sensitivity ------
# is deliberate, uniform-on-every-platform behaviour -- pinned per shape so
# a future partial re-introduction of case-insensitivity (e.g. lowercasing
# only one of the three _is_pytest_file branches) doesn't slip through.

def test_uppercase_conftest_not_detected(tmp_path):
    """`Conftest.PY` does not match the `conftest.py` branch."""
    (tmp_path / "Conftest.PY").write_text("import pytest\n")
    assert detectors.detect_tests(tmp_path) == set()


def test_uppercase_test_prefix_file_not_detected(tmp_path):
    """`TEST_FOO.PY` does not match the `test_*.py` branch -- pytest itself
    WOULD collect this on Windows (its own globbing normcases there); a
    real, deliberate, platform-uniform false negative."""
    (tmp_path / "TEST_FOO.PY").write_text("def test_x(): assert True\n")
    assert detectors.detect_tests(tmp_path) == set()


def test_uppercase_test_suffix_file_not_detected(tmp_path):
    """`BAR_TEST.PY` does not match the `*_test.py` branch."""
    (tmp_path / "BAR_TEST.PY").write_text("def test_x(): assert True\n")
    assert detectors.detect_tests(tmp_path) == set()


def test_uppercase_py_suffix_not_detected_by_stack_walk(tmp_path):
    """detect_stacks's own `.suffix == \".py\"` walk is equally
    case-sensitive -- no pyproject.toml here, so the walk is the only
    possible source of "python"."""
    (tmp_path / "BAR.PY").write_text("# uppercase suffix, not matched by design\n")
    assert "python" not in detectors.detect_stacks(tmp_path, tmp_path)
