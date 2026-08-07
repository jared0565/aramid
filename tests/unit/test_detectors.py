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


def test_rust_repo_detected_via_cargo_toml(tmp_path):
    """A Cargo workspace must report stack "rust" and package manager
    "cargo" -- previously reported (Round 9 feedback from Operation
    Firewall's own coding agent, verified against live repo state): a real
    Cargo workspace was detected as stack "python" / package manager "none",
    because detect_stacks had no Cargo signal at all and fell back to its
    permissive "any .py file anywhere" python heuristic."""
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/x"]\n')
    (tmp_path / "Cargo.lock").write_text('version = 3\n')
    assert "rust" in detectors.detect_stacks(tmp_path, tmp_path)
    assert detectors.detect_package_manager(tmp_path) == "cargo"


def test_rust_stack_detected_without_lockfile_but_no_package_manager(tmp_path):
    """Cargo.toml alone is enough to know this is a Rust repo (mirrors
    package.json alone being enough for "js"); Cargo.lock is required for
    "cargo" as a package manager (mirrors the JS lockfile requirement) --
    a workspace member checked out without its lock is still rust, but
    aramid cannot point a dependency audit at a lockfile that isn't there."""
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "x"\n')
    assert "rust" in detectors.detect_stacks(tmp_path, tmp_path)
    assert detectors.detect_package_manager(tmp_path) is None


def test_dual_stack_python_scripts_alongside_a_real_cargo_workspace(tmp_path):
    """The exact shape of the reported repo: a Cargo workspace that also has
    real, genuine .py utility scripts (not virtualenv/vendored noise) --
    both "python" and "rust" are correct, not a detection bug; aramid
    already treats python+js as a legitimate dual-stack case, and this is
    the same relationship for python+rust."""
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = []\n')
    (tmp_path / "Cargo.lock").write_text('version = 3\n')
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "verify.py").write_text("print('ok')\n")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"python", "rust"}
    assert detectors.detect_package_manager(tmp_path) == "cargo"


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


# --- unrooted stacks: code aramid can see but structurally cannot gate ------
#
# detect_stacks gates "rust" on a ROOT Cargo.toml and "js" on a ROOT
# package.json (python alone has a walk fallback). A repo whose Rust crate
# lives in a subdirectory therefore reports no rust stack at all, so clippy
# and cargo-audit are never selected -- zero Rust gating, reported
# identically to a repo that has no Rust in it. These cover the detector
# that makes that state *nameable*; the notice built on it lives in
# test_pipeline / test_init.
#
# Deliberately NOT fixed by giving rust/js the walk fallback python has:
# cargo/npm run with cwd=root, so selecting them without a root manifest
# converts an ABSENT gate into a BROKEN one, which is strictly worse.


def test_unrooted_rust_crate_is_reported(tmp_path):
    """A nested Cargo.toml with no root counterpart is a real standalone
    crate -- it cannot be a workspace member, because a workspace requires
    the very root manifest whose absence puts us here."""
    crate = tmp_path / "backend"
    crate.mkdir()
    (crate / "Cargo.toml").write_text("[package]\nname = 'svc'\n")
    assert "rust" not in detectors.detect_stacks(tmp_path, tmp_path)
    assert detectors.detect_unrooted_stacks(tmp_path) == {"rust": ["backend"]}


def test_cargo_workspace_is_not_unrooted(tmp_path):
    """The OF shape: root manifest + crates/*/Cargo.toml. The stack is
    detected and gated normally, so nothing here is unrooted -- this is the
    control that stops the check firing on every ordinary workspace."""
    (tmp_path / "Cargo.toml").write_text("[workspace]\nmembers = ['crates/a']\n")
    member = tmp_path / "crates" / "a"
    member.mkdir(parents=True)
    (member / "Cargo.toml").write_text("[package]\nname = 'a'\n")
    assert "rust" in detectors.detect_stacks(tmp_path, tmp_path)
    assert detectors.detect_unrooted_stacks(tmp_path) == {}


def test_unrooted_js_needs_a_lockfile_beside_it(tmp_path):
    """A bare nested package.json is NOT enough. A docs site, a widget, or
    a fixture legitimately carries one that nobody wants npm-audited, and
    telling an operator they are missing JS coverage there is the same
    false-positive class as aramid running pytest on a TS repo. Require the
    lockfile that proves a real installed project -- the same signal
    detect_package_manager and runners/tests.py's C1 gate already use."""
    site = tmp_path / "docs"
    site.mkdir()
    (site / "package.json").write_text('{"name":"docs"}')
    assert detectors.detect_unrooted_stacks(tmp_path) == {}
    (site / "package-lock.json").write_text("{}")
    assert detectors.detect_unrooted_stacks(tmp_path) == {"js": ["docs"]}


def test_unrooted_scan_skips_vendored_and_dot_dirs(tmp_path):
    """Shares _iter_files' pruning, so a vendored manifest under
    node_modules/ cannot manufacture a phantom ungated stack."""
    vendored = tmp_path / "node_modules" / "left-pad"
    vendored.mkdir(parents=True)
    (vendored / "package.json").write_text('{"name":"left-pad"}')
    (vendored / "package-lock.json").write_text("{}")
    buried = tmp_path / ".cache" / "crate"
    buried.mkdir(parents=True)
    (buried / "Cargo.toml").write_text("[package]\nname = 'x'\n")
    assert detectors.detect_unrooted_stacks(tmp_path) == {}


def test_unrooted_both_stacks_and_multiple_dirs_sorted(tmp_path):
    for name in ("svc-b", "svc-a"):
        d = tmp_path / name
        d.mkdir()
        (d / "Cargo.toml").write_text("[package]\nname = 'x'\n")
    web = tmp_path / "web"
    web.mkdir()
    (web / "package.json").write_text('{"name":"w"}')
    (web / "yarn.lock").write_text("")
    assert detectors.detect_unrooted_stacks(tmp_path) == {
        "js": ["web"], "rust": ["svc-a", "svc-b"]}


def test_aramid_own_repo_has_no_unrooted_stacks():
    """Guards the notice against firing on every run of aramid's own gate."""
    assert detectors.detect_unrooted_stacks(REPO_ROOT) == {}


def test_every_tool_named_in_a_notice_is_a_real_runner():
    """The notice tells an operator which gates are not covering them, so a
    name that doesn't exist sends them looking for a tool aramid has never
    had. This caught exactly that: the js entry originally read "npm-audit",
    which is not a runner -- the dependency audit registers under the
    package manager's own name (npm/pnpm/yarn).

    detectors.py cannot import toolset (it is the bottom of the layering,
    which is what lets pipeline.py and commands/init.py share this text
    without a cycle), so the registry cross-check has to live out here."""
    from aramid.toolset import RUNNER_TOOL_NAMES

    for stack, (tools, _remedy) in detectors._ROOT_GATED_HELP.items():
        named = {t for part in tools.split(",") for t in part.strip().split("/")}
        unknown = named - set(RUNNER_TOOL_NAMES)
        assert not unknown, f"{stack} notice names non-existent runner(s): {unknown}"


def test_every_root_gated_stack_has_help_text():
    """A stack added to one table and not the other would KeyError inside
    the notice loop -- i.e. crash the gate, from a detector."""
    assert set(detectors._ROOT_GATED_STACKS) == set(detectors._ROOT_GATED_HELP)


# --- cargo / go test kinds --------------------------------------------------
# Rust is an already-CLAIMED stack (detect_stacks returns "rust"; clippy and
# cargo-audit run on it), so a BLOCK-tier test gate that cannot run there was
# an inconsistency, not a missing feature. Go is added as a test KIND only --
# detect_stacks still does not claim Go, because a `go test` runner without
# vet/staticcheck would be a coverage claim aramid cannot honour.
#
# DETECTION IS FILENAME-ONLY, MEASURED NOT ASSUMED. Sniffing `.rs` contents
# for #[test]/#[cfg(test)] would catch inline unit tests -- the commoner Rust
# layout -- but measured 409 ms against 4 ms for the filename walk on 500
# files / 2.5 MB, in a detector that runs on every gate. An inline-only crate
# instead falls through to the loud "no suite detected" WARN naming
# [tests].command, which is an honest degradation rather than silence.

def _rust(tmp_path, with_tests=True, nested=None):
    root = tmp_path / "rs"
    (root).mkdir(exist_ok=True)
    (root / "Cargo.toml").write_text("[package]\nname='d'\n", encoding="utf-8")
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "lib.rs").write_text("pub fn f() {}\n", encoding="utf-8")
    if with_tests:
        d = (root / nested / "tests") if nested else (root / "tests")
        d.mkdir(parents=True, exist_ok=True)
        (d / "it.rs").write_text("#[test]\nfn t() {}\n", encoding="utf-8")
    return root


def test_cargo_detected_from_a_tests_dir_of_rs_files(tmp_path):
    assert "cargo" in detectors.detect_tests(_rust(tmp_path))


def test_cargo_detected_in_a_workspace_member(tmp_path):
    """Workspaces put member crates under crates/<name>/, each with its own
    tests/. Keying on the walk rather than a root-level glob covers them."""
    assert "cargo" in detectors.detect_tests(_rust(tmp_path, nested="crates/inner"))


def test_no_cargo_without_a_cargo_toml(tmp_path):
    """A bare tests/*.rs with no manifest is not a Cargo project -- and
    `cargo test` there would fail for a reason that is not the repo's."""
    root = tmp_path / "norust"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "it.rs").write_text("#[test]\nfn t() {}\n", encoding="utf-8")
    assert "cargo" not in detectors.detect_tests(root)


def test_inline_only_crate_is_not_detected_and_that_is_deliberate(tmp_path):
    """The documented, measured trade-off: no content sniffing. This must be
    a KNOWN gap with a loud downstream WARN, never an accident -- if someone
    later adds content detection, this test should be updated deliberately,
    not discovered failing."""
    assert "cargo" not in detectors.detect_tests(_rust(tmp_path, with_tests=False))


def _go(tmp_path, with_tests=True):
    root = tmp_path / "go"
    root.mkdir(exist_ok=True)
    (root / "go.mod").write_text("module example.com/d\n\ngo 1.22\n", encoding="utf-8")
    (root / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    if with_tests:
        (root / "main_test.go").write_text(
            "package main\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n",
            encoding="utf-8")
    return root


def test_go_detected_from_a_test_go_file_beside_the_source(tmp_path):
    """Go's convention puts *_test.go next to the source with NO tests/
    directory -- which is exactly why the old marker-based notice never
    fired on a Go repo."""
    assert "go" in detectors.detect_tests(_go(tmp_path))


def test_no_go_without_a_go_mod(tmp_path):
    root = tmp_path / "nogo"
    root.mkdir()
    (root / "main_test.go").write_text("package main\n", encoding="utf-8")
    assert "go" not in detectors.detect_tests(root)


def test_no_go_when_the_module_has_no_test_files(tmp_path):
    assert "go" not in detectors.detect_tests(_go(tmp_path, with_tests=False))


def test_a_python_repo_is_unaffected_by_the_new_kinds(tmp_path):
    """Regression: the new kinds must not widen what a Python repo reports."""
    root = tmp_path / "py"
    root.mkdir()
    (root / "test_x.py").write_text("def test_x(): pass\n", encoding="utf-8")
    assert detectors.detect_tests(root) == {"pytest"}
