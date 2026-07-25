"""Suite-wide fixtures.

`autolearn.load_state`/`save_state` default to `autolearn.state_path()`
(`Path.home() / ".aramid" / "autolearn_state.json"`). The llm-review
consumer READS it on every consume() and the drain WRITES it at rollup
time, so without isolation the suite would read/write real machine state
(the same concern tests/integration/conftest.py documents for the
registry). Autouse-patch the seam to a per-test tmp_path; individual tests
that seed state simply call autolearn.save_state(...) and hit the same
patched location.
"""
import pytest

from aramid import autolearn, toolpath


@pytest.fixture(autouse=True)
def _isolated_autolearn_state(tmp_path, monkeypatch):
    monkeypatch.setattr(autolearn, "state_path",
                        lambda: tmp_path / "autolearn_state.json")


@pytest.fixture(autouse=True)
def _isolated_git_template(tmp_path, monkeypatch):
    """Neutralize git's machine-global `init.templateDir`.

    The suite runs `git init` in ~49 places. A global template -- aramid's own
    (`aramid hooks install`), husky's, a corporate one -- seeds `.git/hooks`
    in every one of those repos, which silently invalidates every assertion
    about hook absence and makes `probe_interpreter` parse a shim that the
    test never installed.

    This is not hypothetical: installing aramid's own template turned 5 tests
    red across test_init, test_doctor and test_gates_end_to_end, and they were
    red for a reason that had nothing to do with the code under test. Worse,
    they stayed GREEN in CI (no global template there), so the suite's result
    depended on the developer's machine config.

    Point at an EMPTY DIRECTORY rather than the empty string. `GIT_TEMPLATE_DIR=""`
    looks like it should mean "no template" and does not: on Windows an empty
    env var is effectively unset, so git falls straight back to
    `init.templateDir`. Verified by probe -- `os.environ` showed `''` while
    `git init` still seeded pre-commit and pre-push. An existing empty
    directory is unambiguous on every platform."""
    empty = tmp_path / "empty-git-template"
    empty.mkdir(exist_ok=True)
    monkeypatch.setenv("GIT_TEMPLATE_DIR", str(empty))


@pytest.fixture(autouse=True)
def _isolated_tools_dir(tmp_path, monkeypatch):
    """Keep `toolpath.resolve` off the real `~/.aramid/tools`.

    `resolve()` falls back to aramid's managed binaries, so on a machine where
    someone ran `aramid doctor --fix` the suite would find a real gitleaks that
    CI does not have -- and a test simulating "BLOCK-tier tool missing" would
    quietly stop simulating anything. Same class as the template above: real
    machine state leaking into test outcomes. Tests that want the managed dir
    patch this themselves; a later monkeypatch wins."""
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "aramid-tools")
