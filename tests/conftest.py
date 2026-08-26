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
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import aramid
from aramid import autolearn, config, toolpath


@pytest.fixture
def recent_iso() -> str:
    """An ISO-8601 timestamp an hour old, for anything a drain will see.

    `cmd_drain` runs `queue.expire_stale(..., item_expiry_days)` against the
    WALL CLOCK, so an item enqueued at a literal date ages out on a calendar
    the test does not control. Four integration tests hardcoded
    `2026-07-20T10:00:00+00:00`, passed for a month, then began failing on
    2026-08-20 with nothing but `aramid drain: 0 item(s) drained, 0 left` --
    and blocked every push, having never gone red in CI because the last run
    predated the expiry.

    An hour rather than `now`: far enough back that any "created before now"
    ordering holds, near enough that no expiry window can reach it.
    `tests/unit/test_queue_test_hygiene.py` keeps new drain tests off literal
    dates; `tests/unit/test_queue.py` is the model for testing the expiry
    boundary itself, which it does in offsets from a clock it owns."""
    return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


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
    patch this themselves; a later monkeypatch wins.

    Set via ENV VAR rather than by patching the function, because several
    tests drive a real `git commit` through an installed hook and the gate
    then runs in a SPAWNED process (git -> sh shim -> interpreter ->
    `aramid check`). A monkeypatch in the pytest process cannot reach that
    child: it would resolve the real ~/.aramid/tools and the test's
    PATH-scrubbing would stop simulating a missing tool. That is exactly how
    test_windows_hooks' fail-open assertion broke. An env var is inherited
    all the way down the chain."""
    monkeypatch.setenv(toolpath.TOOLS_DIR_ENV, str(tmp_path / "aramid-tools"))


@pytest.fixture(autouse=True)
def _isolated_user_config(tmp_path, monkeypatch):
    """Keep `config.load_config` off the real `~/.aramid/config.toml`.

    `load_config` layers `_user_config_path()` (`Path.home() / ".aramid" /
    "config.toml"`) over the packaged defaults before the repo's own
    aramid.toml. Same class as the three fixtures above: a developer machine
    that happens to have a real ~/.aramid/config.toml (e.g. one that sets
    `[tests]`/`test_command` for unrelated reasons) would silently change
    what every `load_config(...)`-calling test sees, while CI -- which has
    no such file -- would keep reporting green. `doctor` (T-2) is the first
    caller of `load_config` these doctor tests exercise, but every other
    `cmd_*` entry point already calls it too, so this protects the whole
    suite, not just the new tests, exactly like the tools-dir fixture
    protects more than just the tests that added it.

    Point at a path that does not exist (matching `probe_tool`'s own
    "not found" contract) rather than an empty file -- `load_config` already
    treats a missing user config as "no override", so this reproduces
    today's typical clean-machine behavior instead of inventing a new one."""
    monkeypatch.setattr(config, "_user_config_path",
                        lambda: tmp_path / "no-such-user-config.toml")


@pytest.fixture
def checkout_env() -> dict[str, str]:
    """`os.environ` with the aramid THIS process imported first on PYTHONPATH.

    For any test that spawns `python -m aramid`, or anything that reaches it
    (a git hook, a shim). `pythonpath = ["src"]` in pyproject is a pytest ini
    setting: it shapes this process's `sys.path`, and a child inherits none of
    it. On a machine running the two-aramid separation (RELEASING.md, "Two
    aramids share this machine") a bare child therefore resolves the INSTALLED
    WHEEL -- a different program from the one under test. Measured 2026-08-26:
    the parent had imported `src/aramid`; the child printed
    `site-packages/aramid`. CI never sees this, because CI installs `-e` and
    a bare child finds the checkout by accident of the install mode. The
    local pre-push gate, which runs this suite, is exactly where it lands.

    Derived from `aramid.__file__` rather than a hardcoded `src` so the child
    is bound to whatever the parent actually imported (test_version.py's
    rationale: a perturbation run pointed at a scratch tree stays honest).
    PREPENDED, not assigned: the product's own `run_subprocess` prepends for
    the same reason -- assigning would drop whatever the developer's
    environment needed (tests/unit/test_worktree_import_env.py).

    Returned as a NEW dict. Editing os.environ in place would bind every later
    child in the session, including the product's own gate subprocesses,
    whose tests assert what THEY prepend. Binding is explicit, per call site.
    Guarded by tests/unit/test_checkout_env.py.
    """
    src_root = Path(aramid.__file__).resolve().parent.parent
    env = dict(os.environ)
    prior = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(src_root) + (os.pathsep + prior if prior else "")
    return env
