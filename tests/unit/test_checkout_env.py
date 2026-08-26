"""`checkout_env` (tests/conftest.py) is what binds a test's child process to
THIS checkout instead of to the installed wheel.

`pythonpath = ["src"]` in pyproject is a pytest ini setting: it shapes the
pytest process's `sys.path`, and a child inherits none of it. On a machine
running the two-aramid separation (RELEASING.md, "Two aramids share this
machine") a bare `python -m aramid` child therefore resolves the INSTALLED
WHEEL -- a different program from the one under test. Measured 2026-08-26:
the parent had imported `src/aramid`, the child printed `site-packages/aramid`.

The false green that produces has a specific shape. A subprocess test for a
NEW CLI flag that asserts exit 3 for mutual exclusion passes against a wheel
that rejects the flag as UNKNOWN -- also exit 3 -- and the assertion is
satisfied by the wrong program for the wrong reason. CI never sees it: CI
installs `-e`, so a bare child finds the checkout by accident of the install
mode. The local pre-push gate, which runs this suite, is exactly where it
lands. `tests/integration/test_cli_dispatch.py` carried this for a release.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

import aramid

PARENT = Path(aramid.__file__).resolve()
PROBE = "import aramid; print(aramid.__file__)"


def _child_import(env: dict) -> Path:
    out = subprocess.run([sys.executable, "-P", "-c", PROBE],
                         env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return Path(out.stdout.strip()).resolve()


def test_a_child_imports_the_same_aramid_as_the_parent(checkout_env):
    """The property every subprocess test relies on. Asserted as file
    IDENTITY, not version: the checkout and the wheel share a version string
    between a release and the next bump, which is precisely when `--version`
    cannot tell them apart."""
    assert _child_import(checkout_env) == PARENT


def test_on_a_two_aramid_machine_the_bare_child_is_a_different_program(checkout_env):
    """The CONTROL for the identity test above, which passes trivially wherever
    a bare child would have found the checkout anyway (an editable install --
    CI). Strip the fixture and look at what the machine resolves on its own:
    if it is a different file, the fixture was load-bearing and the identity
    test has teeth here. If it is the same file, the identity test is VACUOUS
    on this machine -- reported as a skip that says so, never as a pass."""
    bare = dict(os.environ)
    bare.pop("PYTHONPATH", None)
    resolved = _child_import(bare)
    if resolved == PARENT:
        pytest.skip("a bare child already resolves this checkout (editable "
                    "install?) -- the identity test is vacuous on this machine")
    assert resolved != PARENT
    assert _child_import(checkout_env) == PARENT, (
        "the fixture did not override what the machine resolves on its own")


def test_the_fixture_prepends_rather_than_clobbers(monkeypatch, request):
    """`run_subprocess` prepends for the same reason (tests/unit/
    test_worktree_import_env.py): assigning PYTHONPATH outright would silently
    drop whatever the developer's environment needed."""
    monkeypatch.setenv("PYTHONPATH", "/already/here")
    env = request.getfixturevalue("checkout_env")
    parts = env["PYTHONPATH"].split(os.pathsep)
    assert parts[0] == str(PARENT.parent.parent), parts
    assert "/already/here" in parts, "clobbered the caller's PYTHONPATH"


def test_with_no_prior_pythonpath_there_is_no_dangling_separator(monkeypatch, request):
    """An empty trailing entry is the CWD on every platform -- exactly the
    entry `-P` exists to remove, reintroduced by a formatting slip."""
    monkeypatch.delenv("PYTHONPATH", raising=False)
    env = request.getfixturevalue("checkout_env")
    assert env["PYTHONPATH"] == str(PARENT.parent.parent)


def test_the_fixture_does_not_mutate_the_parent(request):
    """A fixture that edited os.environ in place would bind EVERY later child
    -- including the product's own gate subprocesses, whose tests assert
    what THEY prepend. Explicit per-site binding is the contract."""
    before = os.environ.get("PYTHONPATH")
    env = request.getfixturevalue("checkout_env")
    assert os.environ.get("PYTHONPATH") == before, "the fixture edited os.environ"
    assert env["PYTHONPATH"] != before
