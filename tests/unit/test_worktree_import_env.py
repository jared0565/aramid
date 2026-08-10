"""The mechanism that makes a worktree run exercise the WORKTREE's source.

WHY THIS FILE EXISTS. `red_proof._base_import_env` was written for `f462d27`
("force the base run to import base source, not the install") after the
red-first producer was found to be INVERTED: without it, a base-tree pytest run
imports whatever is already installed, and under a pip editable install that is
the live source the push is changing. Every genuinely red-first test passed the
base run and was reported "never red".

It had **one caller and zero tests**. That is the gap this closes, and it is
not academic -- `consumers/mutation.py` ran three worktree subprocesses with no
env at all, so a mutant written into the worktree was never the code under
test. Same bug, same repo, fixed in one module and left armed in the other.

WHAT MAKES THESE TESTS DISCRIMINATING. "The worktree run completed" is true
with or without the env, so asserting it proves nothing about which source tree
was loaded. These build a real src-layout package in a temp directory and make
the ASSERTION ITSELF depend on the answer: the package is importable only if
something put `<root>/src` on the path. A src-layout package is never reached
by pytest's own cwd insertion -- the package sits at `<root>/src/<pkg>`, not
`<root>/<pkg>` -- which is precisely why the installed copy wins outright when
the env is missing.
"""
import sys

from aramid.runners.base import run_subprocess, worktree_import_env

_TIMEOUT_S = 180.0


def _src_layout_repo(root):
    """A minimal src-layout project whose test passes ONLY if `<root>/src` is
    importable. No install, no .pth, nothing on sys.path by default."""
    pkg = root / "src" / "widget"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("VALUE = 'from-the-worktree'\n",
                                     encoding="utf-8")
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_value.py").write_text(
        "from widget import VALUE\n\n\n"
        "def test_value():\n"
        "    assert VALUE == 'from-the-worktree'\n",
        encoding="utf-8")
    return root


def test_a_src_layout_package_is_unreachable_without_the_env(tmp_path):
    """THE FAILURE THIS PREVENTS, demonstrated rather than asserted.

    Run from the project root with no env, pytest cannot import `widget` at
    all: cwd insertion puts `<root>` on the path, and the package is at
    `<root>/src/widget`. Collection fails. In a REAL worktree this does not
    fail -- it silently succeeds against the INSTALLED copy, which is the
    live tree, and that is the whole defect. Here there is no installed copy
    to fall back to, so the same missing path surfaces loudly instead.
    """
    root = _src_layout_repo(tmp_path)
    res = run_subprocess([sys.executable, "-m", "pytest", "-q"],
                         root, _TIMEOUT_S)
    assert res.returncode != 0, (
        "the worktree's own src/ was importable with no PYTHONPATH -- if this "
        "starts passing, pytest's path insertion changed and the premise "
        "behind worktree_import_env needs re-deriving, not this test relaxing")


def test_the_env_makes_the_worktree_source_importable(tmp_path):
    """And the fix, on the identical tree."""
    root = _src_layout_repo(tmp_path)
    res = run_subprocess([sys.executable, "-m", "pytest", "-q"],
                         root, _TIMEOUT_S, env=worktree_import_env(root))
    assert res.returncode == 0, (
        f"worktree source still not importable with the env applied.\n"
        f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")


def test_it_prepends_and_never_replaces_an_existing_pythonpath(monkeypatch, tmp_path):
    """`run_subprocess` merges this over `os.environ`, so ASSIGNING PYTHONPATH
    would silently drop whatever the developer's environment already puts
    there and break imports the worktree run legitimately needs."""
    monkeypatch.setenv("PYTHONPATH", "/already/here")
    env = worktree_import_env(tmp_path)
    parts = env["PYTHONPATH"].split(";" if sys.platform == "win32" else ":")
    assert parts[0] == str(tmp_path / "src")
    assert parts[1] == str(tmp_path)
    assert "/already/here" in parts, "clobbered the caller's PYTHONPATH"
    assert parts.index("/already/here") > 1, "existing entry must not win"


def test_both_layouts_are_covered(tmp_path):
    """`<wt>/src` for src-layout and `<wt>` for flat-layout. A path that does
    not exist is simply inert on sys.path, so offering both costs nothing."""
    env = worktree_import_env(tmp_path)
    parts = env["PYTHONPATH"].split(";" if sys.platform == "win32" else ":")
    assert str(tmp_path / "src") in parts
    assert str(tmp_path) in parts
