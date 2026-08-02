"""Tests for the shared adapter helpers in `aramid.runners._util`.

The path-normalisation case here is deliberately platform-independent: it
drives `relativize` with POSIX path semantics regardless of the host, because
the bug it pins was invisible on Windows and reddened every POSIX CI leg.
"""
from pathlib import PurePosixPath, PureWindowsPath

import pytest

from aramid.runners import _util


# ------------------------------------------------------------ relativize ---

@pytest.mark.parametrize("flavour", [PurePosixPath, PureWindowsPath],
                         ids=["posix", "windows"])
def test_relativize_normalises_backslashes_on_every_platform(flavour, monkeypatch):
    """A Windows-captured tool report must yield a forward-slash pathspec even
    when it is parsed on POSIX.

    `relativize` used to delegate separator handling to `Path`, which is the
    one thing that is NOT portable: `\\` is a separator on Windows but a legal
    FILENAME CHARACTER on POSIX, so `PurePosixPath("src\\main.rs").as_posix()`
    returns the backslash untouched. The result was a helper that honoured its
    own docstring on the maintainer's Windows box and silently violated it
    everywhere else -- `RawFinding.file` is fed straight to
    `git show <ref>:<path>`, which needs forward slashes on every platform.

    Caught by CI, not locally: clippy's fixture is a Windows capture, so
    `tests/unit/test_runner_clippy.py` failed on all four ubuntu legs and
    macos while every windows leg passed.

    Parametrised over both flavours so neither platform can regress alone.
    """
    monkeypatch.setattr(_util, "Path", flavour)

    got = _util.relativize("src\\main.rs", flavour("/repo"))

    assert got == "src/main.rs"
    assert "\\" not in got


def test_relativize_leaves_forward_slash_paths_alone(monkeypatch):
    """The common case (every POSIX-native tool) must be untouched by the fix."""
    monkeypatch.setattr(_util, "Path", PurePosixPath)

    assert _util.relativize("src/main.rs", PurePosixPath("/repo")) == "src/main.rs"


def test_relativize_strips_the_root_prefix_from_an_absolute_path(monkeypatch):
    """The documented primary job -- root-relative output -- still holds."""
    monkeypatch.setattr(_util, "Path", PurePosixPath)

    got = _util.relativize("/repo/src/main.rs", PurePosixPath("/repo"))

    assert got == "src/main.rs"


def test_relativize_falls_back_to_the_original_when_not_under_root(monkeypatch):
    """Outside root, `relative_to` raises ValueError and the helper degrades to
    the slash-normalised original rather than propagating."""
    monkeypatch.setattr(_util, "Path", PurePosixPath)

    got = _util.relativize("/elsewhere/src/main.rs", PurePosixPath("/repo"))

    assert got == "/elsewhere/src/main.rs"
