"""Release-correctness guards on the version string.

`aramid.__version__` is the SINGLE source of truth: `pyproject.toml` declares
`dynamic = ["version"]` and reads the attribute, so the two cannot drift. These
guard the wiring, because the failure is silent and only visible after
shipping -- a wheel whose metadata says one version while `--version` prints
another.

WHY PEP 440 AND NOT SEMVER. The first version of this file validated a strict
semver shape with a hand-written regex, which made a RELEASE CANDIDATE
impossible to express -- both spellings broke a guard:

    __version__ = "0.1.0-rc1"   semver-shaped, but setuptools NORMALISES it to
                                0.1.0rc1 in the wheel, so the metadata guard
                                below failed on a mismatch that was not real
    __version__ = "0.1.0rc1"    what setuptools actually produces, but the
                                semver regex rejected it outright

Python packaging is PEP 440, not semver, so the guards now use
`packaging.version.Version` -- the same normalisation setuptools and pip apply.
`0.1.0-rc1` and `0.1.0rc1` compare EQUAL, which is the whole point.

PEP 440 accepts two-component versions like "0.1", so the release tuple is
checked explicitly for MAJOR.MINOR.PATCH.
"""
import json
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import url2pathname

import pytest
from packaging.version import InvalidVersion, Version

import aramid


def _parse(raw: str) -> Version:
    try:
        return Version(raw)
    except InvalidVersion as exc:  # pragma: no cover - only on a bad bump
        pytest.fail(f"{raw!r} is not a valid PEP 440 version: {exc}")


def test_dunder_version_is_pep440_with_a_full_release_tuple():
    parsed = _parse(aramid.__version__)
    assert len(parsed.release) == 3, (
        f"__version__ is {aramid.__version__!r}, whose release tuple is "
        f"{parsed.release} -- want MAJOR.MINOR.PATCH")


def test_version_flag_prints_the_real_version(checkout_env):
    """The original form of this test asserted only that stdout started with
    'aramid ', despite being named ...prints_semver -- it would have passed on
    `aramid banana`.

    THE SUBPROCESS IS PINNED TO THE CHECKOUT, and that is load-bearing on any
    machine running the two-aramid separation (RELEASING.md, "Two aramids share
    this machine"). `pythonpath = ["src"]` is a pytest ini setting: it shapes
    THIS process's `sys.path` and a child process inherits none of it. So a
    bare `python -m aramid` here resolves the INSTALLED wheel -- a different
    program from the one under test -- and this assertion silently became
    "does the live tool's version equal the checkout's version".

    That comparison passed for as long as the two happened to agree, and went
    red the moment `__version__` was bumped to cut a release: the first bump
    after the separation was built. The failure was real but it was not the
    failure this test names -- nothing was wrong with the CLI wiring.

    Deriving PYTHONPATH from `aramid.__file__` rather than hardcoding `src`
    keeps the child bound to whatever aramid the parent actually imported, so a
    perturbation run pointed at a scratch tree stays honest instead of being
    silently redirected back to the checkout. That derivation now lives in the
    `checkout_env` fixture (tests/conftest.py) shared by every subprocess test:
    it PREPENDS rather than assigns, and pairs with `-P` so the child's cwd
    cannot shadow the package it was just bound to.
    """
    out = subprocess.run([sys.executable, "-P", "-m", "aramid", "--version"],
                         capture_output=True, text=True, env=checkout_env)
    assert out.returncode == 0, out.stderr
    printed = out.stdout.strip()
    assert printed == f"aramid {aramid.__version__}", printed


def _distribution_of_the_imported_tree():
    """The installed distribution that DESCRIBES the `aramid` this process
    imported, or None when the one `importlib.metadata` answers with is some
    other copy.

    `distribution("aramid")` returns whichever metadata comes first on
    sys.path. In this checkout that is the regenerated, gitignored
    `src/aramid.egg-info`, and the comparison below is the checkout against
    the checkout -- the wiring the test exists to prove. In a FRESH WORKTREE
    there is no egg-info, so it answers with the promoted wheel in
    site-packages, and the test silently becomes "does the live tool's
    version equal this tree's". That is not a property of the code: it flips
    at every promotion, and on 2026-08-28 it turned the mutation consumer's
    baseline red for a whole release window (three drains, 1452 passed, this
    one test failed) -- a yield loss nothing reported. Same class as the
    `--version` subprocess test above, one layer down.

    A distribution describes the imported tree when its metadata sits beside
    the package (egg-info next to `src/aramid`, or a dist-info next to the
    package it installed), or when it is an editable install whose recorded
    source directory contains the imported file -- the CI shape, and the only
    leg that exercises that branch (`test_the_real_probe_answers_in_shape`
    carries the same note)."""
    try:
        dist = distribution("aramid")
    except PackageNotFoundError:
        return None
    imported = Path(aramid.__file__).resolve()
    beside = Path(str(dist.locate_file("aramid/__init__.py"))).resolve()
    if beside == imported:
        return dist
    text = dist.read_text("direct_url.json")
    if not text:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not data.get("dir_info", {}).get("editable"):
        return None
    url = data.get("url", "")
    if not url.startswith("file:"):
        return None
    source = Path(url2pathname(urlparse(url).path)).resolve()
    return dist if imported.is_relative_to(source) else None


class _FakeDist:
    """Just enough of `importlib.metadata.Distribution` for the belongs-to
    question: where its package would sit, and its direct_url.json."""
    version = "9.9.9"

    def __init__(self, package_root: Path, direct_url: str | None):
        self._root = package_root
        self._direct_url = direct_url

    def locate_file(self, rel):
        return self._root / rel

    def read_text(self, name):
        return self._direct_url if name == "direct_url.json" else None


def _imported_root() -> Path:
    return Path(aramid.__file__).resolve().parents[1]      # .../src


def test_an_editable_install_of_this_tree_describes_it(monkeypatch, tmp_path):
    """The CI shape: dist-info in site-packages (so `locate_file` points
    somewhere the package is NOT), and a direct_url.json naming this tree as
    the editable source. Must count as describing the imported aramid, or CI
    would skip the only comparison that runs against a fresh install."""
    checkout = _imported_root().parent
    fake = _FakeDist(tmp_path / "site-packages",
                     json.dumps({"url": checkout.as_uri(),
                                 "dir_info": {"editable": True}}))
    monkeypatch.setattr(sys.modules[__name__], "distribution", lambda name: fake)

    assert _distribution_of_the_imported_tree() is fake


def test_an_editable_install_of_some_other_clone_does_not(monkeypatch, tmp_path):
    """Editable, but of a different checkout: the version it carries says
    nothing about this tree. None -> the guard skips rather than comparing
    two unrelated trees."""
    other = tmp_path / "other-clone"
    other.mkdir()
    fake = _FakeDist(tmp_path / "site-packages",
                     json.dumps({"url": other.as_uri(), "dir_info": {"editable": True}}))
    monkeypatch.setattr(sys.modules[__name__], "distribution", lambda name: fake)

    assert _distribution_of_the_imported_tree() is None


def test_a_wheel_somewhere_else_does_not_describe_this_tree(monkeypatch, tmp_path):
    """The fresh-worktree shape that turned the mutation baseline red: the
    promoted wheel in site-packages answers, with no direct_url at all."""
    fake = _FakeDist(tmp_path / "site-packages", None)
    monkeypatch.setattr(sys.modules[__name__], "distribution", lambda name: fake)

    assert _distribution_of_the_imported_tree() is None


def test_installed_metadata_matches_dunder_version():
    """Proves the `dynamic = ["version"]` wiring resolves for the tree this
    process imported. If the attr reference breaks, setuptools falls back to
    a different string and the metadata disagrees with the code beside it.

    Compared as PARSED versions, not strings: setuptools normalises what it
    writes, so `0.1.0-rc1` in the source legitimately becomes `0.1.0rc1`.

    SKIPS, with the two paths named, when `importlib.metadata` answers for a
    different aramid than the one imported -- see
    `_distribution_of_the_imported_tree`. The built artifact is guarded where
    it can be compared with the tree it was built from:
    tests/e2e/test_wheel_packaging.py.

    For a local failure: the metadata is recorded when the egg-info is
    generated, so this legitimately goes red after bumping `__version__`
    until it is regenerated -- in place, never via `pip install -e .`, which
    collapses the two-aramid separation (RELEASING.md):

        python -c 'from setuptools import setup; setup()' egg_info --egg-base src
    """
    dist = _distribution_of_the_imported_tree()
    if dist is None:
        answered = distribution("aramid")
        pytest.skip(
            f"importlib.metadata answers for {answered.locate_file('')} "
            f"({answered.version}), not the imported tree at {aramid.__file__}; "
            "the built artifact is guarded by tests/e2e/test_wheel_packaging.py")
    installed = dist.version
    assert _parse(installed) == _parse(aramid.__version__), (
        f"distribution metadata says {installed!r} but aramid.__version__ is "
        f"{aramid.__version__!r} -- if you just bumped the version, regenerate "
        "the metadata with: python -c 'from setuptools import setup; setup()' "
        "egg_info --egg-base src   (NOT `pip install -e .`, see RELEASING.md)")


@pytest.mark.parametrize("source, packaged", [
    ("0.1.0", "0.1.0"),
    ("0.1.0-rc1", "0.1.0rc1"),      # the case that used to be unexpressible
    ("0.1.0rc1", "0.1.0rc1"),
    ("1.2.3-beta.1", "1.2.3b1"),
    ("2.0.0.dev1", "2.0.0.dev1"),
])
def test_prerelease_spellings_survive_setuptools_normalisation(source, packaged):
    """Regression guard for the trap this file used to contain: a release
    candidate must be expressible. `source` is what a maintainer writes in
    `__version__`; `packaged` is what setuptools puts in the wheel. They must
    compare equal, or cutting an RC fails the metadata guard for no real
    reason."""
    assert _parse(source) == _parse(packaged)
    assert len(_parse(source).release) == 3


@pytest.mark.parametrize("bad", ["0.1", "1", "banana", ""])
def test_malformed_versions_are_rejected(bad):
    """The guard must still have teeth -- proving it accepts RCs is only half
    the job if it now accepts anything."""
    try:
        parsed = Version(bad)
    except InvalidVersion:
        return  # rejected outright, which is the desired outcome
    assert len(parsed.release) != 3, f"{bad!r} should not pass as MAJOR.MINOR.PATCH"
