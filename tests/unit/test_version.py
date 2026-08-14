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
import os
import subprocess
import sys
from importlib.metadata import version as distribution_version
from pathlib import Path

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


def test_version_flag_prints_the_real_version():
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
    silently redirected back to the checkout.
    """
    src_root = Path(aramid.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(src_root)}
    out = subprocess.run([sys.executable, "-m", "aramid", "--version"],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    printed = out.stdout.strip()
    assert printed == f"aramid {aramid.__version__}", printed


def test_installed_metadata_matches_dunder_version():
    """Proves the `dynamic = ["version"]` wiring resolves. If the attr
    reference breaks, setuptools falls back to a different string and the
    published wheel disagrees with the code inside it.

    Compared as PARSED versions, not strings: setuptools normalises what it
    writes into the metadata, so `0.1.0-rc1` in the source legitimately becomes
    `0.1.0rc1` in the wheel. A string comparison would call that a drift.

    NOTE for a local failure: the metadata is recorded at BUILD time, so this
    legitimately goes red after bumping `__version__` until it is regenerated.
    In CI the install is always fresh.

    THE REMEDY IS NOT `pip install -e .`, though this docstring used to say so
    and RELEASING.md's step 2 still did. That command collapses the two-aramid
    separation -- every consumer repo on the machine silently starts running
    this uncommitted working tree -- and RELEASING.md's own "Never `pip install
    -e .` in this repo" section forbids the thing its step 2 required. Regenerate
    the metadata in place instead, which writes only to the gitignored
    `src/aramid.egg-info` and never to site-packages:

        python -c "from setuptools import setup; setup()" egg_info --egg-base src

    Under `pythonpath = ["src"]` that egg-info is what `importlib.metadata`
    resolves, so this guard compares the checkout against the checkout -- which
    is the wiring it exists to prove -- rather than against whichever wheel
    happens to be installed.
    """
    installed = distribution_version("aramid")
    assert _parse(installed) == _parse(aramid.__version__), (
        f"distribution metadata says {installed!r} but aramid.__version__ is "
        f"{aramid.__version__!r} -- if you just bumped the version, regenerate "
        "the metadata with: python -c \"from setuptools import setup; setup()\" "
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
