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
import subprocess
import sys
from importlib.metadata import version as distribution_version

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
    `aramid banana`."""
    out = subprocess.run([sys.executable, "-m", "aramid", "--version"],
                         capture_output=True, text=True)
    assert out.returncode == 0
    printed = out.stdout.strip()
    assert printed == f"aramid {aramid.__version__}", printed


def test_installed_metadata_matches_dunder_version():
    """Proves the `dynamic = ["version"]` wiring resolves. If the attr
    reference breaks, setuptools falls back to a different string and the
    published wheel disagrees with the code inside it.

    Compared as PARSED versions, not strings: setuptools normalises what it
    writes into the metadata, so `0.1.0-rc1` in the source legitimately becomes
    `0.1.0rc1` in the wheel. A string comparison would call that a drift.

    NOTE for a local failure: an editable install records metadata at install
    time, so this legitimately goes red after bumping `__version__` until
    `pip install -e .` is re-run. In CI the install is always fresh. See
    RELEASING.md -- that reinstall is a required release step, because the
    pre-push gate runs this suite.
    """
    installed = distribution_version("aramid")
    assert _parse(installed) == _parse(aramid.__version__), (
        f"distribution metadata says {installed!r} but aramid.__version__ is "
        f"{aramid.__version__!r} -- if you just bumped the version, re-run "
        "`pip install -e .`")


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
