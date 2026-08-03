"""Release-correctness guards on the version string.

`aramid.__version__` is the SINGLE source of truth: `pyproject.toml` declares
`dynamic = ["version"]` and reads the attribute, so the two cannot drift. These
guard the wiring, because the failure is silent and only visible after
shipping -- a wheel whose metadata says one version while `--version` prints
another.

Both are REGRESSION GUARDS, not red-first tests: the values agree today, so
neither could fail on arrival. They were proven to have teeth by mutation
instead -- see the commit that added them.
"""
import re
import subprocess
import sys
from importlib.metadata import version as distribution_version

import aramid

# PEP 440 / semver core: MAJOR.MINOR.PATCH with an optional pre-release or
# build suffix. Deliberately anchored -- "0.1" and "1.0.0.0" must fail.
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]+)?$")


def test_dunder_version_is_semver_shaped():
    assert _SEMVER.match(aramid.__version__), (
        f"__version__ is {aramid.__version__!r}, which is not MAJOR.MINOR.PATCH")


def test_version_flag_prints_the_real_version():
    """The old form of this test asserted only that stdout started with
    'aramid ', despite being named ...prints_semver -- it would have passed on
    `aramid banana`. Assert the actual string, and its shape."""
    out = subprocess.run([sys.executable, "-m", "aramid", "--version"],
                         capture_output=True, text=True)
    assert out.returncode == 0
    printed = out.stdout.strip()
    assert printed == f"aramid {aramid.__version__}", printed
    assert _SEMVER.match(printed.split(" ", 1)[1]), printed


def test_installed_metadata_matches_dunder_version():
    """Proves the `dynamic = ["version"]` wiring actually resolves. If the
    attr reference breaks, setuptools falls back to a different string and the
    published wheel disagrees with the code inside it.

    NOTE for a local failure: an editable install records metadata at install
    time, so this legitimately goes red after bumping `__version__` until
    `pip install -e .` is re-run. In CI the install is always fresh.
    """
    assert distribution_version("aramid") == aramid.__version__, (
        f"distribution metadata says {distribution_version('aramid')!r} but "
        f"aramid.__version__ is {aramid.__version__!r} -- if you just bumped "
        "the version, re-run `pip install -e .`")
