"""The built WHEEL contains every data file aramid loads at runtime.

WHY THIS IS AN E2E TEST AND NOT A CI STEP. It was a CI step -- three literal
paths, unzipped and checked -- which meant the only way to learn that a data
file had fallen out of the wheel was to push and wait for the matrix. Packaging
is environment-independent: nothing about it needs seven legs to discover, so
it belongs where a developer finds out in the same run that would have told
them anything else.

WHY THE EXPECTED LIST IS DERIVED, NOT WRITTEN DOWN. The CI step named
`block_rules.toml`, `defaults.toml` and `owasp.yml` literally. A hand-kept list
of "files that must ship" is the exact shape that goes stale silently: add a
fourth data file, forget the list, and it is missing from the wheel with
nothing failing. This walks the SAME globs `pyproject.toml` declares as
package-data, so a new data file joins the EXPECTED side the moment it exists.

WHAT THIS DOES AND DOES NOT CATCH -- measured, not assumed, because the first
version of this docstring claimed more than the test delivers. Three
perturbations were applied to `pyproject.toml`, each asserted to have actually
landed before building:

    rules/*.yml removed from package-data          -> owasp.yml STILL in wheel
    package-data reduced to data/*.toml            -> owasp.yml STILL in wheel
    include-package-data = false, glob removed too -> owasp.yml STILL in wheel

So under this build backend every file physically under `src/aramid/` ships
regardless of the package-data configuration, and the globs are close to
decorative. That is worth knowing about the CI step this replaces: **it could
not fail via the configuration it appears to be guarding.**

What is left is still worth the ~15 s. This asserts the END STATE of the
shipped artifact, so it catches the regressions that would actually bite -- a
data file moved or renamed out of the package directory, or a change of build
backend or layout -- and it catches them in the same local run that reports
everything else, instead of one matrix round-trip later. For a tool like this
the stakes are concrete: `rules/owasp.yml` is loaded by path at runtime, so a
wheel missing it installs cleanly, starts cleanly, and silently cannot run its
own security rules.
"""
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PKG = REPO / "src" / "aramid"

# Kept in step with [tool.setuptools.package-data] in pyproject.toml. Asserted
# against that file below rather than trusted, because two lists that must
# agree and are never compared are one edit away from disagreeing.
DATA_GLOBS = ("data/*.toml", "data/*.tmpl", "rules/*.yml")


def _expected_members() -> set[str]:
    out = set()
    for pattern in DATA_GLOBS:
        for path in sorted(PKG.glob(pattern)):
            out.add(f"aramid/{path.relative_to(PKG).as_posix()}")
    return out


def test_the_glob_list_here_matches_the_one_pyproject_declares():
    """Keeps the EXPECTED side complete. If pyproject grows a package-data
    pattern this file does not know about, the wheel test below keeps passing
    while checking a subset -- covered-looking and not covered.

    Note what this is NOT: the globs turned out not to control what ships (see
    the module docstring's measurements), so this guards the completeness of
    the expectation, not the correctness of the packaging."""
    import tomllib

    declared = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = declared["tool"]["setuptools"]["package-data"]["aramid"]

    assert sorted(patterns) == sorted(DATA_GLOBS), (
        "pyproject's package-data globs changed; update DATA_GLOBS so this "
        f"test keeps checking all of them: {patterns}")


def test_every_packaged_data_file_is_present_in_the_built_wheel(tmp_path):
    expected = _expected_members()
    assert expected, "no data files matched the globs -- the test would be vacuous"

    build = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path)],
        cwd=REPO, capture_output=True, text=True)
    if build.returncode != 0:
        pytest.fail("wheel build failed:\n"
                    f"{build.stdout[-2000:]}\n{build.stderr[-2000:]}")

    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
    with zipfile.ZipFile(wheels[0]) as zf:
        members = set(zf.namelist())

    missing = sorted(expected - members)
    assert not missing, (
        f"data files declared in pyproject are absent from the wheel: {missing}. "
        "aramid loads these by path at runtime, so the installed package would "
        "start cleanly and be unable to do its job.")
