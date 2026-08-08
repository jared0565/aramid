"""The PyPI page is a published artifact, and nothing else checks it.

Until this landed, `[project]` carried name, version, requires-python and
dependencies -- and nothing else. `twine check` said `long_description
missing`: publishing would have produced a package page with **no description
at all**, and no test, no gate and no CI step would have objected. The wheel
was verified to contain its data files; what it says about itself was never
verified at all.

These are cheap parse-level assertions on purpose. `twine check` is the real
render test and now runs in release.yml, but it needs a build; these fail in
milliseconds, in the suite the pre-push gate actually runs.
"""
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _pyproject() -> dict:
    return tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))


def _project() -> dict:
    return _pyproject()["project"]


def test_the_pypi_page_would_not_be_blank():
    """`description` is the one-line summary in search results; `readme`
    becomes long_description, the page body. Without them the listing is a
    bare name and version."""
    proj = _project()

    assert proj.get("description"), "no `description` -- search results show nothing"
    assert proj.get("readme"), "no `readme` -- the package page body would be empty"
    assert (REPO / proj["readme"]).is_file()


def test_the_page_links_back_to_the_project():
    urls = _project().get("urls") or {}

    assert urls, "no [project.urls] -- the page offers no way back to the source"
    assert any(k.lower() in ("homepage", "repository") for k in urls)


def test_readme_has_no_repo_relative_links():
    """PyPI serves the README detached from the repository, so a relative
    link resolves against pypi.org and 404s. Two did (`docs/user-guide.md`,
    `docs/knowledge-base.md`) -- correct on GitHub, broken on the page."""
    import re

    text = (REPO / _project()["readme"]).read_text(encoding="utf-8")
    links = re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", text)
    relative = [
        link for link in links
        if not link.startswith(("http://", "https://", "#", "mailto:"))
    ]

    assert not relative, (
        "these README links are repo-relative and will 404 on the PyPI page; "
        f"make them absolute github.com URLs: {relative}")


def test_no_license_classifier_alongside_an_spdx_expression():
    """PEP 639: with `license` as an SPDX expression, a `License ::`
    classifier is an ERROR, not a warning -- setuptools refuses to build.
    This one is load-bearing: it broke the build the moment both were
    present, so the guard exists to name the cause rather than leave the next
    person reading a traceback."""
    proj = _project()
    classifiers = proj.get("classifiers") or []

    if isinstance(proj.get("license"), str):
        assert not [c for c in classifiers if c.startswith("License ::")], (
            "remove the `License ::` classifier -- it is superseded by the "
            "SPDX `license` expression and setuptools errors on the pair")


def test_typing_typed_is_only_claimed_if_py_typed_actually_ships():
    """A classifier is a claim on a public page. `Typing :: Typed` asserts the
    package ships type information; without a py.typed marker it is simply
    false, and a consumer's type checker silently gets nothing."""
    classifiers = _project().get("classifiers") or []
    marker = REPO / "src" / "aramid" / "py.typed"

    if "Typing :: Typed" in classifiers:
        assert marker.is_file(), (
            "`Typing :: Typed` is claimed but src/aramid/py.typed does not "
            "exist -- either ship the marker (and its package-data entry) or "
            "drop the classifier")


def test_the_build_backend_floor_supports_the_license_syntax_used():
    """`license = "MIT"` as a bare SPDX string is PEP 639, understood from
    setuptools 77. Declaring a lower floor lets a build resolve a backend that
    cannot parse this file."""
    proj = _project()
    if not isinstance(proj.get("license"), str):
        return

    requires = _pyproject()["build-system"]["requires"]
    setuptools_req = [r for r in requires if r.replace("_", "-").startswith("setuptools")]

    assert setuptools_req, "no setuptools requirement in [build-system]"
    floor = setuptools_req[0].split(">=")[-1].split(",")[0].strip()
    assert int(floor.split(".")[0]) >= 77, (
        f"build-system requires setuptools>={floor}, but the PEP 639 `license` "
        "spelling in this file needs >=77")
