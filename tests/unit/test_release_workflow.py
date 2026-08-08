"""The bytes PyPI receives must be the bytes the gates inspected.

`release` runs four integrity gates against specific files in `dist/` -- twine
check, the packaged-data-file check, a clean-venv wheel smoke test and a
clean-venv sdist smoke test. `publish-pypi` used to do a fresh `actions/checkout`
and `python -m build`, discarding every inspected artifact and uploading newly
produced bytes. `needs: release` ordered the jobs and proved nothing about what
actually reached PyPI.

The rationale in the workflow at the time -- "an artifact round-trip is one more
place the bytes could differ ... and the build is deterministic from the tag" --
had it backwards. An artifact transfers the EXACT inspected bytes; a rebuild
manufactures new ones no gate ever saw, and determinism was an assumption rather
than an enforced control. It also let the GitHub Release and PyPI carry
different artifacts under the same version, on two public channels, with PyPI
unable to be re-uploaded once a version is taken.

Structural on purpose, like test_workflow_pinning: asserting a digest or a step
count would fail on every legitimate edit and teach the next person to update
the expected value, which is how a guard becomes decoration. What is pinned here
is the property -- publish consumes, never rebuilds.
"""
from pathlib import Path

import yaml

_BUILD_MARKERS = ("python -m build", "pip install build", "pyproject-build")


def _workflow() -> dict:
    p = (Path(__file__).resolve().parents[2] / ".github" / "workflows"
         / "release.yml")
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def _steps(job: str) -> list[dict]:
    return _workflow()["jobs"][job]["steps"]


def _uses(steps: list[dict], prefix: str) -> list[dict]:
    return [s for s in steps if str(s.get("uses", "")).startswith(prefix)]


def test_the_guard_can_actually_see_both_jobs():
    """Non-vacuity first. If the file moves or the job names change, every
    assertion below passes against empty lists -- a guard reporting success
    for a reason indistinguishable from a real pass."""
    jobs = _workflow()["jobs"]
    assert "release" in jobs and "publish-pypi" in jobs, f"jobs: {list(jobs)}"
    assert _steps("release"), "release job has no steps"
    assert _steps("publish-pypi"), "publish-pypi job has no steps"


def test_publish_pypi_does_not_rebuild_the_artifact():
    """The defect this file exists for. A rebuild here uploads bytes that none
    of the four gates in `release` inspected."""
    offenders = [
        (s.get("name") or s.get("uses") or "<step>", marker)
        for s in _steps("publish-pypi")
        for marker in _BUILD_MARKERS
        if marker in str(s.get("run", ""))
    ]
    assert not offenders, (
        "publish-pypi builds its own artifact, so PyPI would receive bytes no "
        f"gate inspected: {offenders}. Download the `release` job's uploaded "
        "distribution instead -- PyPI cannot be re-uploaded.")


def test_publish_pypi_consumes_the_distribution_release_uploaded():
    """`needs:` orders the jobs; only a matching artifact name connects the
    bytes. A typo in either name would silently publish nothing, or publish
    something else."""
    uploads = _uses(_steps("release"), "actions/upload-artifact")
    downloads = _uses(_steps("publish-pypi"), "actions/download-artifact")

    assert len(uploads) == 1, f"expected one upload in release, got {len(uploads)}"
    assert len(downloads) == 1, (
        f"expected one download in publish-pypi, got {len(downloads)}")

    up_name = uploads[0].get("with", {}).get("name")
    down_name = downloads[0].get("with", {}).get("name")
    assert up_name and up_name == down_name, (
        f"artifact name mismatch: release uploads {up_name!r}, publish-pypi "
        f"downloads {down_name!r} -- the publish job would find no files")


def test_an_empty_upload_fails_instead_of_publishing_nothing():
    """`if-no-files-found` defaults to `warn`, which would hand the publish job
    an empty directory. A no-op publish that exits green is exactly the
    "success indistinguishable from a check that never ran" shape aramid
    exists to prevent."""
    upload = _uses(_steps("release"), "actions/upload-artifact")[0]
    assert upload.get("with", {}).get("if-no-files-found") == "error", (
        "set `if-no-files-found: error` on the gated-dist upload")
