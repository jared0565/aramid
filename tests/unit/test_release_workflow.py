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


def _needs(job: str) -> list[str]:
    n = _workflow()["jobs"][job].get("needs", [])
    return [n] if isinstance(n, str) else list(n)


def test_the_real_publish_is_gated_on_the_testpypi_rehearsal():
    """PyPI's first upload claims the name permanently and no version can be
    re-uploaded, so this must not be the first time the publish path runs.
    `needs` is what makes the rehearsal a gate rather than a parallel job that
    can fail unnoticed."""
    assert "publish-testpypi" in _workflow()["jobs"], (
        "the TestPyPI rehearsal job is gone -- RELEASING.md offers a rehearsal "
        "and this job is the only thing that performs one")
    assert "publish-testpypi" in _needs("publish-pypi"), (
        "publish-pypi no longer waits on the rehearsal, so a broken publish "
        f"path would first be discovered against PyPI. needs="
        f"{_needs('publish-pypi')}")


def test_the_rehearsal_publishes_the_same_gated_artifact():
    """A rehearsal against different bytes rehearses nothing."""
    downloads = _uses(_steps("publish-testpypi"), "actions/download-artifact")
    uploads = _uses(_steps("release"), "actions/upload-artifact")

    assert len(downloads) == 1, "the rehearsal must consume the gated artifact"
    assert downloads[0].get("with", {}).get("name") == \
        uploads[0].get("with", {}).get("name")


def test_only_the_rehearsal_may_skip_an_existing_version():
    """TestPyPI also forbids re-uploading a version, so `skip-existing` is what
    lets a re-run of a partially-failed release proceed there. On PyPI the same
    flag would turn a failed publish into a silent no-op that exits green --
    success indistinguishable from a check that never ran."""
    rehearsal = _uses(_steps("publish-testpypi"), "pypa/gh-action-pypi-publish")[0]
    real = _uses(_steps("publish-pypi"), "pypa/gh-action-pypi-publish")[0]

    assert rehearsal["with"]["skip-existing"] is True
    assert real["with"]["skip-existing"] is False, (
        "skip-existing on PyPI makes a failed publish look like a success")


def test_the_rehearsal_targets_testpypi_and_the_real_job_does_not():
    """A missing `repository-url` defaults to real PyPI -- so a typo here does
    not fail, it publishes to production twice."""
    rehearsal = _uses(_steps("publish-testpypi"), "pypa/gh-action-pypi-publish")[0]
    real = _uses(_steps("publish-pypi"), "pypa/gh-action-pypi-publish")[0]

    assert "test.pypi.org" in rehearsal["with"]["repository-url"]
    assert "repository-url" not in real.get("with", {}), (
        "the production job must not carry a repository-url override")


def test_an_empty_upload_fails_instead_of_publishing_nothing():
    """`if-no-files-found` defaults to `warn`, which would hand the publish job
    an empty directory. A no-op publish that exits green is exactly the
    "success indistinguishable from a check that never ran" shape aramid
    exists to prevent."""
    upload = _uses(_steps("release"), "actions/upload-artifact")[0]
    assert upload.get("with", {}).get("if-no-files-found") == "error", (
        "set `if-no-files-found: error` on the gated-dist upload")
