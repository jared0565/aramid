"""Dependency floors that exist because a specific lower version breaks aramid
in a way the gate cannot see coming. Each test names the version it excludes
and why, so a future loosening has to argue with the record rather than with
a bare number."""
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[2]


def _requirement(name: str) -> Requirement:
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    for dep in deps:
        req = Requirement(dep)
        if req.name == name:
            return req
    raise AssertionError(f"{name} is not in [project].dependencies")


def test_semgrep_floor_excludes_the_pkg_resources_generation():
    # semgrep <= 1.136.0 pins opentelemetry-instrumentation-requests ~=0.46b0,
    # whose dependencies.py imports pkg_resources; opentelemetry-instrumentation
    # 0.49b0 (2024-11-05) replaced that with importlib.metadata, and semgrep
    # 1.137.0 is the first release pinning that generation (~=0.58b0). Python
    # 3.13 ships no setuptools, so 1.136.0 crashes on import and every
    # semgrep-backed gate fails with it. Measured on CI run 33767096142
    # (2026-09-03): pip backtracked from 1.176.0 down to 1.136.0 on an
    # opentelemetry conflict, and 13 tests failed on ModuleNotFoundError
    # pkg_resources while the twin run on the same commit, resolving 1.176.0,
    # passed. The floor turns that backtrack into a loud install failure.
    spec = _requirement("semgrep").specifier
    assert not spec.contains("1.136.0"), spec
    assert spec.contains("1.137.0"), spec


# There is deliberately no test for semgrep 1.179.0 any more. It was excluded
# (FN-27) because it first shipped no win_amd64 wheel, so Windows built it from
# sdist without semgrep-core.exe (CI run 36983535922, both Windows legs red).
# Its Windows wheel was uploaded 2026-10-02 19:21Z, and on 2026-10-06 it ran:
# installed with --only-binary, a scan fired its control rule, and the four
# integration files that failed in that run passed. The exclusion was then the
# only thing holding PyJWT at 2.13.0, under fourteen advisories that 1.179.0's
# `pyjwt>=2.15.0` clears. Whether a release has a wheel is a fact about PyPI
# that an offline test cannot see; the push gate's pip-audit, which resolves
# this file fresh, is the live guard against re-pinning the vulnerable PyJWT.
