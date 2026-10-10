"""One gitleaks version: the one `doctor --fix` installs is the one CI installs.

gitleaks moves hits between rules from release to release, and the rule id is
part of aramid's finding id. Two versions therefore give one line two ids: a
suppression written against a developer's gitleaks binds nothing in CI, and
the reverse. Until FN-5 `doctor` pinned 8.21.2 while the workflow installed
8.28.0, and `.aramid-suppressions.toml` carried two entries for each of two
fixture lines to cover both.

The two pins live in different files in different syntaxes, so nothing but a
test that reads both keeps them together.
"""
import re
from pathlib import Path

from aramid.commands import doctor

_GITLEAKS_STEP = re.compile(r"^\s*(?:-\s+)?uses:\s*gacts/gitleaks@")
_NEXT_STEP = re.compile(r"^\s*-\s")
_VERSION = re.compile(r"""^\s*version:\s*["']?([^"'\s#]+)""")


def _ci_gitleaks_versions() -> list[tuple[str, str]]:
    """(workflow filename, version) for every step that installs gitleaks.

    A step with no `version:` input is reported as `""`, never skipped: the
    action would install its own default there, which is the drift this test
    exists to see."""
    workflows = Path(__file__).resolve().parents[2] / ".github" / "workflows"
    found = []
    for wf in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        lines = wf.read_text(encoding="utf-8").splitlines()
        for at, line in enumerate(lines):
            if not _GITLEAKS_STEP.match(line):
                continue
            version = ""
            for rest in lines[at + 1:]:
                if _NEXT_STEP.match(rest):
                    break
                m = _VERSION.match(rest)
                if m:
                    version = m.group(1)
                    break
            found.append((wf.name, version))
    return found


def test_ci_installs_the_gitleaks_version_doctor_pins():
    # Set equality, so "no gitleaks step found" fails too: an empty set is
    # not the pin. A guard that compares nothing must not read as agreement.
    found = _ci_gitleaks_versions()
    assert {version for _, version in found} == {doctor.GITLEAKS_VERSION}, (
        f"`doctor --fix` pins gitleaks {doctor.GITLEAKS_VERSION} "
        f"(GITLEAKS_VERSION in commands/doctor.py) and the workflows install "
        f"{found or 'nothing this test can find'}. Move both together, with the "
        "five GITLEAKS_SHA256 values from that release's published checksums.")
