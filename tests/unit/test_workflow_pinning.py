"""Third-party GitHub Actions must be pinned to full commit SHAs.

aramid's CI is not merely infrastructure -- it IS part of the enforcement
boundary. The dogfood steps in .github/workflows/aramid.yml are what prove the
gate works, so whatever runs there decides whether a finding is reported. A
`uses: actions/checkout@v7` reference is a MUTABLE pointer: the upstream owner
(or anyone who compromises them) can move the tag, and aramid's next CI run
executes different code with no diff in this repository and nothing in the log
to notice. For a tool that exists to catch supply-chain and misconfiguration
risk in other people's repositories, shipping that in its own is the one
inconsistency an evaluator would reasonably lead with.

A SHA cannot be moved. The cost is that updates become explicit -- which is the
point: `git log` shows the bump, and a human approves it.

This guard is deliberately structural rather than a snapshot of today's SHAs.
Asserting specific hashes would fail on every legitimate upgrade and teach
whoever hits it to edit the expected value, which is how a guard becomes
decoration.
"""
import re
from pathlib import Path

# `uses:` at the start of a step (optionally after a `-`), never inside a
# comment: `#` can only precede it on a comment line, which this will not
# match because the `#` would have to sit before the whitespace-anchored
# `uses:`.
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)", re.M)
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _workflow_dir() -> Path:
    return Path(__file__).resolve().parents[2] / ".github" / "workflows"


def _uses_refs() -> list[tuple[str, str]]:
    """(workflow filename, ref) for every `uses:` across all workflows."""
    found = []
    for wf in sorted(_workflow_dir().glob("*.yml")):
        text = wf.read_text(encoding="utf-8")
        found += [(wf.name, m.group(1)) for m in _USES.finditer(text)]
    return found


def test_the_guard_can_actually_see_the_workflows():
    """Non-vacuity, first. If the directory moves or the regex stops matching,
    every assertion below passes against an empty list -- a guard reporting
    success for a reason indistinguishable from a real pass."""
    assert _workflow_dir().is_dir(), f"no workflow dir at {_workflow_dir()}"
    refs = _uses_refs()
    assert len(refs) >= 3, (
        f"only {len(refs)} `uses:` reference(s) discovered -- expected at "
        "least checkout, setup-python and gitleaks. The parser has probably "
        "stopped matching, not the workflows stopped using actions.")


def test_every_third_party_action_is_pinned_to_a_commit_sha():
    bad = []
    for name, ref in _uses_refs():
        if ref.startswith("./"):
            continue                    # a local action: nothing to pin
        _, sep, version = ref.partition("@")
        if not sep or not _SHA.match(version):
            bad.append(f"{name}: {ref}")
    assert not bad, (
        "these actions are pinned to a MUTABLE ref; pin each to the full "
        "40-character commit SHA the tag currently points at, keeping the "
        "human-readable version in a trailing comment:\n  " + "\n  ".join(bad))


def test_every_pin_records_the_human_readable_version():
    """A bare SHA is unreadable. Without the trailing `# vN` nobody can tell
    which version is in use, so nobody upgrades, and pinning turns into
    permanent staleness -- a different supply-chain problem."""
    unlabelled = []
    for wf in sorted(_workflow_dir().glob("*.yml")):
        for line in wf.read_text(encoding="utf-8").splitlines():
            m = _USES.match(line)
            if not m or m.group(1).startswith("./"):
                continue
            if "#" not in line.split("uses:", 1)[1]:
                unlabelled.append(f"{wf.name}: {line.strip()}")
    assert not unlabelled, (
        "pinned action(s) with no version comment -- append `# vN.N.N` so the "
        "pin stays legible and upgradable:\n  " + "\n  ".join(unlabelled))
