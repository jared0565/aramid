"""The 1.0 gate is a documented procedure, not folklore: RELEASING.md names
it, MAINTAINERS.md points at it, the user guide explains the surfaces, and
the changelog records the feature. Guards, like tests/unit/test_repo_governance.py."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_releasing_has_the_1_0_gate():
    text = _read("RELEASING.md")
    assert "## The 1.0 gate" in text
    assert "`aramid fleet`" in text and "ready" in text
    assert "API freeze" in text


def test_maintainers_points_at_the_gate():
    assert "The 1.0 gate" in _read("MAINTAINERS.md")


def test_user_guide_names_the_fleet_section_and_six_of_its_strings():
    """Six literal strings, not the surface: a subcommand, flag or config key
    added without a mention in the guide passes here. The drift guard that
    checks every surface is DOC-12 (API-9 renamed this test so its name
    stops claiming that job)."""
    text = _read("docs/user-guide.md")
    for needle in ("### Fleet health, 1.0 readiness and notices", "aramid fleet",
                   "aramid notices ack", "fleet_health.jsonl", "fleet.toml",
                   "ARAMID_FLEET_DIR"):
        assert needle in text, needle


def test_the_guide_and_the_gate_describe_parked_repos():
    """Amendment A2 changed what the 1.0 gate counts; the three documents a
    maintainer reads before tagging have to say so."""
    guide = _read("docs/user-guide.md")
    for needle in ("min_active_repos = 3", "repo-parked", "parked since",
                   "its next gate run restarts the streak"):
        assert needle in guide, needle
    assert "every active registered repo" in _read("RELEASING.md")
    entry = _read("CHANGELOG.md").split("## [0.21.0]", 1)[1].split("\n## [", 1)[0]
    assert "parked" in entry and "min_active_repos" in entry


def test_changelog_records_the_feature():
    unreleased = _read("CHANGELOG.md").split("## [Unreleased]", 1)[1].split("## [0.8.1]", 1)[0]
    assert "aramid fleet" in unreleased and "aramid notices" in unreleased
