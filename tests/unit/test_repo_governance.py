"""The governance files a public security tool is expected to carry.

Structural guards, not prose review. Each one names the property a reader
would check first and that would otherwise decay silently: a SECURITY.md
that stopped naming the private channel, a CONTRIBUTING.md that lost the
gate rules, a MAINTAINERS.md that no longer lists what a successor needs, a
Dependabot config that stopped covering the SHA-pinned actions (which, being
pinned, never update themselves), and a README that stopped linking any of
them. Every assertion first depends on the file existing, so a deleted file
fails here instead of vanishing quietly.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ADVISORY_URL = "https://github.com/jared0565/aramid/security/advisories/new"


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_security_policy_names_the_private_reporting_channel():
    text = _read("SECURITY.md")
    assert ADVISORY_URL in text, "SECURITY.md does not point at private vulnerability reporting"
    assert "supported versions" in text.lower()


def test_security_policy_says_what_is_in_and_out_of_scope():
    """A policy that does not say what counts sends every `--no-verify` report
    to the private channel and every real bypass to the public tracker."""
    text = _read("SECURITY.md").lower()
    assert "in scope" in text
    assert "out of scope" in text
    assert "--no-verify" in text            # the documented non-vulnerability


def test_contributing_guide_states_the_gate_rules():
    text = _read("CONTRIBUTING.md")
    assert "aramid check --staged" in text
    assert "--no-verify" in text            # the prohibition is spelled out
    assert "RELEASING.md" in text


def test_maintainers_file_lists_what_a_successor_needs():
    text = _read("MAINTAINERS.md").lower()
    for needle in ("pypi", "required reviewer", "trusted publish"):
        assert needle in text, f"MAINTAINERS.md no longer mentions {needle!r}"


def test_dependabot_covers_the_sha_pinned_actions():
    """The actions are pinned to commit SHAs on purpose (test_workflow_pinning).
    A pin never moves on its own, so without an updater the pins are the one
    dependency class in this repo that silently ages."""
    cfg = yaml.safe_load(_read(".github/dependabot.yml"))
    ecosystems = {u["package-ecosystem"] for u in cfg["updates"]}
    assert "github-actions" in ecosystems


def test_readme_links_the_governance_docs():
    readme = _read("README.md")
    assert "SECURITY.md" in readme
    assert "CONTRIBUTING.md" in readme
