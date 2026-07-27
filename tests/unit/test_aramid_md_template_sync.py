"""ARAMID.md at the repo root is a TRACKED, rendered artifact of
`src/aramid/data/ARAMID.md.tmpl`, and nothing regenerates it when the template
changes -- `aramid init` is the only generator, and it mutates machine state, so
it is not something anyone runs casually on this repo.

It has now drifted silently TWICE (ticket T-11). The detector-fix branch updated
the template and left ARAMID.md missing a 21-line block, and nobody noticed. The
feat/ledger-not-a-secret branch did the same thing, and that one was caught only
by an adversarial whole-branch review -- meaning the rendered file still taught
`mark-rotated` as the only way to retire a historical secret, which was the exact
discoverability defect that branch existed to fix.

That matters more than ordinary doc staleness: ARAMID.md doubles as aramid's own
in-repo agent instructions, so a stale copy actively teaches agents the wrong
thing. This test pins the two files together so the drift cannot recur silently.
"""
import re
from pathlib import Path

from aramid.commands.init import _render_aramid_md

REPO_ROOT = Path(__file__).resolve().parents[2]

# `_render_aramid_md` stamps __DATE__ with date.today(), but the rendered file's
# "Onboarded" line records when aramid was onboarded HERE (a fixed past date).
# Normalising it is what keeps this test from failing every day for no reason.
_ONBOARDED = re.compile(r"(\*\*Onboarded:\*\* )\d{4}-\d{2}-\d{2}")


def _header_value(text: str, label: str) -> str:
    m = re.search(rf"^- \*\*{re.escape(label)}:\*\* (.+)$", text, re.M)
    assert m is not None, f"ARAMID.md is missing its '{label}' header line"
    return m.group(1).strip()


def test_aramid_md_is_in_sync_with_its_template():
    actual = (REPO_ROOT / "ARAMID.md").read_text(encoding="utf-8")

    # Render using the values ARAMID.md itself records, so this test pins TEMPLATE
    # DRIFT only -- it deliberately does not also assert what aramid's own detected
    # stack ought to be, which is test_detectors.py's job.
    stack_note = _header_value(actual, "Detected stack")
    pkg_mgr = _header_value(actual, "Package manager")
    rendered = _render_aramid_md(
        set() if stack_note == "unknown" else set(stack_note.split(", ")),
        None if pkg_mgr == "none" else pkg_mgr,
    )

    if _ONBOARDED.sub(r"\1DATE", actual) != _ONBOARDED.sub(r"\1DATE", rendered):
        tmpl_lines = set(rendered.splitlines())
        missing = [ln for ln in tmpl_lines - set(actual.splitlines()) if ln.strip()]
        raise AssertionError(
            "ARAMID.md has drifted from src/aramid/data/ARAMID.md.tmpl. "
            "The template is the source of truth; regenerate the rendered file "
            "(preserving its Onboarded date) rather than hand-editing one of them.\n"
            f"{len(missing)} template line(s) absent from ARAMID.md, first few:\n  "
            + "\n  ".join(missing[:5])
        )
