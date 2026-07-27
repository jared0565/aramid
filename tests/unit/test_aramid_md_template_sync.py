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


# The date aramid was onboarded into its own repo. This is a HISTORICAL FACT, not
# a build stamp -- but `_render_aramid_md` stamps `date.today()`, and the sync test
# below has to normalise that away or it would fail every day. Normalising it means
# nothing else checks it, so a future regeneration that forgets to restore the real
# date would silently rewrite history and still pass. Hence this pin: if it fails,
# either restore the date or, if aramid was genuinely re-onboarded, change it here
# deliberately.
ONBOARDED_DATE = "2026-07-25"


def test_aramid_md_records_the_real_onboarding_date():
    actual = (REPO_ROOT / "ARAMID.md").read_text(encoding="utf-8")
    assert _header_value(actual, "Onboarded") == ONBOARDED_DATE, (
        "ARAMID.md's Onboarded date changed. `_render_aramid_md` stamps date.today(), "
        "so this is what a regeneration looks like when the historical date was not "
        "restored -- that records a falsehood. Restore it, or update ONBOARDED_DATE "
        "here if the repo really was re-onboarded."
    )


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
        # Normalise the date here too, else the always-differing Onboarded line shows
        # up as phantom "drift". Iterate the template in order rather than differencing
        # sets -- set order is hash-randomised, so the reported lines would otherwise
        # vary between runs on identical input.
        def _norm(lines):
            return {_ONBOARDED.sub(r"\1DATE", ln) for ln in lines}

        def _only_in(a, b):
            other = _norm(b)
            return [ln for ln in a
                    if ln.strip() and _ONBOARDED.sub(r"\1DATE", ln) not in other]

        # Report BOTH directions: drift can be the template gaining content the
        # rendered file lacks (the observed case, twice) or the rendered file
        # carrying hand-edits the template never had. Iterate in file order --
        # set order is hash-randomised and would vary between runs on identical
        # input, making the diagnostic look nondeterministic.
        missing = _only_in(rendered.splitlines(), actual.splitlines())
        extra = _only_in(actual.splitlines(), rendered.splitlines())
        detail = ""
        if missing:
            detail += (f"\n{len(missing)} template line(s) ABSENT from ARAMID.md:\n  "
                       + "\n  ".join(missing[:5]))
        if extra:
            detail += (f"\n{len(extra)} line(s) in ARAMID.md NOT in the template "
                       f"(hand-edited?):\n  " + "\n  ".join(extra[:5]))
        raise AssertionError(
            "ARAMID.md has drifted from src/aramid/data/ARAMID.md.tmpl. "
            "The template is the source of truth; regenerate the rendered file "
            "(preserving its Onboarded date) rather than hand-editing one of them."
            + detail
        )
