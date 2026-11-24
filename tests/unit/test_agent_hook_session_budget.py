"""The SessionStart block: the gate banner first, and the whole block inside a
budget (interop round 342; operator decision 2026-11-23).

Measured on 0.20.19: a pending handover printed ahead of the banner, and its
8,000-character cap counted body characters only -- every line also carries
the 10-character `aramid: | ` prefix, and the posture lines follow. A
7,900-character body in 40-character lines gave a 10,731-character block with
the GATED banner at character 10,020, past Claude Code's 10,000-character hook
output limit. Now the two fixed lines lead, and the handover is cut so the
whole block stays within `_SESSION_BUDGET`."""
import subprocess

import pytest

from aramid import handover
from aramid.commands import agent_hook as ah

GATED = ("aramid: this repo is GATED (pre-commit + pre-push hooks). Read ARAMID.md;"
         " NEVER pass --no-verify.")
TOOL = ("aramid: aramid is a tool, not an agent to talk to -- the agent channel takes"
        " only bug reports and improvement suggestions for aramid.")
TRUNCATED = "aramid: | ... (truncated; 'aramid handover show' prints all of it)"
PREFIX = "aramid: | "


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    for a in (["init", "-q", "-b", "main"], ["config", "user.email", "t@t"],
              ["config", "user.name", "t"]):
        subprocess.run(["git", *a], cwd=r, check=True, capture_output=True)
    (r / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    (r / "app.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=r, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "seed"], cwd=r, check=True,
                   capture_output=True)
    return r


def _body(size, width):
    line = "y" * (width - 1) + "\n"
    return (line * (size // width + 1))[:size]


def _shown(out):
    """The body lines the block printed, prefix stripped, truncated line out."""
    return [ln.removeprefix(PREFIX) for ln in out.splitlines()
            if ln.startswith(PREFIX) and ln != TRUNCATED]


def test_the_banner_leads_and_the_handover_follows_it(tmp_path):
    r = _repo(tmp_path)
    handover.write(r, "resume step 3\n")

    lines = ah._session_context(r).splitlines()

    assert lines[:2] == [GATED, TOOL]
    assert lines[2].startswith("aramid: PENDING HANDOVER written ")
    assert lines[3].startswith("aramid: position now: HEAD ")  # round 337
    assert lines[4] == "aramid: | resume step 3"
    assert lines[5].startswith("aramid: open findings: ")
    assert lines[-1].startswith("aramid: commands: aramid check --staged")


def test_no_git_still_leads_the_banner_it_qualifies(tmp_path):
    r = _repo(tmp_path)
    handover.write(r, "resume step 3\n")

    lines = ah._session_context(r, git_missing=True).splitlines()

    assert lines[:3] == [ah._NO_GIT, GATED, TOOL]
    assert lines[3].startswith("aramid: PENDING HANDOVER written ")


def test_without_a_handover_the_block_is_the_posture_as_before(tmp_path):
    out = ah._session_context(_repo(tmp_path))
    assert out.startswith(GATED + "\n" + TOOL + "\naramid: open findings: ")
    assert "HANDOVER" not in out and "aramid: |" not in out


@pytest.mark.parametrize("size, width", [(7900, 40), (7900, 20), (9000, 9001),
                                         (20000, 75), (3000, 2)],
                         ids=["7900-in-40", "7900-in-20", "9000-one-line", "20000-in-75",
                              "3000-in-2"])
def test_the_whole_block_stays_within_the_budget(tmp_path, size, width):
    r = _repo(tmp_path)
    body = _body(size, width)
    handover.write(r, body)

    out = ah._session_context(r)

    assert len(out) <= ah._SESSION_BUDGET
    lines = out.splitlines()
    assert lines[:2] == [GATED, TOOL]
    assert lines[-1].startswith("aramid: commands: aramid check --staged")
    assert TRUNCATED in lines
    # what is shown is the body's own start: whole lines, the last maybe cut
    real = body.rstrip("\n").split("\n")
    shown = _shown(out)
    assert shown[:-1] == real[:len(shown) - 1]
    assert real[len(shown) - 1].startswith(shown[-1])


def test_a_handover_that_fits_is_shown_whole(tmp_path):
    r = _repo(tmp_path)
    body = _body(5000, 75)
    handover.write(r, body)

    out = ah._session_context(r)

    assert TRUNCATED not in out
    assert _shown(out) == body.rstrip("\n").split("\n")


def test_a_block_exactly_at_the_budget_is_not_cut_and_one_over_is(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    handover.write(r, _body(3000, 60))
    full = ah._session_context(r)
    assert TRUNCATED not in full

    monkeypatch.setattr(ah, "_SESSION_BUDGET", len(full))
    assert ah._session_context(r) == full

    monkeypatch.setattr(ah, "_SESSION_BUDGET", len(full) - 1)
    cut = ah._session_context(r)
    assert len(cut) <= len(full) - 1
    assert TRUNCATED in cut.splitlines()
    assert len(cut) > len(full) - 70, "the cut keeps all the room it can"


def test_too_little_room_for_an_excerpt_leaves_only_the_pointer(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    handover.write(r, _body(3000, 60))
    full = ah._session_context(r)
    header = next(ln for ln in full.splitlines() if ln.startswith("aramid: PENDING"))
    fixed = len(full) - sum(len(ln) + 1 for ln in full.splitlines()
                            if ln.startswith(PREFIX))
    monkeypatch.setattr(ah, "_SESSION_BUDGET",
                        fixed + len(TRUNCATED) + 1 + ah._MIN_EXCERPT - 1)

    lines = ah._session_context(r).splitlines()

    # round 337: the position is header, kept when no body fits
    assert lines[lines.index(header) + 1].startswith("aramid: position now: HEAD ")
    assert lines[lines.index(header) + 2] == TRUNCATED
    assert _shown("\n".join(lines)) == []


def test_room_for_exactly_the_minimum_excerpt_shows_one(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    handover.write(r, _body(3000, 60))
    full = ah._session_context(r)
    fixed = len(full) - sum(len(ln) + 1 for ln in full.splitlines()
                            if ln.startswith(PREFIX))
    monkeypatch.setattr(ah, "_SESSION_BUDGET",
                        fixed + len(TRUNCATED) + 1 + ah._MIN_EXCERPT)

    out = ah._session_context(r)

    assert len(out) <= ah._SESSION_BUDGET
    assert _shown(out) != []


def test_a_raising_posture_block_still_gets_the_banner_and_the_handover(tmp_path,
                                                                         monkeypatch):
    from aramid.ledger import Ledger
    r = _repo(tmp_path)
    handover.write(r, _body(20000, 40))

    def boom(self, *a, **k):
        raise RuntimeError("ledger locked")
    monkeypatch.setattr(Ledger, "open_findings", boom)

    out = ah._session_context(r)

    lines = out.splitlines()
    assert lines[:2] == [GATED, TOOL]
    assert lines[2].startswith("aramid: PENDING HANDOVER written ")
    assert lines[-1] == TRUNCATED
    assert len(out) <= ah._SESSION_BUDGET
    assert len(out) > ah._SESSION_BUDGET - 70


# ------------------------------------------- _fit_handover, exact outputs --

HEAD = "aramid: PENDING HANDOVER " + "h" * 5            # 30 characters
B1, B2, B3 = (PREFIX + c * 600 for c in "abc")         # 610 characters each


def _room(left):
    """The room that leaves `left` characters for the body lines."""
    return left + (len(HEAD) + 1) + (len(TRUNCATED) + 1)


def _size(lines):
    return sum(len(ln) + 1 for ln in lines)


def test_a_handover_within_the_room_is_returned_as_it_is():
    lines = [HEAD, B1, B2]
    assert ah._fit_handover(lines, _size(lines)) == lines


def test_the_cut_fills_the_room_to_the_character():
    out = ah._fit_handover([HEAD, B1, B2, B3], _room(611 + 100))
    assert out == [HEAD, B1, B2[:99], TRUNCATED]
    assert _size(out) == _room(611 + 100)


def test_a_cut_at_a_line_end_keeps_that_line_whole():
    assert ah._fit_handover([HEAD, B1, B2], _room(611)) == [HEAD, B1, TRUNCATED]
    # one more character is the newline: still nothing of the next line
    assert ah._fit_handover([HEAD, B1, B2], _room(612)) == [HEAD, B1, TRUNCATED]


def test_a_cut_inside_the_prefix_drops_the_fragment_and_one_past_it_keeps_it():
    assert ah._fit_handover([HEAD, B1, B2], _room(611 + 11)) == [HEAD, B1, TRUNCATED]
    assert ah._fit_handover([HEAD, B1, B2], _room(611 + 12)) == [
        HEAD, B1, PREFIX + "b", TRUNCATED]


def test_a_one_line_body_over_the_room_is_cut():
    assert ah._fit_handover([HEAD, B1], _room(520)) == [HEAD, B1[:519], TRUNCATED]


def test_a_body_already_capped_gets_one_truncated_line():
    assert ah._fit_handover([HEAD, B1, B2, TRUNCATED], _room(611 + 100)) == [
        HEAD, B1, B2[:99], TRUNCATED]


def test_an_unverified_handover_line_is_never_cut(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    (r / ".aramid").mkdir(exist_ok=True)
    (r / ".aramid" / "handover.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(ah, "_SESSION_BUDGET", 10)

    lines = ah._session_context(r).splitlines()

    assert lines[:2] == [GATED, TOOL]
    assert lines[2].startswith("aramid: a handover file is present but unreadable (")
    assert TRUNCATED not in lines
