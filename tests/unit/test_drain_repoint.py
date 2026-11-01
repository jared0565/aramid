"""Unit-scope pins for drain._repoint_rewritten: which head the drain
consumes when the queued one was rewritten away (amend, rebase, reset).

tests/integration/test_drain.py drives the same function end to end, but
the drain's mutation run uses tests/unit only (`[mutation].test_command`):
the 19:00Z drain of 2026-11-01 left three mutants of this function alive
that the integration tests kill. git's answers are stubbed here;
tests/unit/test_gitutil_rewritten.py asks real git the same questions."""
from types import SimpleNamespace

import pytest

from aramid import queue
from aramid.commands import drain as drain_mod
from aramid.ledger import Ledger
from aramid.models import EventType

AT = "2026-11-01T20:00:00+00:00"
BASE, DEAD, TIP, OTHER = "b" * 40, "d" * 40, "e" * 40, "f" * 40


@pytest.fixture
def git(monkeypatch):
    """git's answers, set per test. Asked about anything but the dead head
    (or anything but HEAD, for rev_sha), they give the answer that would
    leave the item alone, so a call about the wrong commit cannot pass."""
    ans = SimpleNamespace(on_ref=False, head=OTHER, held=[("feature", TIP)])
    monkeypatch.setattr(drain_mod.gitutil, "on_any_ref",
                        lambda root, sha: ans.on_ref if sha == DEAD else True)
    monkeypatch.setattr(drain_mod.gitutil, "rev_sha",
                        lambda root, rev: ans.head if rev == "HEAD" else None)
    monkeypatch.setattr(drain_mod.gitutil, "branches_that_held",
                        lambda root, sha: ans.held if sha == DEAD else [])
    return ans


@pytest.fixture
def ledger(tmp_path):
    led = Ledger(tmp_path / "ledger.db")
    yield led
    led.close()


def _queue(led, base=BASE, head=DEAD):
    queue.enqueue(led, "2026-11-01T11:10:00+00:00", base, head, 45, ["risky content"])
    return queue.queued_item(queue.materialize_queue(led.events()))


def _coalesces(led):
    return [e.payload for e in led.events() if e.type is EventType.QUEUE_ITEM_COALESCED]


def _repoint(tmp_path, led, item):
    return drain_mod._repoint_rewritten(tmp_path, led, item, AT)


# ------------------------------------------------------- left as it is ---

@pytest.mark.parametrize("why, on_ref, head, held", [
    ("still on a ref", True, OTHER, [("feature", TIP)]),
    ("git could not place it", None, OTHER, [("feature", TIP)]),
    ("checked out detached: someone is working on it", False, DEAD, [("feature", TIP)]),
    ("git could not read the reflogs", False, OTHER, None),
])
def test_left_as_it_is_and_nothing_recorded(tmp_path, ledger, git, why, on_ref, head, held):
    git.on_ref, git.head, git.held = on_ref, head, held
    item = _queue(ledger)
    assert _repoint(tmp_path, ledger, item) is item, why
    assert _coalesces(ledger) == [], why


# ------------------------------------------------------------ re-pointed ---

def test_the_one_branch_whose_reflog_held_it_is_drained_at_its_tip(tmp_path, ledger, git):
    item = _queue(ledger)
    got = _repoint(tmp_path, ledger, item)
    assert (got.base, got.head) == (BASE, TIP)
    assert queue.queued_item(queue.materialize_queue(ledger.events())) == got, (
        "re-pointed in the ledger, not only in the returned value")
    [payload] = _coalesces(ledger)
    assert payload["rewritten"] == DEAD
    assert payload["score"] == 45
    assert payload["reasons"] == sorted([
        "risky content",
        f"rewritten: {DEAD[:12]} is on no branch or tag; drained at feature "
        f"({TIP[:12]}), whose reflog held it"])


def test_an_empty_range_item_takes_its_base_along(tmp_path, ledger, git):
    """base == head is the re-test item; keeping the dead base would hand
    the consumers the rewrite's own diff as a range nobody queued."""
    got = _repoint(tmp_path, ledger, _queue(ledger, base=DEAD, head=DEAD))
    assert (got.base, got.head) == (TIP, TIP)


# ------------------------------------------------- drained as queued ---

def test_no_branch_whose_reflog_held_it_drains_as_queued_and_says_why(tmp_path, ledger, git):
    git.held = []
    got = _repoint(tmp_path, ledger, _queue(ledger))
    assert (got.base, got.head) == (BASE, DEAD)
    assert (f"rewritten: {DEAD[:12]} is on no branch or tag, and no branch's "
            f"reflog holds it; drained as queued") in got.reasons
    [payload] = _coalesces(ledger)
    assert payload["rewritten"] == DEAD


def test_several_branches_whose_reflogs_held_it_drain_as_queued_and_name_them(
        tmp_path, ledger, git):
    git.held = [("topic", OTHER), ("main", TIP)]
    got = _repoint(tmp_path, ledger, _queue(ledger))
    assert (got.base, got.head) == (BASE, DEAD)
    assert (f"rewritten: {DEAD[:12]} is on no branch or tag, and 2 branches' "
            f"reflogs hold it (main, topic); drained as queued") in got.reasons


def test_why_is_recorded_once_however_many_drains_see_it(tmp_path, ledger, git):
    """An item can wait several drains (another repo's item won the budget)."""
    git.held = []
    first = _repoint(tmp_path, ledger, _queue(ledger))
    again = _repoint(tmp_path, ledger, first)
    assert again is first
    assert len(_coalesces(ledger)) == 1
