import os
import time
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import queue, registry
from aramid.commands import drain as drain_mod
from aramid.commands import triage_cmd
from aramid.commands.drain import cmd_drain
from aramid.consumers.base import ConsumerResult
from aramid.ledger import Ledger
from aramid.models import Event, EventType
from aramid.normalizer import RawFinding


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name="r") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    return r


def _commit(root, name, content, msg):
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8")
    _git(root, "add", name)
    _git(root, "commit", "-m", msg)


class _FakeConsumer:
    NAME = "fake"
    calls: list = []

    @classmethod
    def consume(cls, item, ctx):
        cls.calls.append(item)
        raw = RawFinding(tool="semgrep", rule="aramid-regression.warn.deadbeef",
                         severity_raw="WARNING", file="src/auth_login.py", line=1,
                         message="reintroduction")
        return ConsumerResult(consumer=cls.NAME, state="ok", findings=[raw])


@pytest.fixture
def fake_consumer(monkeypatch):
    """Isolate drain tests from the real `regression_pack` consumer, which
    registers itself into the shared `consumers.base.CONSUMERS` dict at
    import time (Task 16) -- and `drain.py` now imports it unconditionally,
    so it is present in CONSUMERS for the rest of this test session. REPLACE
    (not add to) the dict `drain.py` actually iterates so these tests only
    ever run the fake.

    Patched on `drain_mod`, not `aramid.consumers.base`: `drain.py` does
    `from aramid.consumers.base import CONSUMERS`, which binds its own
    module-global name to the dict object at import time. Rebinding
    `base.CONSUMERS` only changes what `base.CONSUMERS` resolves to -- it
    does not touch `drain_mod`'s separate binding, which is the one
    `cmd_drain`'s `_consume_item` loop (`for name, module in
    CONSUMERS.items()`) actually reads. Patching `base.CONSUMERS` here would
    silently leave the real consumer in drain's loop.
    """
    _FakeConsumer.calls = []
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": _FakeConsumer})
    yield _FakeConsumer


@pytest.fixture
def seam(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "central" / "repos.toml")
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "central" / "drain.lock")


def _risky_repo(tmp_path, name="r"):
    r = _repo(tmp_path, name)
    _commit(r, "src/auth_login.py", "def f(x):\n    exec(x)\n", "risky")
    return r


def test_a_commit_made_while_the_drain_runs_is_not_marked_drained_with_it(
        tmp_path, seam, monkeypatch):
    """The consumer here commits to the repo mid-run and triages it, the way
    a developer's post-commit shim does while a 25-minute mutation run is
    going. The drain must mark drained only the head it consumed; the new
    commit stays queued for the next drain instead of vanishing."""
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    popped_head = _head(r)
    consumed = []

    class _CommittingConsumer:
        NAME = "committing"

        @classmethod
        def consume(cls, item, ctx):
            consumed.append(item.head)
            _commit(r, "src/auth_login2.py", "def g(x):\n    exec(x)\n", "landed mid-drain")
            triage_cmd.cmd_triage(r, "HEAD")
            return ConsumerResult(consumer=cls.NAME, state="ok", findings=[])

    monkeypatch.setattr(drain_mod, "CONSUMERS", {"committing": _CommittingConsumer})

    assert cmd_drain([], dry_run=False) == 0

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        left = queue.queued_item(queue.materialize_queue(led.events()))
    finally:
        led.close()
    assert consumed == [popped_head], "the drain consumed the head it popped"
    assert left is not None, "the mid-drain commit was marked drained without being graded"
    assert (left.base, left.head) == (popped_head, _head(r))


def test_drain_sweeps_pops_consumes_records(tmp_path, seam, fake_consumer):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    rc = cmd_drain([], dry_run=False)  # [] + registry -> --all semantics
    assert rc == 0
    assert len(fake_consumer.calls) == 1  # sweep triaged HEAD, item queued, popped
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        events = led.events()
        assert any(e.type is EventType.CONSUMER_RUN_FINISHED for e in events)
        assert any(e.type is EventType.QUEUE_ITEM_DRAINED for e in events)
        assert queue.queued_item(queue.materialize_queue(events)) is None
        state = led.open_findings()
        assert any(rec.get("rule") == "aramid-regression.warn.deadbeef"
                   for rec in state.values())
    finally:
        led.close()


def test_a_manual_triage_of_an_old_range_does_not_rewind_the_sweep(
        tmp_path, seam, fake_consumer):
    """2026-09-06 14:58Z: `aramid triage <old>..<older-head>` was run by hand
    to re-grade one commit; the next drain read the LAST triage row as its
    anchor, triaged old-head..HEAD all over again and coalesced it into the
    item, so the consumer graded the wrong files. The anchor is the newest
    triaged head in HISTORY, not in the ledger: a row for an ancestor of an
    already-triaged head moves nothing."""
    r = _risky_repo(tmp_path)                                      # c1
    c1 = _head(r)
    _commit(r, "src/auth_login2.py", "def g(x):\n    exec(x)\n", "c2")
    c2 = _head(r)
    registry.register(r, "t0")
    cmd_drain([], dry_run=False)                                   # sweep triages c1..c2
    _commit(r, "src/auth_login3.py", "def h(x):\n    exec(x)\n", "c3")
    c3 = _head(r)
    triage_cmd.cmd_triage(r, c1)                                   # manual, old: last row now says c1

    cmd_drain([], dry_run=False)

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        rows = [e.payload for e in led.events() if e.type is EventType.TRIAGE_RECORDED]
    finally:
        led.close()
    assert rows[-1]["head"] == c3
    assert rows[-1]["base"] == c2, (
        f"the sweep re-triaged from the manual row's head {c1[:7]} instead of "
        f"the newest triaged head in history {c2[:7]}")


# ------------------------------------------ a queued head rewritten away ---
# 2026-11-01, this repo: a commit was queued at 11:10Z and amended at 11:18Z.
# The replacement's triage scored 25 against `min_score` 40 -- its paths'
# novelty had been spent by the first commit's triage -- so it was never
# queued and never coalesced, and the 15:00Z drain consumed the PRE-AMEND
# commit: 38 minutes of mutation, plus review and fuzz, on code no branch
# contained, while the commit on main went unchecked. A queued head that no
# branch, tag or remote-tracking branch contains any more was rewritten away
# (amend, rebase, reset); the drain consumes the tip of the one local branch
# whose own reflog recorded it. The first cut took HEAD, and an amend followed
# by a checkout of the base's branch drained an empty range (llm-review
# 865e2d26). The unit pins are tests/unit/test_drain_repoint.py: the drain's
# mutation run never reaches this file.

def _recording(monkeypatch):
    consumed = []

    class _Recording:
        NAME = "recording"

        @classmethod
        def consume(cls, item, ctx):
            consumed.append((item.base, item.head))
            return ConsumerResult(consumer=cls.NAME, state="ok", findings=[])

    monkeypatch.setattr(drain_mod, "CONSUMERS", {"recording": _Recording})
    return consumed


def _queued_now(r):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        return queue.queued_item(queue.materialize_queue(led.events()))
    finally:
        led.close()


def _queued_script_commit(tmp_path, branch=None):
    """base, then one commit that scores 45 on its own (risky content 25 +
    novelty 20) and is queued; the same shape as 2026-11-01's. With `branch`,
    that commit is made on a new branch of that name cut at base."""
    r = _repo(tmp_path)
    _commit(r, "README.md", "x\n", "base")
    base = _head(r)
    if branch:
        _git(r, "checkout", "-q", "-b", branch)
    _commit(r, "tools/run.py", "import subprocess\nsubprocess.run(['true'])\n", "first")
    triage_cmd.cmd_triage(r, "HEAD")                 # what the post-commit shim does
    first = _head(r)
    assert (_queued_now(r).base, _queued_now(r).head) == (base, first)
    registry.register(r, "t0")
    return r, base, first


def test_an_amended_queued_commit_is_drained_at_its_replacement(
        tmp_path, seam, monkeypatch):
    r, base, first = _queued_script_commit(tmp_path)
    (r / "tools" / "run.py").write_text(
        "import subprocess\nsubprocess.run(['true'], check=True)\n", encoding="utf-8")
    _git(r, "commit", "-q", "-a", "--amend", "--no-edit")
    amended = _head(r)
    triage_cmd.cmd_triage(r, "HEAD")                 # 25 now: novelty spent, not queued
    assert _queued_now(r).head == first, (
        "precondition: the replacement did not move the item -- the shape this "
        "test exists for no longer occurs")
    consumed = _recording(monkeypatch)

    assert cmd_drain([], dry_run=False) == 0

    assert consumed == [(base, amended)], (
        f"the drain consumed {consumed}, not {base[:7]}..{amended[:7]}: the "
        f"pre-amend commit {first[:7]} is on no branch")
    assert _queued_now(r) is None, "the replacement was consumed, so nothing is left"


def test_an_amend_on_a_branch_that_is_not_checked_out_is_drained_there(
        tmp_path, seam, monkeypatch):
    """llm-review 865e2d26, on the first cut, which took HEAD: amend a
    queued commit on a feature branch, check out main at the base, and the
    drain consumed base..base -- an empty range -- and marked the item
    drained while the amended branch went unchecked."""
    r, base, first = _queued_script_commit(tmp_path, branch="feature")
    (r / "tools" / "run.py").write_text(
        "import subprocess\nsubprocess.run(['true'], check=True)\n", encoding="utf-8")
    _git(r, "commit", "-q", "-a", "--amend", "--no-edit")
    amended = _head(r)
    triage_cmd.cmd_triage(r, "HEAD")
    assert _queued_now(r).head == first, "precondition: the replacement was not queued"
    _git(r, "checkout", "-q", "main")
    assert _head(r) == base
    consumed = _recording(monkeypatch)

    assert cmd_drain([], dry_run=False) == 0

    assert consumed == [(base, amended)], (
        f"the drain consumed {consumed}, not {base[:7]}..{amended[:7]}, the "
        f"amended feature branch")


def test_a_branch_reset_back_to_its_base_is_not_drained_as_an_empty_range(
        tmp_path, seam, monkeypatch):
    """llm-review 4aa577a6, on the reflog cut: reset the queued commit's
    branch back to the base and re-commit the work on a new branch. The only
    branch whose reflog holds the head sits at the base, and taking its tip
    drained base..base. OPERATOR 2026-11-01 "Refuse an empty range": a tip at
    or behind the base is not taken, and the item is drained as queued."""
    r, base, first = _queued_script_commit(tmp_path, branch="feature")
    _git(r, "reset", "-q", "--hard", base)
    _git(r, "checkout", "-q", "-b", "elsewhere")
    _commit(r, "tools/run.py",
            "import subprocess\nsubprocess.run(['true'], check=True)\n", "redo")
    triage_cmd.cmd_triage(r, "HEAD")
    assert _queued_now(r).head == first, "precondition: the re-commit was not queued"
    consumed = _recording(monkeypatch)

    assert cmd_drain([], dry_run=False) == 0

    assert consumed == [(base, first)], (
        f"the drain consumed {consumed}, not {base[:7]}..{first[:7]} as queued: "
        f"feature's tip is the base")
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        reasons = [rs for e in led.events() if e.type is EventType.QUEUE_ITEM_COALESCED
                   for rs in e.payload.get("reasons", [])]
    finally:
        led.close()
    assert (f"rewritten: {first[:12]} is on no branch or tag, and no branch whose "
            f"reflog holds it (feature) has commits past its base; drained as queued"
            ) in reasons, reasons


def test_a_queued_commit_still_on_a_branch_is_drained_where_it_is(
        tmp_path, seam, monkeypatch):
    """The other limb: HEAD has moved to another branch, but main still holds
    the queued commit. Not an ancestor of HEAD is not rewritten away."""
    r, base, first = _queued_script_commit(tmp_path)
    _git(r, "checkout", "-q", "-b", "elsewhere", base)
    consumed = _recording(monkeypatch)

    assert cmd_drain([], dry_run=False) == 0

    assert consumed == [(base, first)]


def test_a_queued_commit_that_no_longer_exists_is_drained_as_queued(
        tmp_path, seam, monkeypatch):
    """Amended, then pruned: the commit object itself is gone, and so is
    every reflog entry that named it, so no branch can be shown to hold its
    replacement. Drained as queued -- what the drain did before it re-pointed
    anything -- with a reason saying why, instead of a guess."""
    r, base, first = _queued_script_commit(tmp_path)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        item = queue.queued_item(queue.materialize_queue(led.events()))
        led.append(Event(EventType.QUEUE_ITEM_COALESCED, "t-gone", "2026-11-01T11:18:00+00:00",
                         finding_id=item.id,
                         payload={"base": base, "head": "0" * 40, "score": item.score,
                                  "reasons": list(item.reasons)}))
    finally:
        led.close()
    assert _queued_now(r).head == "0" * 40
    consumed = _recording(monkeypatch)

    assert cmd_drain([], dry_run=False) == 0

    assert consumed == [(base, "0" * 40)]
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        reasons = [rs for e in led.events() if e.type is EventType.QUEUE_ITEM_COALESCED
                   for rs in e.payload.get("reasons", [])]
    finally:
        led.close()
    assert ("rewritten: 000000000000 is on no branch or tag, and no branch's reflog "
            "holds it; drained as queued") in reasons, reasons


def _amended_away(tmp_path):
    """Today's sequence up to the drain: queued, amended, replacement not queued."""
    r, base, first = _queued_script_commit(tmp_path)
    (r / "tools" / "run.py").write_text("import subprocess\n", encoding="utf-8")
    _git(r, "commit", "-q", "-a", "--amend", "--no-edit")
    triage_cmd.cmd_triage(r, "HEAD")
    assert _queued_now(r).head == first
    return r, base, first, _head(r)


def test_a_head_git_cannot_place_is_left_where_it_is(tmp_path, seam, monkeypatch):
    """`on_any_ref` answers None when git could not say. That is not "gone":
    the drain does not guess, and consumes the item as queued."""
    r, base, first, _amended = _amended_away(tmp_path)
    monkeypatch.setattr(drain_mod.gitutil, "on_any_ref", lambda root, sha: None)
    consumed = _recording(monkeypatch)

    assert cmd_drain([], dry_run=False) == 0

    assert consumed == [(base, first)]


def test_a_dead_head_checked_out_detached_is_not_re_pointed(tmp_path, seam, monkeypatch):
    """No branch holds it, but HEAD is it: someone is working on that commit.
    Nothing to re-point to, and no `rewritten` reason that would say so."""
    r, base, first = _queued_script_commit(tmp_path)
    _git(r, "checkout", "-q", "--detach")
    _git(r, "branch", "-q", "-f", "main", base)
    consumed = _recording(monkeypatch)

    assert cmd_drain([], dry_run=False) == 0

    assert consumed == [(base, first)]
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        reasons = [rs for e in led.events() if e.type is EventType.QUEUE_ITEM_COALESCED
                   for rs in e.payload.get("reasons", [])]
    finally:
        led.close()
    assert not [rs for rs in reasons if rs.startswith("rewritten:")], reasons


def test_an_empty_range_item_moves_its_base_with_its_head(tmp_path, seam, monkeypatch):
    """The re-test item is base == head (an empty range: only the re-test pass
    has work). Rewritten away, both ends move to the replacement, or the
    consumers would be handed the amend's diff as a range nobody queued."""
    r, base, first, amended = _amended_away(tmp_path)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        item = queue.queued_item(queue.materialize_queue(led.events()))
        led.append(Event(EventType.QUEUE_ITEM_COALESCED, "t-retest", "2026-11-01T11:19:00+00:00",
                         finding_id=item.id,
                         payload={"base": first, "head": first, "score": item.score,
                                  "reasons": [queue.pending_retest_reason(1)]}))
    finally:
        led.close()
    consumed = _recording(monkeypatch)

    assert cmd_drain([], dry_run=False) == 0

    assert consumed == [(amended, amended)]



# ------------------------------------------ the empty-queue re-test item ---
# Consumers run only on a popped item, so a repo with nothing queued never
# re-tested the survivors the gate flipped to `pending_retest`. The drain now
# synthesizes an item for exactly that repo, and nothing else.

def _quiet_repo_with_pending_rows(tmp_path, pending, open_=0):
    """A repo whose HEAD scores below `min_score` (nothing queued by the
    sweep) and whose ledger holds `pending` re-testable pending_retest
    mutation survivors plus `open_` open ones."""
    from aramid.models import Finding, Gate, Severity, Verdict
    r = _repo(tmp_path)
    _commit(r, "docs/readme.md", "hi\n", "benign HEAD")
    (r / ".aramid").mkdir()
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        ids = [f"{i:064x}" for i in range(pending + open_)]
        led.record_run("r1", "2026-09-01T00:00:00+00:00", "drain", {"mutation"}, {"calc.py"},
                       [Finding(id=fid, tool="mutation", rule="int-bound", severity_raw="medium",
                                severity=Severity.MEDIUM, verdict=Verdict.WARN, file="calc.py",
                                line=i + 2, message="mutant survived", evidence="", gate=Gate.ALL)
                        for i, fid in enumerate(ids)])
        for n, fid in enumerate(ids[:pending]):
            led.append(Event(EventType.FINDING_RESOLVED, "gate", f"2026-09-01T00:01:{n:02d}+00:00",
                             finding_id=fid,
                             payload={"auto_resolved": "gap_addressed", "pending_retest": True}))
    finally:
        led.close()
    return r


def test_an_empty_queue_with_pending_rows_drains_a_re_test_item(tmp_path, seam, fake_consumer):
    r = _quiet_repo_with_pending_rows(tmp_path, pending=2, open_=1)
    registry.register(r, "t0")

    rc = cmd_drain([], dry_run=False)

    assert rc == 0
    assert len(fake_consumer.calls) == 1, "the sweep queued nothing; the re-test item was popped"
    item = fake_consumer.calls[0]
    assert item.base == item.head, "an empty range: only the re-test pass has work"
    assert queue.is_pending_retest_item(item)
    assert "2 " in item.reasons[0]
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        events = led.events()
        assert any(e.type is EventType.QUEUE_ITEM_DRAINED for e in events)
        assert queue.queued_item(queue.materialize_queue(events)) is None
    finally:
        led.close()


def test_open_survivors_alone_leave_an_empty_queue_alone(tmp_path, seam, fake_consumer):
    r = _quiet_repo_with_pending_rows(tmp_path, pending=0, open_=2)
    registry.register(r, "t0")

    rc = cmd_drain([], dry_run=False)

    assert rc == 0
    assert fake_consumer.calls == []


def test_dry_run_previews_the_pending_re_tests_and_writes_nothing(
        tmp_path, seam, fake_consumer, capsys):
    r = _quiet_repo_with_pending_rows(tmp_path, pending=2)
    registry.register(r, "t0")
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        before = len(led.events())
    finally:
        led.close()

    rc = cmd_drain([], dry_run=True)

    assert rc == 0
    assert "pending_retests=2" in capsys.readouterr().out
    assert fake_consumer.calls == []
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert len(led.events()) == before
    finally:
        led.close()


def test_drain_bootstrap_sweeps_head_only(tmp_path, seam, fake_consumer):
    """Spec section 2 bootstrap rule: no triage history -> triage HEAD only,
    never the whole past."""
    r = _repo(tmp_path)
    _commit(r, "old_secret_config.py", "exec(1)\n", "old risky commit")
    _commit(r, "docs/readme.md", "hi\n", "benign HEAD")
    registry.register(r, "t0")
    cmd_drain([], dry_run=False)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        # benign HEAD scores novelty only (20 < 40): recorded, nothing queued,
        # and the risky OLD commit was never triaged
        assert queue.last_triaged_head(led) is not None
        assert queue.queued_item(queue.materialize_queue(led.events())) is None
        triage_events = [e for e in led.events() if e.type is EventType.TRIAGE_RECORDED]
        assert len(triage_events) == 1
    finally:
        led.close()


def test_drain_dry_run_writes_nothing(tmp_path, seam, fake_consumer):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    rc = cmd_drain([], dry_run=True)
    assert rc == 0
    assert fake_consumer.calls == []
    assert not (r / ".aramid" / "ledger.db").exists()


def test_drain_isolates_broken_repo_exit_2(tmp_path, seam, fake_consumer):
    good = _risky_repo(tmp_path, "good")
    registry.register(tmp_path / "vanished", "t0")  # path does not exist
    registry.register(good, "t0")
    rc = cmd_drain([], dry_run=False)
    assert rc == 2  # degraded: one repo skipped
    assert len(fake_consumer.calls) == 1  # good repo still drained


def test_a_dry_run_that_cannot_probe_a_repo_exits_2_like_the_drain(
        tmp_path, seam, fake_consumer, capsys):
    """The preview returned 0 whatever it skipped, so on 2026-10-30 it said
    nothing was wrong while every scheduled drain exited 2 over two vanished
    repos. It still previews the rest and still writes nothing."""
    good = _risky_repo(tmp_path, "good")
    registry.register(tmp_path / "vanished", "t0")  # path does not exist
    registry.register(good, "t0")

    rc = cmd_drain([], dry_run=True)

    out, err = capsys.readouterr()
    assert rc == 2
    assert "aramid drain: skipping " in err and "vanished" in err, err
    assert any(str(good) in ln and "(dry-run)" in ln for ln in out.splitlines()), out
    assert fake_consumer.calls == []
    assert not (good / ".aramid" / "ledger.db").exists()


def test_drain_isolates_repo_with_corrupt_config(tmp_path, seam, fake_consumer):
    broken = _risky_repo(tmp_path, "broken")
    (broken / "aramid.toml").write_text("this is not = valid toml [", encoding="utf-8")
    good = _risky_repo(tmp_path, "good")
    registry.register(broken, "t0")
    registry.register(good, "t0")
    rc = cmd_drain([], dry_run=False)
    assert rc == 2  # degraded, not a crash
    assert len(fake_consumer.calls) == 1  # the good repo still drained fully


def test_drain_lock_contention(tmp_path, seam, fake_consumer):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    lock = drain_mod._acquire_lock(600.0)
    assert lock is not None
    try:
        assert cmd_drain([], dry_run=False) == 3  # engine error: locked
        assert fake_consumer.calls == []
    finally:
        drain_mod._release_lock(lock)


def test_drain_respects_max_items(tmp_path, seam, fake_consumer):
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")
    assert cmd_drain([], dry_run=False, max_items=1) == 0
    assert len(fake_consumer.calls) == 1


# --- FIX 1: degraded consumer results must trip exit 2 and leave the item
#     queued for retry, not be swallowed like a silent "ok". -----------------

class _DegradedConsumer:
    NAME = "degraded"
    calls: list = []

    @classmethod
    def consume(cls, item, ctx):
        cls.calls.append(item)
        # Mirrors regression_pack.consume's real "degraded" case: semgrep
        # TIMEOUT/CRASHED/MISSING -- the ruleset was NOT fully evaluated.
        return ConsumerResult(consumer=cls.NAME, state="degraded",
                              note="semgrep timeout")


def test_drain_degraded_consumer_exits_2_and_leaves_item_queued(tmp_path, seam, monkeypatch):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    _DegradedConsumer.calls = []
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"degraded": _DegradedConsumer})

    rc = cmd_drain([], dry_run=False)

    assert rc == 2  # degraded consumer result must surface as exit 2, not 0
    assert len(_DegradedConsumer.calls) == 1
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        item = queue.queued_item(queue.materialize_queue(led.events()))
        # a not-fully-consumed item must NOT be marked drained -- it must
        # stay queued so the next drain retries it.
        assert item is not None
        assert item.state == queue.QUEUED
    finally:
        led.close()


# --- FIX 2: drain must record its narrow (pack-only) ruleset run with EMPTY
#     scope, so it can only ADD detections and never spuriously resolve an
#     open finding from a different (e.g. OWASP) ruleset that also uses
#     tool="semgrep" and happens to share a scanned file. -------------------

class _PackFakeConsumer:
    NAME = "fake"
    calls: list = []

    @classmethod
    def consume(cls, item, ctx):
        cls.calls.append(item)
        raw = RawFinding(tool="semgrep", rule="aramid-regression.block.deadbeef",
                         severity_raw="ERROR", file="src/api.py", line=1,
                         message="reintroduction")
        return ConsumerResult(consumer=cls.NAME, state="ok", findings=[raw])


def test_drain_pack_only_scan_does_not_resolve_unrelated_open_finding(tmp_path, seam, monkeypatch):
    # Order matters: bootstrap sweep triages HEAD only (spec section 2), so
    # the risky commit (the one that scores >= min_score and gets queued)
    # must be LAST, with the benign src/api.py commit first.
    r = _repo(tmp_path)
    _commit(r, "src/api.py", "def handler():\n    return 1\n", "api handler")
    _commit(r, "src/auth_login.py", "def f(x):\n    exec(x)\n", "risky")
    registry.register(r, "t0")

    # Seed a pre-existing OPEN OWASP-style semgrep finding in src/api.py --
    # a full gate detected it once; the drain (pack ruleset only) must never
    # touch it.
    ledger_path = r / ".aramid" / "ledger.db"
    led = Ledger(ledger_path)
    try:
        led.append(Event(EventType.FINDING_DETECTED, "seed-run",
                         "2020-01-01T00:00:00+00:00", finding_id="owasp-finding-1",
                         payload={"tool": "semgrep", "file": "src/api.py",
                                  "rule": "owasp-top-ten.a03", "verdict": "warn",
                                  "severity": "medium", "line": 1,
                                  "message": "owasp finding", "evidence": "",
                                  "historical": False}))
    finally:
        led.close()

    _PackFakeConsumer.calls = []
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": _PackFakeConsumer})

    rc = cmd_drain([], dry_run=False)
    assert rc == 0

    led = Ledger(ledger_path)
    try:
        state = led.open_findings()
        # the pre-existing OWASP finding must still be open: the drain's
        # narrow pack ruleset never re-detected it and must not resolve it
        assert state["owasp-finding-1"]["status"] == "open"
        # the pack finding itself was still detected
        assert any(rec.get("rule") == "aramid-regression.block.deadbeef"
                   for rec in state.values())
    finally:
        led.close()


def test_consumer_extra_merged_into_event_payload(tmp_path, monkeypatch):
    """ConsumerResult.extra rides into the CONSUMER_RUN_FINISHED payload;
    core keys are never overridden by extra."""
    from aramid.commands import drain as drain_mod
    from aramid.ledger import Ledger
    from aramid.models import EventType
    from aramid.queue import QueueItem

    led = Ledger(tmp_path / "l.db")
    fake = SimpleNamespace(consume=lambda item, ctx: ConsumerResult(
        consumer="fake", state="ok",
        extra={"selection": {"served": {"provider": "p"}},
               "note": "MUST NOT WIN"}))
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": fake})
    item = QueueItem(id="q1", base=None, head="h", score=50, reasons=(),
                     state="queued", created_at="2026-07-18T00:00:00+00:00",
                     updated_at="2026-07-18T00:00:00+00:00")
    try:
        ok = drain_mod._consume_item(tmp_path, SimpleNamespace(llm={}), led,
                                     item, lambda: "2026-07-18T00:00:00+00:00")
        assert ok is True
        evs = [e for e in led.events()
               if e.type is EventType.CONSUMER_RUN_FINISHED]
    finally:
        led.close()
    assert evs[0].payload["selection"] == {"served": {"provider": "p"}}
    assert evs[0].payload["note"] == ""          # core key wins over extra


def test_drain_rolls_up_autolearn_state(tmp_path, monkeypatch, recent_iso):
    """cmd_drain folds drained repos' selection events into the (test-
    isolated) machine-global state; a rollup failure never fails the drain."""
    import json as json_mod

    from aramid import autolearn, config as config_mod, gitutil, queue
    from aramid.commands import drain as drain_mod
    from aramid.ledger import Ledger

    repo = tmp_path / "repo"
    repo.mkdir()

    def _git(*a):
        return subprocess.run(["git", *a], cwd=repo, check=True,
                              capture_output=True, text=True)
    _git("init", "-q", "-b", "main")
    _git("config", "user.email", "t@t")
    _git("config", "user.name", "t")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git("add", ".")
    _git("commit", "-m", "c1")
    (repo / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")

    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")
    monkeypatch.setattr(drain_mod, "_lock_path",
                        lambda: tmp_path / "drain.lock")
    monkeypatch.setattr(drain_mod, "_sweep", lambda *a, **k: None)

    led = Ledger(repo / ".aramid" / "ledger.db")
    try:
        queue.enqueue(led, recent_iso, None,
                      gitutil.rev_sha(repo, "HEAD"), 50, ["risky"])
    finally:
        led.close()

    fake = SimpleNamespace(consume=lambda item, ctx: ConsumerResult(
        consumer="fake", state="ok",
        extra={"selection": {
            "target_tier": "cheap", "bucket": "plain",
            "served": {"tier": "cheap", "provider": "p", "model": "m",
                       "effort": ""},
            "attempts": [], "uplift": {"mode": "shadow", "pick": "cheap",
                                       "applied": False, "sampled_q": 0.1},
            "cascade": {"triggered": False, "trigger": None,
                        "applied": False},
            "audit": {"performed": True, "tier": "frontier",
                      "new_findings": 0, "missed_criticals": 0},
            "refutes": [], "hallucination_rejected": 0,
            "tokens": {"in": 1, "out": 1}}}))
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": fake})

    assert drain_mod.cmd_drain([str(repo)]) == 0

    state = json_mod.loads(autolearn.state_path().read_text(encoding="utf-8"))
    assert state["audits"]["performed"] == 1
    assert state["posteriors"]["p/m|cheap|plain"]["clean"] == 1
    assert list(state["cursors"].values())[0] > 0


# ---- a consumer that proved nothing still records that it looked (round 180) ---

class _LookedConsumer:
    """An empty repair claim that names what the run examined."""
    NAME = "fake"

    @classmethod
    def consume(cls, item, ctx):
        from aramid.consumers.base import Repaired
        return ConsumerResult(consumer=cls.NAME, state="ok",
                              repaired=Repaired(tool="mutation", reason="mutant_killed",
                                                ids=(), examined=("f" * 64,)))


def test_an_empty_repair_claim_still_yields_what_the_consumer_examined(tmp_path, seam, monkeypatch):
    """The drain handed the ledger a claim only when it had ids, so a
    completed run that killed nothing wrote no `mutant_killed` yield and a
    consumer's census read NEVER RAN forever (interop round 180)."""
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": _LookedConsumer})

    assert cmd_drain([], dry_run=False) == 0

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        ys = [e for e in led.events() if e.type is EventType.RESOLVER_YIELD
              and e.payload.get("resolver") == "mutant_killed"]
    finally:
        led.close()
    assert len(ys) == 1, "an empty claim is still a run that looked"
    assert (ys[0].payload["tool"], ys[0].payload["considered"],
            ys[0].payload["resolved"]) == ("mutation", 1, 0)


# ------------------------- an item left behind is deferred, and goes first ---
# Interop round 177: two repos with tied scores; the drain-wide budget was
# spent by the first item (checked only BETWEEN items), the second was never
# opened, and the same order would repeat at every scheduled drain.

def _ticks(*values):
    """A scripted clock for `cmd_drain(monotonic=...)`: one value for
    `started`, then one per between-items check."""
    it = iter(values)
    return lambda: next(it)


def _head(r):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, check=True,
                          capture_output=True, text=True).stdout.strip()


def _deferrals(r):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        evs = [e for e in led.events() if e.type is EventType.QUEUE_ITEM_DEFERRED]
        item = queue.queued_item(queue.materialize_queue(led.events()))
    finally:
        led.close()
    return evs, item


def test_budget_stop_defers_the_left_items_in_their_own_ledgers(tmp_path, seam, fake_consumer):
    from aramid.fingerprint import normalize_path
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")

    # started; r1's check passes; r2's check finds the budget gone
    assert cmd_drain([], dry_run=False, monotonic=_ticks(0.0, 0.0, 10_000.0)) == 0

    assert [c.head for c in fake_consumer.calls] == [_head(r1)], "equal scores: registry order"
    evs, item = _deferrals(r2)
    assert len(evs) == 1 and evs[0].finding_id == item.id
    assert evs[0].payload["reason"] == "drain budget"
    assert evs[0].payload["after"] == [normalize_path(str(r1))]
    assert (evs[0].payload["elapsed_s"], evs[0].payload["budget_s"]) == (10_000, 600.0)
    assert (item.deferred, item.deferred_reason) == (1, "drain budget")
    evs1, _ = _deferrals(r1)
    assert evs1 == [], "the item that WAS opened is not deferred"


def test_a_deferred_item_is_opened_first_next_time(tmp_path, seam, fake_consumer):
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")
    cmd_drain([], dry_run=False, monotonic=_ticks(0.0, 0.0, 10_000.0))   # r1 drained, r2 deferred
    _commit(r1, "src/auth_login2.py", "def g(x):\n    exec(x)\n", "risky again")  # r1 re-queues
    fake_consumer.calls = []

    assert cmd_drain([], dry_run=False, monotonic=_ticks(0.0, 0.0, 0.0)) == 0

    heads = [c.head for c in fake_consumer.calls]
    assert heads[0] == _head(r2), "the deferred item goes first, whatever the scores"
    assert len(heads) == 2


def test_item_limit_defers_with_its_own_reason(tmp_path, seam, fake_consumer):
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")

    assert cmd_drain([], dry_run=False, max_items=1) == 0

    evs, item = _deferrals(r2)
    assert len(evs) == 1 and evs[0].payload["reason"] == "item limit"
    assert item.deferred == 1


def test_dry_run_names_the_deferral(tmp_path, seam, fake_consumer, capsys):
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")
    cmd_drain([], dry_run=False, monotonic=_ticks(0.0, 0.0, 10_000.0))
    capsys.readouterr()

    assert cmd_drain([], dry_run=True) == 0

    lines = [ln for ln in capsys.readouterr().out.splitlines() if "(dry-run)" in ln]
    assert any(str(r2) in ln and "deferred=1 (drain budget)" in ln for ln in lines), lines
    assert any(str(r1) in ln and "deferred" not in ln for ln in lines), lines


# --- leftover sweep (what dead consumers left in the temp dir) -------------

def _old_shell(temp, name):
    shell = temp / name
    (shell / "wt").mkdir(parents=True)
    then = time.time() - 24 * 3600
    os.utime(shell, (then, then))
    return shell


def test_drain_removes_what_dead_consumers_left_in_the_temp_dir(
        tmp_path, seam, fake_consumer, monkeypatch, capsys):
    from aramid import leftovers
    temp = tmp_path / "temp"
    monkeypatch.setattr(leftovers, "temp_root", lambda: temp)
    shell = _old_shell(temp, "aramid-mut-dead1234")
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")

    assert cmd_drain([], dry_run=False) == 0

    assert not shell.exists()
    assert "removed 1 leftover worktree dir(s)" in capsys.readouterr().out


def test_drain_dry_run_counts_leftovers_and_keeps_them(
        tmp_path, seam, fake_consumer, monkeypatch, capsys):
    from aramid import leftovers
    temp = tmp_path / "temp"
    monkeypatch.setattr(leftovers, "temp_root", lambda: temp)
    shell = _old_shell(temp, "aramid-red-dead1234")
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")

    assert cmd_drain([], dry_run=True) == 0

    assert shell.exists()
    assert " leftovers=1" in capsys.readouterr().out
