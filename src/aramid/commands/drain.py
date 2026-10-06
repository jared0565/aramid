"""aramid drain -- iterate the registry, catch-up-sweep, pop queued items
by score, hand them to consumers, record everything (spec section 2).

Exit codes reuse the Phase 1 contract: 0 ok, 2 degraded (some repo or
consumer failed; the rest completed), 3 engine error (lock held, registry
unusable). Singleton lock at ~/.aramid/drain.lock: JSON {pid, started_at};
stale when the PID is dead OR the lock is older than 2x the wall-clock
budget (spec section 6).

Hard deadline (FN-14): `[drain].hard_deadline_s` (default 90 minutes,
aramid.drain_limits) after the lock is taken, `_Watchdog` stops the drain
from inside -- a `degraded` row for the running consumer, its children
killed, the lock released, exit 2. The item stays queued."""
import contextlib
import functools
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from aramid import __version__
from aramid import autolearn
from aramid import config as config_mod
from aramid import drain_limits
from aramid import fleet, health
from aramid import gitutil, leftovers, policy, queue, redact, registry, triage
from aramid import ledger as ledger_mod
from aramid.commands import schedule as schedule_mod
from aramid.consumers import base as consumers_base
from aramid.consumers.base import CONSUMERS, ConsumerResult, DrainContext
from aramid.fingerprint import normalize_path
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Gate
from aramid.normalizer import normalize
from aramid.runners import base as runners_base

try:
    import msvcrt   # the drain lock's mutex on Windows (FN-19)
except ImportError:
    msvcrt = None
try:
    import fcntl    # ... and everywhere else
except ImportError:
    fcntl = None

import aramid.consumers.regression_pack  # noqa: F401  -- registers the consumer
from aramid.consumers import llm_review as _llm_review  # noqa: F401  (registers itself)
from aramid.consumers import mutation as _mutation  # noqa: F401  (registers itself)
from aramid.consumers import fuzz as _fuzz  # noqa: F401  (registers itself)
from aramid.consumers import js_mutation as _js_mutation  # noqa: F401  (registers itself)
from aramid.consumers import dast as _dast  # noqa: F401  (registers itself)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lock_path() -> Path:
    """Seam for tests."""
    return Path.home() / ".aramid" / "drain.lock"


def _pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        # S603/S607 justification: fixed argv querying our own recorded
        # PID via the standard Windows tasklist binary.
        # errors="replace" only -- tasklist emits the console/ANSI codepage,
        # NOT UTF-8; the str(pid) containment check below is pure ASCII, which
        # decodes identically under any locale codec. Forcing UTF-8 here would
        # trade one mojibake for another; "replace" removes only the crash mode.
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],  # noqa: S603,S607
                             capture_output=True, text=True, errors="replace")
        return str(pid) in out.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# FN-15: how long past its recorded deadline a lock whose pid still lives is
# held. The watchdog's own exit (row, kill, release) is bounded at seconds;
# a pid still holding the lock minutes after that is not a drain.
_LOCK_MARGIN_S = 300.0


def _write_lock(p: Path, data: dict) -> None:
    """Replace, never truncate-and-write: a drain reading the lock mid-write
    would find it unreadable, call it stale and break it."""
    tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, p)


def _read_own_lock(p: Path) -> dict | None:
    """The lock's contents when this process holds it, else None."""
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError, OSError):
        return None
    return data if isinstance(data, dict) and data.get("pid") == os.getpid() else None


_WIN = sys.platform == "win32"
# FN-19: how long a drain waits for the lock's mutex, and how often it asks.
# A critical section is a read, a pid probe (`tasklist` on Windows: seconds
# at worst) and a write; a mutex held past this is a process hung inside
# one, and a drain that cannot have it starts nothing and removes nothing.
_MUTEX_TIMEOUT_S = 30.0
_MUTEX_POLL_S = 0.05
_sleep = time.sleep     # seam: the poll's wait
_BAD_FD = (OSError, ValueError, OverflowError)


def _try_lock(fd: int) -> bool:
    """One non-blocking try at the OS lock on the mutex file. `flock`, not
    `lockf`: POSIX record locks do not conflict within one process, and a
    drain's watchdog thread takes the mutex too. On Windows one byte at
    offset 0 -- an empty file locks past its end. A bad fd is a lock not had,
    never a raise: CPython says so as OSError, ValueError (a negative fd) or
    OverflowError (outside a C int) -- fuzz 5adab94c."""
    try:
        if _WIN:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except _BAD_FD:
        return False
    return True


def _unlock(fd: int) -> None:
    """Release explicitly: Windows frees a lock on close only eventually. A
    failed unlock is not raised: the caller closes the fd next, and closing
    releases the lock regardless."""
    with contextlib.suppress(*_BAD_FD):
        if _WIN:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)


@contextlib.contextmanager
def _lock_mutex(lock: Path):
    """Hold the OS lock on `<lock>.mutex` for one critical section (FN-19),
    yielding whether it was had: taking the drain lock, releasing it, and
    re-dating it are each a check-then-act, and two drains -- or a drain's
    main thread and its watchdog -- interleaved in one of them ran side by
    side or deleted each other's lock. Tried once, then every
    `_MUTEX_POLL_S` until `_MUTEX_TIMEOUT_S`. The mutex file is NEVER
    deleted: unlinking a file another process has open and locked is how a
    third process ends up locking a different file. Not re-entrant, even in
    one process: a second handle conflicts, so critical sections stay flat."""
    path = lock.with_name(f"{lock.name}.mutex")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT)
    try:
        held = _try_lock(fd)
        for _ in range(round(_MUTEX_TIMEOUT_S / _MUTEX_POLL_S)):
            if held:
                break
            _sleep(_MUTEX_POLL_S)
            held = _try_lock(fd)
        try:
            yield held
        finally:
            if held:
                _unlock(fd)
    finally:
        os.close(fd)


def _acquire_lock(deadline_s: float, *, now: Callable[[], float] = time.time) -> Path | None:
    """Take the drain lock, recording the deadline this drain is armed with
    (FN-15). A lock is held while its pid lives and it is younger than ITS
    OWN recorded deadline plus a margin -- the holder's, not the asker's. A
    lock with no deadline (an aramid <= 0.19.1 wrote it) reads as the
    default one; a lock with no pid or no start is unreadable, so stale --
    never `_pid_alive(-1)`, which on POSIX asks about every process. The
    check and the write are one critical section (FN-19): two drains that
    both saw no lock, or both judged one stale, both ran. A mutex that
    cannot be had starts no drain."""
    p = _lock_path()
    with _lock_mutex(p) as held:
        if not held:
            return None
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                age = now() - float(data["started_at"])
                held_for = float(data.get("deadline_s", drain_limits.DEFAULT_HARD_DEADLINE_S))
                if _pid_alive(int(data["pid"])) and age < held_for + _LOCK_MARGIN_S:
                    return None  # genuinely held
                print("aramid: drain: breaking stale lock", file=sys.stderr)
            except (json.JSONDecodeError, ValueError, OSError, KeyError, TypeError,
                    AttributeError):
                pass  # unreadable lock is stale
        _write_lock(p, {"pid": os.getpid(), "started_at": now(),
                        "deadline_s": float(deadline_s)})
        return p


def _release_lock(p: Path) -> None:
    """Remove the lock only if this process holds it (FN-15): a drain that
    outlived its lock must not delete the next drain's. "Is it mine?" and
    the unlink are one critical section (FN-19): read mine, a newer drain
    breaks it as stale, unlink -- and the newer drain's lock was gone. A
    mutex that cannot be had removes nothing; a lock whose pid has died is
    broken as stale by the next drain. The watchdog's exit calls this too,
    so its wait for the mutex is bounded by `_MUTEX_TIMEOUT_S`."""
    with _lock_mutex(p) as held:
        if not held or _read_own_lock(p) is None:
            return
        try:
            p.unlink()
        except OSError:
            pass


def _bounded(fn: Callable[[], object], timeout_s: float) -> None:
    """Run `fn` on a daemon thread and wait at most `timeout_s`. At the
    deadline nothing may turn into a second hang: a ledger that never
    answers or a taskkill that never returns is abandoned, not awaited."""
    def run():
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 -- best effort at a deadline
            print(f"aramid drain: at the hard deadline: {exc}", file=sys.stderr)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout_s)


# FN-16: deadline kills of one consumer on one item, at one head and under
# one deadline, before it gives up -- the same three as the other give-ups
# (consumers.mutation._BASELINE_GIVE_UP).
_DEADLINE_GIVE_UP = 3


def deadline_note_prefix(deadline_s: float, head: str) -> str:
    """The note family for "stopped at the drain's hard deadline", and a
    CONTRACT: the give-up in `_consume_item` counts rows by it. It carries
    the two things that deserve a fresh try -- a new commit, and a deadline
    the operator raised -- so the advice the give-up prints can work."""
    return (f"stopped at the drain's hard deadline ([drain].hard_deadline_s = "
            f"{deadline_s:g}) (last seen @ {head[:12]})")


def deadline_note(deadline_s: float, head: str, elapsed_s: float) -> str:
    """The deadline row's whole note: the counted prefix, then the rest."""
    return (f"{deadline_note_prefix(deadline_s, head)}, {elapsed_s:.0f} s into the drain; "
            "the item stays queued")


def _deadline_give_up_note(consumer: str, deadline_s: float, head: str) -> str:
    return (f"{consumer} giving up: stopped at the drain's hard deadline "
            f"{_DEADLINE_GIVE_UP} times ([drain].hard_deadline_s = {deadline_s:g}, "
            f"last seen @ {head[:12]}) -- raise [drain].hard_deadline_s or narrow what "
            f"{consumer} runs; a new commit gets a fresh try")


class _Watchdog:
    """The drain's hard deadline (FN-14). A daemon thread that, once the
    deadline falls due, does what an outside kill cannot: writes a
    `degraded` CONSUMER_RUN_FINISHED row for the consumer in flight (so
    consumer health sees the run), kills the children the launchers have
    registered and closes the registry so a looping consumer cannot start
    another (runners.base.kill_live), releases the lock, and ends the
    process with exit 2 -- `os._exit`, because the main thread is inside a
    consumer that will not return. The item is never marked drained, so it
    stays queued.

    One mutex orders it against the main thread: `begin` names the
    consumer about to run, `finishing` holds the mutex while that
    consumer's own rows are written and clears it, so a deadline in that
    window waits and then finds nothing in flight -- never two rows for
    one run. `cancel` takes the same mutex, so a drain that finishes as
    the deadline falls due either exits normally or is stopped, not both.

    Its clock is its own `time.monotonic`, never `cmd_drain`'s injected
    one: tests drive that one to exhaust the between-items budget, and a
    watchdog reading it would fire in them. `monotonic` exists so a test
    can park it exactly on the deadline; `cmd_drain` never passes it."""

    def __init__(self, deadline_s: float, *, lock: Path, clock: Callable[[], str] = _now,
                 exit_: Callable[[int], object] = os._exit,
                 kill: Callable[[], object] | None = None,
                 open_ledger: Callable[[Path], Ledger] | None = None,
                 poll_s: float = 0.5, write_timeout_s: float = 15.0,
                 monotonic: Callable[[], float] = time.monotonic):
        self._monotonic = monotonic
        self._t0 = monotonic()
        self._deadline_s = float(deadline_s)
        self._lock = lock
        self._clock = clock
        self._exit = exit_
        self._kill = kill if kill is not None else (lambda: runners_base.kill_live(close=True))
        self._open_ledger = open_ledger or (lambda root: Ledger(root / ".aramid" / "ledger.db"))
        self._poll_s = poll_s
        self._write_timeout_s = write_timeout_s
        self._mutex = threading.Lock()
        self._stop = threading.Event()
        self._in_flight: tuple | None = None
        self._pending: tuple = (None, [], [])
        self._thread = threading.Thread(target=self._run, name="aramid-drain-deadline",
                                        daemon=True)

    @property
    def deadline_s(self) -> float:
        return self._deadline_s

    def start(self) -> None:
        self._thread.start()

    def pending(self, run_id: str, items: list, after: list) -> None:
        """FN-16: the (root, item id) pairs the drain has not opened yet,
        and the roots it has. At the deadline each gets the DEFERRED row the
        drain's own budget stop would have written, so the next drain opens
        them before the item that ran into the deadline."""
        with self._mutex:
            self._pending = (run_id, list(items), list(after))

    def set_deadline(self, deadline_s: float) -> None:
        """Seconds from this watchdog's start. Armed at the default before
        any config is read, then set from the candidates' configs. The lock
        records the new deadline too (FN-15): another drain judges this
        one's lock by it."""
        self._deadline_s = float(deadline_s)
        with _lock_mutex(self._lock) as held:     # FN-19: read and rewrite, as one
            data = _read_own_lock(self._lock) if held else None
            if data is not None:
                with contextlib.suppress(OSError):
                    _write_lock(self._lock, {**data, "deadline_s": self._deadline_s})

    def begin(self, root: Path, item_id: str, consumer: str, run_id: str, head: str) -> None:
        with self._mutex:
            self._in_flight = (root, item_id, consumer, run_id, self._monotonic(), head)

    @contextlib.contextmanager
    def finishing(self):
        with self._mutex:
            self._in_flight = None
            yield

    def cancel(self) -> None:
        with self._mutex:
            self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(self._poll_s):
            if self._monotonic() - self._t0 >= self._deadline_s:
                self._fire()
                return

    def _record(self, flight: tuple, elapsed: float) -> None:
        root, item_id, consumer, run_id, began, head = flight
        led = self._open_ledger(root)
        try:
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, run_id, self._clock(), payload={
                "consumer": consumer, "item_id": item_id, "state": "degraded",
                "duration_s": round(self._monotonic() - began, 3), "cost": 0.0,
                "finding_count": 0,
                "note": deadline_note(self._deadline_s, head, elapsed)}))
        finally:
            led.close()

    def _defer(self, root: Path, item_id: str, run_id: str, after: list,
               elapsed: float) -> None:
        led = self._open_ledger(root)
        try:
            queue.mark_deferred(led, item_id, run_id, self._clock(), reason="drain deadline",
                                after=after, elapsed_s=int(elapsed), budget_s=self._deadline_s)
        finally:
            led.close()

    def _fire(self) -> None:
        with self._mutex:
            if self._stop.is_set():
                return
            self._stop.set()
            elapsed = self._monotonic() - self._t0
            flight = self._in_flight
            run_id, items, after = self._pending
            if flight is not None:
                _bounded(lambda: self._record(flight, elapsed), self._write_timeout_s)
                in_flight = normalize_path(str(flight[0]))
                if in_flight not in after:
                    after = [*after, in_flight]
            # One bound per repo: a ledger that never answers in one must not
            # cost another its row. `items` never holds the item in flight --
            # it was opened, and deferring it would keep it first.
            for root, item_id in items:
                _bounded(functools.partial(self._defer, root, item_id, run_id, after, elapsed),
                         self._write_timeout_s)
            what = f"{flight[2]} on {flight[0]}" if flight is not None else "no consumer"
            print(f"aramid drain: hard deadline reached after {elapsed:.0f} s "
                  f"([drain].hard_deadline_s = {self._deadline_s:g}); stopped {what}; "
                  "the item stays queued", file=sys.stderr)
            _bounded(self._kill, self._write_timeout_s)
            _release_lock(self._lock)
            for stream in (sys.stdout, sys.stderr):
                with contextlib.suppress(Exception):   # a closed stream cannot stop the exit
                    stream.flush()
            self._exit(2)


def _sweep_anchor(root: Path, ledger, head: str) -> str | None:
    """The newest triaged head in HISTORY, not merely in the ledger. A manual
    `aramid triage <old-range>` writes a row whose head is an ancestor of one
    already triaged; anchoring on the last row then re-triages everything
    since that old head and coalesces it into the queued item (2026-09-06
    14:58Z: the consumer spent its whole mutant budget on the wrong file).
    Walk newest-first; a head that descends from the best so far replaces
    it; stop as soon as HEAD itself is seen. In the common case the newest
    row IS HEAD and git is never asked. Rows beyond `limit` fall back to the
    newest row, as before."""
    best = None
    for h in queue.triaged_heads_newest_first(ledger):
        if h == head:
            return head
        if best is None or gitutil.is_ancestor(root, best, h):
            best = h
    return best


def _sweep(root: Path, cfg, ledger, at: str) -> None:
    head = gitutil.rev_sha(root, "HEAD")
    if head is None:
        return  # empty repo: nothing to triage
    last = _sweep_anchor(root, ledger, head)
    if last == head:
        return
    if last is None:
        # Bootstrap rule (spec section 2): first contact triages HEAD only.
        triage.run_triage(root, cfg, ledger, gitutil.first_parent(root, head), head, at)
    else:
        triage.run_triage(root, cfg, ledger, last, head, at)


def _pending_retest_item(root: Path, cfg, ledger, at: str) -> queue.QueueItem | None:
    """The EMPTY-QUEUE re-test item. Consumers run only on a popped item,
    so a repo with nothing queued never re-tested the mutation survivors
    the gate had flipped to `pending_retest` on a push: the gate said "a
    push addressed this gap" and, with no further commit, nothing ever
    verified it (2026-09-10: three rows sat pending after a drain and
    closed only by a hand-run `triage HEAD` + `drain --repo .`).

    Called only when the queue is empty. Enqueues one item -- base == head
    == HEAD, so every consumer sees an empty range and only the mutation
    consumer's re-test pass has work; scored at `min_score` so the
    drain's own filter admits it; one reason carrying the marker the
    consumer keys on. Not when: the consumer or its re-test knob is off;
    no pending row is re-testable under the consumer's own eligibility
    (suppressed, or nothing to regenerate from -- an item for those would
    cut a worktree to re-test nothing); or the mutation consumer has
    STOOD DOWN here (a give-up returns `ok` and would again, every four
    hours, forever); or every pending row has more occurrences at HEAD than
    the item's budget can test (`unfittable_pending`): the claim is atomic,
    so the consumer would skip each one unspent after paying for a baseline
    -- 13 minutes per drain on this repo for ad415f34, eleven identical
    lines against a room of 3 (2026-10-05). `aramid status` names those
    rows. Rows a re-test kills go `fixed`; rows that survive are re-reported
    open and stop triggering; rows a timeout or the cap left pending get the
    next drain. Never raises past the caller's per-repo isolation."""
    if not _mutation.retests_enabled(cfg):
        return None
    pending = _mutation.pending_retests(ledger, root)
    if not pending:
        return None
    if any(f.name == _mutation.NAME for f in health.stood_down(ledger)):
        return None
    unfittable = {fid for fid, _rel, _need in _mutation.unfittable_pending(ledger, root, cfg)}
    fitting = [p for p in pending if p[0] not in unfittable]
    if not fitting:
        return None
    head = gitutil.rev_sha(root, "HEAD")
    if head is None:
        return None
    return queue.enqueue(ledger, at, head, head, int(cfg.triage.get("min_score", 40)),
                         [queue.pending_retest_reason(len(fitting))])


def _sweep_leftovers(root: Path, *, dry_run: bool) -> leftovers.Sweep:
    """Hygiene, never a failure: the shells and stale worktree registrations
    that killed consumers left behind (see aramid.leftovers). Removed ones
    are said on stdout, ones that would not go on stderr; nothing here
    degrades the drain or reaches the ledger."""
    try:
        report = leftovers.sweep(root, dry_run=dry_run)
    except Exception as exc:
        print(f"aramid drain: {root}: leftover sweep skipped: {exc}", file=sys.stderr)
        return leftovers.Sweep()
    if not dry_run and report.removed:
        print(f"aramid drain: {root}: removed {len(report.removed)} leftover worktree dir(s)")
    if report.failed:
        print(f"aramid drain: {root}: {len(report.failed)} leftover dir(s) would not go: "
              + ", ".join(report.failed), file=sys.stderr)
    return report


def _stopped_at_the_deadline_too_often(ledger, consumer: str, item,
                                       watchdog: "_Watchdog | None") -> bool:
    """FN-16: this consumer ran into the drain's hard deadline on this item,
    at this head and under this deadline, `_DEADLINE_GIVE_UP` times. A
    fourth try would only be killed again, holding the item in the queue;
    giving up is `ok`, so the item drains and `status` names the stand-down.
    No watchdog, no deadline: nothing to give up on."""
    if watchdog is None:
        return False
    prefix = deadline_note_prefix(watchdog.deadline_s, item.head)
    return consumers_base.prior_note_count(ledger, consumer, item.id, prefix) >= _DEADLINE_GIVE_UP


def _consume_item(root: Path, cfg, ledger, item, clock,
                  watchdog: "_Watchdog | None" = None) -> bool:
    """Run every enabled consumer against one queue item. Returns True if
    all consumers finished without error state. `watchdog` (FN-14) is told
    which consumer is running, and holds off while that run's rows are
    written."""
    ok = True
    run_id = uuid.uuid4().hex
    salt = redact.load_or_create_salt(root / ".aramid")

    def finishing():
        return watchdog.finishing() if watchdog is not None else contextlib.nullcontext()
    for name, module in CONSUMERS.items():
        started = time.monotonic()
        if _stopped_at_the_deadline_too_often(ledger, name, item, watchdog):
            result = ConsumerResult(consumer=name, state="ok", note=_deadline_give_up_note(
                name, watchdog.deadline_s, item.head))
        else:
            if watchdog is not None:
                watchdog.begin(root, item.id, name, run_id, item.head)
            try:
                result = module.consume(item, DrainContext(root=root, cfg=cfg,
                                                            ledger=ledger, clock=clock))
            except Exception as exc:
                result = ConsumerResult(consumer=name, state="error", note=str(exc))
        duration = time.monotonic() - started
        findings = []
        if result.findings:
            pin = getattr(module, "PIN_OCCURRENCE", False)
            findings = normalize(result.findings, root, lambda f: item.head, salt,
                                 Gate.ALL, functools.partial(policy.classify, cfg=cfg),
                                 pin_occurrence=pin)
        # Every row this run writes, under the watchdog's mutex: a deadline
        # falling due in here waits, then finds nothing in flight -- the run
        # is recorded once, here, never twice.
        with finishing():
            _record_consumer_run(ledger, run_id, clock, name, item, result,
                                 findings, duration)
        if result.state in ("error", "degraded"):
            ok = False
    # A not-fully-consumed item (any consumer errored or degraded, e.g. a
    # semgrep TIMEOUT/CRASHED/MISSING run of the pack ruleset) must NOT be
    # marked drained: that would drop it from the queue with no retry,
    # letting a bypassed reintroduction escape the backstop. Only mark it
    # drained once every consumer finished cleanly.
    if ok:
        # Name the head consumed: a commit that landed during this run has
        # coalesced past it and must stay queued (queue.materialize_queue).
        with finishing():
            queue.mark_drained(ledger, item.id, run_id, clock(), head=item.head)
    return ok


def _record_consumer_run(ledger, run_id, clock, name, item, result, findings,
                         duration) -> None:
    """One consumer run's rows: its detections, its repair claim, and the
    CONSUMER_RUN_FINISHED row consumer health is built from."""
    if result.findings:
        # The drain runs a narrow ruleset (pack only) -- record detections
        # but resolve NOTHING. Pack and OWASP findings both use
        # tool="semgrep", so a scope of {semgrep}x{scanned files} would
        # still spuriously resolve an open OWASP finding the pack
        # ruleset never re-detects. Only a full gate, which examines the
        # complete ruleset, may resolve. Empty scope makes
        # record_run's resolve loop match nothing; FINDING_DETECTED for
        # the pack findings still fires (detection doesn't depend on
        # scope).
        ledger.record_run(run_id, clock(), "drain", set(), set(), findings,
                          head=item.head)
    # ...and the empty scope above is exactly why this exists. Scope-based
    # resolution INFERS repair from absence, which a narrow ruleset cannot
    # support. A `repaired` claim is the opposite: the consumer re-derived
    # those specific fingerprints and disproved them (mutation re-mutates
    # the same line and the suite kills it). Nothing is inferred from
    # silence, so the reason the scope is empty does not apply.
    #
    # This is the authoritative half of a pair, not a replacement:
    # `mutation_gate.auto_resolve_mutation` resolves at the GATE on intent
    # (source touched, or a `test_<module>.py` added) so a dev is not
    # blocked, and names this re-drain as its backstop. The backstop could
    # only ever re-REPORT; here it can also CONFIRM.
    #
    # Any claim, INCLUDING an empty one: a producer that examined the
    # recorded survivors and killed none still gets its yield row
    # (`considered N, resolved 0`), which the census grades as an
    # outcome. Handing the ledger a claim only when it had ids meant a
    # consumer whose runs never killed a recorded survivor read
    # `mutant_killed NEVER RAN` forever (interop round 180).
    if result.repaired is not None:
        ledger_mod.resolve_repaired(ledger, run_id, clock(),
                                    tool=result.repaired.tool,
                                    reason=result.repaired.reason,
                                    ids=result.repaired.ids,
                                    present_ids={f.id for f in findings},
                                    examined=getattr(result.repaired, "examined", ()))
    payload = {"consumer": name, "item_id": item.id,
               "state": result.state,
               "duration_s": round(duration, 3),
               "cost": result.cost,
               "finding_count": len(findings),
               "note": result.note}
    for key, value in (result.extra or {}).items():
        payload.setdefault(key, value)
    ledger.append(Event(EventType.CONSUMER_RUN_FINISHED, run_id, clock(),
                        payload=payload))

def cmd_drain(targets: list, *, dry_run: bool = False, max_items: int | None = None,
              clock: Callable[[], str] = _now,
              monotonic: Callable[[], float] = time.monotonic) -> int:
    if targets:
        repos = [Path(t) for t in targets]
    else:
        try:
            repos = [Path(e["path"]) for e in registry.load_registry(strict=True)]
        except registry.RegistryUnusable as exc:
            # Not an empty fleet: read as one, the scheduled drain would
            # exit 0 on every run and never drain again.
            print(f"aramid: drain: registry unusable -- {exc}", file=sys.stderr)
            return 3
    if not repos:
        print("aramid drain: no repos registered and none given", file=sys.stderr)
        return 0

    lock = None
    if not dry_run:
        lock = _acquire_lock(drain_limits.DEFAULT_HARD_DEADLINE_S)
        if lock is None:
            print("aramid: drain: another drain is running (lock held)", file=sys.stderr)
            return 3

    # Phase 2b: give consumers a per-drain reset point (budget counters,
    # availability caches). Optional protocol -- only llm_review uses it.
    for _module in CONSUMERS.values():
        _begin = getattr(_module, "begin_drain", None)
        if _begin is not None:
            _begin()

    degraded = False
    started = monotonic()
    drain_run_id = uuid.uuid4().hex
    # FN-14: armed at the default before any config is read -- the sweep
    # and triage below can stall too -- and set from the candidates' own
    # `[drain].hard_deadline_s` once they are known. Cancelled in the same
    # `finally` as the lock, so a drain that ends by itself (or raises)
    # never leaves one behind to `os._exit` whatever imported it.
    watchdog = None
    if lock is not None:
        watchdog = _Watchdog(drain_limits.DEFAULT_HARD_DEADLINE_S, lock=lock, clock=clock)
        watchdog.start()
    try:
        candidates = []  # (score, repo, item, cfg)
        for repo_path in repos:
            try:
                root = gitutil.repo_root(repo_path.resolve())
                cfg = config_mod.load_config(root)
                leftover = _sweep_leftovers(root, dry_run=dry_run)
                if dry_run:
                    # read-only preview: report what WOULD be swept/popped
                    if (root / ".aramid" / "ledger.db").exists():
                        ledger = Ledger(root / ".aramid" / "ledger.db")
                        try:
                            item = queue.queued_item(queue.materialize_queue(ledger.events()))
                            pending = (len(_mutation.pending_retests(ledger, root))
                                       if item is None and _mutation.retests_enabled(cfg) else 0)
                        finally:
                            ledger.close()
                    else:
                        item, pending = None, 0
                    line = f"aramid drain (dry-run): {root} queued={item.score if item else 'none'}"
                    if pending:
                        # What the real drain would synthesize (an empty-queue
                        # re-test item); the stood-down guard is not applied
                        # here, so this is the upper bound.
                        line += f" pending_retests={pending}"
                    if item is not None and item.deferred:
                        # Why the last drain did not open it (round 177).
                        line += f" deferred={item.deferred} ({item.deferred_reason})"
                    if leftover.removed:
                        line += f" leftovers={len(leftover.removed)}"
                    print(line)
                    continue
                ledger = Ledger(root / ".aramid" / "ledger.db")
                try:
                    _sweep(root, cfg, ledger, clock())
                    queue.expire_stale(ledger, clock(),
                                       int(cfg.drain.get("item_expiry_days", 30)))
                    item = queue.queued_item(queue.materialize_queue(ledger.events()))
                    if item is None:
                        item = _pending_retest_item(root, cfg, ledger, clock())
                    if item is not None and item.score < int(cfg.triage.get("min_score", 40)):
                        item = None  # queued, but nothing this drain would pop
                    # The visit itself, whether or not there was work: an
                    # idle drain used to leave no trace, so `status` could
                    # not tell a dead scheduler from an empty queue. Written
                    # before the consumers run so their rows are the newer
                    # ones when there was an item.
                    ledger.append(Event(EventType.DRAIN_VISITED, drain_run_id, clock(),
                                        payload={"queued": item.id if item else None}))
                finally:
                    ledger.close()
                if item is not None:
                    candidates.append((item.score, root, item, cfg))
            except Exception as exc:
                # Per-repo isolation (spec section 6): ANY failure probing one
                # repo -- NotARepo, a missing dir (OSError), a malformed
                # aramid.toml (tomllib.TOMLDecodeError, a ValueError), a corrupt
                # ledger.db (sqlite3.DatabaseError), or a bad-config int() coercion
                # -- degrades that repo only; the rest still drain. Mirrors the
                # per-item consume loop's `except Exception` below.
                print(f"aramid drain: skipping {repo_path}: {exc}", file=sys.stderr)
                degraded = True
        if dry_run:
            return 0

        # Most-DEFERRED first, then score, stable (so registry order still
        # breaks a full tie). One deferral guarantees an item is opened by
        # the second scheduled drain after it was queued; two repos starving
        # each other resolve to the more-deferred one, which is the fair
        # order. Round 177: a tied, quieter repo lost on registry order and
        # the winner spent the drain-wide budget, at every drain.
        candidates.sort(key=lambda c: (-c[2].deferred, -c[0]))
        if watchdog is not None:
            watchdog.set_deadline(drain_limits.drain_deadline_s(
                (c[3] for c in candidates),
                task_limit_minutes=schedule_mod.installed_task_limit_minutes()))
        budget_s = max((float(c[3].drain.get("wall_clock_budget_s", 600.0))
                        for c in candidates), default=600.0)
        # No candidates, no comparison: the loop below is the only reader.
        limit = max_items if max_items is not None else \
                max((int(c[3].drain.get("max_items_per_drain", 10))
                     for c in candidates), default=None)
        drained = 0
        rolled: dict[str, tuple] = {}
        drained_roots: list[str] = []
        for idx, (score_val, root, item, cfg) in enumerate(candidates):
            now = monotonic()
            if drained >= limit or now - started > budget_s:
                left = candidates[idx:]
                reason = "item limit" if drained >= limit else "drain budget"
                print(f"aramid drain: budget reached; {len(left)} item(s) left queued")
                # The budget is drain-wide and checked only BETWEEN items
                # (an item's consumers carry their own budgets; preempting a
                # running mutation would waste 25 minutes and write a
                # degraded row), so what changes is who goes next time:
                # every item left behind gets a DEFERRED row in ITS repo's
                # ledger, which `status` / `--dry-run` show and the next
                # drain sorts on. Same failure shape as every other per-repo
                # write here: a ledger that cannot take the row degrades the
                # drain, never raises out of it.
                for _s, left_root, left_item, _c in left:
                    try:
                        left_ledger = Ledger(left_root / ".aramid" / "ledger.db")
                        try:
                            queue.mark_deferred(left_ledger, left_item.id, drain_run_id, clock(),
                                                reason=reason, after=list(drained_roots),
                                                elapsed_s=int(now - started), budget_s=budget_s)
                        finally:
                            left_ledger.close()
                    except Exception as exc:
                        print(f"aramid drain: {left_root}: could not record the deferral: {exc}",
                              file=sys.stderr)
                        degraded = True
                break
            if watchdog is not None:
                # FN-16: what a deadline inside this item would have to defer.
                watchdog.pending(drain_run_id, [(c[1], c[2].id) for c in candidates[idx + 1:]],
                                 drained_roots)
            # Read once per launch and held module-level, so it is set HERE,
            # beside this repo's consumers: every config is loaded in the
            # candidate loop above, and setting it there would leave the last
            # repo's value governing all of them.
            from aramid.commands.check import apply_stall_window
            apply_stall_window(cfg)
            ledger = Ledger(root / ".aramid" / "ledger.db")
            try:
                if not _consume_item(root, cfg, ledger, item, clock, watchdog=watchdog):
                    degraded = True
            except Exception as exc:
                print(f"aramid drain: {root}: {exc}", file=sys.stderr)
                degraded = True
            finally:
                ledger.close()
            drained += 1
            drained_roots.append(normalize_path(str(root)))
            rolled[str(root)] = (root, cfg)
        if watchdog is not None:
            # Every item was opened, or the budget stop deferred it already.
            watchdog.pending(drain_run_id, [], drained_roots)

        # Auto-learn rollup (autolearn spec section 8.3): fold each drained
        # repo's new ledger events into the machine-global state. Fail-open:
        # a rollup failure never fails the drain.
        for root, cfg in rolled.values():
            al_cfg = cfg.llm.get("autolearn", {})
            if not isinstance(al_cfg, dict) or not al_cfg.get("enabled", True):
                continue
            try:
                led = Ledger(root / ".aramid" / "ledger.db")
                try:
                    events = led.events()
                finally:
                    led.close()
                state = autolearn.rollup(autolearn.load_state(), events,
                                         normalize_path(str(root)))
                autolearn.save_state(state, clock())
            except Exception as exc:
                print(f"aramid drain: autolearn rollup skipped for {root}: {exc}",
                      file=sys.stderr)

        # Fleet judgement (fleet-readiness spec section 6): judge every
        # registered repo's health rows, write the verdict, post notices.
        # Reads only ~/.aramid/fleet_health.jsonl -- never another repo's
        # ledger -- and fails open: a broken store never fails the drain.
        try:
            fleet.run_judgement(clock(), aramid_version=__version__)
        except Exception as exc:
            print(f"aramid drain: fleet judgement skipped: {exc}", file=sys.stderr)
        print(f"aramid drain: {drained} item(s) drained, "
              f"{len(candidates) - drained} left")
        return 2 if degraded else 0
    finally:
        if watchdog is not None:
            watchdog.cancel()
        if lock is not None:
            _release_lock(lock)
