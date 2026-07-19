"""aramid drain -- iterate the registry, catch-up-sweep, pop queued items
by score, hand them to consumers, record everything (spec section 2).

Exit codes reuse the Phase 1 contract: 0 ok, 2 degraded (some repo or
consumer failed; the rest completed), 3 engine error (lock held, registry
unusable). Singleton lock at ~/.aramid/drain.lock: JSON {pid, started_at};
stale when the PID is dead OR the lock is older than 2x the wall-clock
budget (spec section 6)."""
import functools
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from aramid import autolearn
from aramid import config as config_mod
from aramid import gitutil, policy, queue, redact, registry, triage
from aramid.consumers.base import CONSUMERS, ConsumerResult, DrainContext
from aramid.fingerprint import normalize_path
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Gate
from aramid.normalizer import normalize

import aramid.consumers.regression_pack  # noqa: F401  -- registers the consumer
from aramid.consumers import llm_review as _llm_review  # noqa: F401  (registers itself)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lock_path() -> Path:
    """Seam for tests."""
    return Path.home() / ".aramid" / "drain.lock"


def _pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        # noqa justification (S603/S607): fixed argv querying our own recorded
        # PID via the standard Windows tasklist binary.
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],  # noqa: S603,S607
                             capture_output=True, text=True)
        return str(pid) in out.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _acquire_lock(budget_s: float) -> Path | None:
    p = _lock_path()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            age = time.time() - float(data.get("started_at", 0))
            if _pid_alive(int(data.get("pid", -1))) and age < 2 * budget_s:
                return None  # genuinely held
            print("aramid: drain: breaking stale lock", file=sys.stderr)
        except (json.JSONDecodeError, ValueError, OSError):
            pass  # unreadable lock is stale
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"pid": os.getpid(), "started_at": time.time()}),
                 encoding="utf-8")
    return p


def _release_lock(p: Path) -> None:
    try:
        p.unlink()
    except OSError:
        pass


def _sweep(root: Path, cfg, ledger, at: str) -> None:
    head = gitutil.rev_sha(root, "HEAD")
    if head is None:
        return  # empty repo: nothing to triage
    last = queue.last_triaged_head(ledger)
    if last == head:
        return
    if last is None:
        # Bootstrap rule (spec section 2): first contact triages HEAD only.
        triage.run_triage(root, cfg, ledger, gitutil.first_parent(root, head), head, at)
    else:
        triage.run_triage(root, cfg, ledger, last, head, at)


def _consume_item(root: Path, cfg, ledger, item, clock) -> bool:
    """Run every enabled consumer against one queue item. Returns True if
    all consumers finished without error state."""
    ok = True
    run_id = uuid.uuid4().hex
    salt = redact.load_or_create_salt(root / ".aramid")
    for name, module in CONSUMERS.items():
        started = time.monotonic()
        try:
            result = module.consume(item, DrainContext(root=root, cfg=cfg,
                                                        ledger=ledger, clock=clock))
        except Exception as exc:
            result = ConsumerResult(consumer=name, state="error", note=str(exc))
        duration = time.monotonic() - started
        findings = []
        if result.findings:
            findings = normalize(result.findings, root, lambda f: item.head, salt,
                                 Gate.ALL, functools.partial(policy.classify, cfg=cfg))
            # The drain runs a narrow ruleset (pack only) -- record detections
            # but resolve NOTHING. Pack and OWASP findings both use
            # tool="semgrep", so a scope of {semgrep}x{scanned files} would
            # still spuriously resolve an open OWASP finding the pack
            # ruleset never re-detects. Only a full gate, which examines the
            # complete ruleset, may resolve. Empty scope makes
            # record_run's resolve loop match nothing; FINDING_DETECTED for
            # the pack findings still fires (detection doesn't depend on
            # scope).
            ledger.record_run(run_id, clock(), "drain", set(), set(), findings)
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
        if result.state in ("error", "degraded"):
            ok = False
    # A not-fully-consumed item (any consumer errored or degraded, e.g. a
    # semgrep TIMEOUT/CRASHED/MISSING run of the pack ruleset) must NOT be
    # marked drained: that would drop it from the queue with no retry,
    # letting a bypassed reintroduction escape the backstop. Only mark it
    # drained once every consumer finished cleanly.
    if ok:
        queue.mark_drained(ledger, item.id, run_id, clock())
    return ok


def cmd_drain(targets: list, *, dry_run: bool = False, max_items: int | None = None,
              clock: Callable[[], str] = _now,
              monotonic: Callable[[], float] = time.monotonic) -> int:
    repos = [Path(t) for t in targets] if targets else \
            [Path(e["path"]) for e in registry.load_registry()]
    if not repos:
        print("aramid drain: no repos registered and none given", file=sys.stderr)
        return 0

    probe_cfg_budget = 600.0
    lock = None
    if not dry_run:
        lock = _acquire_lock(probe_cfg_budget)
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
    try:
        candidates = []  # (score, repo, item, cfg)
        for repo_path in repos:
            try:
                root = gitutil.repo_root(repo_path.resolve())
                cfg = config_mod.load_config(root)
                if dry_run:
                    # read-only preview: report what WOULD be swept/popped
                    if (root / ".aramid" / "ledger.db").exists():
                        ledger = Ledger(root / ".aramid" / "ledger.db")
                        try:
                            item = queue.queued_item(queue.materialize_queue(ledger.events()))
                        finally:
                            ledger.close()
                    else:
                        item = None
                    print(f"aramid drain (dry-run): {root} queued="
                          f"{item.score if item else 'none'}")
                    continue
                ledger = Ledger(root / ".aramid" / "ledger.db")
                try:
                    _sweep(root, cfg, ledger, clock())
                    queue.expire_stale(ledger, clock(),
                                       int(cfg.drain.get("item_expiry_days", 30)))
                    item = queue.queued_item(queue.materialize_queue(ledger.events()))
                finally:
                    ledger.close()
                if item is not None and item.score >= int(cfg.triage.get("min_score", 40)):
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

        candidates.sort(key=lambda c: -c[0])
        budget_s = max((float(c[3].drain.get("wall_clock_budget_s", 600.0))
                        for c in candidates), default=600.0)
        limit = max_items if max_items is not None else \
                max((int(c[3].drain.get("max_items_per_drain", 10))
                     for c in candidates), default=10)
        drained = 0
        rolled: dict[str, tuple] = {}
        for score_val, root, item, cfg in candidates:
            if drained >= limit or monotonic() - started > budget_s:
                print(f"aramid drain: budget reached; {len(candidates) - drained} "
                      f"item(s) left queued")
                break
            ledger = Ledger(root / ".aramid" / "ledger.db")
            try:
                if not _consume_item(root, cfg, ledger, item, clock):
                    degraded = True
            except Exception as exc:
                print(f"aramid drain: {root}: {exc}", file=sys.stderr)
                degraded = True
            finally:
                ledger.close()
            drained += 1
            rolled[str(root)] = (root, cfg)

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
        print(f"aramid drain: {drained} item(s) drained, "
              f"{len(candidates) - drained} left")
        return 2 if degraded else 0
    finally:
        if lock is not None:
            _release_lock(lock)
