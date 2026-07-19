"""aramid triage <rev> -- score one commit (or A..B range) and enqueue.

Called by the post-commit shim with HEAD (which additionally maps ANY
exit to 0 -- fail-open lives in the shim, spec section 6); usable
manually. Engine errors return 3 per the Phase 1 exit-code contract.

Watchdog (C-list hardening, supersedes Phase 2a spec section 6's "2s
self-timeout"): the shim passes --budget 15; when set, a daemon Timer is
armed BEFORE repo resolution / config load / ledger open, so every hang
class (wedged git subprocess, config read, sqlite, filesystem) is
downstream of it. On expiry it stderr-logs, flushes, and os._exit(3)s --
the shim maps that to 0 (fail-open), SQLite WAL is crash-safe against
the hard exit, and the drain catch-up sweep re-derives the lost enqueue.
Manual `aramid triage` without the flag stays unbounded.
"""
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import gitutil, triage
from aramid.ledger import Ledger


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchdog_kill(budget: float) -> None:
    print(f"aramid: triage: watchdog: exceeded {budget}s -- killing", file=sys.stderr)
    try:
        sys.stderr.flush()
        sys.stdout.flush()
    except Exception:
        pass
    os._exit(3)


def cmd_triage(root, rev: str = "HEAD", budget: float | None = None) -> int:
    timer = None
    if budget is not None:
        timer = threading.Timer(budget, _watchdog_kill, args=(budget,))
        timer.daemon = True
        timer.start()
    try:
        try:
            try:
                repo = gitutil.repo_root(Path(root).resolve())
            except gitutil.NotARepo:
                print("aramid: triage: not a git repository", file=sys.stderr)
                return 3
            if ".." in rev:
                base_rev, head_rev = rev.split("..", 1)
                base = gitutil.rev_sha(repo, base_rev)
                head = gitutil.rev_sha(repo, head_rev)
                if base is None or head is None:
                    print(f"aramid: triage: cannot resolve range {rev!r}", file=sys.stderr)
                    return 3
            else:
                head = gitutil.rev_sha(repo, rev)
                if head is None:
                    print(f"aramid: triage: cannot resolve rev {rev!r}", file=sys.stderr)
                    return 3
                base = gitutil.first_parent(repo, head)
            cfg = config_mod.load_config(repo)
            ledger = Ledger(repo / ".aramid" / "ledger.db")
            try:
                result, queued = triage.run_triage(repo, cfg, ledger, base, head, _now())
            finally:
                ledger.close()
            state = "queued" if queued else "below threshold"
            print(f"aramid triage: {head[:7]} score {result.score} ({state}); "
                  f"{'; '.join(result.reasons) or 'no signals'}")
            return 0
        except Exception as exc:  # engine error tier -- the hook maps this to 0 anyway
            print(f"aramid: triage: engine error: {exc}", file=sys.stderr)
            return 3
    finally:
        if timer is not None:
            timer.cancel()
