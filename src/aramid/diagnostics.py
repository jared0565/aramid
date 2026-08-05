"""Report what the fail-safe handlers swallowed.

aramid is deliberately full of `except Exception: continue` guards. They are
not sloppiness: a malformed ledger record must never crash a gate, and a
provider whose probe raises must never crash the drain. Skipping is the
correct behaviour and stays exactly as it was.

Skipping SILENTLY is the defect. A systematically corrupt ledger, or a
provider that raises on every probe, produces output identical to a clean run
-- which is the precise failure mode this tool exists to prevent: a check that
reports success for a reason indistinguishable from a real pass. Eleven
handlers had no way to say they had swallowed anything.

Two shapes, because the swallows come in two kinds:

  note_skipped   counted in a loop, reported ONCE after it. A corrupted ledger
                 holding 500 bad rows must produce one line, not 500 -- a gate
                 that chatters gets ignored, and then the run that had
                 something to say is ignored too.
  note_failed    named individually, for swallows where the identity is the
                 whole message (which provider never loaded, which file was
                 dropped from a review packet).

stderr, not stdout and not the ledger: this is engine telemetry about aramid
itself rather than a finding about the repo under test, it must not
contaminate the machine-readable report on stdout, and it has to survive a run
that is failing precisely because ledger writes are broken.

Both functions are called from INSIDE exception handlers, so neither may
raise: that would convert a survivable swallow into the crash the handler
existed to prevent.
"""
import sys


def note_skipped(where: str, count: int, noun: str = "malformed record") -> None:
    """Report `count` skipped items from one loop. Silent at zero -- the clean
    path is the common path and must stay quiet."""
    if count <= 0:
        return
    print(f"aramid: {where}: skipped {count} {noun}{'' if count == 1 else 's'}",
          file=sys.stderr)


def note_failed(where: str, subject: str, exc: BaseException) -> None:
    """Report one named swallow, with the exception type so the reader can
    tell a missing binary from a broken one."""
    print(f"aramid: {where}: {subject}: {type(exc).__name__}: {exc}",
          file=sys.stderr)
