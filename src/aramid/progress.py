"""A progress sink for long runners: one line, kept current.

The gate's test suite takes ~19 minutes on this repo and used to print
nothing until it finished (2026-09-05, an operator watching a tag push
asked what the shell was doing). Runners that can read progress from their
child hand short texts to a sink; `StderrReporter` is the sink `run_gate`
provides.

Two behaviours, chosen by the stream:

- **terminal** (`isatty()`): every text overwrites the previous one in
  place (`\\r`, padded to blank the longer line). `flush()` ends the line.
  git relays a hook's stderr to the terminal the push was typed in, so
  this is what a push shows.
- **file / pipe**: one line at most every `min_interval_s`; texts inside
  the interval are HELD, newest wins, and `flush()` writes the held one --
  so a background push log gets a line every 30 s and always the last
  state, never a 99% that was throttled away.

Writes never raise: a vanished stderr must not turn a green suite red.
"""
from __future__ import annotations

import sys
import time
from typing import Callable, TextIO


class StderrReporter:
    def __init__(self, stream: TextIO | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 min_interval_s: float = 30.0):
        self._stream = stream if stream is not None else sys.stderr
        self._clock = clock
        self._interval = min_interval_s
        self._tty = self._isatty()
        self._last_write_at: float | None = None
        self._last_width = 0
        self._held: str | None = None
        self._silenced = False    # the stream failed once: never try again

    def _isatty(self) -> bool:
        try:
            return bool(self._stream.isatty())
        except Exception:  # noqa: BLE001 -- an odd stream is a file, not a fault
            return False

    def _write(self, s: str) -> None:
        if self._silenced:
            return
        try:
            self._stream.write(s)
            self._stream.flush()
        except Exception:  # noqa: BLE001 -- a vanished stderr must not fail the gate
            self._silenced = True

    def __call__(self, text: str) -> None:
        if self._tty:
            pad = " " * max(0, self._last_width - len(text))
            self._write("\r" + text + pad)
            self._last_width = len(text)
            return
        now = self._clock()
        if self._last_write_at is None or now - self._last_write_at >= self._interval:
            self._write(text + "\n")
            self._last_write_at = now
            self._held = None
        else:
            self._held = text

    def flush(self) -> None:
        if self._tty:
            if self._last_width:
                self._write("\n")
                self._last_width = 0
            return
        if self._held is not None:
            self._write(self._held + "\n")
            self._last_write_at = self._clock()
            self._held = None
