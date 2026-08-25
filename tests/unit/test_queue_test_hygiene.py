"""Guard: a test that drains must not enqueue with a literal date.

`cmd_drain` calls `queue.expire_stale(..., item_expiry_days)` against the WALL
CLOCK, so an item enqueued at a hardcoded date silently ages out. Four
integration tests were written with `2026-07-20T10:00:00+00:00`, passed for a
month, and began failing on 2026-08-20 -- 31 days later -- with nothing in the
output but `aramid drain: 0 item(s) drained, 0 left`. They then blocked every
push, and CI never caught it because the last run predated the expiry.

Scoped to files that actually call `cmd_drain`, not to literal dates in
general: `test_status.py` deliberately enqueues at a fixed date and asserts on
that exact string in rendered output, which is correct and must stay. The
hazard is the COMBINATION, and the guard names the combination.

`tests/unit/test_queue.py` is the pattern to copy -- it works entirely in
offsets from a `NOW` it controls (`NOW - timedelta(days=31)` / `days=29`), so
it pins the expiry boundary itself and cannot rot.
"""
import re
from pathlib import Path

import pytest

_TESTS = Path(__file__).resolve().parents[1]
# `enqueue(` ... a quoted ISO date literal, on the same logical call.
_LITERAL_ENQUEUE = re.compile(r"enqueue\([^)]*?[\"']\d{4}-\d{2}-\d{2}", re.S)


def _draining_test_files() -> list[Path]:
    return sorted(p for p in _TESTS.rglob("test_*.py")
                  if "cmd_drain" in p.read_text(encoding="utf-8"))


def test_the_guard_has_files_to_check():
    """A zero-file sweep would pass vacuously and prove nothing -- the same
    false-clean shape this guard exists to prevent."""
    assert _draining_test_files(), "no test file calls cmd_drain -- guard is vacuous"


@pytest.mark.parametrize("path", _draining_test_files(), ids=lambda p: p.name)
def test_draining_tests_do_not_enqueue_at_a_literal_date(path):
    hits = _LITERAL_ENQUEUE.findall(path.read_text(encoding="utf-8"))
    assert not hits, (
        f"{path.name} calls cmd_drain and enqueues at a hardcoded date: {hits!r}. "
        "Queue items expire against the wall clock, so this passes until it "
        "silently does not. Enqueue relative to now instead.")
