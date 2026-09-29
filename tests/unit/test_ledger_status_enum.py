"""`models.Status` is the single source of the ledger's statuses (API-6).

`ledger._materialize` writes every status as a bare literal and never imports
the enum, so the two could drift silently in either direction: a literal the
enum does not name (a row whose status no `Status(...)` reader accepts), or
an enum member nothing writes (a status documented and exported that no
finding can ever reach). Every writer site, replayed through the real
`_materialize`, pins both directions.
"""
import ast
from pathlib import Path

from aramid import ledger
from aramid.models import Event, EventType, Status

_FID = "a" * 64

# (detect payload, events after the detect, the status the writer must give).
# One row per assignment of `status` in `_materialize`.
_WRITES = [
    ({}, [], "open"),
    ({"historical": True}, [], "historical"),
    ({}, [(EventType.FINDING_RESOLVED, {})], "fixed"),
    ({}, [(EventType.FINDING_RESOLVED, {"superseded_by": "b" * 64})], "superseded"),
    ({}, [(EventType.FINDING_RESOLVED, {"pending_retest": True})], "pending_retest"),
    ({}, [(EventType.FINDING_OVERRIDDEN, {"reason": "r"})], "overridden"),
    ({}, [(EventType.FINDING_ROTATED, {})], "rotated"),
    ({}, [(EventType.FINDING_NOT_A_SECRET, {"reason": "r"})], "not_a_secret"),
    ({}, [(EventType.FINDING_OVERRIDDEN, {"reason": "r"}),
          (EventType.FINDING_OVERRIDE_INVALIDATED, {"cause": "armed"})], "open"),
    ({}, [(EventType.FINDING_UNREACHABLE, {"reason": "r"})], "unreachable"),
    ({}, [(EventType.FINDING_OUT_OF_SCOPE, {"reason": "r"})], "out_of_scope"),
]


def _written(detect: dict, after: list) -> str:
    events = [Event(EventType.FINDING_DETECTED, "run", "t", _FID, detect)]
    events += [Event(kind, "run", "t", _FID, payload) for kind, payload in after]
    state, _ = ledger._materialize(events)
    return state[_FID]["status"]


def test_the_status_surface_is_exactly_these_ten():
    """Public surface (API-2): a status is in `ledger filter --status`, in
    every `--json` row and in the printed buckets. Adding or renaming one
    is a CHANGELOG entry, and this goes red first."""
    assert {s.value for s in Status} == {
        "open", "fixed", "overridden", "historical", "rotated", "not_a_secret",
        "unreachable", "superseded", "out_of_scope", "pending_retest"}


def test_each_writer_site_gives_the_status_expected():
    assert [_written(d, a) for d, a, _ in _WRITES] == [want for _, _, want in _WRITES]


def test_the_writer_gives_exactly_the_statuses_the_enum_names():
    assert {_written(d, a) for d, a, _ in _WRITES} == {s.value for s in Status}


def _status_literals_compared(tree: ast.AST) -> set[str]:
    """Every string constant compared (==, !=, in, not in) with an
    `x["status"]` or `x.get("status")` read, anywhere in the module."""
    def is_status_read(node) -> bool:
        if isinstance(node, ast.Subscript):
            return isinstance(node.slice, ast.Constant) and node.slice.value == "status"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return (node.func.attr == "get" and bool(node.args)
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == "status")
        return False

    def constants(node) -> list[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return [c for elt in node.elts for c in constants(elt)]
        return []

    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and is_status_read(node.left):
            for right in node.comparators:
                found.update(constants(right))
    return found


def test_every_status_the_ledger_compares_against_is_an_enum_value():
    """A reader's typo never matches and never errors -- `!= "opne"` is
    simply always true. Found by parsing, because the read sites have no
    single entry point to drive."""
    tree = ast.parse(Path(ledger.__file__).read_text(encoding="utf-8"))
    compared = _status_literals_compared(tree)
    assert compared, "no status comparison found -- the scan has gone blind"
    assert compared <= {s.value for s in Status}, compared - {s.value for s in Status}
