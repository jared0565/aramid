"""The user guide's `check --json` key table names exactly the keys the
report carries (DOC-11).

Two independent computations, compared both ways. The EXPECTED side is the
report itself: one `reporter.render_json` payload, built with one entry in
every array of objects, walked for its keys -- never the hand-written sets in
`test_reporter_json_surface.py`, which pin the same surface from the other
side. The DOCUMENTED side is the first cell of every row of the tables under
the guide's "check --json keys" heading (HEADING below), and nothing else: a key
named anywhere else in the guide (the CI flags bullet, section 3's ratchet
prose) cannot satisfy this, which is the lesson DOC-12's guards learned.

Keys inside an array of objects are written qualified, `findings[].verdict`,
so each is checked in its own scope. `id`, `tool` and `rule` exist both in a
finding and in a `stale_overrides` entry; unqualified, one row would cover
two keys and a row filed under the wrong array would pass.

The guide is found beside the IMPORTED package (`<repo>/src/aramid` ->
`<repo>/docs`), not beside this file, so a run against a scratch copy of the
repo (`-o pythonpath=<scratch>/src`) reads that copy's guide and code
together: the two sides of the comparison always come from one tree.
"""
import json
import re
from collections import Counter
from pathlib import Path

import aramid
from aramid import reporter
from aramid.models import Finding, Gate, Severity, Verdict
from aramid.pipeline import GateResult
from aramid.policy import OverrideRecord
from aramid.pushrefs import Moved

GUIDE = Path(aramid.__file__).resolve().parents[2] / "docs" / "user-guide.md"
HEADING = "#### `check --json` keys"
_KEY_CELL = re.compile(r"^`([^`]+)`$")


def _where() -> str:
    return f"(aramid from {aramid.__file__}; guide {GUIDE})"


def _rendered() -> dict:
    """One report with one entry in every array, so every nested key set is
    actually rendered rather than assumed."""
    finding = Finding("id1", "ruff", "S102", "high", Severity.HIGH, Verdict.WARN,
                      "a.py", 1, "m", "e", Gate.PRE_PUSH)
    result = GateResult(
        exit_code=0, findings=[finding], degraded=["semgrep"], new_ids=["id1"],
        stale_overrides=[OverrideRecord("id2", "ruff", "S102", "a.py", "why")],
        run_id="r1", refs_moved=(Moved("refs/heads/main", "a" * 40, None),))
    return json.loads(reporter.render_json(result))


def _emitted_keys(payload: dict) -> set[str]:
    """Top-level keys, plus `<key>[].<sub>` for every array of objects."""
    keys = set(payload)
    for key, value in payload.items():
        if isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict):
                    keys.update(f"{key}[].{sub}" for sub in entry)
    return keys


def _section_lines() -> list[str]:
    assert GUIDE.is_file(), f"no user guide at {GUIDE} {_where()}"
    lines = GUIDE.read_text(encoding="utf-8").splitlines()
    starts = [i for i, ln in enumerate(lines) if ln.strip() == HEADING]
    assert len(starts) == 1, f"expected one {HEADING!r} heading, found {len(starts)} {_where()}"
    out = []
    for ln in lines[starts[0] + 1:]:
        if ln.startswith("#") or ln.strip() == "---":
            break
        out.append(ln)
    return out


def _documented_keys() -> list[str]:
    """The first cell of every table row in the section, header and
    separator rows aside. A row whose first cell is not one backticked key
    fails rather than being skipped, so a malformed row cannot hide."""
    keys = []
    for ln in _section_lines():
        if not ln.startswith("|"):
            continue
        first = ln.split("|")[1].strip()
        if first == "Key" or set(first) <= set("-: "):
            continue
        m = _KEY_CELL.match(first)
        assert m, f"table row's first cell is not one backticked key: {ln!r} {_where()}"
        keys.append(m.group(1))
    return keys


def test_the_rendered_payload_has_every_nested_array_populated():
    """Non-vacuity: if the fixture stops rendering an entry, the nested
    scopes would silently drop out of the comparison below."""
    payload = _rendered()
    for key in ("findings", "refs_moved", "stale_overrides"):
        assert payload[key] and isinstance(payload[key][0], dict), key


def test_the_table_rows_are_unique():
    dupes = sorted(k for k, n in Counter(_documented_keys()).items() if n > 1)
    assert not dupes, f"duplicate rows in the guide's check --json table: {dupes} {_where()}"


def test_every_emitted_key_has_a_row():
    missing = sorted(_emitted_keys(_rendered()) - set(_documented_keys()))
    assert not missing, (
        f"check --json emits keys the user guide's table does not list: {missing}. "
        f"Add a row under {HEADING!r}. {_where()}")


def test_every_row_names_an_emitted_key():
    extra = sorted(set(_documented_keys()) - _emitted_keys(_rendered()))
    assert not extra, (
        f"the user guide's check --json table lists keys the report does not emit: "
        f"{extra}. {_where()}")
