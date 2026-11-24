"""`aramid doctor` names a control character in a PATH entry (interop round
347 item 1; operator decision 2026-11-24, "name the control char"). bytesTTS
had `C:` + LF + `    \\Users\\...\\jdk-17\\bin` on PATH from a terminal
started before a registry fix; doctor called it a relative entry and said
"make it absolute", and the raw LF split the row in two. Every row prints
its entry escaped, on one line; lookups are unchanged."""
import os

import pytest

from aramid import handover, toolpath
from aramid.commands import doctor

# The entry bytesTTS reported holds a `:`, which is POSIX's PATH separator,
# so it can only be built as one entry on Windows (WSL caught the first
# version splitting it in two). Every other test uses one without a colon.
REPORTED = "C:\n    \\Users\\someone\\jdk-17\\bin"
LF_ENTRY = "jdk\n    \\Users\\someone\\jdk-17\\bin"
TAIL = (": a terminal started before PATH was changed keeps its old PATH -- open a new"
        " terminal, or remove the entry")


def _path(monkeypatch, *entries):
    monkeypatch.setenv("PATH", os.pathsep.join(entries))


def _relative(entry):
    return (f"  WARN     PATH         relative entry `{entry}`: it names a directory of the"
            " repo aramid is judging, which can supply any program but aramid's own tools --"
            " make it absolute or remove it")


@pytest.mark.skipif(os.pathsep != ";", reason="the reported entry holds POSIX's separator")
def test_the_reported_entry_is_named_for_its_line_feed_not_called_relative(monkeypatch):
    _path(monkeypatch, REPORTED)

    assert doctor.relative_path_lines() == [
        "  WARN     PATH         entry `C:\\x0a    \\Users\\someone\\jdk-17\\bin` holds a"
        " control character (LF at character 3)" + TAIL]


def test_an_entry_with_a_line_feed_is_named_for_it_not_called_relative(monkeypatch):
    _path(monkeypatch, LF_ENTRY)

    assert doctor.relative_path_lines() == [
        "  WARN     PATH         entry `jdk\\x0a    \\Users\\someone\\jdk-17\\bin` holds a"
        " control character (LF at character 4)" + TAIL]


def test_an_absolute_entry_with_a_carriage_return_is_named_too(monkeypatch, tmp_path):
    entry = str(tmp_path / "tools") + "\r"
    _path(monkeypatch, entry)

    assert doctor.relative_path_lines() == [
        f"  WARN     PATH         entry `{entry[:-1]}\\x0d` holds a control character"
        f" (CR at character {len(entry)})" + TAIL]


def test_a_tab_and_an_escape_are_named_by_what_they_are(monkeypatch):
    _path(monkeypatch, "a\tb", "x\x1by")

    assert doctor.relative_path_lines() == [
        "  WARN     PATH         entry `a\\x09b` holds a control character (TAB at character 2)"
        + TAIL,
        "  WARN     PATH         entry `x\\x1by` holds a control character (U+001B at character 2)"
        + TAIL]


def test_rows_follow_path_order_and_a_plain_relative_entry_is_as_before(monkeypatch, tmp_path):
    _path(monkeypatch, "bin", LF_ENTRY, str(tmp_path / "abs"), "tools")

    rows = doctor.relative_path_lines()

    assert rows[0] == _relative("bin") and rows[2] == _relative("tools")
    assert rows[1].startswith("  WARN     PATH         entry `jdk\\x0a ") and len(rows) == 3


def test_every_row_is_one_line(monkeypatch):
    _path(monkeypatch, LF_ENTRY, "a\rb", "c\u2028d", "bin")

    rows = doctor.relative_path_lines()

    assert len(rows) == 4
    assert all(r.isprintable() for r in rows), rows


def test_lookups_are_unchanged(monkeypatch):
    """Only the report changes: the entry is still a relative one to aramid."""
    _path(monkeypatch, LF_ENTRY)

    assert toolpath.relative_path_entries() == [LF_ENTRY]


def test_the_one_line_escape_keeps_backslashes_and_escapes_lf_and_tab():
    assert handover.printable_line("C:\\a\nb\tc\x1b") == "C:\\a\\x0ab\\x09c\\x1b"
