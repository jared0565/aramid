"""A finding on a file that has left the repo could never resolve.

`record_run` resolves an open finding only when `rec["file"] in scope_files`,
and every file-discovery path filters with `--diff-filter=ACMR` (gitutil) --
Added/Copied/Modified/Renamed, deliberately excluding Deleted, because you
cannot lint a file that is gone. Correct for scanning, fatal for resolution:
a deleted file is never in scope_files, so its findings stayed open forever.

Reproduced end-to-end before the fix, with the most ordinary developer action
there is -- `git rm` a file and commit:

    AFTER SCAN :  {'be44e94f': ('ruff', 'bad.py', 'open')}
    file exists now? False
    AFTER DELETE: {'be44e94f': ('ruff', 'bad.py', 'open')}

So every repo accumulates immortal findings for every file it ever deletes.

THE OPT-IN MATTERS AS MUCH AS THE FIX. `record_run` has three production
callers, and `commands/init._scan_history` records HISTORICAL gitleaks findings
discovered via `git log --all` -- secrets in old commits, whose paths routinely
do not exist at HEAD. Resolving on "the file is gone" there would silently
clear every historical secret the moment it was recorded, which is a security
regression dressed as a cleanup. Hence `root` is opt-in and only the gate
passes it.
"""
from datetime import datetime, timezone

from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Verdict

NOW = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)


def _finding(fid="a" * 64, tool="ruff", file="bad.py"):
    return Finding(id=fid, tool=tool, rule="S102",
                   severity_raw="error", severity=Severity.HIGH,
                   verdict=Verdict.WARN, file=file, line=2,
                   message="exec used", evidence="exec(x)", gate=Gate.PRE_COMMIT)


def _seed(led, *findings):
    led.record_run("r0", NOW.isoformat(), "pre-commit", set(), set(), list(findings))


def test_finding_on_a_departed_file_resolves_when_its_tool_ran(tmp_path):
    """The bug. `bad.py` is gone, ruff ran, so nothing will ever re-report it."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding())
        led.record_run("r1", NOW.isoformat(), "pre-commit",
                       {"ruff"}, {"other.py"}, [], root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "fixed"
    finally:
        led.close()


def test_finding_on_a_file_that_still_exists_stays_open(tmp_path):
    """THE GUARD THIS MUST NOT BREAK. At pre-commit `scope_files` is the STAGED
    set, so a finding in a tracked-but-unstaged file is legitimately out of
    scope and simply was not re-scanned. It must stay open -- resolving it
    would clear findings merely for not having been looked at.
    """
    led = Ledger(tmp_path / "l.db")
    (tmp_path / "bad.py").write_text("def f(x):\n    exec(x)\n", encoding="utf-8")
    try:
        _seed(led, _finding())
        led.record_run("r1", NOW.isoformat(), "pre-commit",
                       {"ruff"}, {"other.py"}, [], root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


def test_departed_file_stays_open_when_its_tool_did_not_run(tmp_path):
    """The tool clause is untouched: if ruff never ran, its absence of findings
    says nothing, regardless of whether the file is still there."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding())
        led.record_run("r1", NOW.isoformat(), "pre-commit",
                       {"gitleaks"}, {"other.py"}, [], root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


def test_a_departed_file_in_a_subdirectory_still_resolves(tmp_path):
    """Containment must not cost the ordinary nested case."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding(file="src/pkg/bad.py"))
        led.record_run("r1", NOW.isoformat(), "pre-commit",
                       {"ruff"}, {"other.py"}, [], root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "fixed"
    finally:
        led.close()


# ------------------------------------------------- paths outside the repo ---

# `root / file` does NOT keep you inside root. Measured on Windows:
#
#     Path(r'F:\Projects\aramid') / 'C:/Windows/win.ini'  ->  C:\Windows\win.ini
#     Path(r'F:\Projects\aramid') / '/etc/passwd'         ->  F:\etc\passwd
#
# An absolute `file` discards root entirely, and `..` is never normalized away.
# The escaped path then almost never exists, `_departed` reports True, and the
# finding is silently RESOLVED. A path that was never inside the repository
# cannot have departed it, so the honest answer is "not departed" -- which is
# also the safe direction, since it leaves the finding open.


def test_an_absolute_path_outside_the_repo_is_not_departed(tmp_path):
    outside = tmp_path.parent / "not_in_the_repo.py"     # absolute, outside root
    assert not outside.exists()                          # so the join escapes to nothing
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding(file=str(outside)))
        led.record_run("r1", NOW.isoformat(), "pre-commit",
                       {"ruff"}, {"other.py"}, [], root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


def test_a_traversing_path_is_not_departed(tmp_path):
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding(file="../../etc/passwd"))
        led.record_run("r1", NOW.isoformat(), "pre-commit",
                       {"ruff"}, {"other.py"}, [], root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


def test_traversal_that_lands_back_inside_the_repo_is_still_judged(tmp_path):
    """`src/../bad.py` IS `bad.py`. Containment rejects escapes, not every
    path that happens to contain a dot-dot segment."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding(file="src/../bad.py"))
        led.record_run("r1", NOW.isoformat(), "pre-commit",
                       {"ruff"}, {"other.py"}, [], root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "fixed"
    finally:
        led.close()


def test_without_root_the_old_behaviour_is_unchanged(tmp_path):
    """Protects `init._scan_history` and `drain._consume_item`, which pass no
    root. A historical gitleaks finding names a path in an OLD commit that
    frequently does not exist at HEAD; resolving on absence there would clear
    every historical secret on sight.
    """
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding(tool="gitleaks", file="deleted/old_secret.py"))
        led.record_run("r1", NOW.isoformat(), "historical-scan",
                       {"gitleaks"}, {"other.py"}, [])
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()
