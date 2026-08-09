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

2026-08-09: THE FIX ABOVE ONLY EVER REACHED RUNNERS, AND THE OBVIOUS
GENERALISATION WAS TRIED AND REVERTED. It sits behind
`if rec["tool"] not in scope_tools: continue`, and that set holds runner
labels, so `red-proof` and `tdd` -- synchronous producers that emit no
RunnerResult -- could never reach it. Their findings on a deleted file stayed
immortal, with no resolver of their own to fall back on.

Moving the departed check AHEAD of the tool gate fixes that in one line, and
is wrong. `_departed` answers "gone" for anything that does not exist, and not
every producer stores a path: `consumers/dast.py` writes
`file=f"{f.method} {f.path}"`, so "GET /login" joins to `root/GET/login`,
passes containment, and reads as departed. The move would have written every
open DAST finding `fixed` -- a false repair, of security findings, into an
append-only audit trail, which is the very class the tool clause exists to
prevent. `test_a_dast_style_endpoint_is_never_treated_as_departed` pins it.

So departure is OPT-IN PER PRODUCER (`ledger.resolve_departed`), and a
producer that never opts in keeps findings open. Fail-safe by default, rather
than a denylist of shapes each new consumer must remember to join.

Separately, `_is_synthetic_path` closes a defect that needed no design change
to be live: `<test-suite>` is not a path, `_departed` said True for it on every
platform, and "python" IS in scope_tools whenever aramid's own tests runner
exits OK -- so `record_run` was already resolving BLOCK-tier suite findings
without the `suite_completed` evidence `tests_gate` demands.
"""
from datetime import datetime, timezone

from aramid.ledger import Ledger, resolve_departed
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
    says nothing, regardless of whether the file is still there.

    Kept deliberately after the 2026-08-09 work, which considered moving the
    departed check AHEAD of this clause and reverted. See the module docstring
    and `ledger.record_run` -- resolving here would reach producers whose
    stored `file` is not a path at all.
    """
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding())
        led.record_run("r1", NOW.isoformat(), "pre-commit",
                       {"gitleaks"}, {"other.py"}, [], root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


# --------------------------------------- resolve_departed: producer opt-in ---


def test_a_producer_finding_on_a_departed_file_resolves(tmp_path):
    """THE GAP. A producer whose name can never appear in `scope_tools` had
    findings that could never resolve, no matter what happened to the file.

    `scope_tools` is `{r.tool for r in results if OK}`, i.e. runner labels
    (`Path(argv[0]).name`). `red-proof` and `tdd` emit no RunnerResult at all,
    so `record_run` bails at the tool clause one line before the departed check
    -- and unlike a runner they have no second route: `auto_resolve_red_proof`
    clears only via `proven_red`, which needs a base-tree pytest run on a file
    that is not there to run.

    Live instance in aramid's own ledger: `890d7493a3e3`, red-proof on
    `tests/unit/test_zz_ci_dump_rehearsal.py`. Committed in `2d7dfe51`, judged
    from range `a2e101f2..2d7dfe51`, then the push was blocked, the commit
    rewritten into `e2ef7f0` without that file. Open across every later run
    until it was closed by hand.
    """
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding(tool="red-proof", file="tests/unit/test_gone.py"))
        got = resolve_departed(led, "r1", NOW.isoformat(), root=tmp_path,
                               tool="red-proof", present_ids=set())
        assert got == ["a" * 64]
        assert led.open_findings()["a" * 64]["status"] == "fixed"
    finally:
        led.close()


def test_resolve_departed_leaves_a_present_file_alone(tmp_path):
    """Opting in must not become "resolve this producer's findings"."""
    led = Ledger(tmp_path / "l.db")
    (tmp_path / "still_here.py").write_text("x = 1\n", encoding="utf-8")
    try:
        _seed(led, _finding(tool="red-proof", file="still_here.py"))
        assert resolve_departed(led, "r1", NOW.isoformat(), root=tmp_path,
                                tool="red-proof", present_ids=set()) == []
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


def test_resolve_departed_skips_a_finding_this_run_re_fired(tmp_path):
    """Same requirement as `auto_resolve_red_proof`: resolution runs AFTER
    `record_run`, so a finding the producer just re-raised is already open
    again and must not be resolved out from under itself."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding(tool="red-proof", file="tests/unit/test_gone.py"))
        assert resolve_departed(led, "r1", NOW.isoformat(), root=tmp_path,
                                tool="red-proof",
                                present_ids={"a" * 64}) == []
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


def test_resolve_departed_touches_only_the_named_producer(tmp_path):
    """`tool=` is a filter, not a hint. A `tdd` finding on the same missing
    file must survive a red-proof pass -- otherwise one producer opting in
    would silently opt in every other."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led,
              _finding(fid="a" * 64, tool="red-proof", file="gone.py"),
              _finding(fid="b" * 64, tool="tdd", file="gone.py"),
              _finding(fid="c" * 64, tool="mutation", file="gone.py"))
        resolve_departed(led, "r1", NOW.isoformat(), root=tmp_path,
                         tool="red-proof", present_ids=set())
        state = led.open_findings()
        assert state["a" * 64]["status"] == "fixed"
        assert state["b" * 64]["status"] == "open"
        assert state["c" * 64]["status"] == "open"
    finally:
        led.close()


def test_resolve_departed_is_a_no_op_without_a_root(tmp_path):
    """Mirrors `_departed`'s own opt-in: no repo to check, nothing cleared."""
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding(tool="red-proof", file="tests/unit/test_gone.py"))
        assert resolve_departed(led, "r1", NOW.isoformat(), root=None,
                                tool="red-proof", present_ids=set()) == []
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


def test_a_dast_style_endpoint_is_never_treated_as_departed(tmp_path):
    """THE REASON THE CHECK IS OPT-IN AND NOT GLOBAL.

    `consumers/dast.py` stores `file=f"{f.method} {f.path}"` -- "GET /login",
    a method and an endpoint. It is not a repo path, nothing of that name
    exists, and it joins to `root/GET/login`, which is INSIDE root and so
    passes the containment check. `_departed` therefore answers True.

    The first attempt at the producer fix moved the departed check ahead of
    `record_run`'s tool gate, which would have written every open DAST finding
    `fixed` on the next gate run -- a false repair, of security findings, into
    an append-only audit trail. `dast` must never appear in a `resolve_departed`
    call; this pins the consequence so the reasoning is not merely a comment.
    """
    from aramid.ledger import _departed
    assert _departed(tmp_path, "GET /login") is True, (
        "if this ever becomes False the note above is stale, but do NOT take "
        "it as licence to make departure global -- fix the reasoning first")

    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding(tool="dast", file="GET /login"))
        # A full gate-shaped run: dast is a consumer, never in scope_tools,
        # and nothing opts it in.
        led.record_run("r1", NOW.isoformat(), "pre-push",
                       {"gitleaks", "python", "semgrep"}, {"other.py"}, [],
                       root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


# ------------------------------------------------ the synthetic-path guard ---


def test_a_synthetic_marker_is_never_departed(tmp_path):
    """A path-shaped-but-not-a-path label must never be judged by existence.

    This is reachable in the SHIPPED code with no design change at all: the
    `tests` runner's findings carry tool "python" under aramid's own
    `[tests].command`, and "python" IS in scope_tools whenever that runner
    exits OK -- so `record_run` reaches `_departed("<test-suite>")`, gets True,
    and resolves a BLOCK-tier suite finding without the `suite_completed`
    evidence `tests_gate.auto_resolve_tests` demands. Measured in aramid's own
    ledger: of 4 historical resolutions of whole-suite findings, 3 carry an
    EMPTY payload (record_run) and only 1 carries
    `auto_resolved: suite_completed_clean`.

    Generic on the `<...>` shape rather than importing the one marker we know
    about: `record_run` sees only a string, a second marker inherits the guard
    for free, and a real file honestly named `<x>` failing the check errs
    toward leaving a finding OPEN.
    """
    led = Ledger(tmp_path / "l.db")
    try:
        _seed(led, _finding(tool="python", file="<test-suite>"))
        led.record_run("r1", NOW.isoformat(), "pre-push",
                       {"python"}, {"other.py"}, [], root=tmp_path)
        assert led.open_findings()["a" * 64]["status"] == "open"
    finally:
        led.close()


def test_the_real_suite_marker_matches_the_synthetic_shape():
    """The tripwire. The guard above is written against a SHAPE; this proves
    the shape still covers the actual marker the tests runner emits. Rename
    `_SUITE_FILE_MARKER` to something without angle brackets and this goes red
    here, rather than silently reopening the resolve-a-BLOCK-finding route.

    Checked against the scenario it CLAIMS to catch, not merely against a
    broken guard -- those fail for different reasons, and only the first is
    what this test is for. Measured:

        "<test-suite>"   -> True    (current)
        "__test_suite__" -> False   -> this test goes RED
        "test-suite"     -> False   -> this test goes RED
        ":test-suite:"   -> False   -> this test goes RED
        "<suite>"        -> True    -> stays green, correctly: a rename that
                                       KEEPS the brackets is still guarded
    """
    from aramid.ledger import _is_synthetic_path
    from aramid.runners.tests import _SUITE_FILE_MARKER

    assert _is_synthetic_path(_SUITE_FILE_MARKER), (
        f"{_SUITE_FILE_MARKER!r} is the whole-suite marker but no longer reads "
        "as synthetic, so ledger._departed will judge it by whether a file of "
        "that name exists -- and resolve BLOCK-tier suite findings on runs "
        "that never established the suite passed.")


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
