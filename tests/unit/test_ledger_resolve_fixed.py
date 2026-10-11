"""`aramid ledger resolve --fixed` at unit scope (FN-36): closing an
llm-review finding on evidence.

The close writes a permanent row into an append-only ledger and is the one
way a person, or an agent, can turn an open LLM finding into `fixed`. So
every refusal is asserted whole, with its exit code and with nothing
appended, and the success is asserted as the exact event.

Seams. A small real git repo, built once per module (`template`): c1
carries the bug, c2 fixes it, c3 is later unrelated work, and `side` is a
commit HEAD never saw. Tests that only read the repository share it and
reset its ledger; a test that commits, adds a file or builds a real worktree
gets a private copy (`own_repo`). The "tests" are tiny scripts that exit 0
or 1, run with this interpreter, so a red-proof round trip costs two process
starts and one worktree. The event clock and run id are injected, as in
test_ledger_cmd_marks.py. Where the point is what aramid does with a run
that did not finish, `evidenced_close.run_subprocess` is replaced."""
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import evidenced_close, gitutil
from aramid.commands import ledger_cmd as lc
from aramid.commands.ledger_cmd import cmd_ledger_resolve_args, cmd_ledger_resolve_fixed
from aramid.consumers import js_mutation
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Source, Verdict
from aramid.runners.base import RunnerResult, ToolState

AT = "2026-10-10T12:00:00+00:00"
RUN = "e" * 32
FID = "llm1"

_ROOT = """import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import calc
"""
# Passes when `route` sends `country` where `want` says.
_CHECK_ROUTE = _ROOT + """
sys.exit(0 if calc.route({country!r}) == {want!r} else 1)
"""
# Exits 1 for the missing fix and for nothing else. Each other way the tree
# without the fix could be wrong has an exit code of its own:
#   3  support/helper.py, which the fix ADDED, was taken away with it
#   4  tests/check_obsolete.py, a test the fix DELETED, came back
#   5  c3's later work was undone too (extra.py gone, or legacy.py back)
#   6  calc.other(), which c3 changed in the fix's own file, was undone
_CHECK_TREE = _ROOT + """

def there(rel):
    return os.path.exists(os.path.join(ROOT, rel))


if not there("support/helper.py"):
    sys.exit(3)
if there("tests/check_obsolete.py"):
    sys.exit(4)
if not there("extra.py") or there("legacy.py"):
    sys.exit(5)
if calc.other() != 2:
    sys.exit(6)
sys.exit(0 if calc.route("CN") == "ASIA" else 1)
"""
# Exits 7 when tests/check_obsolete.py is not there, and otherwise 1 for the
# missing fix.
_CHECK_BACK = _ROOT + """
if not os.path.exists(os.path.join(ROOT, "tests", "check_obsolete.py")):
    sys.exit(7)
sys.exit(0 if calc.route("CN") == "ASIA" else 1)
"""
# Passes when the fix is in. Each run also adds a word to `log`: whether the
# tree it ran in holds extra.py, which c3 added after the fix.
_CHECK_LATE = _ROOT + """
with open({log!r}, "a", encoding="utf-8") as log:
    log.write("with-c3 " if os.path.exists(os.path.join(ROOT, "extra.py")) else "without-c3 ")
sys.exit(0 if calc.route("CN") == "ASIA" else 1)
"""
# Passes when app/i/rate.py, the neighbour of app/[id]/, holds the fixed rate.
_CHECK_RATE = _ROOT + """
sys.path.insert(0, os.path.join(ROOT, "app", "i"))
import rate
sys.exit(0 if rate.RATE == 2 else 1)
"""
_CALC_BUG = "def route(country):\n    return 'EU'\n\n\ndef other():\n    return 1\n"
_CALC_FIXED = ("def route(country):\n    if country == 'CN':\n        return 'ASIA'\n"
               "    return 'EU'\n\n\ndef other():\n    return 1\n")


def _git(root, *args):
    cp = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
        cwd=root, capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    return cp.stdout.strip()


def _commit(root, message):
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def template(tmp_path_factory):
    """c1: the bug.
    c2: the fix. It changes calc.py, ADDS two checks and a helper outside
        tests/, DELETES an obsolete check, and rewrites checks/routes_check.py
        -- a test in a place no naming rule recognises.
    c3: later work: a new file, a deleted one, and another hunk of calc.py."""
    base = tmp_path_factory.mktemp("fn36")
    root, empty = base / "repo", base / "empty-template"
    root.mkdir()
    empty.mkdir()
    # Explicit: a module-scoped fixture runs before the per-test isolation
    # that neutralizes a machine-wide `init.templateDir` (tests/conftest.py).
    _git(root, "init", "-q", f"--template={empty}", "-b", "main")
    _write(root, ".gitignore", ".aramid/\nnode_modules/\n__pycache__/\n")
    _write(root, "calc.py", _CALC_BUG)
    _write(root, "legacy.py", "OLD = 1\n")
    _write(root, "tests/check_old.py", _CHECK_ROUTE.format(country="FR", want="EU"))
    _write(root, "tests/check_obsolete.py", "import sys\nsys.exit(0)\n")
    _write(root, "checks/routes_check.py", "import sys\nsys.exit(0)\n")
    c1 = _commit(root, "c1: the bug")

    _git(root, "checkout", "-q", "-b", "side")
    _write(root, "side.py", "SIDE = 1\n")
    side = _commit(root, "side: never merged")
    _git(root, "checkout", "-q", "main")

    _write(root, "calc.py", _CALC_FIXED)
    _write(root, "tests/check_cn.py", _CHECK_ROUTE.format(country="CN", want="ASIA"))
    _write(root, "tests/check_tree.py", _CHECK_TREE)
    _write(root, "support/helper.py", "READY = True\n")
    _write(root, "checks/routes_check.py", _CHECK_ROUTE.format(country="CN", want="ASIA"))
    (root / "tests" / "check_obsolete.py").unlink()
    c2 = _commit(root, "c2: the fix")

    _write(root, "extra.py", "X = 1\n")
    (root / "legacy.py").unlink()
    _write(root, "calc.py", _CALC_FIXED.replace("return 1", "return 2"))
    c3 = _commit(root, "c3: later work")
    return SimpleNamespace(root=root, c1=c1, c2=c2, c3=c3, side=side, answers={})


def _finding(critical=False, tool="llm-review", file="calc.py"):
    return Finding(FID, tool, "llm/logic", "critical" if critical else "high",
                   Severity.CRITICAL if critical else Severity.HIGH, Verdict.WARN,
                   file, 2, "route ignores CN", "return 'EU'", Gate.PRE_PUSH,
                   source=Source.LLM if tool == "llm-review" else Source.DETERMINISTIC,
                   confirmed=critical)


def _ledger(root):
    return Ledger(root / ".aramid" / "ledger.db")


def _seed(root, finding, head=None):
    led = _ledger(root)
    try:
        led.record_run("r1", "2026-10-09T00:00:00+00:00", "pre-push",
                       {finding.tool}, {finding.file}, [finding], head=head)
    finally:
        led.close()


def _fresh(template, finding, head=None):
    """The module's repo with an empty ledger holding just `finding`."""
    shutil.rmtree(template.root / ".aramid", ignore_errors=True)
    _seed(template.root, finding, head=head)
    return template


# What these git subcommands say about the shared repository depends on its
# commits alone, and no test moves them.
_ASKED_ONCE = (("rev-parse",), ("merge-base",), ("diff",), ("ls-tree",))


@pytest.fixture
def repo(template, monkeypatch):
    """The module's repo, shared, with the finding raised at c1. For tests
    that leave the repository itself alone: only the ledger is reset.

    A close asks git half a dozen questions about the commits before it runs
    anything, and each git start costs about 80 ms on Windows. The commits of
    the shared repository never change, so each question is put to real git
    once and the answer kept. `git status` is always asked: it is the one
    answer a test could change by leaving a tracked file edited."""
    real = gitutil._run

    def asked_once(root, *args):
        if root == template.root and args[:1] in _ASKED_ONCE:
            if args not in template.answers:
                template.answers[args] = real(root, *args)
            return template.answers[args]
        return real(root, *args)
    monkeypatch.setattr(gitutil, "_run", asked_once)
    return _fresh(template, _finding(), head=template.c1)


@pytest.fixture
def own_repo(template, tmp_path):
    """A private copy with the same finding, for tests that commit, add
    files or build a real worktree."""
    root = tmp_path / "repo"
    shutil.copytree(template.root, root, ignore=shutil.ignore_patterns(".aramid"))
    _seed(root, _finding(), head=template.c1)
    return SimpleNamespace(root=root, c1=template.c1, c2=template.c2, c3=template.c3,
                           side=template.side)


@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(lc, "_now", lambda: AT)
    monkeypatch.setattr(lc, "uuid", SimpleNamespace(uuid4=lambda: SimpleNamespace(hex=RUN)))


def _run_script(rel):
    """`--test` text that runs one of the repo's check scripts."""
    return shlex.join([sys.executable, rel])


CHECK_CN = _run_script("tests/check_cn.py")
CHECK_OLD = _run_script("tests/check_old.py")
CHECK_TREE = _run_script("tests/check_tree.py")


def _closes(root):
    """Every evidenced close in the ledger. Keyed on the payload, not on the
    injected run id, so "nothing recorded" holds without the clock too."""
    led = _ledger(root)
    try:
        return [e for e in led.events()
                if e.type is EventType.FINDING_RESOLVED
                and e.payload.get("auto_resolved") == "evidenced_close"]
    finally:
        led.close()


def _status(root):
    led = _ledger(root)
    try:
        return led.open_findings()[FID]["status"]
    finally:
        led.close()


def _refused(capsys, root, rc, line):
    """One refusal: exit 3, exactly this line on stderr, nothing recorded."""
    assert rc == 3
    assert capsys.readouterr() == ("", f"aramid: ledger resolve: {line}\n")
    assert _closes(root) == []
    assert _status(root) == "open"


# ------------------------------------------------- refusals before any run --

@pytest.mark.parametrize("reason", ["", "   ", None])
def test_fixed_requires_a_reason(tmp_path, capsys, reason):
    _seed(tmp_path, _finding())

    rc = cmd_ledger_resolve_fixed(tmp_path, FID, "HEAD", "pytest", reason)

    _refused(capsys, tmp_path, rc, "--reason is required")


@pytest.mark.parametrize("test", ["", "   ", None])
def test_fixed_requires_a_test_command(tmp_path, capsys, test):
    _seed(tmp_path, _finding())

    rc = cmd_ledger_resolve_fixed(tmp_path, FID, "HEAD", test, "r")

    _refused(capsys, tmp_path, rc,
             "--test is required with --fixed -- the command that runs the test proving "
             "the fix, e.g. --test \"python -m pytest tests/test_x.py::test_y\"")


def test_fixed_refuses_a_test_command_that_does_not_parse(tmp_path, capsys):
    _seed(tmp_path, _finding())

    rc = cmd_ledger_resolve_fixed(tmp_path, FID, "HEAD", 'pytest -k "unclosed', "r")

    _refused(capsys, tmp_path, rc,
             "--test does not parse as a command (No closing quotation)")


def test_fixed_reports_an_unreadable_config_as_an_engine_error(tmp_path, capsys):
    _seed(tmp_path, _finding())
    (tmp_path / "aramid.toml").write_text("this is not = valid = toml\n", encoding="utf-8")

    assert cmd_ledger_resolve_fixed(tmp_path, FID, "HEAD", "pytest", "r") == 3
    assert capsys.readouterr().err.startswith("aramid: ledger resolve: engine error: ")
    assert _closes(tmp_path) == []


def test_fixed_unknown_id(tmp_path, capsys):
    _seed(tmp_path, _finding())

    assert cmd_ledger_resolve_fixed(tmp_path, "nope", "HEAD", "pytest", "r") == 3
    assert capsys.readouterr() == ("", "aramid: ledger resolve: unknown finding id nope\n")
    assert _closes(tmp_path) == []


@pytest.mark.parametrize("tool", ["ruff", "mutation"])
def test_fixed_closes_llm_review_findings_only(tmp_path, capsys, tool):
    _seed(tmp_path, _finding(tool=tool))

    rc = cmd_ledger_resolve_fixed(tmp_path, FID, "HEAD", "pytest", "r")

    _refused(capsys, tmp_path, rc,
             f"{FID} is a {tool!r} finding -- --fixed closes an llm-review finding only. "
             f"A deterministic tool resolves or re-reports its own finding on its next "
             f"run, and a mutation survivor closes on a verified re-test")


@pytest.mark.parametrize("status, event", [
    ("fixed", Event(EventType.FINDING_RESOLVED, "r2", AT, finding_id=FID,
                    payload={"auto_resolved": "evidence_gone"})),
    ("overridden", Event(EventType.FINDING_OVERRIDDEN, "r2", AT, finding_id=FID,
                         payload={"reason": "ok"})),
])
def test_fixed_refuses_a_finding_that_is_not_open(tmp_path, capsys, status, event):
    _seed(tmp_path, _finding())
    led = _ledger(tmp_path)
    led.append(event)
    led.close()

    assert cmd_ledger_resolve_fixed(tmp_path, FID, "HEAD", "pytest", "r") == 3
    assert capsys.readouterr() == (
        "", f"aramid: ledger resolve: {FID} is not open (status={status}) -- resolve "
            f"--fixed only applies to an open finding\n")
    assert _closes(tmp_path) == []


def test_a_confirmed_critical_is_refused_without_red_proof(tmp_path, capsys):
    _seed(tmp_path, _finding(critical=True))

    rc = cmd_ledger_resolve_fixed(tmp_path, FID, "HEAD", "pytest", "r")

    _refused(capsys, tmp_path, rc,
             f"{FID} is a confirmed critical finding -- it closes only with red proof. "
             f"Add --red-proof: the test is then also run with the fix backed out and "
             f"must fail there")


# ------------------------------------------------------------- the commit --

def test_fixed_refuses_a_commit_git_does_not_know(repo, capsys):
    rc = cmd_ledger_resolve_fixed(repo.root, FID, "0badc0de", CHECK_CN, "r")

    _refused(capsys, repo.root, rc, "--fixed '0badc0de' is not a commit in this repo")


def test_fixed_refuses_a_commit_head_never_saw(repo, capsys):
    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.side, CHECK_CN, "r")

    _refused(capsys, repo.root, rc,
             f"{repo.side[:12]} is not part of HEAD's history -- the fix must be in the "
             f"tree the test runs on")


def test_fixed_refuses_a_commit_that_predates_the_finding(repo, capsys):
    """The finding was raised AT c1, so c1 cannot be what fixed it."""
    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c1, CHECK_CN, "r")

    _refused(capsys, repo.root, rc,
             f"{repo.c1[:12]} was already in the tree when {FID} was raised (at "
             f"{repo.c1[:12]}) -- a fix cannot predate its finding")


def test_a_finding_with_no_recorded_head_cannot_be_checked_for_predating(
        template, clock):
    """Detections older than 2026-09-06 carry no `head`. The check is skipped
    for them rather than refusing every old finding."""
    root = _fresh(template, _finding()).root            # no head recorded

    assert cmd_ledger_resolve_fixed(root, FID, template.c1, CHECK_CN, "r") == 0
    assert _status(root) == "fixed"


# ------------------------------------------------------- the run at HEAD --

def test_fixed_refuses_a_program_that_cannot_be_found(repo, capsys):
    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, "no-such-program-fn36 x", "r")

    _refused(capsys, repo.root, rc,
             "`no-such-program-fn36` was not found -- --test must start with a program "
             "that can be run from the repo root")


def test_fixed_refuses_a_test_that_fails_at_head(repo, capsys):
    failing = shlex.join([sys.executable, "-c", "import sys; sys.exit(7)"])

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, failing, "r")

    _refused(capsys, repo.root, rc,
             "the test exits 7 at HEAD -- it must pass (exit 0) on the tree that "
             "carries the fix")


def test_a_run_that_times_out_at_head_is_not_a_pass(repo, capsys, monkeypatch):
    monkeypatch.setattr(evidenced_close, "run_subprocess",
                        lambda argv, cwd, timeout_s, env=None: RunnerResult(
                            "python", ToolState.TIMEOUT, stderr="killed"))

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r")

    _refused(capsys, repo.root, rc,
             "the test did not pass at HEAD: it did not finish within 300 s -- a run "
             "that did not finish is not a pass")


def test_a_run_that_crashes_at_head_says_why(repo, capsys, monkeypatch):
    monkeypatch.setattr(evidenced_close, "run_subprocess",
                        lambda argv, cwd, timeout_s, env=None: RunnerResult(
                            "python", ToolState.CRASHED, stderr="aramid: python not started"))

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r")

    _refused(capsys, repo.root, rc,
             "the test did not pass at HEAD: aramid: python not started -- a run that "
             "did not finish is not a pass")


def test_a_program_the_os_refuses_to_start_is_a_refusal_not_a_crash(repo, capsys, monkeypatch):
    def boom(argv, cwd, timeout_s, env=None):
        raise OSError("exec format error")
    monkeypatch.setattr(evidenced_close, "run_subprocess", boom)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, "tool x", "r")

    _refused(capsys, repo.root, rc, "`tool` could not be started (exec format error)")


def test_fixed_refuses_a_tree_with_uncommitted_changes_to_tracked_files(own_repo, capsys):
    """The event records the commit the test passed at, and an edited tracked
    file makes the tree something other than that commit."""
    repo = own_repo
    _write(repo.root, "calc.py", _CALC_FIXED + "\n# edited\n")
    _write(repo.root, "extra.py", "X = 2\n")

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r")

    _refused(capsys, repo.root, rc,
             "2 tracked file(s) have uncommitted changes -- the close records the commit "
             "the test passed at, so commit or stash them first")


def test_an_untracked_file_does_not_stand_in_the_way(own_repo, clock):
    """A scratch file next to the code is not a change to the commit."""
    repo = own_repo
    _write(repo.root, "notes.txt", "x\n")

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r") == 0
    assert _status(repo.root) == "fixed"


def test_each_run_is_bounded_by_the_repos_own_tests_timeout(own_repo, capsys, monkeypatch):
    """`[tests].timeout_s` from the repo's aramid.toml, not the default."""
    repo = own_repo
    _write(repo.root, "aramid.toml", "[tests]\ntimeout_s = 7\n")
    given = []

    def fake(argv, cwd, timeout_s, env=None):
        given.append(timeout_s)
        return _TIMEOUT
    monkeypatch.setattr(evidenced_close, "run_subprocess", fake)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r")

    _refused(capsys, repo.root, rc,
             "the test did not pass at HEAD: it did not finish within 7 s -- a run "
             "that did not finish is not a pass")
    assert given == [7.0]


@pytest.mark.parametrize("tests_cfg, expected", [
    ({"timeout_s": 7}, 7.0),
    ({"timeout_s": 2.5}, 2.5),
    ({}, 300.0),
    ({"timeout_s": None}, 300.0),
    ({"timeout_s": "abc"}, 300.0),     # the loader warned and kept the text
    ({"timeout_s": True}, 300.0),      # ... and a boolean, which float() reads as 1
    ({"timeout_s": 0}, 300.0),
    ({"timeout_s": -5}, 300.0),
    ("nope", 300.0),                   # `tests = "nope"`: not a table at all
])
def test_the_timeout_is_the_configured_number_or_the_default(tests_cfg, expected):
    assert evidenced_close.run_timeout(SimpleNamespace(tests=tests_cfg)) == expected


# --------------------------------------------------------------- success --

def test_a_close_appends_exactly_one_event_and_reads_fixed(repo, capsys, clock):
    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN,
                                  "  guard added in route()  ")

    assert rc == 0
    assert capsys.readouterr() == (
        f"aramid: ledger: {FID} closed as fixed in {repo.c2[:12]} -- the test passes at "
        f"HEAD, red proof not run (guard added in route())\n", "")
    assert _closes(repo.root) == [
        Event(EventType.FINDING_RESOLVED, RUN, AT, finding_id=FID,
              payload={"auto_resolved": "evidenced_close", "commit": repo.c2,
                       "test_argv": [sys.executable, "tests/check_cn.py"], "test_rc": 0,
                       "reason": "guard added in route()", "head": repo.c3,
                       "red_proof": None, "via": "cli"})]
    assert _status(repo.root) == "fixed"


def test_the_commit_may_be_named_by_any_rev_and_is_recorded_as_a_full_sha(repo, clock):
    assert cmd_ledger_resolve_fixed(repo.root, FID, "HEAD~1", CHECK_CN, "r") == 0
    assert _closes(repo.root)[0].payload["commit"] == repo.c2


def test_the_fix_need_not_touch_the_findings_own_file(template, clock):
    """Round 316's 82d77aaa: the fix landed only in a caller."""
    root = _fresh(template, _finding(file="handlers.py"), head=template.c1).root

    assert cmd_ledger_resolve_fixed(root, FID, template.c2, CHECK_CN, "r") == 0
    assert _status(root) == "fixed"


@pytest.mark.parametrize("test, argv", [
    ('python -m pytest tests/test_x.py::test_y -k "a and b"',
     ["python", "-m", "pytest", "tests/test_x.py::test_y", "-k", "a and b"]),
    ('npx vitest run src/orders.test.ts -t "routes CN"',
     ["npx", "vitest", "run", "src/orders.test.ts", "-t", "routes CN"]),
])
def test_the_argv_is_recorded_exactly_as_split(repo, clock, monkeypatch, test, argv):
    ran = []

    def fake(run_argv, cwd, timeout_s, env=None):
        ran.append(run_argv)
        return RunnerResult("x", ToolState.OK, returncode=0)
    monkeypatch.setattr(evidenced_close, "run_subprocess", fake)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, test, "r") == 0
    assert _closes(repo.root)[0].payload["test_argv"] == argv
    assert ran == [argv]


def test_a_finding_that_changed_while_the_test_ran_is_not_closed(repo, capsys, clock,
                                                                 monkeypatch):
    """The test can run for minutes; a gate may override or resolve the
    finding meanwhile. The close is recorded against an open finding only."""
    def overridden_meanwhile(argv, cwd, timeout_s, env=None):
        led = _ledger(repo.root)
        led.append(Event(EventType.FINDING_OVERRIDDEN, "r9", AT, finding_id=FID,
                         payload={"reason": "accepted"}))
        led.close()
        return RunnerResult("x", ToolState.OK, returncode=0)
    monkeypatch.setattr(evidenced_close, "run_subprocess", overridden_meanwhile)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r") == 3
    assert capsys.readouterr() == (
        "", f"aramid: ledger resolve: {FID} is no longer open (status=overridden) -- it "
            f"changed while the test ran; nothing was recorded\n")
    assert _closes(repo.root) == []
    assert _status(repo.root) == "overridden"


# ------------------------------------------------------------- red proof --
#
# Three tests build a real worktree and really run the checks, because what
# they pin is the tree git leaves: what is backed out, what stays, what a
# conflict does. The rest decide nothing about the tree, so `git worktree`,
# `git revert` and `git checkout` answer 0 without acting and the three
# runs are scripted.

def _worktrees(root):
    return _git(root, "worktree", "list").splitlines()


def _sub(args):
    """A git call without its leading `-c name=value` options."""
    args = tuple(args)
    while args[:1] == ("-c",):
        args = args[2:]
    return args


def _hook_log(root):
    """Give the repo a `post-checkout` hook that logs its third argument each
    time it runs: 1 for a checkout of a commit, 0 for a checkout of paths."""
    hooks = root.parent / "hooks"
    hooks.mkdir()
    log = root.parent / "post-checkout.log"
    hook = hooks / "post-checkout"
    hook.write_text(f'#!/bin/sh\necho "$3" >> "{log.as_posix()}"\n', encoding="utf-8",
                    newline="\n")
    hook.chmod(0o755)
    _git(root, "config", "core.hooksPath", hooks.as_posix())
    return log


def _git_stub(monkeypatch, *subcommands, rc=0, stderr="", stdout=""):
    """Real git, except a call whose subcommand starts with one of
    `subcommands`: that answers `rc`, `stdout` and `stderr` and does nothing.
    Returns the stubbed calls, each as it was made."""
    real = gitutil._run
    calls = []

    def fake(root, *args):
        if any(_sub(args)[:len(sub)] == sub for sub in subcommands):
            calls.append(args)
            return subprocess.CompletedProcess(args, rc, stdout, stderr)
        return real(root, *args)
    monkeypatch.setattr(gitutil, "_run", fake)
    return calls


_TREE = (("worktree",), ("revert",), ("checkout",))


def _lit(*paths):
    """The paths as `git checkout` is given them: literal, never a pattern."""
    return tuple(f":(literal){path}" for path in paths)


_OK = RunnerResult("python", ToolState.OK, returncode=0)
_RED = RunnerResult("python", ToolState.OK, returncode=1)
_TIMEOUT = RunnerResult("python", ToolState.TIMEOUT, stderr="killed")


def _scripted(monkeypatch, *results):
    """Replace the runs with `results`, in order: HEAD, control, without the
    fix. Returns the (cwd, env) each run was given."""
    queue, seen = list(results), []

    def fake(argv, cwd, timeout_s, env=None):
        seen.append((cwd, env))
        return queue.pop(0)
    monkeypatch.setattr(evidenced_close, "run_subprocess", fake)
    return seen


def test_red_proof_fails_the_test_once_the_fix_is_backed_out_and_records_it(
        own_repo, capsys, clock):
    repo = own_repo

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    assert rc == 0
    assert capsys.readouterr() == (
        f"aramid: ledger: {FID} closed as fixed in {repo.c2[:12]} -- the test passes at "
        f"HEAD, failed (exit 1) without the fix (r)\n", "")
    # c2 changed six paths. Backed out: calc.py and checks/routes_check.py.
    # Kept: the helper it added, and its three paths under tests/.
    assert _closes(repo.root)[0].payload["red_proof"] == {
        "at": "head", "base": repo.c1, "control_rc": 0, "pre_fix_rc": 1, "backed_out": 2}
    assert _status(repo.root) == "fixed"
    # The repo itself is untouched and the worktree is gone.
    assert _git(repo.root, "status", "--porcelain") == ""
    assert _git(repo.root, "rev-parse", "HEAD") == repo.c3
    assert len(_worktrees(repo.root)) == 1


def test_only_the_fix_is_backed_out(own_repo, clock):
    """check_tree exits 1 for the missing fix alone. It would exit 3 had the
    helper the fix added gone with it, 4 had the test the fix deleted come
    back, 5 or 6 had c3's later work been undone as well.

    And nothing else separates the two runs: the repo's `post-checkout` hook
    runs once, for the worktree (1), and not again when the kept paths are
    checked out between the runs (that would log 0)."""
    repo = own_repo
    log = _hook_log(repo.root)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_TREE, "r",
                                    red_proof=True) == 0
    assert _closes(repo.root)[0].payload["red_proof"]["pre_fix_rc"] == 1
    assert log.read_text(encoding="utf-8").split() == ["1"]


def test_a_fix_whose_lines_changed_again_is_proved_at_the_fix_commit(own_repo, capsys,
                                                                     clock):
    """c4 changes the fix's own lines again, so git cannot back c2 out of
    HEAD. Red proof moves to c2 itself: a worktree at c2, the check the
    command names brought in from HEAD (c4 wrote it; c2 does not have it),
    a control there, then c2's two source paths put back to c1.

    check_late exits 1 for the missing fix. Not brought in, python would
    exit 2 for a file that is not there. And the repo's `post-checkout` hook
    runs once per worktree (1, 1) and for neither checkout of paths (0).

    The check says what tree each of its four runs was in: the repo and
    HEAD's worktree hold c3's later file, the two runs at c2 do not."""
    repo = own_repo
    runs = repo.root.parent / "runs.log"
    _write(repo.root, "calc.py", _CALC_FIXED.replace("return 'ASIA'", "return 'ASIA'  # CN")
           .replace("return 1", "return 2"))
    _write(repo.root, "tests/check_late.py", _CHECK_LATE.format(log=runs.as_posix()))
    c4 = _commit(repo.root, "c4: the fix's own lines again, and a check written later")
    log = _hook_log(repo.root)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2,
                                  _run_script("tests/check_late.py"), "r", red_proof=True)

    assert rc == 0
    assert capsys.readouterr() == (
        f"aramid: ledger: {FID} closed as fixed in {repo.c2[:12]} -- the test passes at "
        f"HEAD, failed (exit 1) without the fix as the code stood at {repo.c2[:12]} (r)\n",
        "")
    assert _closes(repo.root)[0].payload["red_proof"] == {
        "at": "commit", "base": repo.c1, "control_rc": 0, "pre_fix_rc": 1,
        "backed_out": 2, "head_conflicts": 1, "brought": 1}
    assert log.read_text(encoding="utf-8").split() == ["1", "1"]
    assert runs.read_text(encoding="utf-8").split() == [
        "with-c3", "with-c3", "without-c3", "without-c3"]
    assert _git(repo.root, "status", "--porcelain") == ""
    assert _git(repo.root, "rev-parse", "HEAD") == c4
    assert len(_worktrees(repo.root)) == 1


def test_the_kept_paths_are_as_head_has_them_whatever_happened_since_the_fix(
        own_repo, clock):
    """c4 touches three paths that c2's back-out leaves alone, each its own
    way, and red proof still shows exit 1, the missing fix:

      tests/check_cn.py        c2 added it, c4 edits it. Backing c2 out
                               would delete a file that changed since: a
                               conflict, and no obstacle, in a kept path.
      tests/check_obsolete.py  c2 deleted it, c4 brings it back. Another
                               conflict. Removed as "deleted by the fix",
                               the command would exit 7.
      support/helper.py        c2 added it, c4 deletes it. git refuses to
                               check out a path HEAD does not hold."""
    repo = own_repo
    _write(repo.root, "tests/check_cn.py",
           _CHECK_ROUTE.format(country="CN", want="ASIA") + "# edited later\n")
    _write(repo.root, "tests/check_obsolete.py", "import sys\nsys.exit(0)  # back\n")
    _write(repo.root, "tests/check_back.py", _CHECK_BACK)
    (repo.root / "support" / "helper.py").unlink()
    _commit(repo.root, "c4: the fix's own tests and helper, again")

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2,
                                    _run_script("tests/check_back.py"), "r",
                                    red_proof=True) == 0
    assert _closes(repo.root)[0].payload["red_proof"] == {
        "at": "head", "base": repo.c1, "control_rc": 0, "pre_fix_rc": 1, "backed_out": 2}
    assert _git(repo.root, "status", "--porcelain") == ""
    assert len(_worktrees(repo.root)) == 1


def test_a_kept_path_with_brackets_in_its_name_brings_back_only_itself(own_repo, clock):
    """app/[id]/rate.py is new in the fix, so it stays. Read as a git
    pattern it also names app/i/rate.py, which the fix CHANGED. Checked out
    along with it, the fix would be back and the test would pass."""
    repo = own_repo
    _write(repo.root, "app/i/rate.py", "RATE = 1\n")
    _write(repo.root, "tests/check_rate.py", _CHECK_RATE)
    _commit(repo.root, "c4: a rate, and it is wrong")
    _write(repo.root, "app/i/rate.py", "RATE = 2\n")
    _write(repo.root, "app/[id]/rate.py", "RATE = 2\n")
    fix = _commit(repo.root, "c5: the rate fixed")

    assert cmd_ledger_resolve_fixed(repo.root, FID, fix, _run_script("tests/check_rate.py"),
                                    "r", red_proof=True) == 0
    assert _closes(repo.root)[0].payload["red_proof"] == {
        "at": "head", "base": _git(repo.root, "rev-parse", "HEAD~1"), "control_rc": 0,
        "pre_fix_rc": 1, "backed_out": 1}


def test_the_tree_is_built_by_git_in_this_order(repo, clock, monkeypatch):
    """A detached worktree of HEAD; the fix backed out without committing;
    the kept paths that HEAD holds checked out from it again, as literal
    paths and with hooks off -- the helper the fix added and its tests, but
    not the test it deleted, which HEAD does not hold and which is removed
    instead; then the worktree goes."""
    calls = _git_stub(monkeypatch, *_TREE)
    seen = _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    wt = seen[1][0]
    assert calls == [
        ("worktree", "add", "--detach", str(wt), repo.c3),
        ("revert", "--no-commit", repo.c2),
        ("-c", f"core.hooksPath={wt.parent / 'no-hooks'}", "checkout", repo.c3, "--",
         *_lit("support/helper.py", "tests/check_cn.py", "tests/check_tree.py")),
        ("worktree", "remove", "--force", str(wt)),
        ("worktree", "prune")]


def test_a_test_file_the_command_names_stays_where_no_naming_rule_knows_it(
        repo, clock, monkeypatch):
    """checks/routes_check.py is no test by its name. The command runs it,
    so it is the file under test and is not backed out with the fix."""
    calls = _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2,
                                    _run_script("checks/routes_check.py"), "r",
                                    red_proof=True) == 0
    checkout = [_sub(c) for c in calls if _sub(c)[0] == "checkout"]
    assert checkout == [("checkout", repo.c3, "--", *_lit(
        "checks/routes_check.py", "support/helper.py", "tests/check_cn.py",
        "tests/check_tree.py"))]
    assert _closes(repo.root)[0].payload["red_proof"]["backed_out"] == 1


def test_head_decides_which_kept_paths_come_back(repo, clock, monkeypatch):
    """Not what the commit did to the path. Here HEAD is said to hold the
    test c2 deleted and to have lost the helper c2 added: the first is
    checked out, and git is not asked for the second, which it would
    refuse."""
    calls = _git_stub(monkeypatch, *_TREE)
    _git_stub(monkeypatch, ("ls-tree",),
              stdout="calc.py\0tests/check_cn.py\0tests/check_obsolete.py\0"
                     "tests/check_tree.py\0")
    _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    checkout = [_sub(c) for c in calls if _sub(c)[0] == "checkout"]
    assert checkout == [("checkout", repo.c3, "--", *_lit(
        "tests/check_cn.py", "tests/check_obsolete.py", "tests/check_tree.py"))]


def test_no_checkout_is_made_when_head_holds_none_of_the_kept_paths(repo, clock,
                                                                   monkeypatch):
    calls = _git_stub(monkeypatch, *_TREE)
    _git_stub(monkeypatch, ("ls-tree",), stdout="calc.py\0")
    _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    assert [c[0] for c in calls] == ["worktree", "revert", "worktree", "worktree"]


def test_the_paths_a_command_names():
    assert evidenced_close._named_paths(
        ["python", "-m", "pytest", "tests/a.py::test_x", "./b/c.py", "d\\e.py", "-k", "x"]
    ) == {"python", "-m", "pytest", "tests/a.py", "b/c.py", "d/e.py", "-k", "x"}


def test_a_merge_commit_is_backed_out_against_the_branch_it_was_merged_into(
        own_repo, clock, monkeypatch):
    repo = own_repo
    _git(repo.root, "checkout", "-q", "-b", "feature")
    _write(repo.root, "calc.py", _CALC_FIXED.replace("return 1", "return 3"))
    _commit(repo.root, "feature: other() again")
    _git(repo.root, "checkout", "-q", "main")
    _git(repo.root, "merge", "-q", "--no-ff", "-m", "merge feature", "feature")
    merge = _git(repo.root, "rev-parse", "HEAD")
    calls = _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, merge, CHECK_CN, "r",
                                    red_proof=True) == 0
    assert [c for c in calls if c[0] == "revert"] == [
        ("revert", "--no-commit", "-m", "1", merge)]


def test_red_proof_refuses_a_test_that_never_saw_the_bug(repo, capsys, monkeypatch):
    """It passes with the fix and without it. A command that runs no test at
    all (`true`) lands here too."""
    _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK, _OK, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_OLD, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"the test also passes with {repo.c2[:12]} backed out -- it does not detect "
             f"what that commit fixed, so it is not evidence that the finding is fixed")


def test_red_proof_refuses_a_test_that_fails_in_a_clean_checkout(repo, capsys, monkeypatch):
    """It passes in the repo and exits 2 in the checkout: an untracked test
    file does that. Without the control this would read as "fails without
    the fix"."""
    _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK, RunnerResult("python", ToolState.OK, returncode=2))

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             "red proof could not be run: the test passes in the repo but exits 2 in a "
             "clean checkout of HEAD -- it depends on something that is not committed "
             "(an untracked file, a build step, an install), so a failure without the fix "
             "would prove nothing")


def test_a_control_run_that_does_not_finish_is_named_as_such(repo, capsys, monkeypatch):
    _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK, _TIMEOUT)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             "red proof could not be run: the test passes in the repo but did not run "
             "(it did not finish within 300 s) in a clean checkout of HEAD -- it depends "
             "on something that is not committed (an untracked file, a build step, an "
             "install), so a failure without the fix would prove nothing")


def test_a_run_without_the_fix_that_times_out_is_not_a_failing_test(repo, capsys,
                                                                   monkeypatch):
    _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK, _OK, _TIMEOUT)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"red proof could not be shown: with {repo.c2[:12]} backed out the test did "
             f"not finish (it did not finish within 300 s) -- that is not a failing test")


def test_the_worktree_runs_import_the_worktrees_own_source(repo, clock, monkeypatch):
    """Both worktree runs get `worktree_import_env`, with the worktree as
    cwd; the HEAD run gets the repo root and no env."""
    _git_stub(monkeypatch, *_TREE)
    seen = _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    (head_cwd, head_env), (control_cwd, control_env), (before_cwd, before_env) = seen
    assert (head_cwd, head_env) == (repo.root, None)
    assert control_cwd == before_cwd != repo.root
    assert control_env == before_env
    assert control_env["PYTHONPATH"].split(os.pathsep)[:2] == [
        str(control_cwd / "src"), str(control_cwd)]
    assert control_env["PYTHONDONTWRITEBYTECODE"] == "1"


@pytest.mark.parametrize("rel, text", [
    ("tests/check_more.py", "import sys\nsys.exit(0)\n"),   # a test alone
    ("brand_new.py", "NEW = 1\n"),                           # a new file alone
])
def test_red_proof_refuses_a_commit_that_changes_no_existing_source(own_repo, capsys,
                                                                    rel, text):
    """Nothing the commit did can be backed out: its tests stay, and so does
    every file it added (taking test support away would fake a failure)."""
    repo = own_repo
    _write(repo.root, rel, text)
    c4 = _commit(repo.root, "c4")

    rc = cmd_ledger_resolve_fixed(repo.root, FID, c4, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"{c4[:12]} changes no existing source file -- only tests, or only new "
             f"files. Red proof backs the commit out and reruns the test, so there is "
             f"nothing it could take away")


def test_red_proof_refuses_a_commit_with_no_parent(template, capsys, monkeypatch):
    root = _fresh(template, _finding()).root     # no head: c1 is not refused as predating
    _scripted(monkeypatch, _OK)

    rc = cmd_ledger_resolve_fixed(root, FID, template.c1, CHECK_OLD, "r", red_proof=True)

    _refused(capsys, root, rc,
             f"red proof backs the fix out, and {template.c1[:12]} has no parent commit "
             f"to go back to")


def test_node_modules_is_linked_for_the_runs_and_unlinked_before_the_worktree_goes(
        repo, clock, monkeypatch):
    """A JS test needs the repo's installed dependencies in the worktree, and
    removing the worktree through the link would reach the real directory."""
    order = []
    real = gitutil._run

    def spy(root, *args):
        if _sub(args)[:1] in _TREE:
            if args[:2] == ("worktree", "remove"):
                order.append("remove")
            return subprocess.CompletedProcess(args, 0, "", "")
        return real(root, *args)
    monkeypatch.setattr(gitutil, "_run", spy)
    monkeypatch.setattr(js_mutation, "_link_node_modules",
                        lambda src, wt: order.append(("link", src)) or True)
    monkeypatch.setattr(js_mutation, "_unlink_node_modules",
                        lambda wt: order.append("unlink"))
    _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    assert order == [("link", repo.root), "unlink", "remove"]


def test_each_worktree_gets_its_own_node_modules_link_and_loses_it_first(repo, clock,
                                                                        monkeypatch):
    order = []
    real = gitutil._run

    def fake(root, *args):
        if args[:2] == ("worktree", "remove"):
            order.append(("remove", Path(args[-1]).name))
        if args[:1] == ("revert",):
            return subprocess.CompletedProcess(args, 1, "", "error: could not revert\n")
        if args[:2] == ("diff", "--name-only"):
            return subprocess.CompletedProcess(args, 0, "calc.py\0", "")
        if _sub(args)[:1] in _TREE:
            return subprocess.CompletedProcess(args, 0, "", "")
        return real(root, *args)
    monkeypatch.setattr(gitutil, "_run", fake)
    monkeypatch.setattr(js_mutation, "_link_node_modules",
                        lambda root, wt: order.append(("link", wt.name)) or True)
    monkeypatch.setattr(js_mutation, "_unlink_node_modules",
                        lambda wt: order.append(("unlink", wt.name)))
    _scripted(monkeypatch, _OK, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    assert order == [("link", "wt"), ("unlink", "wt"), ("remove", "wt"),
                     ("link", "wt-fix"), ("unlink", "wt-fix"), ("remove", "wt-fix")]


def test_nothing_is_unlinked_when_the_repo_has_no_node_modules(repo, clock, monkeypatch):
    _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK, _OK, _RED)
    unlinked = []
    monkeypatch.setattr(js_mutation, "_unlink_node_modules", unlinked.append)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    assert unlinked == []


def test_a_node_modules_link_that_fails_is_a_refusal(repo, capsys, monkeypatch):
    calls = _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK)

    def cannot(src, wt):
        raise OSError("mklink /J failed: access denied")
    monkeypatch.setattr(js_mutation, "_link_node_modules", cannot)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             "red proof could not be run: node_modules could not be linked into the "
             "worktree (mklink /J failed: access denied)")
    assert [c[:2] for c in calls][-2:] == [("worktree", "remove"), ("worktree", "prune")]


def test_a_confirmed_critical_closes_with_red_proof(template, clock, monkeypatch):
    root = _fresh(template, _finding(critical=True), head=template.c1).root
    _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(root, FID, template.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    assert _status(root) == "fixed"


def test_a_close_through_mcp_is_marked_as_one(repo, clock, monkeypatch):
    _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True, via="mcp") == 0
    assert _closes(repo.root)[0].payload["via"] == "mcp"


def test_a_cleanup_git_cannot_do_is_named_and_does_not_change_the_answer(
        repo, capsys, clock, monkeypatch):
    """The proof was shown before the cleanup started. A worktree git cannot
    remove is a leak to name, not a reason to lose the close or to raise."""
    real = gitutil._run

    def fake(root, *args):
        if args[:2] == ("worktree", "remove"):
            raise gitutil.GitTimeout("git worktree timed out after 600 s and was killed")
        if _sub(args)[:1] in _TREE:
            return subprocess.CompletedProcess(args, 0, "", "")
        return real(root, *args)
    monkeypatch.setattr(gitutil, "_run", fake)
    seen = _scripted(monkeypatch, _OK, _OK, _RED)

    try:
        assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                        red_proof=True) == 0
        wt = seen[1][0]
        assert capsys.readouterr().err == (
            f"aramid: ledger resolve: worktree cleanup leaked at {wt}\n")
        assert _status(repo.root) == "fixed"
        # Left where it is, not removed: a link to the repo's node_modules
        # may still be in there, and removing through it reaches the real one.
        assert wt.parent.is_dir()
    finally:
        # The leak this test provokes is real: the command's own temp dir.
        shutil.rmtree(seen[1][0].parent, ignore_errors=True)


# ----------------------------------------------------- git that says no --

def test_a_git_that_does_not_answer_is_an_engine_error(repo, capsys, monkeypatch):
    def hung(root, rev):
        raise gitutil.GitTimeout("git rev-parse timed out after 600 s and was killed")
    monkeypatch.setattr(gitutil, "rev_sha", hung)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r")

    _refused(capsys, repo.root, rc,
             "engine error: git rev-parse timed out after 600 s and was killed")


def test_fixed_refuses_when_git_cannot_read_the_working_tree(repo, capsys, monkeypatch):
    _git_stub(monkeypatch, ("status",), rc=128, stderr="fatal: index file corrupt\n")

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r")

    _refused(capsys, repo.root, rc,
             "git could not read the working tree's state: fatal: index file corrupt")


def test_red_proof_refuses_when_git_cannot_read_what_the_commit_changed(repo, capsys,
                                                                       monkeypatch):
    _git_stub(monkeypatch, ("diff",), rc=128, stderr="fatal: bad object\n")
    _scripted(monkeypatch, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"git could not read what {repo.c2[:12]} changed: fatal: bad object")


def test_red_proof_refuses_when_git_cannot_list_the_files_of_head(repo, capsys,
                                                                   monkeypatch):
    _git_stub(monkeypatch, ("ls-tree",), rc=128, stderr="fatal: not a tree object\n")
    _scripted(monkeypatch, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             "red proof could not be run: git could not list the files of HEAD "
             "(fatal: not a tree object)")


def test_a_worktree_git_cannot_create_is_a_refusal(repo, capsys, monkeypatch):
    _git_stub(monkeypatch, ("worktree", "add"), rc=128, stderr="fatal: no space left\n")
    _scripted(monkeypatch, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             "red proof could not be run: git worktree add failed (fatal: no space left)")


def _revert_fails(monkeypatch, unmerged, listing_rc=0):
    """`git revert` exits 1 and leaves `unmerged` in conflict, as `git diff
    --name-only` lists them (or cannot: `listing_rc`). Returns the listing
    calls, each as it was made."""
    _git_stub(monkeypatch, ("worktree",), ("checkout",))
    _git_stub(monkeypatch, ("revert",), rc=1,
              stderr="error: could not revert 0a1b2c3... c2: the fix\n"
                     "hint: After resolving the conflicts, mark them with\n")
    return _git_stub(monkeypatch, ("diff", "--name-only"), rc=listing_rc,
                     stdout="".join(f"{path}\0" for path in unmerged))


# A conflict in a path that has to be backed out, as git lists it, with what
# the refusal calls it and how many paths it counts. tests/check_cn.py stays
# at HEAD, so it is not one of them.
_STUCK = [
    (["calc.py"], "calc.py", 1),
    (["calc.py", "legacy.py"], "calc.py and 1 more file(s)", 2),
    (["tests/check_cn.py", "calc.py", "CHANGELOG.md", "docs/guide.md"],
     "CHANGELOG.md and 2 more file(s)", 3),
]


@pytest.mark.parametrize("unmerged, _named, count", _STUCK)
def test_a_conflict_in_a_path_that_has_to_be_backed_out_moves_red_proof_to_the_fix_commit(
        repo, capsys, clock, monkeypatch, unmerged, _named, count):
    _revert_fails(monkeypatch, unmerged)
    _scripted(monkeypatch, _OK, _OK, _OK, RunnerResult("python", ToolState.OK, returncode=3))

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    assert capsys.readouterr() == (
        f"aramid: ledger: {FID} closed as fixed in {repo.c2[:12]} -- the test passes at "
        f"HEAD, failed (exit 3) without the fix as the code stood at {repo.c2[:12]} (r)\n",
        "")
    assert _closes(repo.root)[0].payload["red_proof"] == {
        "at": "commit", "base": repo.c1, "control_rc": 0, "pre_fix_rc": 3, "backed_out": 2,
        "head_conflicts": count, "brought": 1}


def test_the_proof_at_the_fix_commit_is_built_by_git_in_this_order(repo, clock,
                                                                  monkeypatch):
    """HEAD's worktree goes before the one at the fix commit is made. The
    test the command names comes in from HEAD before the control. The
    commit's two source paths go back to its parent before the last run.
    Both checkouts are of literal paths, with hooks off."""
    calls = _git_stub(monkeypatch, ("worktree",), ("checkout",))
    _git_stub(monkeypatch, ("revert",), rc=1, stderr="error: could not revert\n")
    _git_stub(monkeypatch, ("diff", "--name-only"), stdout="calc.py\0")
    seen = _scripted(monkeypatch, _OK, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    wt, fix = seen[1][0], seen[2][0]
    assert (wt.name, fix.name, fix.parent) == ("wt", "wt-fix", wt.parent)
    off = ("-c", f"core.hooksPath={wt.parent / 'no-hooks'}")
    assert calls == [
        ("worktree", "add", "--detach", str(wt), repo.c3),
        ("worktree", "remove", "--force", str(wt)),
        ("worktree", "prune"),
        ("worktree", "add", "--detach", str(fix), repo.c2),
        (*off, "checkout", repo.c3, "--", *_lit("tests/check_cn.py")),
        (*off, "checkout", repo.c1, "--", *_lit("calc.py", "checks/routes_check.py")),
        ("worktree", "remove", "--force", str(fix)),
        ("worktree", "prune")]
    # Both runs there are in that worktree, on its own source.
    assert [cwd for cwd, _env in seen] == [repo.root, wt, fix, fix]
    assert seen[2][1] == seen[3][1]
    assert seen[2][1]["PYTHONPATH"].split(os.pathsep)[:2] == [str(fix / "src"), str(fix)]
    # Nothing leaked, so the directory both worktrees were in is gone.
    assert not wt.parent.exists()


def test_nothing_is_brought_in_when_the_command_names_no_file_head_holds(repo, clock,
                                                                        monkeypatch):
    """`-k` and a word after it name no file. The test then has to exist at
    the fix commit already, and the control says whether it does."""
    calls = _git_stub(monkeypatch, ("worktree",), ("checkout",))
    _git_stub(monkeypatch, ("revert",), rc=1, stderr="error: could not revert\n")
    _git_stub(monkeypatch, ("diff", "--name-only"), stdout="calc.py\0")
    _scripted(monkeypatch, _OK, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, "python -m pytest -k cn", "r",
                                    red_proof=True) == 0
    checkouts = [_sub(c) for c in calls if _sub(c)[0] == "checkout"]
    assert checkouts == [("checkout", repo.c1, "--", *_lit("calc.py", "checks/routes_check.py"))]
    assert _closes(repo.root)[0].payload["red_proof"]["brought"] == 0


@pytest.mark.parametrize("unmerged, named, _count", _STUCK)
def test_a_test_that_does_not_pass_at_the_fix_commit_is_refused_and_the_conflict_named(
        repo, capsys, monkeypatch, unmerged, named, _count):
    """Named, so the person sees WHICH file a later commit changed. It is
    often a CHANGELOG and not the fix."""
    _revert_fails(monkeypatch, unmerged)
    _scripted(monkeypatch, _OK, _OK, RunnerResult("python", ToolState.OK, returncode=4))

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"red proof could not be run: {repo.c2[:12]} can no longer be backed out of "
             f"HEAD -- it conflicts with later changes to {named} -- and at "
             f"{repo.c2[:12]} itself the test exits 4: as it is at HEAD it does not run "
             f"against the code as it stood when the fix was made")


def test_a_control_at_the_fix_commit_that_does_not_finish_is_named_as_such(
        repo, capsys, monkeypatch):
    _revert_fails(monkeypatch, ["calc.py"])
    _scripted(monkeypatch, _OK, _OK, _TIMEOUT)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"red proof could not be run: {repo.c2[:12]} can no longer be backed out of "
             f"HEAD -- it conflicts with later changes to calc.py -- and at "
             f"{repo.c2[:12]} itself the test did not run (it did not finish within 300 s): "
             f"as it is at HEAD it does not run against the code as it stood when the fix "
             f"was made")


def test_at_the_fix_commit_a_test_that_never_saw_the_bug_is_refused(repo, capsys,
                                                                   monkeypatch):
    _revert_fails(monkeypatch, ["calc.py"])
    _scripted(monkeypatch, _OK, _OK, _OK, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"the test also passes at {repo.c2[:12]} with that commit backed out -- it "
             f"does not detect what that commit fixed, so it is not evidence that the "
             f"finding is fixed")


def test_at_the_fix_commit_a_run_that_times_out_is_not_a_failing_test(repo, capsys,
                                                                     monkeypatch):
    _revert_fails(monkeypatch, ["calc.py"])
    _scripted(monkeypatch, _OK, _OK, _OK, _TIMEOUT)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"red proof could not be shown: at {repo.c2[:12]}, with that commit backed "
             f"out, the test did not finish (it did not finish within 300 s) -- that is "
             f"not a failing test")


def test_a_test_git_cannot_bring_in_from_head_is_a_refusal(repo, capsys, monkeypatch):
    _revert_fails(monkeypatch, ["calc.py"])
    _git_stub(monkeypatch, ("checkout", repo.c3), rc=1, stderr="error: unable to write\n")
    _scripted(monkeypatch, _OK, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             "red proof could not be run: git could not bring the test in from HEAD "
             "(error: unable to write)")


def test_files_git_cannot_put_back_to_the_parent_are_a_refusal(repo, capsys, monkeypatch):
    _revert_fails(monkeypatch, ["calc.py"])
    _git_stub(monkeypatch, ("checkout", repo.c1), rc=1, stderr="error: unable to write\n")
    _scripted(monkeypatch, _OK, _OK, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"red proof could not be run: git could not put {repo.c2[:12]}'s files back "
             f"to its parent (error: unable to write)")


def test_a_worktree_git_cannot_create_at_the_fix_commit_is_a_refusal(repo, capsys,
                                                                    monkeypatch):
    _revert_fails(monkeypatch, ["calc.py"])
    real = gitutil._run

    def fake(root, *args):
        if args[:2] == ("worktree", "add") and args[-1] == repo.c2:
            return subprocess.CompletedProcess(args, 128, "", "fatal: no space left\n")
        return real(root, *args)
    monkeypatch.setattr(gitutil, "_run", fake)
    _scripted(monkeypatch, _OK, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             "red proof could not be run: git worktree add failed (fatal: no space left)")


def test_a_confirmed_critical_closes_on_a_proof_at_the_fix_commit(template, clock,
                                                                  monkeypatch):
    """Either red proof meets the rule for a confirmed critical: the one at
    HEAD, or this one when the fix can no longer be backed out of HEAD."""
    root = _fresh(template, _finding(critical=True), head=template.c1).root
    _revert_fails(monkeypatch, ["calc.py"])
    _scripted(monkeypatch, _OK, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(root, FID, template.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    assert _status(root) == "fixed"
    assert _closes(root)[0].payload["red_proof"]["at"] == "commit"


def test_a_conflict_only_in_paths_that_stay_at_head_does_not_stop_red_proof(
        repo, clock, monkeypatch):
    """Both are among c2's kept paths; `_keep_at_head` overwrites them. git
    is asked for the UNMERGED paths, once."""
    listed = _revert_fails(monkeypatch, ["tests/check_cn.py", "support/helper.py"])
    _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    assert _closes(repo.root)[0].payload["red_proof"]["pre_fix_rc"] == 1
    assert listed == [("diff", "--name-only", "--diff-filter=U", "-z")]


@pytest.mark.parametrize("unmerged, listing_rc", [
    ([], 0),                # the back-out failed and left no conflict
    (["calc.py"], 128),     # ... or git cannot say what it left
])
def test_a_back_out_that_fails_with_no_conflict_git_can_name_quotes_gits_first_line(
        repo, capsys, monkeypatch, unmerged, listing_rc):
    """Not known to be harmless, so it is refused, with what git said."""
    _revert_fails(monkeypatch, unmerged, listing_rc)
    _scripted(monkeypatch, _OK, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"red proof could not be run: git could not back {repo.c2[:12]} out of HEAD "
             f"(error: could not revert 0a1b2c3... c2: the fix)")


def test_red_proof_refuses_when_the_kept_paths_cannot_be_put_back(repo, capsys,
                                                                 monkeypatch):
    _git_stub(monkeypatch, ("worktree",), ("revert",))
    _git_stub(monkeypatch, ("checkout",), rc=1, stderr="error: pathspec did not match\n")
    _scripted(monkeypatch, _OK, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             "red proof could not be run: git could not put the test files back after "
             "backing the fix out (error: pathspec did not match)")


def test_what_git_said_is_cut_to_two_hundred_characters(repo, capsys, monkeypatch):
    _git_stub(monkeypatch, ("worktree", "add"), rc=128, stderr="  " + "x" * 300 + "\n")
    _scripted(monkeypatch, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc,
             f"red proof could not be run: git worktree add failed ({'x' * 200})")


def test_a_git_that_refused_without_a_word_is_still_a_refusal(repo, capsys, monkeypatch):
    _git_stub(monkeypatch, ("worktree", "add"), rc=128, stderr="")
    _scripted(monkeypatch, _OK)

    rc = cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r", red_proof=True)

    _refused(capsys, repo.root, rc, "red proof could not be run: git worktree add failed ()")


def test_the_kept_paths_are_put_back_a_hundred_at_a_time(repo, clock, monkeypatch):
    """One `git checkout` per path is slow on a wide commit and one for all
    of them can pass Windows' command-line limit."""
    wide = [("M", "calc.py")] + [("A", f"tests/t{i:03}.py") for i in range(101)]
    monkeypatch.setattr(evidenced_close, "_changed", lambda root, base, commit: wide)
    calls = _git_stub(monkeypatch, *_TREE)
    _git_stub(monkeypatch, ("ls-tree",), stdout="".join(f"{rel}\0" for _, rel in wide))
    _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, CHECK_CN, "r",
                                    red_proof=True) == 0
    checkouts = [_sub(c) for c in calls if _sub(c)[0] == "checkout"]
    assert [c[:3] for c in checkouts] == [("checkout", repo.c3, "--")] * 2
    assert [c[3:] for c in checkouts] == [
        _lit(*(rel for _, rel in wide[1:101])), _lit(wide[101][1])]
    assert _closes(repo.root)[0].payload["red_proof"]["backed_out"] == 1


# -------------------------------------------------- which resolution it is --

def test_test_or_red_proof_without_fixed_is_refused(tmp_path, capsys):
    _seed(tmp_path, _finding())
    line = ("aramid: ledger resolve: --test and --red-proof belong to --fixed <commit> -- "
            "they are the evidence that an llm-review finding is fixed\n")

    assert cmd_ledger_resolve_args(tmp_path, [FID], test="pytest", reason="r") == 3
    assert capsys.readouterr() == ("", line)
    assert cmd_ledger_resolve_args(tmp_path, [FID], red_proof=True, reason="r") == 3
    assert capsys.readouterr() == ("", line)


def test_fixed_with_out_of_scope_is_refused(tmp_path, capsys):
    _seed(tmp_path, _finding())

    assert cmd_ledger_resolve_args(tmp_path, [FID], out_of_scope=True, fixed="HEAD",
                                   test="pytest", reason="r") == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger resolve: --fixed and --out-of-scope are two different "
            "resolutions -- give one\n")


def test_fixed_closes_one_finding_at_a_time(tmp_path, capsys):
    _seed(tmp_path, _finding())

    assert cmd_ledger_resolve_args(tmp_path, [FID, "other"], fixed="HEAD", test="pytest",
                                   reason="r") == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger resolve: --fixed closes one finding at a time (2 ids given) "
            "-- each needs the test that proves its own fix\n")
    assert _closes(tmp_path) == []


def test_fixed_goes_to_the_evidenced_close(repo, clock, monkeypatch):
    _git_stub(monkeypatch, *_TREE)
    _scripted(monkeypatch, _OK, _OK, _RED)

    assert cmd_ledger_resolve_args(repo.root, [FID], fixed=repo.c2, test=CHECK_CN,
                                   red_proof=True, reason="r") == 0
    payload = _closes(repo.root)[0].payload
    assert (payload["commit"], payload["via"], payload["red_proof"]["pre_fix_rc"]) == (
        repo.c2, "cli", 1)


def test_without_fixed_every_id_goes_to_out_of_scope_and_the_worst_exit_wins(
        tmp_path, capsys, monkeypatch):
    calls = []

    def fake(root, fid, out_of_scope, reason):
        calls.append((fid, out_of_scope, reason))
        return {"a": 0, "b": 3, "c": 0}[fid]
    monkeypatch.setattr(lc, "cmd_ledger_resolve", fake)

    assert cmd_ledger_resolve_args(tmp_path, ["a", "b", "c"], out_of_scope=True,
                                   reason="scoped") == 3
    assert calls == [("a", True, "scoped"), ("b", True, "scoped"), ("c", True, "scoped")]
