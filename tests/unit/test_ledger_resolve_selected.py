"""The evidenced close as aramid's MCP server makes it (FN-36, spec section
9.2): test selectors, never a command.

At the command line `--test` is a command, and whoever can type it can run
that program anyway. Through MCP the same argument would make aramid's server
run whatever its caller names. So the server builds the command itself: the
`[tests].select_command` that the repo's COMMITTED `aramid.toml` declares,
followed by selectors that can only be committed test files.

Every refusal here is asserted whole. Seams: a small real git repo built
once per module (two commits: the bug, then the fix with a check and an
`aramid.toml`). Tests that only ask what command would be built share it,
or its twin that declares pytest; a test that commits or closes gets a
private copy. `evidenced_close.run_subprocess` is replaced where the point
is the argv."""
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import config, evidenced_close, gitutil
from aramid.commands import ledger_cmd as lc
from aramid.commands.ledger_cmd import cmd_ledger_resolve_selected
from aramid.evidenced_close import Refused, selected_command
from aramid.ledger import Ledger
from aramid.models import EventType, Finding, Gate, Severity, Source, Verdict
from aramid.runners.base import RunnerResult, ToolState

FID = "llm1"
PY = Path(sys.executable).as_posix()
CHECK = """import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import calc
sys.exit(0 if calc.route("CN") == "ASIA" else 1)
"""
_OK = RunnerResult("python", ToolState.OK, returncode=0)
_RED = RunnerResult("python", ToolState.OK, returncode=1)


def _git(root, *args):
    cp = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
        cwd=root, capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    return cp.stdout.strip()


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _commit(root, message):
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def _toml(select_command):
    """An aramid.toml declaring `select_command`: a TOML value, written out."""
    if select_command is None:
        return "schema_version = 1\n"
    return f"schema_version = 1\n\n[tests]\nselect_command = {select_command}\n"


@pytest.fixture(scope="module")
def template(tmp_path_factory):
    """c1: the bug. c2: the fix, a check under tests/, a test at a path with
    brackets in it, a source file, and an aramid.toml that declares this
    interpreter as the command the selectors are appended to."""
    base = tmp_path_factory.mktemp("fn36sel")
    root, empty = base / "repo", base / "empty-template"
    root.mkdir()
    empty.mkdir()
    # Explicit: a module-scoped fixture runs before the per-test isolation
    # that neutralizes a machine-wide `init.templateDir` (tests/conftest.py).
    _git(root, "init", "-q", f"--template={empty}", "-b", "main")
    _write(root, ".gitignore", ".aramid/\n__pycache__/\n")
    _write(root, "calc.py", "def route(country):\n    return 'EU'\n")
    c1 = _commit(root, "c1: the bug")
    _write(root, "calc.py",
           "def route(country):\n    return 'ASIA' if country == 'CN' else 'EU'\n")
    _write(root, "tests/check_cn.py", CHECK)
    _write(root, "tests/unit/test_calc.py", "def test_cn():\n    assert True\n")
    _write(root, "app/[id]/+page.test.ts", "// a test\n")
    _write(root, "tests/@scope/a_b-c.test.js", "// a test\n")
    _write(root, "scripts/deploy.py", "raise SystemExit('never run this')\n")
    _write(root, "aramid.toml", _toml(f'["{PY}"]'))
    c2 = _commit(root, "c2: the fix")
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        finding = Finding(FID, "llm-review", "llm/logic", "high", Severity.HIGH, Verdict.WARN,
                          "calc.py", 2, "route ignores CN", "return 'EU'", Gate.PRE_PUSH,
                          source=Source.LLM)
        led.record_run("r1", "2026-10-09T00:00:00+00:00", "pre-push", {"llm-review"},
                       {"calc.py"}, [finding], head=c1)
    finally:
        led.close()
    return SimpleNamespace(root=root, c1=c1, c2=c2, base=base)


def _copy(template, to):
    shutil.copytree(template.root, to)
    return SimpleNamespace(root=to, c1=template.c1, c2=template.c2)


@pytest.fixture
def repo(template, tmp_path):
    """A private copy, for a test that commits or closes."""
    return _copy(template, tmp_path / "repo")


@pytest.fixture
def shared(template):
    """The module's repo itself, for tests that only ask what would be run."""
    return template


@pytest.fixture(scope="module")
def shared_pytest(template):
    """A twin that declares pytest, so a selector may carry a node id. Shared
    like `shared`: nothing writes to it."""
    twin = _copy(template, template.base / "pytest-twin")
    _declare(twin, '"python -m pytest -q"')
    return twin


def _declare(repo, select_command):
    """Commit an aramid.toml that declares `select_command` (a TOML value)."""
    _write(repo.root, "aramid.toml", _toml(select_command))
    return _commit(repo.root, "declare")


def _closes(root):
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        return [e for e in led.events()
                if e.type is EventType.FINDING_RESOLVED
                and e.payload.get("auto_resolved") == "evidenced_close"]
    finally:
        led.close()


def _status(root):
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        return led.open_findings()[FID]["status"]
    finally:
        led.close()


def _refused(capsys, root, rc, line):
    assert rc == 3
    assert capsys.readouterr() == ("", f"aramid: ledger resolve: {line}\n")
    assert _closes(root) == []
    assert _status(root) == "open"


# ------------------------------------------------- the command it builds --

def test_the_command_is_the_declared_one_with_the_selectors_appended(shared):
    root = shared.root
    assert selected_command(root, ["tests/check_cn.py"]) == [PY, "tests/check_cn.py"]
    assert selected_command(root, ["tests/check_cn.py", "tests/unit/test_calc.py"]) == [
        PY, "tests/check_cn.py", "tests/unit/test_calc.py"]


@pytest.mark.parametrize("declared, argv", [
    ('"python -m pytest -q"', ["python", "-m", "pytest", "-q"]),
    ('["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]',
     ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]),
    ('"npx vitest run"', ["npx", "vitest", "run"]),
])
def test_a_declared_command_is_a_string_or_a_list_like_every_other_command(
        repo, declared, argv):
    _declare(repo, declared)

    assert selected_command(repo.root, ["tests/check_cn.py"]) == [*argv, "tests/check_cn.py"]


@pytest.mark.parametrize("selector, argument", [
    ("./tests/check_cn.py", "tests/check_cn.py"),
    (".\\tests\\check_cn.py", "tests/check_cn.py"),
    ("tests\\unit\\test_calc.py::test_cn", "tests/unit/test_calc.py::test_cn"),
    ("tests/unit/test_calc.py::TestRoute::test_cn[CN-ASIA]",
     "tests/unit/test_calc.py::TestRoute::test_cn[CN-ASIA]"),
    ("app/[id]/+page.test.ts", "app/[id]/+page.test.ts"),
    ("tests/@scope/a_b-c.test.js", "tests/@scope/a_b-c.test.js"),
])
def test_a_selector_is_given_to_the_command_as_the_path_git_knows(shared_pytest, selector,
                                                                 argument):
    assert selected_command(shared_pytest.root, [selector]) == [
        "python", "-m", "pytest", "-q", argument]


# -------------------------------------------- where the command comes from --

def test_a_repo_that_declares_no_command_is_refused_and_the_key_named(repo):
    _declare(repo, None)

    with pytest.raises(Refused) as exc:
        selected_command(repo.root, ["tests/check_cn.py"])

    assert str(exc.value) == (
        "the aramid.toml at HEAD declares no [tests].select_command -- through MCP the "
        "close runs only a command the repo has committed, with the test selectors "
        "appended. Declare one, for example select_command = \"python -m pytest -q\", "
        "commit it and call again; or close at the command line with --test")


@pytest.mark.parametrize("declared", ['""', "[]"])
def test_an_empty_declaration_is_no_declaration(repo, declared):
    _declare(repo, declared)

    with pytest.raises(Refused, match="declares no \\[tests\\].select_command"):
        selected_command(repo.root, ["tests/check_cn.py"])


def test_an_uncommitted_declaration_does_not_count(repo):
    """The working tree's aramid.toml is not read: an agent that can edit a
    file could otherwise declare any program and run it through the server."""
    _declare(repo, None)
    _write(repo.root, "aramid.toml", _toml('"python evil.py"'))

    with pytest.raises(Refused, match="declares no \\[tests\\].select_command"):
        selected_command(repo.root, ["tests/check_cn.py"])


def test_the_user_level_config_cannot_declare_it(repo):
    _declare(repo, None)
    user = config._user_config_path()
    user.parent.mkdir(parents=True, exist_ok=True)
    user.write_text('[tests]\nselect_command = "python evil.py"\n', encoding="utf-8")

    with pytest.raises(Refused, match="declares no \\[tests\\].select_command"):
        selected_command(repo.root, ["tests/check_cn.py"])


def test_a_repo_whose_aramid_toml_is_not_committed_is_refused(repo):
    _git(repo.root, "rm", "-q", "--cached", "aramid.toml")
    _git(repo.root, "commit", "-q", "-m", "untrack the config")

    with pytest.raises(Refused) as exc:
        selected_command(repo.root, ["tests/check_cn.py"])

    assert str(exc.value) == (
        "HEAD holds no aramid.toml -- through MCP the close runs only a command the "
        "repo has committed ([tests].select_command); commit the file, or close at "
        "the command line with --test")


def test_a_config_that_does_not_parse_is_refused(repo):
    _write(repo.root, "aramid.toml", "[tests\nselect_command = 1\n")
    _commit(repo.root, "broken")

    with pytest.raises(Refused, match="^the aramid.toml at HEAD does not parse \\("):
        selected_command(repo.root, ["tests/check_cn.py"])


@pytest.mark.parametrize("declared, shown", [
    ("7", "7"),
    ("true", "True"),
    ('["python", 3]', "['python', 3]"),
    ('{ a = 1 }', "{'a': 1}"),
])
def test_a_declaration_of_the_wrong_type_is_refused(repo, declared, shown):
    _declare(repo, declared)

    with pytest.raises(Refused) as exc:
        selected_command(repo.root, ["tests/check_cn.py"])

    assert str(exc.value) == (
        f"[tests].select_command at HEAD should be a string or a list of strings, "
        f"got {shown}")


def test_a_tests_section_that_is_not_a_table_is_no_declaration(repo):
    _write(repo.root, "aramid.toml", "schema_version = 1\ntests = 3\n")
    _commit(repo.root, "not a table")

    with pytest.raises(Refused, match="declares no \\[tests\\].select_command"):
        selected_command(repo.root, ["tests/check_cn.py"])


def test_a_declared_string_that_does_not_split_is_refused(repo):
    _declare(repo, '"python -m pytest \'unclosed"')

    with pytest.raises(Refused) as exc:
        selected_command(repo.root, ["tests/check_cn.py"])

    assert str(exc.value) == ("[tests].select_command at HEAD does not parse as a command "
                              "(No closing quotation)")


# ------------------------------------------------- what a selector may be --

@pytest.mark.parametrize("selector", ["-k", "--collect-only", "-", "-p=no:x"])
def test_a_selector_cannot_be_an_option(shared, selector):
    with pytest.raises(Refused) as exc:
        selected_command(shared.root, [selector])

    assert str(exc.value) == (
        f"test selector {selector!r} starts with `-` -- a selector names a test file, "
        f"it is never an option of the command")


@pytest.mark.parametrize("selector, bad", [
    ("tests/check_cn.py & calc", "' ' '&'"),
    ("tests/check_cn.py|more", "'|'"),
    ("tests/check_cn.py>out", "'>'"),
    ("tests/%PATH%.py", "'%'"),
    ('tests/"x".py', "'\"'"),
    ("tests/x^.py", "'^'"),
    ("tests/x!.py", "'!'"),
    ("tests/(group)/a.test.ts", "'(' ')'"),
    ("tests/a b.py", "' '"),
    ("tests/a.py\nb", "'\\n'"),
    ("tests/$(id).py", "'$' '(' ')'"),
    ("tests/`id`.py", "'`'"),
    ("tests/a;b.py", "';'"),
    ("tests/a,b.py", "','"),
    ("tests/a=b.py", "'='"),
    ("tests/a'b.py", '"\'"'),
    # Letters and digits to Python, and not ASCII. U+02BA is a letter that
    # Windows turns into a double quote when a program reads its command line
    # in the ANSI code page ("best fit"), so "a letter" is no safe class.
    ("tests/caf\u00e9.py", "'\u00e9'"),
    ("tests/x\u02ba.py", "'\u02ba'"),
    ("tests/\uff41.py", "'\uff41'"),
    ("tests/x\u00b2.py", "'\u00b2'"),
])
def test_a_selector_holds_plain_characters_only(shared, selector, bad):
    """On Windows a declared command such as `npx vitest run` starts a `.cmd`
    shim, and cmd.exe reads `& | < > ^ % "` in an argument as syntax whatever
    quoting was applied. Nothing is run for a selector that holds one."""
    with pytest.raises(Refused) as exc:
        selected_command(shared.root, [selector])

    assert str(exc.value) == (
        f"test selector {selector!r} holds {bad} -- through MCP a selector is made of "
        f"ASCII letters, digits and `_ . / [ ] : @ + -` only; close this one at the "
        f"command line with --test")


@pytest.mark.parametrize("selector, path", [
    ("tests/nope.py", "tests/nope.py"),
    ("tests", "tests"),                               # a directory is not a file
    ("tests/unit", "tests/unit"),
    ("../outside/tests/check_cn.py", "../outside/tests/check_cn.py"),
    ("/etc/tests/check_cn.py", "/etc/tests/check_cn.py"),
    ("Tests/Check_CN.py", "Tests/Check_CN.py"),       # as committed, to the letter
    ("tests/nope.py::test_x", "tests/nope.py"),
])
def test_a_selector_names_a_file_head_holds(shared_pytest, selector, path):
    with pytest.raises(Refused) as exc:
        selected_command(shared_pytest.root, [selector])

    assert str(exc.value) == (
        f"test selector {selector!r} names no file that HEAD holds ({path}) -- a selector "
        f"is a committed test file, and for pytest it may go on with `::` and a test in "
        f"that file")


@pytest.mark.parametrize("selector", ["calc.py", "scripts/deploy.py", "aramid.toml",
                                      "scripts/deploy.py::test_x"])
def test_a_selector_names_a_file_in_a_test_location(shared_pytest, selector):
    """pytest imports any file it is handed, so a committed script named as a
    "test" would be run. Only what aramid already calls a test file is taken."""
    with pytest.raises(Refused) as exc:
        selected_command(shared_pytest.root, [selector])

    assert str(exc.value) == (
        f"test selector {selector!r} is not a test file by aramid's rules (under tests/ "
        f"or __tests__/, test_*.py, *_test.py, *.test.*, *.spec.*) -- through MCP only "
        f"such a file is run; close this one at the command line with --test")


def test_a_node_id_is_read_only_when_the_declared_command_is_pytest(shared, shared_pytest):
    """`::` belongs to pytest. For any other command the selector is a path
    and nothing else, so `file::rest` names no file."""
    node = "tests/unit/test_calc.py::test_cn"
    assert selected_command(shared_pytest.root, [node])[-1] == node

    with pytest.raises(Refused) as exc:
        selected_command(shared.root, [node])

    assert str(exc.value) == (
        "test selector 'tests/unit/test_calc.py::test_cn' names no file that HEAD holds "
        "(tests/unit/test_calc.py::test_cn) -- a selector is a committed test file, and "
        "for pytest it may go on with `::` and a test in that file")


def test_a_backslash_after_the_file_is_refused(shared_pytest):
    with pytest.raises(Refused) as exc:
        selected_command(shared_pytest.root, ["tests/unit/test_calc.py::test\\cn"])

    assert str(exc.value) == (
        "test selector 'tests/unit/test_calc.py::test\\\\cn' holds a backslash after the "
        "file name -- only the path may be written with one")


@pytest.mark.parametrize("selectors", [[], [""], ["tests/check_cn.py", ""], [3], "tests/x.py",
                                       None])
def test_selectors_are_a_list_of_names(shared, selectors):
    with pytest.raises(Refused) as exc:
        selected_command(shared.root, selectors)

    assert str(exc.value) == ("no test selector was given -- name at least one committed "
                              "test file")


def test_git_that_cannot_list_head_is_a_refusal(shared, monkeypatch):
    repo = shared
    real = gitutil._run

    def fake(root, *args):
        if args[:1] == ("ls-tree",):
            return subprocess.CompletedProcess(args, 128, "", "fatal: bad object\n")
        return real(root, *args)
    monkeypatch.setattr(gitutil, "_run", fake)

    with pytest.raises(Refused) as exc:
        selected_command(repo.root, ["tests/check_cn.py"])

    assert str(exc.value) == ("the test selectors could not be checked: git could not list "
                              "the files of HEAD (fatal: bad object)")


def test_a_repo_with_no_commit_is_a_refusal(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")

    with pytest.raises(Refused) as exc:
        selected_command(root, ["tests/check_cn.py"])

    assert str(exc.value) == "HEAD names no commit -- there is nothing to run a test on"


# ------------------------------------------------------- the close itself --

def test_a_close_through_selectors_really_runs_and_records_red_proof(repo, capsys, monkeypatch):
    """Real runs, a real worktree: the check passes at HEAD and fails with c2
    backed out. The event carries the command that ran and says who asked."""
    monkeypatch.setattr(lc, "_now", lambda: "2026-10-11T12:00:00+00:00")

    rc = cmd_ledger_resolve_selected(repo.root, FID, repo.c2, ["tests/check_cn.py"], "r")

    assert rc == 0
    assert capsys.readouterr() == (
        f"aramid: ledger: {FID} closed as fixed in {repo.c2[:12]} -- the test passes at "
        f"HEAD, failed (exit 1) without the fix (r)\n", "")
    payload = _closes(repo.root)[0].payload
    assert payload["via"] == "mcp"
    assert payload["test_argv"] == [PY, "tests/check_cn.py"]
    assert payload["red_proof"]["at"] == "head"
    assert payload["red_proof"]["pre_fix_rc"] == 1
    assert _status(repo.root) == "fixed"


def test_red_proof_is_not_optional_through_selectors(repo, monkeypatch):
    """Two runs, always, and neither in the working tree: the control in a
    clean checkout of HEAD, and the one without the fix."""
    seen = []

    def fake(argv, cwd, timeout_s, env=None):
        seen.append((list(argv), Path(cwd)))
        return [_OK, _RED][len(seen) - 1]
    monkeypatch.setattr(evidenced_close, "run_subprocess", fake)
    real = gitutil._run

    def git(root, *args):
        sub = args[2:] if args[:1] == ("-c",) else args
        if sub[:1] in (("worktree",), ("revert",), ("checkout",)):
            return subprocess.CompletedProcess(args, 0, "", "")
        return real(root, *args)
    monkeypatch.setattr(gitutil, "_run", git)

    assert cmd_ledger_resolve_selected(repo.root, FID, repo.c2, ["tests/check_cn.py"],
                                       "r") == 0
    assert [argv[1:] for argv, _cwd in seen] == [["tests/check_cn.py"]] * 2
    assert all(cwd.name == "wt" and cwd.resolve() != repo.root.resolve() for _a, cwd in seen)
    assert _closes(repo.root)[0].payload["red_proof"]["pre_fix_rc"] == 1


# ------------------------------- nothing uncommitted takes part (the review) --

_MARK = "import pathlib\npathlib.Path({marker!r}).write_text('ran', encoding='utf-8')\n"
_ROUTE_TEST = "tests/unit/test_route.py::test_cn_is_routed"


def _with_a_pytest_test(repo):
    """`repo` with pytest as the declared command and a pytest test of the
    fix, both committed."""
    _write(repo.root, "tests/unit/test_route.py",
           "import calc\n\n\ndef test_cn_is_routed():\n    assert calc.route('CN') == 'ASIA'\n")
    _write(repo.root, "aramid.toml",
           _toml(f'["{PY}", "-m", "pytest", "-q", "-p", "no:cacheprovider"]'))
    return _commit(repo.root, "c3: a pytest test of the fix")


@pytest.mark.parametrize("planted", ["conftest.py", "pytest.py"])
def test_an_untracked_file_in_the_working_tree_is_not_run_by_a_close_through_mcp(
        repo, tmp_path, capsys, planted):
    """Whoever calls the MCP tool may be able to write files and not to run
    programs. pytest loads every conftest.py it finds, and `python -m pytest`
    imports a pytest.py standing where it starts in place of pytest, so in the
    working tree a file nobody committed would be run for that caller. No run
    of a close through MCP is in the working tree."""
    _with_a_pytest_test(repo)
    marker = tmp_path / "ran.marker"
    _write(repo.root, planted, _MARK.format(marker=str(marker)))

    rc = cmd_ledger_resolve_selected(repo.root, FID, repo.c2, [_ROUTE_TEST], "guarded")

    assert (rc, capsys.readouterr().err) == (0, "")
    assert not marker.exists()
    assert _closes(repo.root)[0].payload["red_proof"]["at"] == "head"


def test_a_committed_conftest_is_the_repos_own_code_and_runs(repo, tmp_path, capsys):
    """The other half, and what shows the marker above can fire: what a
    commit holds is what the repo declared, and it runs."""
    _with_a_pytest_test(repo)
    marker = tmp_path / "ran.marker"
    _write(repo.root, "conftest.py", _MARK.format(marker=str(marker)))
    _commit(repo.root, "c4: a conftest")

    rc = cmd_ledger_resolve_selected(repo.root, FID, repo.c2, [_ROUTE_TEST], "guarded")

    assert (rc, capsys.readouterr().err) == (0, "")
    assert marker.read_text(encoding="utf-8") == "ran"


def test_an_uncommitted_edit_neither_stops_a_close_through_mcp_nor_takes_part(
        repo, capsys):
    """At the command line a tracked file with uncommitted changes refuses the
    close, because the test runs on the working tree. Through MCP it runs on
    HEAD as committed, so the edit is simply not there: this one takes the
    fix back out, and the close still stands."""
    _with_a_pytest_test(repo)
    _write(repo.root, "calc.py", "def route(country):\n    return 'EU'\n")

    rc = cmd_ledger_resolve_selected(repo.root, FID, repo.c2, [_ROUTE_TEST], "guarded")

    assert (rc, capsys.readouterr().err) == (0, "")
    assert _status(repo.root) == "fixed"


def _plant_post_checkout(repo, marker):
    """A `post-checkout` hook in the repo's own hooks directory: a file no
    commit holds, which git runs whenever it checks a tree out. It adds the
    commit it was run for (git's second argument) to the marker, one a line."""
    hooks = repo.root / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\necho \"$2\" >> '{marker.as_posix()}'\n", encoding="utf-8",
                    newline="\n")
    hook.chmod(0o755)


def _rewrite_the_fix(repo):
    """A later commit changes the fix's own line again, so git can no longer
    back the fix out of HEAD and red proof moves to the fix commit."""
    _write(repo.root, "calc.py",
           "def route(country):\n    return 'ASIA' if country in ('CN', 'JP') else 'EU'\n")
    return _commit(repo.root, "c3: JP too")


def test_the_repos_post_checkout_hook_is_not_run_by_a_close_through_mcp(repo, tmp_path, capsys):
    """git runs `post-checkout` when it makes a worktree, and the hook is a
    file in the repository that no commit holds: the same caller who can
    write a conftest.py can write that. Through MCP the worktree is made
    with hooks off."""
    marker = tmp_path / "hook.marker"
    _plant_post_checkout(repo, marker)

    rc = cmd_ledger_resolve_selected(repo.root, FID, repo.c2, ["tests/check_cn.py"], "guarded")

    assert (rc, capsys.readouterr().err) == (0, "")
    assert not marker.exists()
    assert _closes(repo.root)[0].payload["red_proof"]["at"] == "head"


def test_nor_by_the_worktree_at_the_fix_commit(repo, tmp_path, capsys):
    """The second worktree, the one red proof moves to, is made the same way."""
    _rewrite_the_fix(repo)
    marker = tmp_path / "hook.marker"
    _plant_post_checkout(repo, marker)

    rc = cmd_ledger_resolve_selected(repo.root, FID, repo.c2, ["tests/check_cn.py"], "guarded")

    assert (rc, capsys.readouterr().err) == (0, "")
    assert _closes(repo.root)[0].payload["red_proof"]["at"] == "commit"
    assert not marker.exists()


@pytest.mark.parametrize("later_commit, at", [(False, "head"), (True, "commit")])
def test_at_the_command_line_the_hook_runs_as_for_every_worktree(repo, tmp_path, capsys,
                                                                later_commit, at):
    """The other half, and what shows the marker above can fire: the close
    at the command line is unchanged, in either worktree. The hook names
    the commit of each checkout it ran for, so the worktree at the fix
    commit is told apart from the one at HEAD that is made before it."""
    if later_commit:
        _rewrite_the_fix(repo)
    head = _git(repo.root, "rev-parse", "HEAD")
    marker = tmp_path / "hook.marker"
    _plant_post_checkout(repo, marker)

    rc = lc.cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, [PY, "tests/check_cn.py"], "r",
                                     red_proof=True)

    assert (rc, capsys.readouterr().err) == (0, "")
    assert _closes(repo.root)[0].payload["red_proof"]["at"] == at
    ran_for = set(marker.read_text(encoding="utf-8").split())
    assert ran_for == ({head, repo.c2} if later_commit else {head})


def test_a_test_that_fails_in_the_clean_checkout_is_refused_in_those_words(repo, capsys):
    """There is no run in the repo to compare with, so the refusal does not
    say the test passes there."""
    _with_a_pytest_test(repo)
    _write(repo.root, "tests/unit/test_route.py",
           "def test_cn_is_routed():\n    assert False\n")
    _commit(repo.root, "c4: the test is broken")

    rc = cmd_ledger_resolve_selected(repo.root, FID, repo.c2, [_ROUTE_TEST], "guarded")

    _refused(capsys, repo.root, rc,
             "the test exits 1 in a clean checkout of HEAD -- through MCP every run is in "
             "one, never in the working tree, and it must pass (exit 0) there")


def test_a_close_marked_as_made_through_mcp_always_carries_red_proof(repo, capsys):
    """`red_proof=False` cannot be combined with the MCP route: the control of
    red proof is the only run that shows the test passing at HEAD, so without
    it a close would rest on no run at all."""
    rc = lc.cmd_ledger_resolve_fixed(repo.root, FID, repo.c2, [PY, "tests/check_cn.py"], "r",
                                     red_proof=False, via="mcp")

    assert (rc, capsys.readouterr().err) == (0, "")
    assert _closes(repo.root)[0].payload["red_proof"]["at"] == "head"


def test_a_refused_selector_runs_nothing_and_records_nothing(repo, capsys, monkeypatch):
    def never(*a, **k):
        raise AssertionError("nothing may be run for a refused selector")
    monkeypatch.setattr(evidenced_close, "run_subprocess", never)

    rc = cmd_ledger_resolve_selected(repo.root, FID, repo.c2, ["tests/check_cn.py & calc"],
                                     "r")

    _refused(capsys, repo.root, rc,
             "test selector 'tests/check_cn.py & calc' holds ' ' '&' -- through MCP a "
             "selector is made of ASCII letters, digits and `_ . / [ ] : @ + -` only; close "
             "this one at the command line with --test")


def test_a_git_that_does_not_answer_is_an_engine_error(repo, capsys, monkeypatch):
    def hung(root, rev):
        raise gitutil.GitTimeout("git rev-parse timed out after 600 s and was killed")
    monkeypatch.setattr(gitutil, "rev_sha", hung)

    rc = cmd_ledger_resolve_selected(repo.root, FID, repo.c2, ["tests/check_cn.py"], "r")

    _refused(capsys, repo.root, rc,
             "engine error: git rev-parse timed out after 600 s and was killed")


def test_a_close_through_selectors_needs_a_reason_like_any_other(repo, capsys):
    rc = cmd_ledger_resolve_selected(repo.root, FID, repo.c2, ["tests/check_cn.py"], "  ")

    _refused(capsys, repo.root, rc, "--reason is required")


# ---------------------------------------------- the shim that reads syntax --

@pytest.mark.skipif(sys.platform != "win32", reason="cmd.exe is the reader under test")
def test_every_character_a_selector_may_hold_reaches_a_cmd_shim_as_one_argument(repo):
    """The other half of the character rule: what IS allowed arrives whole.
    A `.cmd` shim, as `npx` is on Windows, writes down the arguments it was
    given; the selector uses every punctuation mark the rule lets through."""
    selector = "tests/[id]/+page@x-y_z.test.js"
    _write(repo.root, selector, "// a test\n")
    # Text mode writes the CRLF line ends a batch file wants on Windows.
    _write(repo.root, "tools/runner.cmd",
           '@echo off\n>"%~dp0seen.txt" echo [%1][%2]\nexit /b 0\n')
    _declare(repo, '"tools/runner.cmd"')

    argv = selected_command(repo.root, [selector])
    res = evidenced_close._run(argv, repo.root, repo.root, 60.0)

    assert (res.state, res.returncode) == (ToolState.OK, 0)
    assert (repo.root / "tools" / "seen.txt").read_text(encoding="utf-8").strip() == (
        f"[{selector}][]")
