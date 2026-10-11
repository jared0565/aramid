"""evidenced_close -- the proof behind `aramid ledger resolve --fixed` (FN-36).

An llm-review finding closes by itself only when its evidence quote leaves
its file (`review.auto_resolve_llm`). A fix that guards the path to the
quoted line, or lands in a caller, leaves the quote where it was, so the
finding stays open although it is fixed. This module runs the evidence
offered for such a fix: a test command that passes at HEAD and, when red
proof is asked for, fails once the fixing commit is backed out.

Nothing here reads or writes the ledger. `commands.ledger_cmd` decides
which finding may be closed and records the event; this module only answers
"does the command pass" and "does it fail without the fix", and raises
`Refused` with the operator's line when it cannot say yes.

RED PROOF, AND WHY IT HAS A CONTROL. The run without the fix happens in a
throwaway worktree, and a command can fail there for reasons that say
nothing about the fix: the test file is not committed, dependencies are not
installed in a fresh checkout, the selector matches nothing. Exit codes
cannot tell those apart across runners (pytest, vitest and go test each
number them differently). So the same worktree is used twice:

  1. checked out at HEAD, the command must exit 0 -- the control;
  2. the fixing commit is backed out (`git revert --no-commit`), and the
     command must now exit non-zero.

The only difference between the two runs is what that one commit changed,
so a failure in the second is a failure for want of the fix. Commits after
the fix stay. If one of them changed the fix's own lines again, git cannot
back the fix out of that file. In a file that stays at HEAD anyway (next
section) that is no obstacle: the conflict is undone with everything else
the back-out did to it. Anywhere else it leaves no tree to run the test
on, and the proof moves to the fix commit (last section).

WHAT STAYS AT HEAD WHEN THE FIX IS BACKED OUT, and why each:

  - test files the commit touched (`_is_test_path`) -- a test written with
    the fix has to exist to be run against the tree without it;
  - files the command names -- a test in a file no naming rule recognises
    is still the file under test;
  - files the commit ADDED -- taking one away fails the command when it is
    test support (a helper, a fixture), and that failure would read as red.
    The cost is a fix that consists of new files only: nothing is left to
    back out, so it is refused. That is the safe side of the trade.

HOOKS. `git worktree add` runs the repo's `post-checkout` hook, as it does
for every worktree aramid builds, and it runs before the control, so both
runs see whatever it did. Putting the kept paths back is a `git checkout`
too and would run the hook a second time, BETWEEN the two runs; every
checkout of paths here is made with hooks off (`_checkout`), so nothing
but the back-out separates them. `git revert --no-commit` makes no commit
and runs no hook (measured 2026-10-10).

WHAT IT STILL CANNOT TELL, two things:

  - test support that the fixing commit MODIFIED, outside every recognised
    test location and not named in the command, is backed out with the fix.
    A failure caused by that reads as red;
  - HEAD with one commit taken out is a tree nobody committed. When a later
    commit uses something the fix introduced, the command fails there
    because the tree no longer fits together, and that reads as red too. It
    shows the test needs the commit, which is less than showing it detects
    the bug.

WHEN THE FIX CAN NO LONGER BE BACKED OUT OF HEAD. `git revert` takes the
whole commit, so one later change that overlaps it in any backed-out file
stops the back-out, and a CHANGELOG or a guide counts there like source.
Red proof is then shown where the fix was made, in a second worktree:

  1. checked out at the fix commit, with the files the command names
     brought in as HEAD has them -- the test on offer is the one at HEAD,
     and it may have been written after the fix. The command must exit 0:
     the control;
  2. the paths that would have been backed out are put back as the
     commit's parent has them (`git checkout <parent> -- <paths>`: no
     merge, so nothing can conflict), and the command must exit non-zero.

That is a different claim, and the event says which one was shown
(`red_proof.at`, "head" or "commit"): the test caught the bug in the code
as it stood when the fix was made. It says nothing of the commits since;
that the test passes at HEAD is the other half, checked first either way.
A test that does not run against the older code -- it uses something a
later commit brought -- fails the control, and the close is refused with
the file in conflict named. The first limit above holds here as well.
Replayed on this repo's own month-old case: refused at HEAD 2026-10-10,
closed at the fix commit 2026-10-11 (spec section 9).
"""
import contextlib
import shlex
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

from aramid import gitutil
from aramid.consumers import js_mutation
from aramid.runners import tests as tests_runner
from aramid.runners.base import ToolState, run_subprocess, worktree_import_env

# `git checkout <rev> -- <paths>` is given this many paths at a time: one
# call per path is slow on a wide commit, and one call for all of them can
# pass Windows' command-line limit.
_CHECKOUT_CHUNK = 100


# The punctuation a test selector may hold, besides letters and digits
# (`selected_command`). A backslash is let in for the path alone, where it is
# rewritten to a forward slash before anything else looks at it.
_SELECTOR_PUNCT = frozenset("_./\\[]:@+-")


class Refused(Exception):
    """The close cannot be recorded. `str(exc)` completes the sentence
    "aramid: ledger resolve: ..." and says what to do instead."""


def split_command(test: str | None) -> list[str]:
    """`--test` as the argv the event records, split POSIX-style like a
    string `[tests].command` (`runners.tests._argv`): quotes group, and a
    Windows path wants forward slashes."""
    try:
        argv = shlex.split(test or "")
    except ValueError as exc:
        raise Refused(f"--test does not parse as a command ({exc})") from None
    if not argv:
        raise Refused("--test is required with --fixed -- the command that runs the "
                      "test proving the fix, e.g. --test \"python -m pytest "
                      "tests/test_x.py::test_y\"")
    return argv


def run_timeout(cfg) -> float:
    """`[tests].timeout_s`, the bound on each run of the command. Read as
    the gate reads it (`pipeline` guards a `tests` that is not a table the
    same way; `runners.tests._timeout` applies the same default). A value
    the config loader has already called wrong -- text, a boolean, zero or
    less -- is the default, not a crash and not a run that cannot finish."""
    tests_cfg = cfg.tests if isinstance(cfg.tests, dict) else {}
    configured = tests_cfg.get("timeout_s")
    if isinstance(configured, bool) or not isinstance(configured, (int, float)) \
            or configured <= 0:
        return tests_runner.TIMEOUT_S
    return float(configured)


def _is_test_path(rel: str) -> bool:
    """Both shapes aramid already knows: pytest's (`gitutil.is_test_file`)
    and the JS one the js_mutation consumer uses (`*.test.*`, `*.spec.*`,
    `__tests__/`)."""
    return gitutil.is_test_file(rel) or js_mutation._is_test_file(rel)


def _named_paths(argv: list[str]) -> set[str]:
    """Every argv token as the repo-relative path it would name: a pytest
    node id loses its `::test` part, a leading `./` goes, separators are
    forward. Most tokens name nothing; only an exact match with a path the
    commit changed is ever used."""
    return {token.split("::")[0].replace("\\", "/").removeprefix("./") for token in argv}


def _said(cp) -> str:
    """The first line git printed when it refused, short enough to quote."""
    lines = (cp.stderr or "").strip().splitlines()
    return lines[0][:200] if lines else ""


def _run(argv: list[str], root: Path, cwd: Path, timeout_s: float, env=None):
    """One run of the command. The executable is anchored against the REPO
    root, not the cwd, so `.venv/Scripts/python` names the same interpreter
    in the worktree as in the repo (a worktree has no virtualenv)."""
    try:
        return run_subprocess(tests_runner._argv(argv, root), cwd, timeout_s, env=env)
    except OSError as exc:
        raise Refused(f"`{argv[0]}` could not be started ({exc})") from None


def _unfinished(res, timeout_s: float) -> str:
    if res.state is ToolState.TIMEOUT:
        return f"it did not finish within {timeout_s:g} s"
    return (res.stderr or "").strip() or "it could not be run"


def passes_at_head(root: Path, argv: list[str], timeout_s: float) -> None:
    """The command exits 0 from the repo root, and the tree it ran on IS
    HEAD as far as tracked files go: the event records the commit the test
    passed at, and an uncommitted edit would make that a different tree."""
    cp = gitutil._run(root, "status", "--porcelain", "--untracked-files=no")
    if cp.returncode != 0:
        raise Refused(f"git could not read the working tree's state: {_said(cp)}")
    dirty = [line for line in cp.stdout.splitlines() if line.strip()]
    if dirty:
        raise Refused(f"{len(dirty)} tracked file(s) have uncommitted changes -- the "
                      f"close records the commit the test passed at, so commit or "
                      f"stash them first")
    res = _run(argv, root, root, timeout_s)
    if res.state is ToolState.MISSING:
        raise Refused(f"`{argv[0]}` was not found -- --test must start with a program "
                      f"that can be run from the repo root")
    if res.state is not ToolState.OK:
        raise Refused(f"the test did not pass at HEAD: {_unfinished(res, timeout_s)} -- "
                      f"a run that did not finish is not a pass")
    if res.returncode != 0:
        raise Refused(f"the test exits {res.returncode} at HEAD -- it must pass (exit 0) "
                      f"on the tree that carries the fix")


def _changed(root: Path, base: str, commit: str) -> list[tuple[str, str]]:
    """(status letter, path) for every path the commit changed. A rename is
    reported as a delete and an add, so each path has one rule."""
    cp = gitutil._run(root, "diff", "--name-status", "--no-renames", "-z", base, commit)
    if cp.returncode != 0:
        raise Refused(f"git could not read what {commit[:12]} changed: {_said(cp)}")
    fields = [f for f in cp.stdout.split("\0") if f]
    return list(zip(fields[0::2], fields[1::2]))


def _held(root: Path, head: str, doing: str = "red proof could not be run") -> set[str]:
    """Every path `head` holds. `doing` opens the refusal when git cannot say."""
    cp = gitutil._run(root, "ls-tree", "-r", "-z", "--name-only", head)
    if cp.returncode != 0:
        raise Refused(f"{doing}: git could not list the files of HEAD ({_said(cp)})")
    return {f for f in cp.stdout.split("\0") if f}


def _declared(root: Path, head: str) -> list[str]:
    """`[tests].select_command` as the `aramid.toml` that `head` holds declares
    it, as an argv. The committed file and no other: not the working tree's
    copy, and not the user-level config that `load_config` merges in. Either
    of those could be written by whoever is asking for the run."""
    text = gitutil.blob_at(root, head, "aramid.toml")
    if text is None:
        raise Refused("HEAD holds no aramid.toml -- through MCP the close runs only a "
                      "command the repo has committed ([tests].select_command); commit "
                      "the file, or close at the command line with --test")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise Refused(f"the aramid.toml at HEAD does not parse ({exc})") from None
    tests = data.get("tests")
    command = tests.get("select_command") if isinstance(tests, dict) else None
    if command is None or command == "" or command == []:
        raise Refused("the aramid.toml at HEAD declares no [tests].select_command -- "
                      "through MCP the close runs only a command the repo has committed, "
                      "with the test selectors appended. Declare one, for example "
                      "select_command = \"python -m pytest -q\", commit it and call again; "
                      "or close at the command line with --test")
    if isinstance(command, str):
        try:
            return shlex.split(command)
        except ValueError as exc:
            raise Refused(f"[tests].select_command at HEAD does not parse as a command "
                          f"({exc})") from None
    if isinstance(command, list) and all(isinstance(part, str) for part in command):
        return list(command)
    raise Refused(f"[tests].select_command at HEAD should be a string or a list of "
                  f"strings, got {command!r}")


def _selector(selector: str, held: set[str], node_ids: bool) -> str:
    """One test selector as the argument the command is given.

    A selector can only be a committed test file, and for pytest (`node_ids`)
    a test in it. Each rule closes one way of turning "name a test" into
    "run something else":

      - no leading `-`, so it is never an option of the command;
      - plain characters only. A declared command such as `npx vitest run`
        starts a `.cmd` shim on Windows, and cmd.exe reads `& | < > ^ % "`
        in an argument as syntax whatever quoting was applied;
      - a file HEAD holds, so nothing outside the repository and nothing
        uncommitted;
      - a test file by aramid's own rules. pytest imports any file it is
        handed, so a committed script named as a "test" would be run."""
    if selector.startswith("-"):
        raise Refused(f"test selector {selector!r} starts with `-` -- a selector names a "
                      f"test file, it is never an option of the command")
    bad = [ch for ch in dict.fromkeys(selector)
           if not (ch.isalnum() or ch in _SELECTOR_PUNCT)]
    if bad:
        raise Refused(f"test selector {selector!r} holds {' '.join(map(repr, bad))} -- "
                      f"through MCP a selector is made of letters, digits and "
                      f"`_ . / [ ] : @ + -` only; close this one at the command line "
                      f"with --test")
    path, sep, rest = selector.partition("::") if node_ids else (selector, "", "")
    if "\\" in rest:
        raise Refused(f"test selector {selector!r} holds a backslash after the file name "
                      f"-- only the path may be written with one")
    path = path.replace("\\", "/").removeprefix("./")
    if path not in held:
        raise Refused(f"test selector {selector!r} names no file that HEAD holds ({path}) "
                      f"-- a selector is a committed test file, and for pytest it may go "
                      f"on with `::` and a test in that file")
    if not _is_test_path(path):
        raise Refused(f"test selector {selector!r} is not a test file by aramid's rules "
                      f"(under tests/ or __tests__/, test_*.py, *_test.py, *.test.*, "
                      f"*.spec.*) -- through MCP only such a file is run; close this one "
                      f"at the command line with --test")
    return path + sep + rest


def selected_command(root: Path, selectors) -> list[str]:
    """The command of a close made through MCP: what the repo's committed
    `aramid.toml` declares as `[tests].select_command`, with `selectors`
    appended. Raises `Refused` when the repo declares none or a selector is
    anything but a committed test file (`_selector`).

    At the command line `--test` is a command, and whoever can type it can
    run that program anyway. Through MCP the same argument would make
    aramid's server run whatever its caller names, which no aramid MCP tool
    does: `aramid_check` runs only the repo's own suite."""
    if not isinstance(selectors, (list, tuple)) or not selectors \
            or not all(isinstance(s, str) and s.strip() for s in selectors):
        raise Refused("no test selector was given -- name at least one committed test "
                      "file")
    head = gitutil.rev_sha(root, "HEAD")
    if head is None:
        raise Refused("HEAD names no commit -- there is nothing to run a test on")
    argv = _declared(root, head)
    held = _held(root, head, "the test selectors could not be checked")
    node_ids = tests_runner._is_pytest_argv(argv)
    return argv + [_selector(s, held, node_ids) for s in selectors]


def _conflicts(wt: Path) -> set[str]:
    """The paths a failed back-out left in conflict. Empty when it left none,
    and when git cannot say."""
    cp = gitutil._run(wt, "diff", "--name-only", "--diff-filter=U", "-z")
    if cp.returncode != 0:
        return set()
    return {f for f in cp.stdout.split("\0") if f}


class _Stuck(Exception):
    """`commit` cannot be backed out of HEAD: `paths`, which have to be
    backed out, are in conflict with later changes. Not a refusal yet: red
    proof is then tried at the fix commit itself (`_at_the_fix_commit`)."""

    def __init__(self, paths: list[str]):
        super().__init__(paths)
        self.paths = paths


def _checkout(wt: Path, rev: str, paths: list[str], no_hooks: Path):
    """`git checkout <rev> -- <paths>` in `wt`. Returns git's reply for the
    call that failed, or None when every call worked.

    The pathspecs are literal: `app/[id]/page.test.ts` is a character class
    to git, and unmarked it also checks out `app/i/` and `app/d/` (measured
    2026-10-10). `no_hooks` is an empty directory: with it as the hooks path
    the checkout cannot run the repo's `post-checkout` (see HOOKS in the
    module docstring)."""
    for i in range(0, len(paths), _CHECKOUT_CHUNK):
        cp = gitutil._run(wt, "-c", f"core.hooksPath={no_hooks}", "checkout", rev, "--",
                          *(f":(literal){rel}" for rel in paths[i:i + _CHECKOUT_CHUNK]))
        if cp.returncode != 0:
            return cp
    return None


def _keep_at_head(wt: Path, head: str, kept: list[str], held: set[str],
                  no_hooks: Path) -> None:
    """Put the paths that stay back as `head` has them, whatever the back-out
    did to them, a conflict included: a kept path that `head` holds (`held`)
    is checked out from it, any other is removed.

    `head` decides, and not what the commit did to the path. A later commit
    may have deleted a file the fix added, and `git checkout` refuses a path
    its tree does not hold; or brought back a test the fix deleted, and
    removing that one would fail the command for a missing file (both
    measured 2026-10-10)."""
    for rel in kept:
        if rel not in held:
            (wt / rel).unlink(missing_ok=True)
    failed = _checkout(wt, head, [rel for rel in kept if rel in held], no_hooks)
    if failed is not None:
        raise Refused(f"red proof could not be run: git could not put the test "
                      f"files back after backing the fix out ({_said(failed)})")


@contextlib.contextmanager
def _worktree(root: Path, wt: Path, rev: str, leaks: list[Path]):
    """A detached worktree of `rev` at `wt`, the repo's `node_modules` linked
    in when it has one, the way the js_mutation consumer does it. Yields the
    environment for a run there. The worktree is removed on the way out,
    whatever happened; one that could not be removed is named and put in
    `leaks`, and the caller then leaves its directory alone."""
    linked = False
    try:
        cp = gitutil._run(root, "worktree", "add", "--detach", str(wt), rev)
        if cp.returncode != 0:
            raise Refused(f"red proof could not be run: git worktree add failed "
                          f"({_said(cp)})")
        try:
            linked = js_mutation._link_node_modules(root, wt)
        except OSError as exc:
            raise Refused(f"red proof could not be run: node_modules could not be "
                          f"linked into the worktree ({exc})") from None
        yield worktree_import_env(wt)
    finally:
        try:
            if linked:
                # BEFORE the directory goes: removing through the link would
                # reach the repo's real node_modules (js_mutation invariant).
                js_mutation._unlink_node_modules(wt)
            gitutil._run(root, "worktree", "remove", "--force", str(wt))
            gitutil._run(root, "worktree", "prune")
        except Exception:
            leaks.append(wt)
            print(f"aramid: ledger resolve: worktree cleanup leaked at {wt}",
                  file=sys.stderr)


def _how(res, timeout_s: float) -> str:
    """What a control run did instead of passing."""
    if res.state is ToolState.OK:
        return f"exits {res.returncode}"
    return f"did not run ({_unfinished(res, timeout_s)})"


def _named(stuck: list[str]) -> str:
    """The paths in conflict, as a refusal names them: the first, and how
    many more."""
    more = f" and {len(stuck) - 1} more file(s)" if len(stuck) > 1 else ""
    return f"{stuck[0]}{more}"


def _at_head(root: Path, wt: Path, commit: str, head: str, argv: list[str],
             timeout_s: float, kept: list[str], held: set[str], no_hooks: Path,
             leaks: list[Path]) -> int:
    """The proof the module docstring describes first: a worktree of `head`,
    the control, `commit` backed out, the kept paths put back. Returns the
    exit code of the run without the fix; raises `_Stuck` when the back-out
    conflicts in a path that has to be backed out."""
    with _worktree(root, wt, head, leaks) as env:
        control = _run(argv, root, wt, timeout_s, env)
        if control.state is not ToolState.OK or control.returncode != 0:
            raise Refused(f"red proof could not be run: the test passes in the repo but "
                          f"{_how(control, timeout_s)} in a clean checkout of HEAD -- it "
                          f"depends on something that is not committed (an untracked "
                          f"file, a build step, an install), so a failure without the "
                          f"fix would prove nothing")

        # A merge commit is backed out against its first parent: the branch
        # the fix was merged INTO.
        mainline = ("-m", "1") if gitutil.rev_sha(root, f"{commit}^2") else ()
        cp = gitutil._run(wt, "revert", "--no-commit", *mainline, commit)
        if cp.returncode != 0:
            # A back-out that conflicts has still backed out every path it
            # could (measured 2026-10-10). A conflict in a path that stays at
            # HEAD is undone below with the rest of what the back-out did to
            # that path. One anywhere else leaves no tree to run the test on.
            conflicts = _conflicts(wt)
            if not conflicts:
                raise Refused(f"red proof could not be run: git could not back "
                              f"{commit[:12]} out of HEAD ({_said(cp)})")
            stuck = sorted(conflicts - set(kept))
            if stuck:
                raise _Stuck(stuck)
        _keep_at_head(wt, head, kept, held, no_hooks)

        before = _run(argv, root, wt, timeout_s, env)
        if before.state is not ToolState.OK:
            raise Refused(f"red proof could not be shown: with {commit[:12]} backed out "
                          f"the test did not finish ({_unfinished(before, timeout_s)}) "
                          f"-- that is not a failing test")
        if before.returncode == 0:
            raise Refused(f"the test also passes with {commit[:12]} backed out -- it does "
                          f"not detect what that commit fixed, so it is not evidence "
                          f"that the finding is fixed")
        return before.returncode


def _at_the_fix_commit(root: Path, wt: Path, commit: str, head: str, base: str,
                       argv: list[str], timeout_s: float, backed: list[str],
                       brought: list[str], stuck: list[str], no_hooks: Path,
                       leaks: list[Path]) -> int:
    """The proof for a fix that can no longer be backed out of HEAD (see the
    module docstring): a worktree of `commit`, the files the command names
    brought in from `head`, the control, then the paths that have to be
    backed out (`backed`) put back to `base`. Returns the exit code of the
    run without the fix."""
    c = commit[:12]
    with _worktree(root, wt, commit, leaks) as env:
        failed = _checkout(wt, head, brought, no_hooks)
        if failed is not None:
            raise Refused(f"red proof could not be run: git could not bring the test in "
                          f"from HEAD ({_said(failed)})")
        control = _run(argv, root, wt, timeout_s, env)
        if control.state is not ToolState.OK or control.returncode != 0:
            raise Refused(f"red proof could not be run: {c} can no longer be backed out "
                          f"of HEAD -- it conflicts with later changes to {_named(stuck)} "
                          f"-- and at {c} itself the test {_how(control, timeout_s)}: as "
                          f"it is at HEAD it does not run against the code as it stood "
                          f"when the fix was made")
        # No merge here, and so no `git revert`: every path in `backed` was
        # modified or deleted by the commit, so its parent holds it. A revert
        # would refuse once the test from HEAD is in the tree and the commit
        # touched that file too (measured 2026-10-11).
        failed = _checkout(wt, base, backed, no_hooks)
        if failed is not None:
            raise Refused(f"red proof could not be run: git could not put {c}'s files "
                          f"back to its parent ({_said(failed)})")
        before = _run(argv, root, wt, timeout_s, env)
        if before.state is not ToolState.OK:
            raise Refused(f"red proof could not be shown: at {c}, with that commit backed "
                          f"out, the test did not finish ({_unfinished(before, timeout_s)}) "
                          f"-- that is not a failing test")
        if before.returncode == 0:
            raise Refused(f"the test also passes at {c} with that commit backed out -- it "
                          f"does not detect what that commit fixed, so it is not evidence "
                          f"that the finding is fixed")
        return before.returncode


def red_proof(root: Path, commit: str, head: str, argv: list[str],
              timeout_s: float) -> dict:
    """Show that the command FAILS without `commit`: backed out of `head`,
    or, when later commits make that impossible, at `commit` itself. Both
    are full shas, `head` the one the caller records on the event. Returns
    what the event records, `at` saying which of the two was shown; raises
    `Refused` when red cannot be shown."""
    base = gitutil.first_parent(root, commit)
    if base is None:
        raise Refused(f"red proof backs the fix out, and {commit[:12]} has no parent "
                      f"commit to go back to")
    changed = _changed(root, base, commit)
    named = _named_paths(argv)
    kept = [rel for status, rel in changed
            if status == "A" or _is_test_path(rel) or rel in named]
    staying = set(kept)
    backed = [rel for _status, rel in changed if rel not in staying]
    if not backed:
        raise Refused(f"{commit[:12]} changes no existing source file -- only tests, or "
                      f"only new files. Red proof backs the commit out and reruns the "
                      f"test, so there is nothing it could take away")
    held = _held(root, head)

    tmp = Path(tempfile.mkdtemp(prefix="aramid-close-"))
    no_hooks = tmp / "no-hooks"
    no_hooks.mkdir()
    leaks: list[Path] = []
    try:
        proof = {"base": base, "control_rc": 0, "backed_out": len(backed)}
        try:
            rc = _at_head(root, tmp / "wt", commit, head, argv, timeout_s, kept, held,
                          no_hooks, leaks)
            return {"at": "head", **proof, "pre_fix_rc": rc}
        except _Stuck as stuck:
            brought = sorted(named & held)
            rc = _at_the_fix_commit(root, tmp / "wt-fix", commit, head, base, argv,
                                    timeout_s, backed, brought, stuck.paths, no_hooks,
                                    leaks)
            return {"at": "commit", **proof, "pre_fix_rc": rc,
                    "head_conflicts": len(stuck.paths), "brought": len(brought)}
    finally:
        if not leaks:
            shutil.rmtree(tmp, ignore_errors=True)
