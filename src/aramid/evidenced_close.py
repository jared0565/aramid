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
back the fix out of that file, and red proof is refused rather than guessed
-- unless the file is one that stays at HEAD anyway (next section), where
the conflict is undone with everything else the back-out did to it.

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
too and would run the hook a second time, BETWEEN the two runs; that call
is made with hooks off, so nothing but the back-out separates them.
`git revert --no-commit` makes no commit and runs no hook (measured
2026-10-10).

WHAT IT STILL CANNOT TELL, two things:

  - test support that the fixing commit MODIFIED, outside every recognised
    test location and not named in the command, is backed out with the fix.
    A failure caused by that reads as red;
  - HEAD with one commit taken out is a tree nobody committed. When a later
    commit uses something the fix introduced, the command fails there
    because the tree no longer fits together, and that reads as red too. It
    shows the test needs the commit, which is less than showing it detects
    the bug.

AND WHAT IT CANNOT DO: back out a commit whose lines were changed again
afterwards. `git revert` takes the whole commit, so one later change that
overlaps it in any backed-out file refuses the proof, and a CHANGELOG or a
guide counts there like source. The refusal names the file. Replayed on
this repo's own month-old case, 2026-10-10: refused (spec section 8.2).
"""
import shlex
import shutil
import sys
import tempfile
from pathlib import Path

from aramid import gitutil
from aramid.consumers import js_mutation
from aramid.runners import tests as tests_runner
from aramid.runners.base import ToolState, run_subprocess, worktree_import_env

# `git checkout <rev> -- <paths>` is given this many paths at a time: one
# call per path is slow on a wide commit, and one call for all of them can
# pass Windows' command-line limit.
_CHECKOUT_CHUNK = 100


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


def _held(root: Path, head: str) -> set[str]:
    """Every path `head` holds."""
    cp = gitutil._run(root, "ls-tree", "-r", "-z", "--name-only", head)
    if cp.returncode != 0:
        raise Refused(f"red proof could not be run: git could not list the files of "
                      f"HEAD ({_said(cp)})")
    return {f for f in cp.stdout.split("\0") if f}


def _conflicts(wt: Path) -> set[str]:
    """The paths a failed back-out left in conflict. Empty when it left none,
    and when git cannot say."""
    cp = gitutil._run(wt, "diff", "--name-only", "--diff-filter=U", "-z")
    if cp.returncode != 0:
        return set()
    return {f for f in cp.stdout.split("\0") if f}


def _keep_at_head(wt: Path, head: str, kept: list[str], held: set[str],
                  no_hooks: Path) -> None:
    """Put the paths that stay back as `head` has them, whatever the back-out
    did to them, a conflict included: a kept path that `head` holds (`held`)
    is checked out from it, any other is removed.

    `head` decides, and not what the commit did to the path. A later commit
    may have deleted a file the fix added, and `git checkout` refuses a path
    its tree does not hold; or brought back a test the fix deleted, and
    removing that one would fail the command for a missing file.

    The pathspecs are literal: `app/[id]/page.test.ts` is a character class
    to git, and unmarked it also checks out `app/i/` and `app/d/` (all three
    measured 2026-10-10). `no_hooks` is an empty directory: with it as the
    hooks path the checkout cannot run the repo's `post-checkout` (see HOOKS
    in the module docstring)."""
    restore = []
    for rel in kept:
        if rel in held:
            restore.append(f":(literal){rel}")
        else:
            (wt / rel).unlink(missing_ok=True)
    for i in range(0, len(restore), _CHECKOUT_CHUNK):
        cp = gitutil._run(wt, "-c", f"core.hooksPath={no_hooks}", "checkout", head, "--",
                          *restore[i:i + _CHECKOUT_CHUNK])
        if cp.returncode != 0:
            raise Refused(f"red proof could not be run: git could not put the test "
                          f"files back after backing the fix out ({_said(cp)})")


def red_proof(root: Path, commit: str, head: str, argv: list[str],
              timeout_s: float) -> dict:
    """Show that the command FAILS once `commit` is backed out of `head`,
    with the control described in the module docstring. Both are full shas,
    `head` the one the caller records on the event. Returns what the event
    records; raises `Refused` when red cannot be shown."""
    base = gitutil.first_parent(root, commit)
    if base is None:
        raise Refused(f"red proof backs the fix out, and {commit[:12]} has no parent "
                      f"commit to go back to")
    changed = _changed(root, base, commit)
    named = _named_paths(argv)
    kept = [rel for status, rel in changed
            if status == "A" or _is_test_path(rel) or rel in named]
    backed_out = len(changed) - len(kept)
    if not backed_out:
        raise Refused(f"{commit[:12]} changes no existing source file -- only tests, or "
                      f"only new files. Red proof backs the commit out and reruns the "
                      f"test, so there is nothing it could take away")
    held = _held(root, head)

    tmp = Path(tempfile.mkdtemp(prefix="aramid-close-"))
    wt = tmp / "wt"
    no_hooks = tmp / "no-hooks"
    no_hooks.mkdir()
    linked = False
    try:
        cp = gitutil._run(root, "worktree", "add", "--detach", str(wt), head)
        if cp.returncode != 0:
            raise Refused(f"red proof could not be run: git worktree add failed "
                          f"({_said(cp)})")
        try:
            linked = js_mutation._link_node_modules(root, wt)
        except OSError as exc:
            raise Refused(f"red proof could not be run: node_modules could not be "
                          f"linked into the worktree ({exc})") from None
        env = worktree_import_env(wt)

        control = _run(argv, root, wt, timeout_s, env)
        if control.state is not ToolState.OK or control.returncode != 0:
            how = (f"exits {control.returncode}" if control.state is ToolState.OK
                   else f"did not run ({_unfinished(control, timeout_s)})")
            raise Refused(f"red proof could not be run: the test passes in the repo but "
                          f"{how} in a clean checkout of HEAD -- it depends on "
                          f"something that is not committed (an untracked file, a "
                          f"build step, an install), so a failure without the fix "
                          f"would prove nothing")

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
                more = f" and {len(stuck) - 1} more file(s)" if len(stuck) > 1 else ""
                raise Refused(f"red proof could not be run: {commit[:12]} can no longer be "
                              f"backed out of HEAD -- it conflicts with later changes to "
                              f"{stuck[0]}{more}")
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
        return {"base": base, "control_rc": 0, "pre_fix_rc": before.returncode,
                "backed_out": backed_out}
    finally:
        try:
            if linked:
                # BEFORE the directory goes: removing through the link would
                # reach the repo's real node_modules (js_mutation invariant).
                js_mutation._unlink_node_modules(wt)
            gitutil._run(root, "worktree", "remove", "--force", str(wt))
            gitutil._run(root, "worktree", "prune")
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            print(f"aramid: ledger resolve: worktree cleanup leaked at {wt}",
                  file=sys.stderr)
