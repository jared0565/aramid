"""`hooks.hooks_dir` in a linked `git worktree` (found measuring interop round
343; operator decision 2026-11-23). There `.git` is a FILE naming the main
repo's git directory, and git runs the hooks of the shared one. Reading
`<root>/.git/hooks` made `aramid init` in a worktree crash (FileExistsError
creating it) and `aramid doctor` there say the gate hooks were missing while
every commit in the worktree went through them. git's own answer is
`git rev-parse --git-path hooks`."""
import subprocess

from aramid import hooks


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout


def _main_and_worktree(tmp_path):
    m = tmp_path / "main"
    m.mkdir()
    _git(m, "init", "-q", "-b", "main")
    _git(m, "config", "user.email", "t@t")
    _git(m, "config", "user.name", "t")
    (m / "a.txt").write_text("a\n")
    _git(m, "add", "-A")
    _git(m, "commit", "-q", "-m", "seed")
    _git(m, "worktree", "add", "-q", str(tmp_path / "wt"), "-b", "feature")
    return m, tmp_path / "wt"


def test_a_worktree_s_hooks_are_the_main_repo_s(tmp_path):
    m, wt = _main_and_worktree(tmp_path)
    assert (wt / ".git").is_file()

    assert hooks.hooks_dir(wt).resolve() == (m / ".git" / "hooks").resolve()


def test_core_hooks_path_still_wins_in_a_worktree(tmp_path):
    m, wt = _main_and_worktree(tmp_path)
    _git(m, "config", "core.hooksPath", "custom-hooks")

    assert hooks.hooks_dir(wt) == (wt / "custom-hooks").resolve()


def test_outside_a_repo_the_path_is_the_conventional_one(tmp_path):
    d = tmp_path / "outside"
    d.mkdir()
    assert hooks.hooks_dir(d) == d / ".git" / "hooks"


def test_install_in_a_worktree_writes_the_shared_hooks(tmp_path):
    m, wt = _main_and_worktree(tmp_path)

    hooks.install(wt, tmp_path / "python.exe")

    shared = m / ".git" / "hooks"
    assert (shared / "pre-commit").is_file() and (shared / "pre-push").is_file()
    assert (wt / ".git").is_file(), "the worktree's .git file is left as it was"
