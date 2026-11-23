"""`gitutil.main_checkout`: the main checkout a linked `git worktree` belongs
to (interop round 343, operator decision 2026-11-23). A gate run in a
worktree credits its fleet row to the registered repo through it, and
`aramid init` in a worktree registers the main checkout through it."""
import subprocess

from aramid import gitutil


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout


def _main(tmp_path):
    m = tmp_path / "main"
    m.mkdir()
    _git(m, "init", "-q", "-b", "main")
    _git(m, "config", "user.email", "t@t")
    _git(m, "config", "user.name", "t")
    (m / "a.txt").write_text("a\n")
    _git(m, "add", "-A")
    _git(m, "commit", "-q", "-m", "seed")
    return m


def test_a_linked_worktree_names_its_main_checkout(tmp_path):
    m = _main(tmp_path)
    _git(m, "worktree", "add", "-q", str(tmp_path / "wt"), "-b", "feature")

    assert gitutil.main_checkout(tmp_path / "wt") == m.resolve()


def test_from_a_subdirectory_of_the_worktree_too(tmp_path):
    m = _main(tmp_path)
    _git(m, "worktree", "add", "-q", str(tmp_path / "wt"), "-b", "feature")
    sub = tmp_path / "wt" / "deep"
    sub.mkdir()

    assert gitutil.main_checkout(sub) == m.resolve()


def test_the_main_checkout_belongs_to_no_other(tmp_path):
    assert gitutil.main_checkout(_main(tmp_path)) is None


def test_a_worktree_of_a_bare_repo_has_no_main_checkout(tmp_path):
    m = _main(tmp_path)
    bare = tmp_path / "bare.git"
    _git(tmp_path, "clone", "-q", "--bare", str(m), str(bare))
    _git(bare, "worktree", "add", "-q", str(tmp_path / "wt"), "-b", "feature")

    assert gitutil.main_checkout(tmp_path / "wt") is None


def test_outside_a_repo_there_is_no_answer(tmp_path):
    d = tmp_path / "outside"
    d.mkdir()
    assert gitutil._run(d, "rev-parse", "--is-inside-work-tree").returncode != 0
    assert gitutil.main_checkout(d) is None
