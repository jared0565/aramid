"""FN-58's reader stays cheap where branches are many.

The first cut asked every branch tip for every departed path with its own `git show`,
then the merge base and `git show` again. Measured 2026-10-25 (Windows, a scratch repo, 10
files deleted at HEAD and 50 stale branches cut before the delete): 60 s for one
`resolve_departed` call. Two facts make most of that unnecessary:

  - a tip the certified revision reaches (a merged branch, a stale one) is its own merge base
    with it, so it holds nothing that revision lacks: `for-each-ref --no-merged` leaves it
    out, one git process per certified revision however many there are;
  - whether a path is at a tip is one `ls-tree` per tip, cached, whatever the number of
    paths asked about.

These count git processes, which is what a gate pays for on Windows."""
import subprocess

from aramid import gitutil
from aramid.departure import Departure


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _repo(root, *, deleted, merged=0, unmerged=0):
    """`deleted` test files committed at c1 and removed at c2 (HEAD on main); `merged` branches
    left at c1 (HEAD reaches them); `unmerged` branches cut at c1, each with one commit of its
    own that touches none of those files (every one INHERITS them)."""
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    names = [f"tests/test_{i}.py" for i in range(deleted)]
    for name in [*names, "keep.py"]:
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x = 1\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "c1")
    for b in range(merged):
        _git(root, "branch", f"stale{b}")
    for b in range(unmerged):
        _git(root, "checkout", "-q", "-b", f"snap{b}")
        (root / f"own{b}.py").write_text("y = 2\n", encoding="utf-8")
        _git(root, "add", "-A")
        _git(root, "commit", "-q", "-m", f"snap{b}")
        _git(root, "checkout", "-q", "main")
    _git(root, "rm", "-q", *names)
    _git(root, "commit", "-q", "-m", "c2 deletes them")
    return names


def _counted(monkeypatch):
    calls = []
    run = gitutil._run

    def counting(root, *args):
        calls.append(args[0])
        return run(root, *args)
    monkeypatch.setattr(gitutil, "_run", counting)
    return calls


def _gone(root, names, calls):
    reader = Departure(root)
    before = len(calls)
    assert all(reader.gone(name) for name in names)
    return len(calls) - before


def test_a_merged_branch_costs_no_git_process_at_all(tmp_path, monkeypatch):
    calls = _counted(monkeypatch)
    one = _gone(tmp_path / "one", _repo(tmp_path / "one", deleted=1, merged=1), calls)
    many = _gone(tmp_path / "many", _repo(tmp_path / "many", deleted=1, merged=12), calls)
    assert many == one, calls


def test_the_branch_walk_does_not_grow_with_the_paths_asked_about(tmp_path, monkeypatch):
    calls = _counted(monkeypatch)
    one = _gone(tmp_path / "one", _repo(tmp_path / "one", deleted=1, unmerged=3), calls)
    ten = _gone(tmp_path / "ten", _repo(tmp_path / "ten", deleted=10, unmerged=3), calls)
    assert ten == one, calls


def test_a_branch_and_its_tracking_ref_at_one_commit_are_read_once(tmp_path, monkeypatch):
    """Every pushed branch is listed twice, local and remote-tracking, at one commit: the tips
    are commits, each read once, not refs."""
    calls = _counted(monkeypatch)
    alone = _gone(tmp_path / "alone", _repo(tmp_path / "alone", deleted=1, unmerged=3), calls)
    names = _repo(tmp_path / "pushed", deleted=1, unmerged=3)
    for b in range(3):
        _git(tmp_path / "pushed", "update-ref", f"refs/remotes/origin/snap{b}", f"snap{b}")
    assert _gone(tmp_path / "pushed", names, calls) == alone, calls
