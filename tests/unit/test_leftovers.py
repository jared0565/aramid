"""The leftover sweep: what a killed consumer or a Windows file lock left
behind in the temp dir, removed by the next drain. Old shells and stale
worktree registrations go; anything young or locked stays; dirs that are
not ours are never touched; a dir that will not go is reported, not raised."""
import os
import subprocess
import time
from pathlib import Path

from aramid import leftovers

DAY = 24 * 3600


def _git(root, *a):
    return subprocess.run(["git", "-C", str(root), *a],
                          capture_output=True, text=True, check=False)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "a.py")
    _git(r, "commit", "-q", "-m", "one")
    return r


def _age(path: Path, seconds: float) -> None:
    then = time.time() - seconds
    os.utime(path, (then, then))


def _registered(root) -> list[str]:
    out = _git(root, "worktree", "list", "--porcelain").stdout
    return [ln.split(" ", 1)[1] for ln in out.splitlines() if ln.startswith("worktree ")]


def _names(paths) -> list[str]:
    return sorted(Path(p).name for p in paths)


def test_old_leftover_dirs_go_and_young_ones_stay(tmp_path):
    root = _repo(tmp_path)
    temp = tmp_path / "temp"
    old = temp / "aramid-mut-old1234"
    (old / "wt").mkdir(parents=True)
    _age(old, DAY)
    young = temp / "aramid-red-new1234"
    (young / "wt").mkdir(parents=True)

    report = leftovers.sweep(root, temp=temp)

    assert not old.exists()
    assert young.exists()
    assert _names(report.removed) == ["aramid-mut-old1234"]
    assert _names(report.kept_young) == ["aramid-red-new1234"]
    assert report.failed == [] and report.kept_live == []


def test_a_stale_registration_goes_with_its_dir(tmp_path):
    root = _repo(tmp_path)
    temp = tmp_path / "temp"
    shell = temp / "aramid-red-stale123"
    shell.mkdir(parents=True)
    wt = shell / "wt"
    assert _git(root, "worktree", "add", "--detach", str(wt), "HEAD").returncode == 0
    _age(shell, DAY)
    assert len(_registered(root)) == 2

    report = leftovers.sweep(root, temp=temp)

    assert len(_registered(root)) == 1
    assert not shell.exists()
    assert _names(report.removed) == ["aramid-red-stale123"]


def test_a_locked_registration_is_never_touched_however_old(tmp_path):
    root = _repo(tmp_path)
    temp = tmp_path / "temp"
    shell = temp / "aramid-fuzz-live1234"
    shell.mkdir(parents=True)
    wt = shell / "wt"
    assert _git(root, "worktree", "add", "--detach", str(wt), "HEAD").returncode == 0
    assert _git(root, "worktree", "lock", "--reason", "aramid fuzz running", str(wt)).returncode == 0
    _age(shell, DAY)

    report = leftovers.sweep(root, temp=temp)

    assert len(_registered(root)) == 2
    assert wt.exists()
    assert _names(report.kept_live) == ["aramid-fuzz-live1234"]
    assert report.removed == []


def test_dirs_that_are_not_ours_are_not_the_sweeps_business(tmp_path):
    root = _repo(tmp_path)
    temp = tmp_path / "temp"
    for name in ("aramid-cwd-abc123", "pytest-of-someone", "aramid-mut"):
        d = temp / name
        d.mkdir(parents=True)
        _age(d, DAY)
    f = temp / "aramid-mut-afile12"      # right prefix, but a file
    f.write_text("", encoding="utf-8")
    _age(f, DAY)

    report = leftovers.sweep(root, temp=temp)

    assert sorted(p.name for p in temp.iterdir()) == [
        "aramid-cwd-abc123", "aramid-mut", "aramid-mut-afile12", "pytest-of-someone"]
    assert report.removed == [] and report.kept_young == [] and report.failed == []


def test_dry_run_names_what_it_would_remove_and_removes_nothing(tmp_path):
    root = _repo(tmp_path)
    temp = tmp_path / "temp"
    old = temp / "aramid-jsmut-old12345"
    (old / "wt").mkdir(parents=True)
    _age(old, DAY)
    shell = temp / "aramid-red-stale123"
    shell.mkdir(parents=True)
    assert _git(root, "worktree", "add", "--detach", str(shell / "wt"), "HEAD").returncode == 0
    _age(shell, DAY)

    report = leftovers.sweep(root, temp=temp, dry_run=True)

    assert old.exists() and shell.exists()
    assert len(_registered(root)) == 2
    assert _names(report.removed) == ["aramid-jsmut-old12345", "aramid-red-stale123"]


def test_a_missing_temp_dir_is_an_empty_sweep(tmp_path):
    root = _repo(tmp_path)
    report = leftovers.sweep(root, temp=tmp_path / "nope")
    assert report.removed == [] and report.failed == []


def test_a_dir_that_will_not_go_is_reported_not_raised(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    temp = tmp_path / "temp"
    stuck = temp / "aramid-mut-stuck123"
    (stuck / "wt").mkdir(parents=True)
    _age(stuck, DAY)
    monkeypatch.setattr(leftovers.shutil, "rmtree", lambda *a, **k: None)

    report = leftovers.sweep(root, temp=temp)

    assert stuck.exists()
    assert _names(report.failed) == ["aramid-mut-stuck123"]
    assert report.removed == []
