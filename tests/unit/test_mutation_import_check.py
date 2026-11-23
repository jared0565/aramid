"""The mutation consumer's import check (interop round 327; operator
decisions 2026-11-23): does the suite run the worktree's copy of each file
it mutates?

The baseline run gets a fresh PYTHONPYCACHEPREFIX beside the worktree, so
every Python process that inherits aramid's environment writes the bytecode
of what it imports there, as a mirror of each source's absolute path
(measured 2026-11-23: the drive letter is dropped on Windows, a child
started with a modified environment still writes, `python -I` writes
nothing, and nothing lands in the worktree). These tests write that
bytecode with the real interpreter, so the mirror is CPython's own on every
platform CI runs.

  - nothing written at all: no process was observed -- grade as today;
  - nothing written for the worktree: nothing ran from it -- withhold
    every file, naming where each was imported from, if anywhere;
  - otherwise per file: imported from the worktree -- grade; imported from
    elsewhere -- withhold; imported from nowhere -- an untested module,
    graded as today."""
import os
import subprocess
import sys
from pathlib import PurePosixPath

import pytest

from aramid.consumers import mutation as mut


def _tree(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _child(probe, path_entries, code):
    """A real interpreter under the baseline's environment, importing."""
    env = {**os.environ, "PYTHONPYCACHEPREFIX": str(probe), "PYTHONDONTWRITEBYTECODE": "",
           "PYTHONPATH": os.pathsep.join(str(p) for p in path_entries)}
    cp = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr


def test_a_module_imported_from_the_worktree_is_seen_there(tmp_path):
    wt, probe = tmp_path / "wt", tmp_path / "probe"
    _tree(wt, {"pkg/__init__.py": "", "pkg/mod.py": "X = 1\n"})
    _child(probe, [wt], "import pkg.mod")

    check = mut.import_check(probe, wt, ["pkg/mod.py", "pkg/__init__.py"])

    assert check == mut.ImportCheck(observed=True, from_wt=True, where={
        "pkg/mod.py": mut.WORKTREE, "pkg/__init__.py": mut.WORKTREE})
    assert mut.ungraded(check) == {}


def test_a_src_layout_module_is_seen_in_the_worktree_too(tmp_path):
    wt, probe = tmp_path / "wt", tmp_path / "probe"
    _tree(wt, {"src/pkg/__init__.py": "", "src/pkg/mod.py": "X = 1\n"})
    _child(probe, [wt / "src"], "import pkg.mod")

    assert mut.import_check(probe, wt, ["src/pkg/mod.py"]).where == {
        "src/pkg/mod.py": mut.WORKTREE}


def test_a_module_imported_from_another_tree_is_named_and_withheld(tmp_path):
    """The reported shape: the suite ran from the worktree (its helper came
    from there), but the module under mutation came from the main checkout."""
    wt, other, probe = tmp_path / "wt", tmp_path / "main", tmp_path / "probe"
    _tree(wt, {"helper.py": "", "src/pkg/__init__.py": "", "src/pkg/mod.py": "X = 1\n"})
    _tree(other, {"src/pkg/__init__.py": "", "src/pkg/mod.py": "X = 2\n"})
    _child(probe, [other / "src", wt], "import helper, pkg.mod")

    check = mut.import_check(probe, wt, ["src/pkg/mod.py"])

    assert check.observed and check.from_wt
    where = check.where["src/pkg/mod.py"]
    assert where.endswith(os.sep.join(["main", "src", "pkg", "mod.py"]))
    assert "wt" + os.sep not in where
    assert mut.ungraded(check) == {"src/pkg/mod.py": where}


@pytest.mark.parametrize("rel", ["src/pkg/mod.py", "pkg/mod.py"])
def test_the_other_copy_is_found_by_its_package_whatever_the_layout(tmp_path, rel):
    """An installed copy (no `src/`), imported beside a same-named module of
    another package that sorts first: the path named is this package's."""
    wt, site, probe = tmp_path / "wt", tmp_path / "site", tmp_path / "probe"
    _tree(wt, {"helper.py": "", rel: "X = 1\n", str(PurePosixPath(rel).parent / "__init__.py"): ""})
    _tree(site, {"aaa/__init__.py": "", "aaa/mod.py": "", "pkg/__init__.py": "",
                 "pkg/mod.py": "X = 2\n"})
    _child(probe, [site, wt], "import helper, aaa.mod, pkg.mod")

    where = mut.import_check(probe, wt, [rel]).where[rel]

    assert where is not None and where.endswith(os.sep.join(["site", "pkg", "mod.py"])), where


def test_when_nothing_ran_from_the_worktree_every_file_is_withheld(tmp_path):
    """A wrapper that runs the suite in the main checkout: every file is
    withheld, the one it imported named, the one it never imported too."""
    wt, other, probe = tmp_path / "wt", tmp_path / "main", tmp_path / "probe"
    _tree(wt, {"calc.py": "X = 1\n", "rates.py": "Y = 1\n"})
    _tree(other, {"calc.py": "X = 2\n"})
    _child(probe, [other], "import calc")

    check = mut.import_check(probe, wt, ["calc.py", "rates.py"])

    assert check.observed and not check.from_wt
    assert check.where["rates.py"] is None
    assert check.where["calc.py"].endswith(os.sep.join(["main", "calc.py"]))
    assert mut.ungraded(check) == {"calc.py": check.where["calc.py"], "rates.py": None}


def test_an_untested_module_is_graded_as_today(tmp_path):
    """The suite ran from the worktree and simply never imported it."""
    wt, probe = tmp_path / "wt", tmp_path / "probe"
    _tree(wt, {"helper.py": "", "untested.py": "X = 1\n"})
    _child(probe, [wt], "import helper")

    check = mut.import_check(probe, wt, ["untested.py"])

    assert check == mut.ImportCheck(observed=True, from_wt=True, where={"untested.py": None})
    assert mut.ungraded(check) == {}


def test_no_bytecode_at_all_means_nothing_was_observed(tmp_path):
    """`python -I` or an environment of its own: grade as today."""
    wt, probe = tmp_path / "wt", tmp_path / "probe"
    _tree(wt, {"calc.py": "X = 1\n"})
    probe.mkdir()

    for p in (probe, tmp_path / "never-made"):
        check = mut.import_check(p, wt, ["calc.py"])
        assert check == mut.ImportCheck(observed=False, from_wt=False, where={})
        assert mut.ungraded(check) == {}


def test_the_baseline_env_writes_bytecode_to_the_probe_only(tmp_path):
    wt, probe = tmp_path / "wt", tmp_path / "probe"
    env = mut.baseline_env(wt, probe)
    assert env["PYTHONPYCACHEPREFIX"] == str(probe)
    assert env["PYTHONDONTWRITEBYTECODE"] == ""
    assert env["PYTHONPATH"].split(os.pathsep)[:2] == [str(wt / "src"), str(wt)]


def test_the_mirror_is_cpythons_own(tmp_path, monkeypatch):
    """`_mirror` must agree with `cache_from_source` under a prefix, a UNC
    share included: CPython strips only an `X:` drive."""
    import importlib.util
    probe = tmp_path / "probe"
    monkeypatch.setattr(sys, "pycache_prefix", str(probe))
    dirs = [tmp_path / "wt" / "src" / "pkg"]
    if os.name == "nt":
        dirs.append(r"\server\share\repo\pkg")
    for d in dirs:
        want = importlib.util.cache_from_source(os.path.join(str(d), "mod.py"))
        assert str(mut._mirror(probe, d)) == os.path.dirname(want), d


def test_a_worktree_path_differing_only_in_case_is_the_worktree_on_windows(tmp_path):
    pyc = tmp_path / "Probe" / "WT" / "calc.cpython-314.pyc"
    assert mut._within(pyc, tmp_path / "probe" / "wt") is (os.name == "nt")
    assert mut._within(pyc, tmp_path / "Probe" / "WT")
    assert not mut._within(tmp_path / "Probe" / "WTX" / "calc.pyc", tmp_path / "Probe" / "WT")
