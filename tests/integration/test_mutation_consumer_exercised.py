"""Integration: the mutation consumer grades only what the suite ran from
the worktree (interop round 327; operator decisions 2026-11-23). Real git
worktrees and real pytest on a tiny repo, as tests/integration/
test_mutation_consumer.py does.

The reported shape: a test command that runs the suite in the main checkout
(graphite's ran a dev venv whose editable install named it), so a mutant
written into the worktree is never the code under test and every one reads
as a survivor. Each arm below is a test command; the control and the
untested module grade as before, a wrapper is withheld with a note (one
passing aramid's environment on, and one starting its suite without it), and
a command aramid cannot observe at all (`python -E`) grades as before with a
note."""
import os
import subprocess
import sys

from aramid import config as config_mod
from aramid.consumers import mutation as mut_consumer
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.queue import QueueItem

ADULT = ("def is_adult(age):\n"
         "    if age >= 18:\n"
         "        return True\n"
         "    return False\n")
WEAK_TEST = ("from calc import is_adult\n"
             "def test_type():\n"
             "    assert isinstance(is_adult(5), bool)\n")
NO_IMPORT_TEST = "def test_nothing_imports_calc():\n    assert True\n"
PYTEST = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


def _toml_list(argv):
    return "[" + ", ".join(f"'{a}'" for a in argv) + "]"


def _repo(tmp_path, test_body, command=None, extra_files=()):
    r = tmp_path / "r"
    (r / "tests").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    toml = ("schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 3\n"
            "wall_budget_s = 300\nmutant_timeout_s = 60\n")
    if command is not None:
        toml += f"test_command = {_toml_list(command)}\n"
    (r / "aramid.toml").write_text(toml, encoding="utf-8")
    (r / "conftest.py").write_text("import sys, pathlib\n"
                                   "sys.path.insert(0, str(pathlib.Path(__file__).parent))\n",
                                   encoding="utf-8")
    (r / "calc.py").write_text("def is_adult(age):\n    return False\n", encoding="utf-8")
    (r / "tests" / "test_calc.py").write_text(test_body, encoding="utf-8")
    for name, content in extra_files:
        (r / name).write_text(content, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "calc.py").write_text(ADULT, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)


def _consume(r, base, head, monkeypatch, tmp_path):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id="q1", base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")
    try:
        return mut_consumer.consume(item, DrainContext(root=r, cfg=cfg, ledger=led,
                                                       clock=lambda: "t"))
    finally:
        led.close()


def test_the_suite_run_from_the_worktree_is_graded_as_before(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok"
    assert res.findings and all("mutant survived" in f.message for f in res.findings)
    assert res.extra["not_exercised"] == 0 and res.extra["imports_unobserved"] == 0
    assert "not graded" not in res.note and "import check" not in res.note


def test_a_suite_run_in_the_main_checkout_is_not_graded(tmp_path, monkeypatch):
    """The reported bug: the wrapper runs pytest in `r` itself, so the
    worktree's mutants are never imported. Before, every one survived."""
    runner = ("import subprocess, sys\n"
              f"CANON = {str(tmp_path / 'r')!r}\n"
              "sys.exit(subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p',"
              " 'no:cacheprovider'], cwd=CANON).returncode)\n")
    r, base, head = _repo(tmp_path, WEAK_TEST, command=[sys.executable, "run_elsewhere.py"],
                          extra_files=[("run_elsewhere.py", runner)])

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["not_exercised"] == 1 and res.extra["tested"] == 0
    assert ("; 1 file(s) not graded, their mutants were not the code under test: calc.py "
            "(imported from ") in res.note
    assert res.note.endswith(f"{os.sep}r{os.sep}calc.py)")
    assert "aramid-mut-" not in res.note


def test_a_wrapper_whose_suite_has_an_environment_of_its_own_is_not_graded(tmp_path, monkeypatch):
    """Round 327's shape as reported: "PYTHONPATH precedes site-packages on
    sys.path, but nothing sets it" -- the wrapper starts its suite without
    aramid's environment, so the suite writes no bytecode at all. The
    wrapper's own imports still show that nothing ran from the worktree."""
    runner = ("import os, subprocess, sys\n"
              f"CANON = {str(tmp_path / 'r')!r}\n"
              "env = {k: v for k, v in os.environ.items() if not k.startswith('PYTHON')}\n"
              "sys.exit(subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p',"
              " 'no:cacheprovider'], cwd=CANON, env=env).returncode)\n")
    r, base, head = _repo(tmp_path, WEAK_TEST, command=[sys.executable, "run_elsewhere.py"],
                          extra_files=[("run_elsewhere.py", runner)])

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["not_exercised"] == 1 and res.extra["imports_unobserved"] == 0
    assert res.note.endswith("; 1 file(s) not graded, their mutants were not the code under "
                             "test: calc.py (the tests ran nothing from the tree under test)")


def test_an_untested_module_is_graded_as_before(tmp_path, monkeypatch):
    """The suite ran from the worktree and never imported calc.py: its
    survivors are the real gap, and stay findings."""
    r, base, head = _repo(tmp_path, NO_IMPORT_TEST)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.findings and all("mutant survived" in f.message for f in res.findings)
    assert res.extra["not_exercised"] == 0 and res.extra["imports_unobserved"] == 0


def test_a_command_aramid_cannot_observe_is_graded_with_a_note(tmp_path, monkeypatch):
    """`-E` ignores every PYTHON* variable, the cache prefix among them."""
    r, base, head = _repo(tmp_path, WEAK_TEST, command=[sys.executable, "-E", *PYTEST[1:]])

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.findings and all("mutant survived" in f.message for f in res.findings)
    assert res.extra["imports_unobserved"] == 1 and res.extra["not_exercised"] == 0
    assert res.note.endswith(
        "; the import check saw no Python process under aramid's environment (a command "
        "that runs Python isolated, or with an environment of its own, hides it), so "
        "mutants were graded unchecked")
