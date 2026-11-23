"""Red proof and pytest's "did not run" exits (interop round 335 item 3;
operator decision 2026-11-23).

Red proof reads any non-zero exit without the fix as red. pytest also exits
non-zero when the test never ran: 4 when a test or file the command names is
not found, 5 when nothing was collected. Measured 2026-11-23 with a real red
proof: a test added to a file the fix MODIFIED, outside every test location
aramid recognises (pytest finds it through `python_files`), selected with -k
and naming no file -- the file was backed out with the fix, pytest exited 5,
and that was accepted as red. For a pytest command, 4 and 5 are now refused;
2 (a collection error, such as an import of what the fix added) still reads
as red, as the user guide's limits say, and other runners are unchanged."""
import subprocess
import sys

import pytest

from aramid import evidenced_close
from aramid.runners.base import RunnerResult, ToolState

CHECK_C1 = "import calc\n\n\ndef test_eu():\n    assert calc.route('FR') == 'EU'\n"
CHECK_C2 = CHECK_C1 + "\n\ndef test_cn_routes_to_asia():\n    assert calc.route('CN') == 'ASIA'\n"
CALC_FIXED = "def route(c):\n    if c == 'CN':\n        return 'ASIA'\n    return 'EU'\n"
PYTEST = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir=."]
BY_K = PYTEST + ["-k", "cn_routes"]


@pytest.mark.parametrize("argv, runs", [
    (["pytest", "-q"], True),
    (["py.test"], True),
    (["C:/venv/Scripts/pytest.exe", "-x"], True),
    (["C:\\venv\\Scripts\\PYTEST.EXE"], True),
    ([sys.executable, "-m", "pytest", "-k", "cn"], True),
    (["python", "-X", "dev", "-m", "pytest"], True),
    (["uv", "run", "pytest", "tests"], True),
    (["poetry", "run", "py.test"], True),
    (["uv", "run", "python", "-m", "pytest"], True),
    (["python", "tests/check_cn.py"], False),
    (["npx", "vitest", "run", "-t", "pytest"], False),
    (["python", "-m", "unittest", "pytest"], False),
    (["uv", "run", "python", "check.py"], False),
    (["uv", "sync", "pytest"], False),
    (["uv", "run"], False),
    (["pytest-watch"], False),
    (["python", "-m"], False),
    ([], False),
])
def test_runs_pytest_reads_the_program_not_any_word(argv, runs):
    assert evidenced_close.runs_pytest(argv) is runs


def _git(root, *args):
    cp = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                         "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
                        cwd=root, capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    return cp.stdout.strip()


@pytest.fixture
def hollow(tmp_path):
    """c1: the bug, and a check file pytest collects (`python_files`) that
    no aramid naming rule calls a test. c2: the fix, and a new test function
    in that MODIFIED file."""
    root, empty = tmp_path / "repo", tmp_path / "empty-template"
    root.mkdir()
    empty.mkdir()
    _git(root, "init", "-q", f"--template={empty}", "-b", "main")
    (root / ".gitignore").write_text("__pycache__/\n.pytest_cache/\n", encoding="utf-8")
    (root / "pytest.ini").write_text("[pytest]\npython_files = check_*.py\n", encoding="utf-8")
    (root / "calc.py").write_text("def route(c):\n    return 'EU'\n", encoding="utf-8")
    (root / "checks").mkdir()
    (root / "checks" / "check_routes.py").write_text(CHECK_C1, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "c1")
    (root / "calc.py").write_text(CALC_FIXED, encoding="utf-8")
    (root / "checks" / "check_routes.py").write_text(CHECK_C2, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "c2")
    return root, _git(root, "rev-parse", "HEAD")


def _refusal(commit, rc, why, *, at_commit=False):
    where = (f"at {commit[:12]}, with that commit backed out," if at_commit
             else f"with {commit[:12]} backed out")
    return (f"red proof could not be shown: {where} pytest exited {rc} ({why}) -- the test "
            f"did not run there, so it proves nothing. If {commit[:12]} changed the file "
            f"the test is in, name that file in the command: red proof then runs it as "
            f"HEAD has it")


def test_a_test_backed_out_with_the_fix_is_not_red(hollow):
    """The measured case, real pytest: without the fix nothing is collected."""
    root, c2 = hollow
    with pytest.raises(evidenced_close.Refused) as caught:
        evidenced_close.red_proof(root, c2, c2, BY_K, 120.0)
    assert str(caught.value) == _refusal(c2, 5, "no tests were collected")


def test_the_same_test_named_by_its_file_is_red(hollow):
    """The control arm, real pytest: named, the file stays at HEAD, and the
    test runs without the fix and fails."""
    root, c2 = hollow
    proof = evidenced_close.red_proof(
        root, c2, c2, PYTEST + ["checks/check_routes.py", "-k", "cn_routes"], 120.0)
    assert proof["pre_fix_rc"] == 1


_OK = RunnerResult("python", ToolState.OK, returncode=0)


def _scripted(monkeypatch, *codes):
    """The runs answer exit 0 and then each of `codes`, in order."""
    queue = [_OK, *(RunnerResult("python", ToolState.OK, returncode=c) for c in codes)]
    monkeypatch.setattr(evidenced_close, "run_subprocess",
                        lambda argv, cwd, timeout_s, env=None: queue.pop(0))


def test_a_named_test_pytest_cannot_find_is_not_red(hollow, monkeypatch):
    root, c2 = hollow
    _scripted(monkeypatch, 4)
    with pytest.raises(evidenced_close.Refused) as caught:
        evidenced_close.red_proof(root, c2, c2, BY_K, 120.0)
    assert str(caught.value) == _refusal(
        c2, 4, "a test or file the command names was not found")


@pytest.mark.parametrize("rc", [1, 2, 3])
def test_every_other_pytest_failure_is_still_red(hollow, monkeypatch, rc):
    root, c2 = hollow
    _scripted(monkeypatch, rc)
    assert evidenced_close.red_proof(root, c2, c2, BY_K, 120.0)["pre_fix_rc"] == rc


@pytest.mark.parametrize("rc", [4, 5])
def test_a_command_that_is_not_pytest_keeps_every_exit_as_red(hollow, monkeypatch, rc):
    root, c2 = hollow
    _scripted(monkeypatch, rc)
    proof = evidenced_close.red_proof(root, c2, c2, ["npx", "vitest", "run"], 120.0)
    assert proof["pre_fix_rc"] == rc


def test_at_the_fix_commit_too(hollow, monkeypatch):
    """c3 rewrites the fixed line, so c2 no longer backs out of HEAD and the
    proof moves to c2 itself: the same refusal, said there."""
    root, c2 = hollow
    (root / "calc.py").write_text(CALC_FIXED.replace("'ASIA'", "'ASIA-PAC'"),
                                  encoding="utf-8")
    (root / "checks" / "check_routes.py").write_text(
        CHECK_C2.replace("'ASIA'", "'ASIA-PAC'"), encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "c3")
    c3 = _git(root, "rev-parse", "HEAD")
    _scripted(monkeypatch, 0, 5)
    with pytest.raises(evidenced_close.Refused) as caught:
        evidenced_close.red_proof(root, c2, c3, BY_K, 120.0)
    assert str(caught.value) == _refusal(c2, 5, "no tests were collected", at_commit=True)
