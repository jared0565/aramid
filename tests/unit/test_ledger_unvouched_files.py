"""`Ledger.record_run(unvouched_files=)`: nothing recorded under a file the run
could not hand any tool resolves (operator decision 2026-11-22).

gitleaks' commit scan reads git itself, so it still catches a secret in a file
whose name is not valid UTF-8, and records it under the name it reports: one
U+FFFD per byte that is not UTF-8 (measured, gitleaks 8.30.1). No revision
holds that name, so the departed check read the file as gone, and the next
`check --all`, which leaves such a file out, closed the secret's row while the
secret was still staged. A run that left the file out cannot vouch for it.
"""
import subprocess

import pytest

from aramid.ledger import Ledger
from aramid.models import Gate, Severity, Verdict
from aramid.normalizer import RawFinding, normalize

GONE = "caf�.py"


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    for args in (("init", "-b", "main"), ("config", "user.email", "t@t"),
                 ("config", "user.name", "t")):
        subprocess.run(["git", *args], cwd=r, check=True, capture_output=True)
    (r / "plain.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "plain.py"], cwd=r, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "base"], cwd=r, check=True, capture_output=True)
    return r


def _finding(root):
    raw = RawFinding(tool="gitleaks", rule="github-pat", severity_raw="high", file=GONE,
                     line=2, message="m", line_content='TOKEN = "placeholder"')
    return normalize([raw], root, lambda f: "HEAD", b"salt", Gate.PRE_COMMIT,
                     lambda *a: (Severity.HIGH, Verdict.BLOCK))[0]


@pytest.mark.parametrize("unvouched, status", [(frozenset({GONE}), "open"), (frozenset(), "fixed")])
def test_a_row_under_a_file_the_run_could_not_hand_a_tool_does_not_depart(
        tmp_path, unvouched, status):
    root = _repo(tmp_path)
    ledger = Ledger(tmp_path / "l.db")
    try:
        found = _finding(root)
        ledger.record_run("commit", "2026-11-22T00:00:00Z", "pre-commit", {"gitleaks"},
                          {"plain.py"}, [found], root=root)
        # A whole-tree check: gitleaks ran over every file it was handed and
        # found nothing, and the odd file was not one of them.
        ledger.record_run("all", "2026-11-22T00:01:00Z", "pre-commit", {"gitleaks"},
                          {"plain.py"}, [], root=root, unvouched_files=unvouched)
        assert ledger.open_findings()[found.id]["status"] == status
    finally:
        ledger.close()
