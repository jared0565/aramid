"""`aramid init` ALWAYS regenerates ARAMID.md, and until now said nothing.

The file is aramid-owned and TRACKED, so a regeneration that changes it leaves
the consumer's tree dirty with a file they did not write, no line of output
saying so, and nothing that ever mentions it again. In one consumer it sat
uncommitted long enough that another repo's agent reported it as an open item.

Deliberately a NOTICE, not an auto-commit. Committing inside a consumer's repo
would mean choosing their branch/author/signing policy, and would need
`--no-verify` to avoid `init` re-entering aramid's own pre-commit gate -- i.e.
shipping a hook bypass in the tool whose entire purpose is that the hook runs.
The same operator asked in interop round 117 that shadow-resistance be
automated, and the answer there was "report it every run", not "remediate it".
"""
import subprocess
from pathlib import Path

from aramid.commands.init import render_aramid_md_notice


def _repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    for a in (("init", "-q"), ("config", "user.email", "t@t"),
              ("config", "user.name", "t")):
        subprocess.run(["git", *a], cwd=r, check=True, capture_output=True)
    (r / "seed.txt").write_text("x")
    subprocess.run(["git", "add", "-A"], cwd=r, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=r, check=True, capture_output=True)
    return r


def _commit_all(r: Path) -> None:
    subprocess.run(["git", "add", "-A"], cwd=r, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "add"], cwd=r, check=True, capture_output=True)


def test_untracked_aramid_md_is_reported(tmp_path):
    r = _repo(tmp_path)
    (r / "ARAMID.md").write_text("# generated\n")
    notice = render_aramid_md_notice(r)
    assert "ARAMID.md" in notice
    assert "git add ARAMID.md" in notice, "must give the command, not just a complaint"


def test_a_committed_and_unchanged_aramid_md_is_SILENT(tmp_path):
    """The common path. A line on every re-init is noise that trains people to
    skip the whole summary."""
    r = _repo(tmp_path)
    (r / "ARAMID.md").write_text("# generated\n")
    _commit_all(r)
    assert render_aramid_md_notice(r) == ""


def test_a_regenerated_aramid_md_that_CHANGED_is_reported(tmp_path):
    r = _repo(tmp_path)
    (r / "ARAMID.md").write_text("# generated v1\n")
    _commit_all(r)
    (r / "ARAMID.md").write_text("# generated v2 -- template moved\n")
    notice = render_aramid_md_notice(r)
    assert "ARAMID.md" in notice


def test_no_aramid_md_at_all_is_silent(tmp_path):
    assert render_aramid_md_notice(_repo(tmp_path)) == ""


def test_a_git_failure_is_silent_rather_than_a_false_alarm(tmp_path):
    """Not a git repo at all: report nothing. Telling someone to commit a file
    in a directory git does not manage is worse than saying nothing."""
    d = tmp_path / "plain"
    d.mkdir()
    (d / "ARAMID.md").write_text("# generated\n")
    assert render_aramid_md_notice(d) == ""
