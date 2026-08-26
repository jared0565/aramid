"""`aramid init` writes .gitignore entries into a consumer's tree and, until
now, said nothing about it.

The sibling of `test_init_aramid_md_notice.py` and the same defect class: the
tool edits an artifact in someone else's repo and leaves no line of output
naming it. Measured while verifying round 121 end to end -- a fresh onboard
leaves three untracked files (`.gitignore`, `ARAMID.md`, `aramid.toml`);
`aramid.toml` is announced and ARAMID.md now is, so `.gitignore` was the last
one still silent (interop round 121 section 4, flagged there and deliberately
not bundled into that commit).

One-time rather than recurring, which is the one real difference from
ARAMID.md: `_update_gitignore` only ever writes entries that are MISSING, so a
second `init` is silent by construction rather than by a guard.
"""
import subprocess
from pathlib import Path

from aramid.commands.init import (GITIGNORE_ENTRIES, _update_gitignore,
                                  render_gitignore_notice)


def _repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    for a in (("init", "-q"), ("config", "user.email", "t@t"),
              ("config", "user.name", "t")):
        subprocess.run(["git", *a], cwd=r, check=True, capture_output=True)
    (r / "seed.txt").write_text("x")
    subprocess.run(["git", "add", "-A"], cwd=r, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=r, check=True,
                    capture_output=True)
    return r


def _notice(r: Path) -> str:
    """Drive the writer, then render -- the way `_init_one` does. Rendering
    from a hand-built argument pair would test the formatter against my own
    assumptions rather than against what the writer actually did."""
    added, created = _update_gitignore(r)
    return render_gitignore_notice(r, added, created)


def test_a_created_gitignore_is_reported(tmp_path):
    r = _repo(tmp_path)
    assert not (r / ".gitignore").exists()

    notice = _notice(r)

    assert ".gitignore" in notice
    assert "created" in notice, "a file aramid created should not read as an edit"
    assert "git add .gitignore" in notice, "must give the command, not just a complaint"


def test_appending_to_an_existing_gitignore_is_reported_as_an_edit(tmp_path):
    """A tracked .gitignore that aramid appends to leaves the tree dirty --
    a different situation from creating one, and the operator's `git status`
    will look different, so the notice must not call it a creation."""
    r = _repo(tmp_path)
    (r / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=r, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "gi"], cwd=r, check=True,
                    capture_output=True)

    notice = _notice(r)

    assert ".gitignore" in notice
    assert "created" not in notice, "appending to an existing file is not creating it"
    assert "git add .gitignore" in notice
    # The pre-existing line must survive -- this is the whole reason the writer
    # appends rather than rewrites.
    assert "node_modules/" in (r / ".gitignore").read_text(encoding="utf-8")


def test_the_notice_names_only_the_entries_it_actually_added(tmp_path):
    """The discriminating case. A notice that lists GITIGNORE_ENTRIES wholesale
    would pass every other test here while telling the operator it wrote lines
    that were already there -- and one of those lines is what a teammate would
    go looking for and not find in the diff.
    """
    r = _repo(tmp_path)
    already = GITIGNORE_ENTRIES[0]
    (r / ".gitignore").write_text(f"{already}\n", encoding="utf-8")

    added, created = _update_gitignore(r)
    notice = render_gitignore_notice(r, added, created)

    assert already not in added, "re-added an entry that was already present"
    assert set(added) == set(GITIGNORE_ENTRIES[1:])
    assert already not in notice, (
        f"notice claims to have added {already}, which was already there:\n{notice}")
    for entry in added:
        assert entry in notice, f"notice omits an entry it added ({entry}):\n{notice}"


def test_a_gitignore_that_already_has_every_entry_is_SILENT(tmp_path):
    """The re-init path. A line on every `init` is noise that trains people to
    skip the whole summary -- and here there is genuinely nothing to report,
    because nothing was written."""
    r = _repo(tmp_path)
    (r / ".gitignore").write_text("\n".join(GITIGNORE_ENTRIES) + "\n", encoding="utf-8")

    added, created = _update_gitignore(r)

    assert added == []
    assert created is False
    assert render_gitignore_notice(r, added, created) == ""


def test_a_second_init_is_silent_by_construction(tmp_path):
    """End to end, because the silence above is only worth having if the real
    sequence produces it: write, then write again."""
    r = _repo(tmp_path)
    assert _notice(r) != "", "first init said nothing"
    assert _notice(r) == "", "second init repeated itself"


def test_a_git_failure_is_silent_rather_than_a_false_alarm(tmp_path):
    """Not a git repo at all: report nothing. Telling someone to commit a file
    in a directory git does not manage is worse than saying nothing -- the same
    rule `render_aramid_md_notice` follows."""
    d = tmp_path / "plain"
    d.mkdir()

    added, created = _update_gitignore(d)

    assert added, "the writer should still do its job outside git"
    assert render_gitignore_notice(d, added, created) == ""
