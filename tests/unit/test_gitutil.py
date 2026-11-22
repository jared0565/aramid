import subprocess
import sys
from pathlib import Path

import pytest

from aramid import gitutil

def _git(root, *a): subprocess.run(["git", *a], cwd=root, check=True,
                                   capture_output=True, text=True)

def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    return r

def _commit(root: Path, name: str, content: str, msg: str) -> None:
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", name], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", msg], cwd=root, check=True, capture_output=True)

def test_repo_root_and_blob(tmp_path):
    r = _repo(tmp_path)
    (r / "a.py").write_text("print(1)\n")
    _git(r, "add", "a.py")
    _git(r, "commit", "-m", "x")
    assert gitutil.repo_root(r / ".") == r.resolve()
    assert gitutil.read_blob(r, "HEAD", "a.py") == "print(1)\n"

def test_not_a_repo_raises(tmp_path):
    import pytest
    with pytest.raises(gitutil.NotARepo):
        gitutil.repo_root(tmp_path)

def test_armed_root_is_the_git_root_only_where_aramid_init_ran(tmp_path, monkeypatch):
    """FN-30: the one rule the SessionStart hook, the MCP tools and `aramid
    handover` resolve a repo by. Since 0.20.4 it decides where a handover
    file lands, so it lives once, here."""
    r = _repo(tmp_path)
    (r / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    sub = r / "src" / "pkg"
    sub.mkdir(parents=True)
    assert gitutil.armed_root(r) == r.resolve()
    assert gitutil.armed_root(sub) == r.resolve(), "a subdirectory resolves to the root"
    monkeypatch.chdir(sub)
    assert gitutil.armed_root(None) == r.resolve(), "no start means the cwd"

    plain = tmp_path / "plain"
    plain.mkdir()
    _git(plain, "init", "-b", "main")
    assert gitutil.armed_root(plain) is None, "a repo aramid never armed"
    (plain / "aramid.toml").mkdir()
    assert gitutil.armed_root(plain) is None, "a directory named aramid.toml is not the file"
    bare = tmp_path / "bare"
    bare.mkdir()
    assert gitutil.armed_root(bare) is None, "a directory outside git"
    assert gitutil.armed_root(tmp_path / "nowhere") is None, "a path that does not exist"

def test_resolve_range_new_branch_no_remote_returns_none(tmp_path):
    # spec §3 invariant: a brand-new branch with no upstream/origin must NOT hard-error;
    # resolve_range returns None meaning "scan all commits reachable from HEAD".
    r = _repo(tmp_path)
    (r / "a.py").write_text("x=1\n")
    _git(r, "add", "a.py")
    _git(r, "commit", "-m", "c1")
    assert gitutil.resolve_range(r) is None

def test_read_for_fingerprint_untracked_uses_worktree(tmp_path):
    r = _repo(tmp_path)
    (r / "u.py").write_bytes(b"secret=1\r\n")   # untracked, CRLF (write_bytes: avoid
    # Windows text-mode newline translation on write, which would otherwise turn the
    # literal \r\n into \r\r\n before it ever reaches read_for_fingerprint)
    content = gitutil.read_for_fingerprint(r, "HEAD", "u.py")
    assert content == "secret=1\n"            # non-empty, LF-normalized

def test_read_for_fingerprint_reads_an_untracked_file_as_utf8(tmp_path, cp1252_locale):
    """A tracked file's text comes from `git show`, which gitutil decodes as
    UTF-8. The untracked fallback read the worktree in the locale code page,
    so on Windows the same line hashed differently once the file was added.
    A byte that is not UTF-8 is still replaced, never raised."""
    r = _repo(tmp_path)
    (r / "u.py").write_bytes('name = "naïve"\r\n'.encode("utf-8") + b'raw = "\xff"\n')
    assert gitutil.read_for_fingerprint(r, "HEAD", "u.py") == \
        'name = "naïve"\nraw = "�"\n'

def test_rev_sha_and_first_parent(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    root_sha = gitutil.rev_sha(r, "HEAD")
    assert root_sha and len(root_sha) == 40
    assert gitutil.first_parent(r, "HEAD") is None  # root commit
    _commit(r, "b.py", "y = 2\n", "second")
    assert gitutil.first_parent(r, "HEAD") == root_sha
    assert gitutil.rev_sha(r, "not-a-rev") is None


def test_diff_paths_single_commit_and_root(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    head1 = gitutil.rev_sha(r, "HEAD")
    assert gitutil.diff_paths(r, None, head1) == ["a.py"]  # root commit: full tree
    _commit(r, "sub/b.py", "y = 2\n", "second")
    head2 = gitutil.rev_sha(r, "HEAD")
    assert gitutil.diff_paths(r, head1, head2) == ["sub/b.py"]


def test_diff_text_contains_added_lines_and_truncates(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    h1 = gitutil.rev_sha(r, "HEAD")
    _commit(r, "a.py", "x = 1\nexec(x)  # обед\n", "second")
    h2 = gitutil.rev_sha(r, "HEAD")
    text = gitutil.diff_text(r, h1, h2)
    assert "+exec(x)" in text
    full = gitutil.diff_text(r, h1, h2)
    full_bytes = len(full.encode("utf-8"))
    assert len(full) < full_bytes  # precondition: multi-byte content present
    cap = full_bytes - 2  # cut lands inside the trailing multi-byte run
    truncated = gitutil.diff_text(r, h1, h2, max_bytes=cap)
    assert len(truncated.encode("utf-8")) <= cap
    assert truncated != full  # naive char-slice would return the FULL text here


def test_diff_text_cuts_at_400_000_bytes_by_default(monkeypatch):
    # The default cap at its edge, on git's answer as given: one byte over
    # is cut to the cap, and a text at the cap comes back whole.
    def answer(text):
        return lambda root, *args: subprocess.CompletedProcess(args, 0, text, "")
    monkeypatch.setattr(gitutil, "_run", answer("x" * 400_001))
    assert gitutil.diff_text(Path("."), "a", "b") == "x" * 400_000
    monkeypatch.setattr(gitutil, "_run", answer("x" * 400_000))
    assert gitutil.diff_text(Path("."), "a", "b") == "x" * 400_000


def test_diff_text_decodes_utf8_not_locale_codec(tmp_path):
    # FIX 3 regression: _run's subprocess.run(..., text=True) used to decode
    # with the locale-preferred codec (no encoding= kwarg). On this dev box
    # (Windows, cp1252 preferred encoding, UTF-8 mode off) that mojibakes
    # git's UTF-8 output -- reproducing the bug locally. CI (windows-latest,
    # Python 3.12, also cp1252-preferred) is the real proving ground for the
    # harder failure mode: a byte sequence cp1252 can't decode at all raises
    # UnicodeDecodeError and would crash triage's per-commit diff scan.
    r = _repo(tmp_path)
    _commit(r, "a.py", "# café\n", "first")
    h1 = gitutil.rev_sha(r, "HEAD")
    _commit(r, "a.py", "# café\n# Привет\n", "second")
    h2 = gitutil.rev_sha(r, "HEAD")
    text = gitutil.diff_text(r, h1, h2)
    assert "café" in text
    assert "Привет" in text
    assert "Ã©" not in text  # mojibake marker: utf-8 "é" mis-decoded as cp1252


def test_diff_text_paths_scoping(tmp_path):
    # FIX 3 regression: the `paths=` pathspec passed to diff_text scopes the
    # diff to exactly those files -- an unscoped diff of two changed files
    # shows both; scoped to one path shows only that file (no other file's
    # header/hunk text leaks in).
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    h1 = gitutil.rev_sha(r, "HEAD")
    (r / "a.py").write_text("x = 2\n", encoding="utf-8")
    (r / "b.py").write_text("y = 1\n", encoding="utf-8")
    _git(r, "add", "a.py", "b.py")
    _git(r, "commit", "-m", "second")
    h2 = gitutil.rev_sha(r, "HEAD")

    unscoped = gitutil.diff_text(r, h1, h2)
    assert "a.py" in unscoped and "b.py" in unscoped

    scoped = gitutil.diff_text(r, h1, h2, paths=["a.py"])
    assert "a.py" in scoped
    assert "b.py" not in scoped

def test_diff_new_lines_maps_changed_lines(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\ny = 2\nz = 3\n", "c1")
    base = gitutil.rev_sha(r, "HEAD")
    _commit(r, "a.py", "x = 1\ny = 99\nz = 3\nw = 4\n", "c2")
    head = gitutil.rev_sha(r, "HEAD")
    assert gitutil.diff_new_lines(r, base, head) == {"a.py": {2, 4}}

def test_diff_new_lines_root_commit_and_deletion(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "c1")
    head = gitutil.rev_sha(r, "HEAD")
    # base=None (root/bootstrap): whole file counts as new
    assert gitutil.diff_new_lines(r, None, head) == {"a.py": {1}}
    # pure deletion contributes nothing on the new side
    base = head
    _commit(r, "b.py", "q = 1\n", "c2")
    (r / "a.py").unlink()
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "c3")
    head2 = gitutil.rev_sha(r, "HEAD")
    assert "a.py" not in gitutil.diff_new_lines(r, base, head2)


def test_blob_at_tells_an_empty_file_from_a_missing_one(tmp_path):
    """`read_blob` answers "" for both, and a resolver that reads "" as
    "no lines" would treat "git could not say" as a departed file. `blob_at`
    answers None when git has no blob: missing, untracked, or a path that
    escapes the tree."""
    r = _repo(tmp_path)
    _commit(r, "empty.py", "", "empty")
    _commit(r, "full.py", "x = 1\n", "full")
    (r / "untracked.py").write_text("y = 2\n", encoding="utf-8")
    assert gitutil.blob_at(r, "HEAD", "empty.py") == ""
    assert gitutil.blob_at(r, "HEAD", "full.py") == "x = 1\n"
    assert gitutil.blob_at(r, "HEAD", "missing.py") is None
    assert gitutil.blob_at(r, "HEAD", "untracked.py") is None
    assert gitutil.blob_at(r, "HEAD", "../outside.py") is None


def test_resolve_range_falls_back_to_origin_head_merge_base(tmp_path):
    """The drain confirms a mutant against the unit suite alone, and the
    merge-base fallback (`mb.returncode == 0`) plus `range_commits`' own
    return-code test were reached only through tests/integration."""
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "base")
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, check=True,
                          capture_output=True, text=True).stdout.strip()
    assert gitutil.resolve_range(r) is None, "no upstream, no origin/HEAD"

    _git(r, "update-ref", "refs/remotes/origin/main", "HEAD")
    _git(r, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    _commit(r, "a.py", "x = 2\n", "head")
    assert gitutil.resolve_range(r) == f"{base}..HEAD"

    _git(r, "update-ref", "refs/remotes/origin/main", "HEAD")
    assert gitutil.resolve_range(r) == f"{gitutil.rev_sha(r, 'HEAD')}..HEAD"

    _git(r, "remote", "add", "origin", str(r))
    _git(r, "branch", "--set-upstream-to=origin/main")
    assert gitutil.resolve_range(r) == "@{u}..HEAD"


def test_range_commits_lists_the_range_or_head_and_is_empty_for_a_bad_spec(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "one")
    first = gitutil.rev_sha(r, "HEAD")
    _commit(r, "a.py", "x = 2\n", "two")
    second = gitutil.rev_sha(r, "HEAD")
    assert gitutil.range_commits(r, None) == [second, first]
    assert gitutil.range_commits(r, f"{first}..HEAD") == [second]
    assert gitutil.range_commits(r, "nope..HEAD") == []


# --- a new branch in a clone without origin/HEAD (round 233) ----------------

def test_resolve_range_new_branch_without_origin_head_diffs_against_the_remote(tmp_path):
    """demo-store2, channel round 233 (2026-09-19): a clone made by `git init`
    + `git remote add` never has refs/remotes/origin/HEAD, so the first push
    of a NEW BRANCH fell through to the full-history sentinel meant for a
    brand-new repo -- and gitleaks reported two secrets that live only in
    old commits as live BLOCKs at the current line numbers. The push's real
    delta is what no remote-tracking ref has yet: the base is the newest
    commit already on any remote."""
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "base")
    base = gitutil.rev_sha(r, "HEAD")
    _git(r, "update-ref", "refs/remotes/origin/main", "HEAD")   # a remote ref; no origin/HEAD, no upstream
    _git(r, "checkout", "-q", "-b", "feature")
    _commit(r, "a.py", "x = 2\n", "head")

    assert gitutil.resolve_range(r) == f"{base}..HEAD"


def test_resolve_range_new_branch_at_a_commit_the_remote_holds_is_an_empty_range(tmp_path):
    """A branch created at a commit the remote already has pushes no
    commits: tip..HEAD, not the whole history."""
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "base")
    _git(r, "update-ref", "refs/remotes/origin/main", "HEAD")
    _git(r, "checkout", "-q", "-b", "feature")

    assert gitutil.resolve_range(r) == f"{gitutil.rev_sha(r, 'HEAD')}..HEAD"


def test_resolve_range_uses_the_closest_of_several_remote_refs(tmp_path):
    """`origin/old` behind the branch point, `origin/main` at it: the base is
    the branch point. (`git merge-base HEAD a b` is the base of HEAD and a
    hypothetical merge of a and b.)"""
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "old")
    _git(r, "update-ref", "refs/remotes/origin/old", "HEAD")
    _commit(r, "a.py", "x = 2\n", "main")
    point = gitutil.rev_sha(r, "HEAD")
    _git(r, "update-ref", "refs/remotes/origin/main", "HEAD")
    _git(r, "checkout", "-q", "-b", "feature")
    _commit(r, "a.py", "x = 3\n", "head")

    assert gitutil.resolve_range(r) == f"{point}..HEAD"


def test_resolve_range_is_none_when_the_only_remote_ref_shares_no_history(tmp_path):
    """A remote ref with no common ancestor (an orphan branch, a remote of
    another project) fails the merge-base: None, i.e. the full-history
    scan, never a bare "..HEAD" range."""
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "ours")
    _git(r, "checkout", "-q", "--orphan", "elsewhere")
    _git(r, "rm", "-q", "--cached", "a.py")
    _commit(r, "b.py", "y = 1\n", "theirs")
    _git(r, "update-ref", "refs/remotes/origin/elsewhere", "HEAD")
    (r / "a.py").unlink()          # untracked on this branch; it would block the checkout
    _git(r, "checkout", "-q", "main")

    assert gitutil.resolve_range(r) is None


# A name git escapes: U+02D0 is two UTF-8 bytes above 0x7F, so with
# core.quotePath on (git's default) a listing that is not `-z` prints it as
# "pronounced-a\313\220ramid.js" -- quotes, backslashes and octal included.
_ODD = "pronounced-a" + chr(0x2D0) + "ramid.js"


def _quoting_repo(tmp_path) -> Path:
    """`_repo` with git's default quoting forced on in the repo itself, so the
    answer is the same whatever the developer's global config says."""
    r = _repo(tmp_path)
    _git(r, "config", "core.quotePath", "true")
    return r


def test_every_name_listing_returns_a_non_ascii_name_as_it_is_on_disk(tmp_path):
    """aramid read git's name listings line by line, so every runner was
    handed the ESCAPED name, a file that does not exist. Measured on the
    published 0.20.14: `check --all` copied nothing for gitleaks to scan, so a
    secret in that file was missed with no word said, and semgrep exited 2
    for the whole repo. `-z` hands over the name as it is on disk."""
    r = _quoting_repo(tmp_path)
    (r / _ODD).write_text("t = 1\n", encoding="utf-8")
    _git(r, "add", "--", _ODD)
    assert gitutil.staged_files(r) == [_ODD]
    _git(r, "commit", "-m", "root")
    root = gitutil.rev_sha(r, "HEAD")
    assert gitutil.diff_paths(r, None, root) == [_ODD]
    _commit(r, _ODD, "t = 1\nu = 2\n", "second")
    head = gitutil.rev_sha(r, "HEAD")
    assert gitutil.all_tracked_files(r) == [_ODD]
    assert (r / gitutil.all_tracked_files(r)[0]).is_file()
    assert gitutil.changed_files(r, f"{root}..HEAD") == [_ODD]
    assert gitutil.diff_paths(r, root, head) == [_ODD]


def test_the_changed_line_map_keys_a_non_ascii_name_as_it_is_on_disk(tmp_path):
    """`diff_new_lines` reads the name from the `+++ b/...` header, which git
    escapes the same way and which has no `-z` form."""
    r = _quoting_repo(tmp_path)
    _commit(r, _ODD, "t = 1\n", "root")
    root = gitutil.rev_sha(r, "HEAD")
    assert gitutil.diff_new_lines(r, None, root) == {_ODD: {1}}
    _commit(r, _ODD, "t = 1\nu = 2\n", "second")
    assert gitutil.diff_new_lines(r, root, gitutil.rev_sha(r, "HEAD")) == {_ODD: {2}}


def test_the_changed_line_map_decodes_every_escape_git_writes_in_a_header(monkeypatch):
    """git also escapes a quote, a backslash and control characters whatever
    core.quotePath says. Windows cannot put those in a file name, so this
    arm is git's own output as given; it runs on every platform."""
    patch = ('+++ "b/a\\"q\\\\s\\tt\\303\\251.py"\n'
             "@@ -0,0 +1 @@\n+x\n"
             "+++ b/plain.py\n"
             "@@ -0,0 +3,2 @@\n+y\n+z\n")
    monkeypatch.setattr(gitutil, "_run",
                        lambda root, *args, **kw: subprocess.CompletedProcess(args, 0, patch, ""))
    assert gitutil.diff_new_lines(Path("."), "a", "b") == {
        'a"q\\s\tt' + chr(0xE9) + ".py": {1}, "plain.py": {3, 4}}


def test_a_changed_line_that_starts_with_two_pluses_is_not_a_file_header(tmp_path):
    """Under --unified=0 an added line reading `++ two` is printed `+++ two`,
    and a removed `-- x` is printed `--- x`: the spelling of a file header.
    Read as one, the file's next hunk was credited to a path named `two` and
    its own changed lines dropped -- a mutation or fuzz run scoped to that
    file then missed them (reported by the drain's llm-review 2026-11-21; in
    the parser since v0.1.0). A hunk's body is the line counts its header
    gives; nothing inside it is a header. A pure deletion keys nothing."""
    r = _repo(tmp_path)
    ten = [f"l{i}" for i in range(1, 11)]
    _commit(r, "a.md", "\n".join(ten) + "\n", "c1")
    _commit(r, "c.md", "\n".join(["k1", "-- x", *ten]) + "\n", "c2")
    _commit(r, "f.md", "\n".join(ten) + "\n", "c3")
    base = gitutil.rev_sha(r, "HEAD")
    a = list(ten)
    a[1], a[8] = "++ two", "nine!"
    (r / "a.md").write_text("\n".join(a) + "\n", encoding="utf-8")
    c = ["k1", "++ y", *ten]
    c[10] = "changed"
    (r / "c.md").write_text("\n".join(c) + "\n", encoding="utf-8")
    (r / "f.md").write_text("\n".join(ten[:2] + ten[3:]) + "\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "c4")
    assert gitutil.diff_new_lines(r, base, gitutil.rev_sha(r, "HEAD")) == {
        "a.md": {2, 9}, "c.md": {2, 11}}


@pytest.mark.parametrize("brk", ["\x0c", "\r", " "], ids=["form-feed", "lone-cr", "u2028"])
def test_a_line_break_git_does_not_end_lines_with_stays_inside_its_hunk_line(tmp_path, brk):
    """git ends a patch line with `\\n` and nothing else. 0.20.16 split the
    patch with `str.splitlines()`, which also breaks on a form feed and on
    U+2028, and read it through a text-mode pipe, which turns a lone `\\r`
    into `\\n`. One changed line `z<break>@@ -1,0 +1,50 @@` then counted as
    two, the second read as a hunk header, and its 50-line "body" swallowed
    b.md's change (drain llm-review 2026-11-21, row 74bc559a; reproduced on
    the installed 0.20.16). 0.20.15 over-scoped the same input and kept b.md."""
    r = _repo(tmp_path)
    _git(r, "config", "core.autocrlf", "false")
    (r / "a.md").write_bytes(b"l1\nl2\nl3\n")
    (r / "b.md").write_bytes(b"x\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "c1")
    base = gitutil.rev_sha(r, "HEAD")
    (r / "a.md").write_bytes(("l1\nz" + brk + "@@ -1,0 +1,50 @@\nl3\n").encode("utf-8"))
    (r / "b.md").write_bytes(b"x\ny\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "c2")
    assert gitutil.diff_new_lines(r, base, gitutil.rev_sha(r, "HEAD")) == {
        "a.md": {2}, "b.md": {2}}


def test_a_no_newline_marker_inside_a_hunk_is_not_one_of_its_lines(tmp_path):
    """`\\ No newline at end of file` qualifies the hunk line before it and is
    not one of the lines the header counts, so the parse goes on past it to
    the next file. (Counting it would end the hunk a line early, which no
    diff git writes can show: the marker only sits in a file's last hunk,
    and the next file's own header comes before any hunk of its own.)"""
    r = _repo(tmp_path)
    _commit(r, "d.md", "d1\nlast", "c1")
    _commit(r, "e.md", "e1\n", "c2")
    base = gitutil.rev_sha(r, "HEAD")
    (r / "d.md").write_text("d1\n++ z", encoding="utf-8")
    (r / "e.md").write_text("e1\ne2\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "c3")
    assert gitutil.diff_new_lines(r, base, gitutil.rev_sha(r, "HEAD")) == {
        "d.md": {2}, "e.md": {2}}


def test_a_quoted_name_keeps_the_digits_that_follow_an_ordinary_character(tmp_path):
    """`\\ooo` is an escape only after a backslash: in `caf\\303\\251-2024.py`
    the `-202` that follows the escapes is three characters of the name."""
    r = _quoting_repo(tmp_path)
    name = "caf" + chr(0xE9) + "-2024.py"
    _commit(r, name, "t = 1\n", "root")
    assert gitutil.diff_new_lines(r, None, gitutil.rev_sha(r, "HEAD")) == {name: {1}}


# A git that names `caf\xe9.py` in Latin-1, as Linux lets a file be named:
# raw in a `-z` listing and in an unquoted header (core.quotePath false), and
# C-quoted in a header (`caf\351.md`). Windows and macOS cannot create such
# a name, so this stands in for git on every platform.
_LATIN1_GIT = r'''
import sys
out = sys.stdout.buffer
if "--unified=0" in sys.argv:
    out.write(b"diff --git a/caf\xe9.py b/caf\xe9.py\n--- /dev/null\n+++ b/caf\xe9.py\n"
              b"@@ -0,0 +1 @@\n+x\n"
              b'diff --git "a/caf\\351.md" "b/caf\\351.md"\n--- /dev/null\n+++ "b/caf\\351.md"\n'
              b"@@ -0,0 +1 @@\n+y\n"
              b"diff --git a/plain.py b/plain.py\n--- /dev/null\n+++ b/plain.py\n"
              b"@@ -0,0 +1,2 @@\n+p\n+q\n")
else:
    out.write(b"caf\xe9.py\0plain.py\0")
'''


def test_a_name_that_is_not_utf8_is_left_out_and_said_once(monkeypatch, capsys):
    """Measured in WSL Ubuntu on 0.20.15: handed a Latin-1 name, which aramid
    decoded to `caf�.py`, ruff reported `No such file` for it, semgrep
    skipped the file without a word, and `check --all` missed a token in it.
    Handed the real bytes, ruff and gitleaks report the file under another
    name and semgrep still skips it. So such a name is left out of every
    listing and of the changed-line map, and the run says so once per name.
    gitleaks' commit and push scans read git themselves and still see it."""
    monkeypatch.setattr(gitutil, "_GIT", (sys.executable, "-c", _LATIN1_GIT))
    monkeypatch.setattr(gitutil, "_UNREADABLE_SAID", set(), raising=False)
    root = Path(".")
    assert gitutil.staged_files(root) == ["plain.py"]
    assert gitutil.all_tracked_files(root) == ["plain.py"]
    assert gitutil.changed_files(root, None) == ["plain.py"]
    assert gitutil.diff_paths(root, None, "h") == ["plain.py"]
    assert gitutil.diff_paths(root, "b", "h") == ["plain.py"]
    assert gitutil.diff_new_lines(root, "b", "h") == {"plain.py": {1, 2}}
    assert capsys.readouterr().err.splitlines() == [
        "aramid: git: caf\\xe9.py is not handed to the tools: its name is not valid UTF-8",
        "aramid: git: caf\\xe9.md is not handed to the tools: its name is not valid UTF-8"]


def test_a_listing_hands_the_names_it_left_out_to_its_caller(monkeypatch):
    """The gate's three listings take a list to put each left-out name in,
    so the gate can count the file as unscanned (operator decision
    2026-11-22: a coverage gap, not only a stderr line)."""
    monkeypatch.setattr(gitutil, "_GIT", (sys.executable, "-c", _LATIN1_GIT))
    root = Path(".")
    for listing in (lambda sink: gitutil.staged_files(root, left_out=sink),
                    lambda sink: gitutil.all_tracked_files(root, left_out=sink),
                    lambda sink: gitutil.changed_files(root, None, left_out=sink)):
        sink: list[str] = []
        assert listing(sink) == ["plain.py"]
        assert sink == ["caf\udce9.py"]
    assert gitutil.shown_name("caf\udce9.py") == "caf\\xe9.py"


def test_a_listed_name_keeps_a_carriage_return_it_holds(monkeypatch):
    """A `-z` listing ends a name with NUL, so a `\\r` inside one is part of
    the name (Linux allows it). Read through a text-mode pipe it became `\\n`,
    a file that does not exist; the listings now take git's bytes as they are."""
    monkeypatch.setattr(gitutil, "_GIT", (
        sys.executable, "-c", r'import sys; sys.stdout.buffer.write(b"a\rb.py\0c\r\nd.py\0plain.py\0")'))
    root = Path(".")
    want = ["a\rb.py", "c\r\nd.py", "plain.py"]
    assert gitutil.staged_files(root) == want
    assert gitutil.all_tracked_files(root) == want
    assert gitutil.changed_files(root, None) == want
    assert gitutil.diff_paths(root, None, "h") == want
    assert gitutil.diff_paths(root, "b", "h") == want


def test_the_left_out_name_is_printed_with_no_control_character_left_raw(monkeypatch, capsys):
    """The name is the repo's to choose, and a terminal acts on what it is
    printed: a name holding an escape sequence as well as a byte that is not
    UTF-8 must reach stderr as text, its control characters escaped."""
    monkeypatch.setattr(gitutil, "_GIT", (
        sys.executable, "-c", r'import sys; sys.stdout.buffer.write(b"\x1b[2J\tx\xe9.py\0")'))
    monkeypatch.setattr(gitutil, "_UNREADABLE_SAID", set())
    assert gitutil.all_tracked_files(Path(".")) == []
    assert capsys.readouterr().err.splitlines() == [
        "aramid: git: \\x1b[2J\\tx\\xe9.py is not handed to the tools: its name is not valid UTF-8"]
