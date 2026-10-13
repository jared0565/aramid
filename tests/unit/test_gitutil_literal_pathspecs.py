"""FN-42: a repo path aramid hands git is a path, never a pattern or an option.

git reads a path after `--` as a pathspec, so `app/[id]/page.test.ts` is a
character class that also names `app/i/page.test.ts`; and a path that comes
before any `--` and starts with `-` is an option. Each case asks git the old
way too, as a CONTROL that must still give the wrong answer in its fixture: a
fixture that stopped making the collision would otherwise pass unseen."""
import subprocess
from pathlib import Path

from aramid import gitutil

BRACKETED = "app/[id]/page.test.ts"
SIBLING = "app/i/page.test.ts"


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)


def _repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    for args in (("init", "-b", "main"), ("config", "user.email", "t@t"),
                 ("config", "user.name", "t"), ("config", "core.autocrlf", "false")):
        assert _git(r, *args).returncode == 0
    return r


def _commit(root: Path, files: dict[str, str], msg: str) -> str:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    assert _git(root, "add", "-A").returncode == 0
    assert _git(root, "commit", "-q", "-m", msg).returncode == 0
    return _git(root, "rev-parse", "HEAD").stdout.strip()


def test_the_one_spelling_marks_every_path_literal():
    assert gitutil.literal_pathspec(["a.py", BRACKETED]) == [
        "--", ":(literal)a.py", f":(literal){BRACKETED}"]


def test_newest_commit_touching_names_the_bracketed_files_own_commit(tmp_path):
    r = _repo(tmp_path)
    own = _commit(r, {BRACKETED: "a\n"}, "the bracketed file")
    sibling = _commit(r, {SIBLING: "b\n"}, "a sibling the pattern also names")
    control = _git(r, "log", "-1", "--format=%H", "HEAD", "--", BRACKETED)
    assert control.stdout.strip() == sibling, "control: unmarked, [id] is a character class"

    assert gitutil.newest_commit_touching(r, None, BRACKETED) == own
    assert gitutil.newest_commit_touching(r, None, SIBLING) == sibling
    assert gitutil.newest_commit_touching(r, f"{own}..HEAD", BRACKETED) == "HEAD", \
        "no commit in the range touched it"


def test_diff_text_scoped_to_a_bracketed_path_leaves_the_sibling_out(tmp_path):
    """The scoping exists to keep what `filter_paths` dropped out of an
    outbound packet (`review.build_packet`)."""
    r = _repo(tmp_path)
    base = _commit(r, {"README.md": "r\n"}, "base")
    head = _commit(r, {BRACKETED: "a\n", SIBLING: "b\n"}, "both")
    for control in (_git(r, "diff", "--name-only", f"{base}..{head}", "--", BRACKETED),
                    _git(r, "show", "--format=", "--name-only", head, "--", BRACKETED)):
        assert sorted(control.stdout.split()) == sorted([BRACKETED, SIBLING]), \
            "control: unmarked, the sibling is in the diff"

    for since in (base, None):
        text = gitutil.diff_text(r, since, head, paths=[BRACKETED])
        assert f"b/{BRACKETED}" in text
        assert SIBLING not in text
    plain = gitutil.diff_text(r, base, head, paths=[SIBLING])
    assert f"b/{SIBLING}" in plain
    assert "[id]" not in plain


def test_is_tracked_reads_an_untracked_bracketed_path_as_untracked(tmp_path):
    r = _repo(tmp_path)
    _commit(r, {"lib/a/u.ts": "tracked\n"}, "a")
    untracked = "lib/[ab]/u.ts"
    (r / "lib" / "[ab]").mkdir()
    (r / untracked).write_text("working\n", encoding="utf-8")
    assert _git(r, "ls-files", "--error-unmatch", untracked).returncode == 0, \
        "control: unmarked, [ab] names the tracked lib/a/u.ts"

    assert gitutil.is_tracked(r, untracked) is False
    assert gitutil.is_tracked(r, "lib/a/u.ts") is True
    assert gitutil.read_for_fingerprint(r, "HEAD", untracked) == "working\n", \
        "an untracked file is fingerprinted from the working tree"


def test_is_tracked_reads_a_path_that_starts_with_a_dash_as_a_path(tmp_path):
    r = _repo(tmp_path)
    _commit(r, {"a.py": "x\n"}, "a")
    (r / "-x.py").write_text("y\n", encoding="utf-8")
    assert _git(r, "ls-files", "--error-unmatch", "-x.py").returncode == 0, \
        "control: before any --, -x.py is ls-files' -x option, and no path is named"

    assert gitutil.is_tracked(r, "-x.py") is False
    assert _git(r, "add", "--", "-x.py").returncode == 0
    assert _git(r, "commit", "-q", "-m", "track it").returncode == 0
    assert gitutil.is_tracked(r, "-x.py") is True


def test_a_caller_that_set_git_literal_pathspecs_does_not_blind_the_mark(tmp_path, monkeypatch):
    """`git --literal-pathspecs commit` hands its hooks GIT_LITERAL_PATHSPECS=1
    (measured 2026-10-12), and with it set git does not read `:(literal)`: the
    mark becomes part of a name no file has."""
    r = _repo(tmp_path)
    base = _commit(r, {"README.md": "r\n"}, "base")
    head = _commit(r, {BRACKETED: "a\n", SIBLING: "b\n"}, "both")
    monkeypatch.setenv("GIT_LITERAL_PATHSPECS", "1")
    control = _git(r, "log", "-1", "--format=%H", "HEAD", "--", f":(literal){BRACKETED}")
    assert control.returncode == 0 and control.stdout.strip() == "", \
        "control: with the variable set, the marked path names nothing"

    assert gitutil.newest_commit_touching(r, None, BRACKETED) == head
    assert gitutil.is_tracked(r, BRACKETED) is True
    text = gitutil.diff_text(r, base, head, paths=[BRACKETED])
    assert f"b/{BRACKETED}" in text and SIBLING not in text


def test_a_blob_read_of_an_untracked_bracketed_path_finds_no_blob(tmp_path):
    """`<rev>:<path>` names a blob, but with no `--` after it git reads an
    argument that names no object and holds a wildcard as a pathspec, and
    `git show` answers rc 0 with HEAD's commit or with nothing (measured
    2026-10-13 on git 2.53, and on 2.55 in CI)."""
    r = _repo(tmp_path)
    _commit(r, {"lib/a/u.ts": "tracked\n", BRACKETED: "a\n"}, "a")
    untracked = "lib/[ab]/u.ts"
    (r / "lib" / "[ab]").mkdir()
    (r / untracked).write_text("working\n", encoding="utf-8")
    controls = [_git(r, "show", spec).returncode for spec in (f"HEAD:{untracked}", f":{untracked}")]
    assert 0 in controls, "control: with no --, git reads one form or the other as a pathspec"

    for ref in ("HEAD", ":"):
        assert gitutil.read_blob(r, ref, untracked) == ""
        assert gitutil.read_blob(r, ref, BRACKETED) == "a\n"
        assert gitutil.read_for_fingerprint(r, ref, untracked) == "working\n"
    assert gitutil.blob_at(r, "HEAD", untracked) is None, "no blob, not an empty one"
    assert gitutil.blob_at(r, "HEAD", BRACKETED) == "a\n"
