"""The git pre-push stdin contract, owned by `aramid.pushrefs`.

Interop round 176 (graphite-agent), reproduced here: over smart HTTP git
runs the pre-push hook first and only then resolves the refspec by NAME in
`send-pack`, so a commit made while the hook runs ships while `git push`
prints the pre-hook range. The gate has to know which refs it certified and
notice when one of them moved.
"""
import io
import subprocess
from pathlib import Path

from aramid import pushrefs

ZERO = "0" * 40


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout.strip()


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    _git(r, "commit", "-q", "--allow-empty", "-m", "c0")
    return r


# ------------------------------------------------------------------ parse ---

def test_parse_reads_the_four_fields_git_writes_per_line():
    a, b = "a" * 40, "b" * 40
    got = pushrefs.parse_push_lines(f"refs/heads/main {a} refs/heads/main {b}\n")
    assert got == [pushrefs.PushRef("refs/heads/main", a, "refs/heads/main", b)]


def test_parse_drops_a_deletion_nothing_ships():
    # `git push origin :gone` -> local ref "(delete)" and an all-zero sha.
    assert pushrefs.parse_push_lines(f"(delete) {ZERO} refs/heads/gone {'c' * 40}\n") == []


def test_parse_skips_a_malformed_line_and_keeps_the_rest():
    a = "a" * 40
    text = f"garbage\nrefs/heads/main {a} refs/heads/main {ZERO}\n\n"
    assert [r.local_ref for r in pushrefs.parse_push_lines(text)] == ["refs/heads/main"]


def test_parse_of_nothing_is_nothing():
    assert pushrefs.parse_push_lines("") == []


# ---------------------------------------------------------- read_hook_stdin ---

def test_stdin_is_read_only_under_the_marker(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("refs/heads/main x refs/heads/main y\n"))
    monkeypatch.delenv(pushrefs.HOOK_ENV, raising=False)
    assert pushrefs.read_hook_stdin() is None
    monkeypatch.setenv(pushrefs.HOOK_ENV, "pre-push")
    monkeypatch.setattr("sys.stdin", io.StringIO("refs/heads/main x refs/heads/main y\n"))
    assert pushrefs.read_hook_stdin() == "refs/heads/main x refs/heads/main y\n"


def test_a_tty_is_never_read_even_under_the_marker(monkeypatch):
    class Tty:
        def isatty(self):
            return True

        def read(self):
            raise AssertionError("must not block on a terminal")
    monkeypatch.setenv(pushrefs.HOOK_ENV, "pre-push")
    monkeypatch.setattr("sys.stdin", Tty())
    assert pushrefs.read_hook_stdin() is None


# --------------------------------------------------------- certify + drift ---

def test_a_commit_after_certify_is_drift_naming_both_shas(tmp_path):
    r = _repo(tmp_path)
    before = _git(r, "rev-parse", "HEAD")
    cert = pushrefs.certify(
        r, [pushrefs.PushRef("refs/heads/main", before, "refs/heads/main", ZERO)], hook=True)
    assert cert.head_at_start == before and cert.hook is True
    _git(r, "commit", "-q", "--allow-empty", "-m", "during the hook")
    after = _git(r, "rev-parse", "HEAD")
    assert pushrefs.drift(r, cert) == [pushrefs.Moved("refs/heads/main", before, after)]


def test_no_commit_is_no_drift(tmp_path):
    r = _repo(tmp_path)
    sha = _git(r, "rev-parse", "HEAD")
    cert = pushrefs.certify(
        r, [pushrefs.PushRef("refs/heads/main", sha, "refs/heads/main", ZERO)], hook=True)
    assert pushrefs.drift(r, cert) == []


def test_without_refs_head_itself_is_certified(tmp_path):
    # By hand (no marker) there are no stdin lines: HEAD at start vs now.
    r = _repo(tmp_path)
    before = _git(r, "rev-parse", "HEAD")
    cert = pushrefs.certify(r, [], hook=False)
    assert pushrefs.drift(r, cert) == []
    _git(r, "commit", "-q", "--allow-empty", "-m", "moved")
    after = _git(r, "rev-parse", "HEAD")
    assert pushrefs.drift(r, cert) == [pushrefs.Moved("HEAD", before, after)]


def test_a_ref_that_no_longer_resolves_counts_as_moved(tmp_path):
    # Fail closed on drift: a ref the gate cannot re-resolve is not certified.
    r = _repo(tmp_path)
    sha = _git(r, "rev-parse", "HEAD")
    cert = pushrefs.certify(
        r, [pushrefs.PushRef("refs/heads/gone", sha, "refs/heads/gone", ZERO)], hook=True)
    assert pushrefs.drift(r, cert) == [pushrefs.Moved("refs/heads/gone", sha, None)]


# ----------------------------------------------------------------- render ---

def test_render_is_the_line_the_finding_asked_for():
    moved = [pushrefs.Moved("refs/heads/main", "12a1d68" + "0" * 33, "673c804" + "1" * 33)]
    assert pushrefs.render(moved) == \
        "main moved during the gate: 12a1d68 -> 673c804; re-run the push"


def test_render_names_every_moved_ref_one_per_line():
    moved = [pushrefs.Moved("refs/heads/main", "a" * 40, "b" * 40),
             pushrefs.Moved("refs/heads/dev", "c" * 40, None)]
    assert pushrefs.render(moved).splitlines() == [
        "main moved during the gate: aaaaaaa -> bbbbbbb; re-run the push",
        "dev moved during the gate: ccccccc -> (no longer resolves); re-run the push"]


def test_payload_shapes_are_plain_dicts():
    cert = pushrefs.Certification(
        (pushrefs.PushRef("refs/heads/main", "a" * 40, "refs/heads/main", ZERO),), "a" * 40, True)
    assert pushrefs.payload_refs(cert) == [{"local_ref": "refs/heads/main", "local_sha": "a" * 40,
                                           "remote_ref": "refs/heads/main", "remote_sha": ZERO}]
    assert pushrefs.payload_moved([pushrefs.Moved("refs/heads/main", "a" * 40, "b" * 40)]) == \
        [{"ref": "refs/heads/main", "before": "a" * 40, "after": "b" * 40}]
